 /******************************************************************************
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * xc_gnttab functions:
 * Copyright (c) 2007-2008, D G Murray <Derek.Murray@cl.cam.ac.uk>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ioctl.h>

#include <xen/memory.h>

#include "xenctrl.h"
#include "xenctrlosdep.h"

#define PRIVCMD_DEV     "/dev/xen/privcmd"

#define PERROR(_m, _a...) xc_osdep_log(xch,XTL_ERROR,XC_INTERNAL_ERROR,_m \
                  " (%d = %s)", ## _a , errno, xc_strerror(xch, errno))

/*------------------------- Privcmd device interface -------------------------*/
static xc_osdep_handle freebsd_privcmd_open(xc_interface *xch)
{
    int flags, saved_errno;
    int fd = open(PRIVCMD_DEV, O_RDWR);

    if ( fd == -1 )
    {
        PERROR("Could not obtain handle on privileged command interface "
               PRIVCMD_DEV);
        return XC_OSDEP_OPEN_ERROR;
    }

    /*
     * Although we return the file handle as the 'xc handle' the API
     * does not specify / guarentee that this integer is in fact
     * a file handle. Thus we must take responsiblity to ensure
     * it doesn't propagate (ie leak) outside the process.
     */
    if ( (flags = fcntl(fd, F_GETFD)) < 0 )
    {
        PERROR("Could not get file handle flags");
        goto error;
    }

    flags |= FD_CLOEXEC;

    if ( fcntl(fd, F_SETFD, flags) < 0 )
    {
        PERROR("Could not set file handle flags");
        goto error;
    }

    return (xc_osdep_handle)fd;

 error:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;

    return XC_OSDEP_OPEN_ERROR;
}

static int freebsd_privcmd_close(xc_interface *xch, xc_osdep_handle h)
{
    int fd = (int)h;

    return close(fd);
}

/*------------------------ Privcmd hypercall interface -----------------------*/
static void *freebsd_privcmd_alloc_hypercall_buffer(xc_interface *xch,
                                                    xc_osdep_handle h,
                                                    int npages)
{
    size_t size = npages * XC_PAGE_SIZE;
    void *p;

    /* Address returned by mmap is page aligned. */
    p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,
             -1, 0);
    if (p == NULL)
        return NULL;

    /*
     * Since FreeBSD doesn't have the MAP_LOCKED flag,
     * lock memory using mlock.
     */
    if ( mlock(p, size) < 0 )
    {
        munmap(p, size);
        return NULL;
    }

    return p;
}

static void freebsd_privcmd_free_hypercall_buffer(xc_interface *xch,
                                                  xc_osdep_handle h, void *ptr,
                                                  int npages)
{

    int saved_errno = errno;
    /* Unlock pages */
    munlock(ptr, npages * XC_PAGE_SIZE);

    munmap(ptr, npages * XC_PAGE_SIZE);
    /* We MUST propagate the hypercall errno, not unmap call's. */
    errno = saved_errno;
}

static int freebsd_privcmd_hypercall(xc_interface *xch, xc_osdep_handle h,
                                     privcmd_hypercall_t *hypercall)
{
    int fd = (int)h;
    int ret;

    ret = ioctl(fd, IOCTL_PRIVCMD_HYPERCALL, hypercall);

    return (ret == 0) ? hypercall->retval : ret;
}

/*----------------------- Privcmd foreign map interface ----------------------*/
static void *freebsd_privcmd_map_foreign_bulk(xc_interface *xch,
                                               xc_osdep_handle h,
                                               uint32_t dom, int prot,
                                               const xen_pfn_t *arr, int *err,
                                               unsigned int num)
{
    int fd = (int)h;
    privcmd_mmapbatch_t ioctlx;
    void *addr;
    int rc;

    addr = mmap(NULL, num << XC_PAGE_SHIFT, prot, MAP_SHARED, fd, 0);
    if ( addr == MAP_FAILED )
    {
        PERROR("xc_map_foreign_bulk: mmap failed");
        return NULL;
    }

    ioctlx.num = num;
    ioctlx.dom = dom;
    ioctlx.addr = (unsigned long)addr;
    ioctlx.arr = arr;
    ioctlx.err = err;

    rc = ioctl(fd, IOCTL_PRIVCMD_MMAPBATCH, &ioctlx);
    if ( rc < 0 )
    {
        int saved_errno = errno;
        PERROR("xc_map_foreign_bulk: ioctl failed");
        (void)munmap(addr, num << XC_PAGE_SHIFT);
        errno = saved_errno;
        return NULL;
    }

    return addr;
}

static void *freebsd_privcmd_map_foreign_range(xc_interface *xch,
                                               xc_osdep_handle h,
                                               uint32_t dom, int size, int prot,
                                               unsigned long mfn)
{
    xen_pfn_t *arr;
    int num;
    int i;
    void *ret;

    num = (size + XC_PAGE_SIZE - 1) >> XC_PAGE_SHIFT;
    arr = calloc(num, sizeof(xen_pfn_t));
    if ( arr == NULL )
        return NULL;

    for ( i = 0; i < num; i++ )
        arr[i] = mfn + i;

    ret = xc_map_foreign_pages(xch, dom, prot, arr, num);
    free(arr);
    return ret;
}

static void *freebsd_privcmd_map_foreign_ranges(xc_interface *xch,
                                                xc_osdep_handle h,
                                                uint32_t dom, size_t size,
                                                int prot, size_t chunksize,
                                                privcmd_mmap_entry_t entries[],
                                                int nentries)
{
    xen_pfn_t *arr;
    int num_per_entry;
    int num;
    int i;
    int j;
    void *ret;

    num_per_entry = chunksize >> XC_PAGE_SHIFT;
    num = num_per_entry * nentries;
    arr = calloc(num, sizeof(xen_pfn_t));
    if ( arr == NULL )
        return NULL;

    for ( i = 0; i < nentries; i++ )
        for ( j = 0; j < num_per_entry; j++ )
            arr[i * num_per_entry + j] = entries[i].mfn + j;

    ret = xc_map_foreign_pages(xch, dom, prot, arr, num);
    free(arr);
    return ret;
}

/*----------------------------- Privcmd handlers -----------------------------*/
static struct xc_osdep_ops freebsd_privcmd_ops = {
    .open = &freebsd_privcmd_open,
    .close = &freebsd_privcmd_close,

    .u.privcmd = {
        .alloc_hypercall_buffer = &freebsd_privcmd_alloc_hypercall_buffer,
        .free_hypercall_buffer = &freebsd_privcmd_free_hypercall_buffer,

        .hypercall = &freebsd_privcmd_hypercall,

        .map_foreign_bulk = &freebsd_privcmd_map_foreign_bulk,
        .map_foreign_range = &freebsd_privcmd_map_foreign_range,
        .map_foreign_ranges = &freebsd_privcmd_map_foreign_ranges,
    },
};

/*---------------------------- FreeBSD interface -----------------------------*/
static struct xc_osdep_ops *
freebsd_osdep_init(xc_interface *xch, enum xc_osdep_type type)
{
    switch ( type )
    {
    case XC_OSDEP_PRIVCMD:
        return &freebsd_privcmd_ops;
    default:
        return NULL;
    }
}

xc_osdep_info_t xc_osdep_info = {
    .name = "FreeBSD Native OS interface",
    .init = &freebsd_osdep_init,
    .fake = 0,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
