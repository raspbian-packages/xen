/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h"

#include <string.h>
#include <stdio.h>
#include <sys/time.h> /* for struct timeval */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "libxl.h"
#include "libxl_internal.h"

char *libxl__device_frontend_path(libxl__gc *gc, libxl__device *device)
{
    char *dom_path = libxl__xs_get_dompath(gc, device->domid);

    /* Console 0 is a special case */
    if (device->kind == LIBXL__DEVICE_KIND_CONSOLE && device->devid == 0)
        return libxl__sprintf(gc, "%s/console", dom_path);

    return libxl__sprintf(gc, "%s/device/%s/%d", dom_path,
                          libxl__device_kind_to_string(device->kind),
                          device->devid);
}

char *libxl__device_backend_path(libxl__gc *gc, libxl__device *device)
{
    char *dom_path = libxl__xs_get_dompath(gc, device->backend_domid);

    return libxl__sprintf(gc, "%s/backend/%s/%u/%d", dom_path,
                          libxl__device_kind_to_string(device->backend_kind),
                          device->domid, device->devid);
}

int libxl__device_generic_add(libxl__gc *gc, libxl__device *device,
                             char **bents, char **fents)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *frontend_path, *backend_path;
    xs_transaction_t t;
    struct xs_permissions frontend_perms[2];
    struct xs_permissions backend_perms[2];

    frontend_path = libxl__device_frontend_path(gc, device);
    backend_path = libxl__device_backend_path(gc, device);

    frontend_perms[0].id = device->domid;
    frontend_perms[0].perms = XS_PERM_NONE;
    frontend_perms[1].id = device->backend_domid;
    frontend_perms[1].perms = XS_PERM_READ;

    backend_perms[0].id = device->backend_domid;
    backend_perms[0].perms = XS_PERM_NONE;
    backend_perms[1].id = device->domid;
    backend_perms[1].perms = XS_PERM_READ;

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    /* FIXME: read frontend_path and check state before removing stuff */

    if (fents) {
        xs_rm(ctx->xsh, t, frontend_path);
        xs_mkdir(ctx->xsh, t, frontend_path);
        xs_set_permissions(ctx->xsh, t, frontend_path, frontend_perms, ARRAY_SIZE(frontend_perms));
        xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/backend", frontend_path), backend_path, strlen(backend_path));
        libxl__xs_writev(gc, t, frontend_path, fents);
    }

    if (bents) {
        xs_rm(ctx->xsh, t, backend_path);
        xs_mkdir(ctx->xsh, t, backend_path);
        xs_set_permissions(ctx->xsh, t, backend_path, backend_perms, ARRAY_SIZE(backend_perms));
        xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/frontend", backend_path), frontend_path, strlen(frontend_path));
        libxl__xs_writev(gc, t, backend_path, bents);
    }

    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN)
            goto retry_transaction;
        else
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "xs transaction failed");
    }

    return 0;
}

typedef struct {
    libxl__gc *gc;
    libxl_device_disk *disk;
    struct stat stab;
} disk_try_backend_args;

static int disk_try_backend(disk_try_backend_args *a,
                            libxl_disk_backend backend) {
    /* returns 0 (ie, DISK_BACKEND_UNKNOWN) on failure, or
     * backend on success */
    libxl_ctx *ctx = libxl__gc_owner(a->gc);
    switch (backend) {

    case LIBXL_DISK_BACKEND_PHY:
        if (!(a->disk->format == LIBXL_DISK_FORMAT_RAW ||
              a->disk->format == LIBXL_DISK_FORMAT_EMPTY)) {
            goto bad_format;
        }
        if (a->disk->format != LIBXL_DISK_FORMAT_EMPTY &&
            !S_ISBLK(a->stab.st_mode)) {
            LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s, backend phy"
                       " unsuitable as phys path not a block device",
                       a->disk->vdev);
            return 0;
        }

        return backend;

    case LIBXL_DISK_BACKEND_TAP:
        if (!libxl__blktap_enabled(a->gc)) {
            LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s, backend tap"
                       " unsuitable because blktap not available",
                       a->disk->vdev);
            return 0;
        }
        if (!(a->disk->format == LIBXL_DISK_FORMAT_RAW ||
              a->disk->format == LIBXL_DISK_FORMAT_VHD)) {
            goto bad_format;
        }
        return backend;

    case LIBXL_DISK_BACKEND_QDISK:
        return backend;

    default:
        LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s, backend "
                   " %d unknown", a->disk->vdev, backend);
        return 0;

    }
    abort(); /* notreached */

 bad_format:
    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s, backend %s"
               " unsuitable due to format %s",
               a->disk->vdev,
               libxl_disk_backend_to_string(backend),
               libxl_disk_format_to_string(a->disk->format));
    return 0;
}

int libxl__device_disk_set_backend(libxl__gc *gc, libxl_device_disk *disk) {
    libxl_ctx *ctx = libxl__gc_owner(gc);
    libxl_disk_backend ok;
    disk_try_backend_args a;

    a.gc = gc;
    a.disk = disk;

    LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s spec.backend=%s",
               disk->vdev,
               libxl_disk_backend_to_string(disk->backend));

    if (disk->format == LIBXL_DISK_FORMAT_EMPTY) {
        if (!disk->is_cdrom) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Disk vdev=%s is empty"
                       " but not cdrom",
                       disk->vdev);
            return ERROR_INVAL;
        }
        memset(&a.stab, 0, sizeof(a.stab));
    } else {
        if (stat(disk->pdev_path, &a.stab)) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Disk vdev=%s "
                             "failed to stat: %s",
                             disk->vdev, disk->pdev_path);
            return ERROR_INVAL;
        }
        if (!S_ISBLK(a.stab.st_mode) &
            !S_ISREG(a.stab.st_mode)) {
            LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Disk vdev=%s "
                             "phys path is not a block dev or file: %s",
                             disk->vdev, disk->pdev_path);
            return ERROR_INVAL;
        }
    }

    if (disk->backend != LIBXL_DISK_BACKEND_UNKNOWN) {
        ok= disk_try_backend(&a, disk->backend);
    } else {
        ok=
            disk_try_backend(&a, LIBXL_DISK_BACKEND_PHY) ?:
            disk_try_backend(&a, LIBXL_DISK_BACKEND_TAP) ?:
            disk_try_backend(&a, LIBXL_DISK_BACKEND_QDISK);
        if (ok)
            LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Disk vdev=%s, using backend %s",
                       disk->vdev,
                       libxl_disk_backend_to_string(ok));
    }
    if (!ok) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "no suitable backend for disk %s",
                   disk->vdev);
        return ERROR_INVAL;
    }
    disk->backend = ok;
    return 0;
}

char *libxl__device_disk_string_of_format(libxl_disk_format format)
{
    switch (format) {
        case LIBXL_DISK_FORMAT_QCOW: return "qcow";
        case LIBXL_DISK_FORMAT_QCOW2: return "qcow2";
        case LIBXL_DISK_FORMAT_VHD: return "vhd";
        case LIBXL_DISK_FORMAT_RAW:
        case LIBXL_DISK_FORMAT_EMPTY: return "aio";
        default: return NULL;
    }
}

char *libxl__device_disk_string_of_backend(libxl_disk_backend backend)
{
    switch (backend) {
        case LIBXL_DISK_BACKEND_QDISK: return "qdisk";
        case LIBXL_DISK_BACKEND_TAP: return "phy";
        case LIBXL_DISK_BACKEND_PHY: return "phy";
        default: return NULL;
    }
}

int libxl__device_physdisk_major_minor(const char *physpath, int *major, int *minor)
{
    struct stat buf;
    if (stat(physpath, &buf) < 0)
        return -1;
    *major = major(buf.st_rdev);
    *minor = minor(buf.st_rdev);
    return 0;
}

static int device_virtdisk_matches(const char *virtpath, const char *devtype,
                                   int *index_r, int max_index,
                                   int *partition_r, int max_partition) {
    const char *p;
    char *ep;
    int tl, c;
    long pl;

    tl = strlen(devtype);
    if (memcmp(virtpath, devtype, tl))
        return 0;

    /* We decode the drive letter as if it were in base 52
     * with digits a-zA-Z, more or less */
    *index_r = -1;
    p = virtpath + tl;
    for (;;) {
        c = *p++;
        if (c >= 'a' && c <= 'z') {
            c -= 'a';
        } else {
            --p;
            break;
        }
        (*index_r)++;
        (*index_r) *= 26;
        (*index_r) += c;

        if (*index_r > max_index)
            return 0;
    }

    if (!*p) {
        *partition_r = 0;
        return 1;
    }

    if (*p=='0')
        return 0; /* leading zeroes not permitted in partition number */

    pl = strtoul(p, &ep, 10);
    if (pl > max_partition || *ep)
        return 0;

    *partition_r = pl;
    return 1;
}

int libxl__device_disk_dev_number(const char *virtpath, int *pdisk,
                                  int *ppartition)
{
    int disk, partition;
    char *ep;
    unsigned long ul;
    int chrused;

    chrused = -1;
    if ((sscanf(virtpath, "d%ip%i%n", &disk, &partition, &chrused)  >= 2
         && chrused == strlen(virtpath) && disk < (1<<20) && partition < 256)
        ||
        device_virtdisk_matches(virtpath, "xvd",
                                &disk, (1<<20)-1,
                                &partition, 255)) {
        if (pdisk) *pdisk = disk;
        if (ppartition) *ppartition = partition;
        if (disk <= 15 && partition <= 15)
            return (202 << 8) | (disk << 4) | partition;
        else
            return (1 << 28) | (disk << 8) | partition;
    }

    errno = 0;
    ul = strtoul(virtpath, &ep, 0);
    if (!errno && !*ep && ul <= INT_MAX) {
        /* FIXME: should parse ul to determine these. */
        if (pdisk || ppartition)
            return -1;
        return ul;
    }

    if (device_virtdisk_matches(virtpath, "hd",
                                &disk, 3,
                                &partition, 63)) {
        if (pdisk) *pdisk = disk;
        if (ppartition) *ppartition = partition;
        return ((disk<2 ? 3 : 22) << 8) | ((disk & 1) << 6) | partition;
    }
    if (device_virtdisk_matches(virtpath, "sd",
                                &disk, 15,
                                &partition, 15)) {
        if (pdisk) *pdisk = disk;
        if (ppartition) *ppartition = partition;
        return (8 << 8) | (disk << 4) | partition;
    }
    return -1;
}

int libxl__device_remove(libxl__gc *gc, char *be_path)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    xs_transaction_t t;
    char *state_path = libxl__sprintf(gc, "%s/state", be_path);
    char *state = libxl__xs_read(gc, XBT_NULL, state_path);
    int rc = 0;

    if (!state)
        goto out;
    if (atoi(state) != 4) {
        libxl__device_destroy_tapdisk(gc, be_path);
        xs_rm(ctx->xsh, XBT_NULL, be_path);
        goto out;
    }

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_write(ctx->xsh, t, libxl__sprintf(gc, "%s/online", be_path), "0", strlen("0"));
    xs_write(ctx->xsh, t, state_path, "5", strlen("5"));
    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN)
            goto retry_transaction;
        else {
            rc = -1;
            goto out;
        }
    }

    xs_watch(ctx->xsh, state_path, be_path);
    libxl__device_destroy_tapdisk(gc, be_path);
    rc = 1;
out:
    return rc;
}

int libxl__device_destroy(libxl__gc *gc, libxl__device *dev)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *be_path = libxl__device_backend_path(gc, dev);
    char *fe_path = libxl__device_frontend_path(gc, dev);

    xs_rm(ctx->xsh, XBT_NULL, be_path);
    xs_rm(ctx->xsh, XBT_NULL, fe_path);

    libxl__device_destroy_tapdisk(gc, be_path);

    return 0;
}

static int wait_for_dev_destroy(libxl__gc *gc, struct timeval *tv)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int nfds, rc;
    unsigned int n;
    fd_set rfds;
    char **l1 = NULL;

    rc = 1;
    nfds = xs_fileno(ctx->xsh) + 1;
    FD_ZERO(&rfds);
    FD_SET(xs_fileno(ctx->xsh), &rfds);
    if (select(nfds, &rfds, NULL, NULL, tv) > 0) {
        l1 = xs_read_watch(ctx->xsh, &n);
        if (l1 != NULL) {
            char *state = libxl__xs_read(gc, XBT_NULL, l1[XS_WATCH_PATH]);
            if (!state || atoi(state) == 6) {
                xs_unwatch(ctx->xsh, l1[0], l1[1]);
                xs_rm(ctx->xsh, XBT_NULL, l1[XS_WATCH_TOKEN]);
                LIBXL__LOG(ctx, LIBXL__LOG_DEBUG, "Destroyed device backend at %s", l1[XS_WATCH_TOKEN]);
                rc = 0;
            }
            free(l1);
        }
    }
    return rc;
}

int libxl__devices_destroy(libxl__gc *gc, uint32_t domid, int force)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *path, *be_path, *fe_path;
    unsigned int num1, num2;
    char **l1 = NULL, **l2 = NULL;
    int i, j, n_watches = 0;

    path = libxl__sprintf(gc, "/local/domain/%d/device", domid);
    l1 = libxl__xs_directory(gc, XBT_NULL, path, &num1);
    if (!l1) {
        if (errno != ENOENT) {
            LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "unable to get xenstore"
                             " device listing %s", path);
            goto out;
        }
        num1 = 0;
    }
    for (i = 0; i < num1; i++) {
        if (!strcmp("vfs", l1[i]))
            continue;
        path = libxl__sprintf(gc, "/local/domain/%d/device/%s", domid, l1[i]);
        l2 = libxl__xs_directory(gc, XBT_NULL, path, &num2);
        if (!l2)
            continue;
        for (j = 0; j < num2; j++) {
            fe_path = libxl__sprintf(gc, "/local/domain/%d/device/%s/%s", domid, l1[i], l2[j]);
            be_path = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "%s/backend", fe_path));
            if (be_path != NULL) {
                if (force) {
                    xs_rm(ctx->xsh, XBT_NULL, be_path);
                    xs_rm(ctx->xsh, XBT_NULL, fe_path);
                    libxl__device_destroy_tapdisk(gc, be_path);
                } else {
                    if (libxl__device_remove(gc, be_path) > 0)
                        n_watches++;
                }
            }
        }
    }

    /* console 0 frontend directory is not under /local/domain/<domid>/device */
    fe_path = libxl__sprintf(gc, "/local/domain/%d/console", domid);
    be_path = libxl__xs_read(gc, XBT_NULL, libxl__sprintf(gc, "%s/backend", fe_path));
    if (be_path && strcmp(be_path, "")) {
        if (force) {
            xs_rm(ctx->xsh, XBT_NULL, be_path);
            xs_rm(ctx->xsh, XBT_NULL, fe_path);
        } else {
            if (libxl__device_remove(gc, be_path) > 0)
                n_watches++;
        }
    }

    if (!force) {
        /* Linux-ism. Most implementations leave the timeout
         * untouched after select. Linux, however, will chip
         * away the elapsed time from it, which is what we
         * need to enforce a single time span waiting for
         * device destruction. */
        struct timeval tv;
        tv.tv_sec = LIBXL_DESTROY_TIMEOUT;
        tv.tv_usec = 0;
        while (n_watches > 0) {
            if (wait_for_dev_destroy(gc, &tv)) {
                break;
            } else {
                n_watches--;
            }
        }
    }
out:
    return 0;
}

int libxl__device_del(libxl__gc *gc, libxl__device *dev)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    struct timeval tv;
    char *backend_path;
    int rc;

    backend_path = libxl__device_backend_path(gc, dev);

    rc = libxl__device_remove(gc, backend_path);
    if (rc == -1) {
        rc = ERROR_FAIL;
        goto out;
    }

    tv.tv_sec = LIBXL_DESTROY_TIMEOUT;
    tv.tv_usec = 0;
    (void)wait_for_dev_destroy(gc, &tv);

    xs_rm(ctx->xsh, XBT_NULL, libxl__device_frontend_path(gc, dev));
    rc = 0;

out:
    return rc;
}

int libxl__wait_for_device_model(libxl__gc *gc,
                                 uint32_t domid, char *state,
                                 libxl__spawn_starting *spawning,
                                 int (*check_callback)(libxl__gc *gc,
                                                       uint32_t domid,
                                                       const char *state,
                                                       void *userdata),
                                 void *check_callback_userdata)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    char *path;
    char *p;
    unsigned int len;
    int rc = 0;
    struct xs_handle *xsh;
    int nfds;
    fd_set rfds;
    struct timeval tv;
    unsigned int num;
    char **l = NULL;

    xsh = xs_daemon_open();
    if (xsh == NULL) {
        LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Unable to open xenstore connection");
        goto err;
    }

    path = libxl__sprintf(gc, "/local/domain/0/device-model/%d/state", domid);
    xs_watch(xsh, path, path);
    tv.tv_sec = LIBXL_DEVICE_MODEL_START_TIMEOUT;
    tv.tv_usec = 0;
    nfds = xs_fileno(xsh) + 1;
    if (spawning && spawning->fd > xs_fileno(xsh))
        nfds = spawning->fd + 1;

    while (rc > 0 || (!rc && tv.tv_sec > 0)) {
        if ( spawning ) {
            rc = libxl__spawn_check(gc, spawning);
            if ( rc ) {
                LIBXL__LOG(ctx, LIBXL__LOG_ERROR,
                           "Device Model died during startup");
                rc = -1;
                goto err_died;
            }
        }
        p = xs_read(xsh, XBT_NULL, path, &len);
        if ( NULL == p )
            goto again;

        if ( NULL != state && strcmp(p, state) )
            goto again;

        if ( NULL != check_callback ) {
            rc = (*check_callback)(gc, domid, p, check_callback_userdata);
            if ( rc > 0 )
                goto again;
        }

        free(p);
        xs_unwatch(xsh, path, path);
        xs_daemon_close(xsh);
        return rc;
again:
        free(p);
        FD_ZERO(&rfds);
        FD_SET(xs_fileno(xsh), &rfds);
        if (spawning)
            FD_SET(spawning->fd, &rfds);
        rc = select(nfds, &rfds, NULL, NULL, &tv);
        if (rc > 0) {
            if (FD_ISSET(xs_fileno(xsh), &rfds)) {
                l = xs_read_watch(xsh, &num);
                if (l != NULL)
                    free(l);
                else
                    goto again;
            }
            if (spawning && FD_ISSET(spawning->fd, &rfds)) {
                unsigned char dummy;
                if (read(spawning->fd, &dummy, sizeof(dummy)) != 1)
                    LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_DEBUG,
                                     "failed to read spawn status pipe");
            }
        }
    }
    LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Device Model not ready");
err_died:
    xs_unwatch(xsh, path, path);
    xs_daemon_close(xsh);
err:
    return -1;
}

int libxl__wait_for_backend(libxl__gc *gc, char *be_path, char *state)
{
    libxl_ctx *ctx = libxl__gc_owner(gc);
    int watchdog = 100;
    unsigned int len;
    char *p;
    char *path = libxl__sprintf(gc, "%s/state", be_path);
    int rc = -1;

    while (watchdog > 0) {
        p = xs_read(ctx->xsh, XBT_NULL, path, &len);
        if (p == NULL) {
            if (errno == ENOENT) {
                LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Backend %s does not exist",
                       be_path);
            } else {
                LIBXL__LOG_ERRNO(ctx, LIBXL__LOG_ERROR, "Failed to access backend %s",
                       be_path);
            }
            goto out;
        } else {
            if (!strcmp(p, state)) {
                rc = 0;
                goto out;
            } else {
                usleep(100000);
                watchdog--;
            }
        }
    }
    LIBXL__LOG(ctx, LIBXL__LOG_ERROR, "Backend %s not ready", be_path);
out:
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
