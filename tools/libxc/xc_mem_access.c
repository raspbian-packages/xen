/******************************************************************************
 *
 * tools/libxc/xc_mem_access.c
 *
 * Interface to low-level memory access mode functionality
 *
 * Copyright (c) 2011 Virtuata, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "xc_private.h"
#include <xen/memory.h>

void *xc_mem_access_enable(xc_interface *xch, domid_t domain_id, uint32_t *port)
{
    return xc_vm_event_enable(xch, domain_id, HVM_PARAM_MONITOR_RING_PFN,
                              port, 0);
}

void *xc_mem_access_enable_introspection(xc_interface *xch, domid_t domain_id,
                                         uint32_t *port)
{
    return xc_vm_event_enable(xch, domain_id, HVM_PARAM_MONITOR_RING_PFN,
                              port, 1);
}

int xc_mem_access_disable(xc_interface *xch, domid_t domain_id)
{
    return xc_vm_event_control(xch, domain_id,
                               XEN_VM_EVENT_MONITOR_DISABLE,
                               XEN_DOMCTL_VM_EVENT_OP_MONITOR,
                               NULL);
}

int xc_mem_access_resume(xc_interface *xch, domid_t domain_id)
{
    xen_mem_access_op_t mao =
    {
        .op    = XENMEM_access_op_resume,
        .domid = domain_id
    };

    return do_memory_op(xch, XENMEM_access_op, &mao, sizeof(mao));
}

int xc_set_mem_access(xc_interface *xch,
                      domid_t domain_id,
                      xenmem_access_t access,
                      uint64_t first_pfn,
                      uint32_t nr)
{
    xen_mem_access_op_t mao =
    {
        .op     = XENMEM_access_op_set_access,
        .domid  = domain_id,
        .access = access,
        .pfn    = first_pfn,
        .nr     = nr
    };

    return do_memory_op(xch, XENMEM_access_op, &mao, sizeof(mao));
}

int xc_get_mem_access(xc_interface *xch,
                      domid_t domain_id,
                      uint64_t pfn,
                      xenmem_access_t *access)
{
    int rc;
    xen_mem_access_op_t mao =
    {
        .op    = XENMEM_access_op_get_access,
        .domid = domain_id,
        .pfn   = pfn
    };

    rc = do_memory_op(xch, XENMEM_access_op, &mao, sizeof(mao));

    if ( rc == 0 )
        *access = mao.access;

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End: 
 */
