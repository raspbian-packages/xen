/*
 * Copyright (C) 2007 Advanced Micro Devices, Inc.
 * Author: Leo Duran <leo.duran@amd.com>
 * Author: Wei Wang <wei.wang2@amd.com> - adapted to xen
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>
#include <xen/sched.h>
#include <asm/mm.h>
#include "pci-direct.h"
#include "pci_regs.h"

struct list_head amd_iommu_head;
long amd_iommu_poll_comp_wait = COMPLETION_WAIT_DEFAULT_POLLING_COUNT;
static long amd_iommu_cmd_buffer_entries = IOMMU_CMD_BUFFER_DEFAULT_ENTRIES;
int nr_amd_iommus = 0;

/* will set if amd-iommu HW is found */
int amd_iommu_enabled = 0;

static int enable_amd_iommu = 0;
boolean_param("enable_amd_iommu", enable_amd_iommu);

static void deallocate_domain_page_tables(struct hvm_iommu *hd)
{
    if ( hd->root_table )
        free_xenheap_page(hd->root_table);
}

static void deallocate_domain_resources(struct hvm_iommu *hd)
{
    deallocate_domain_page_tables(hd);
}

static void __init init_cleanup(void)
{
    struct amd_iommu *iommu;

    for_each_amd_iommu ( iommu )
        unmap_iommu_mmio_region(iommu);
}

static void __init deallocate_iommu_table_struct(
    struct table_struct *table)
{
    if ( table->buffer )
    {
        free_xenheap_pages(table->buffer,
                           get_order_from_bytes(table->alloc_size));
        table->buffer = NULL;
    }
}

static void __init deallocate_iommu_resources(struct amd_iommu *iommu)
{
    deallocate_iommu_table_struct(&iommu->dev_table);
    deallocate_iommu_table_struct(&iommu->cmd_buffer);;
}

static void __init detect_cleanup(void)
{
    struct amd_iommu *iommu, *next;

    list_for_each_entry_safe ( iommu, next, &amd_iommu_head, list )
    {
        list_del(&iommu->list);
        deallocate_iommu_resources(iommu);
        xfree(iommu);
    }
}

static int requestor_id_from_bdf(int bdf)
{
    /* HACK - HACK */
    /* account for possible 'aliasing' by parent device */
    return bdf;
}

static int __init allocate_iommu_table_struct(struct table_struct *table,
                                              const char *name)
{
    table->buffer = (void *) alloc_xenheap_pages(
        get_order_from_bytes(table->alloc_size));

    if ( !table->buffer )
    {
        dprintk(XENLOG_ERR, "AMD IOMMU: Error allocating %s\n", name);
        return -ENOMEM;
    }

    memset(table->buffer, 0, table->alloc_size);

    return 0;
}

static int __init allocate_iommu_resources(struct amd_iommu *iommu)
{
    /* allocate 'device table' on a 4K boundary */
    iommu->dev_table.alloc_size =
        PAGE_ALIGN(((iommu->last_downstream_bus + 1) *
                    IOMMU_DEV_TABLE_ENTRIES_PER_BUS) *
                   IOMMU_DEV_TABLE_ENTRY_SIZE);
    iommu->dev_table.entries =
        iommu->dev_table.alloc_size / IOMMU_DEV_TABLE_ENTRY_SIZE;

    if ( allocate_iommu_table_struct(&iommu->dev_table,
                                     "Device Table") != 0 )
        goto error_out;

    /* allocate 'command buffer' in power of 2 increments of 4K */
    iommu->cmd_buffer_tail = 0;
    iommu->cmd_buffer.alloc_size =
        PAGE_SIZE << get_order_from_bytes(
            PAGE_ALIGN(amd_iommu_cmd_buffer_entries *
                       IOMMU_CMD_BUFFER_ENTRY_SIZE));

    iommu->cmd_buffer.entries =
        iommu->cmd_buffer.alloc_size / IOMMU_CMD_BUFFER_ENTRY_SIZE;

    if ( allocate_iommu_table_struct(&iommu->cmd_buffer,
                                     "Command Buffer") != 0 )
        goto error_out;

    return 0;

 error_out:
    deallocate_iommu_resources(iommu);
    return -ENOMEM;
}

int iommu_detect_callback(u8 bus, u8 dev, u8 func, u8 cap_ptr)
{
    struct amd_iommu *iommu;

    iommu = (struct amd_iommu *) xmalloc(struct amd_iommu);
    if ( !iommu )
    {
        dprintk(XENLOG_ERR, "AMD IOMMU: Error allocating amd_iommu\n");
        return -ENOMEM;
    }
    memset(iommu, 0, sizeof(struct amd_iommu));
    spin_lock_init(&iommu->lock);

    /* get capability and topology information */
    if ( get_iommu_capabilities(bus, dev, func, cap_ptr, iommu) != 0 )
        goto error_out;
    if ( get_iommu_last_downstream_bus(iommu) != 0 )
        goto error_out;

    list_add_tail(&iommu->list, &amd_iommu_head);

    /* allocate resources for this IOMMU */
    if (allocate_iommu_resources(iommu) != 0)
        goto error_out;

    return 0;

 error_out:
    xfree(iommu);
    return -ENODEV;
}

static int __init amd_iommu_init(void)
{
    struct amd_iommu *iommu;
    unsigned long flags;

    for_each_amd_iommu ( iommu )
    {
        spin_lock_irqsave(&iommu->lock, flags);

        /* register IOMMU data strucures in MMIO space */
        if ( map_iommu_mmio_region(iommu) != 0 )
            goto error_out;
        register_iommu_dev_table_in_mmio_space(iommu);
        register_iommu_cmd_buffer_in_mmio_space(iommu);

        /* enable IOMMU translation services */
        enable_iommu(iommu);
        nr_amd_iommus++;

        spin_unlock_irqrestore(&iommu->lock, flags);
    }

    amd_iommu_enabled = 1;

    return 0;

 error_out:
    init_cleanup();
    return -ENODEV;
}

struct amd_iommu *find_iommu_for_device(int bus, int devfn)
{
    struct amd_iommu *iommu;

    for_each_amd_iommu ( iommu )
    {
        if ( bus == iommu->root_bus )
        {
            if ( (devfn >= iommu->first_devfn) &&
                 (devfn <= iommu->last_devfn) )
                return iommu;
        }
        else if ( bus <= iommu->last_downstream_bus )
        {
            if ( iommu->downstream_bus_present[bus] )
                return iommu;
        }
    }

    return NULL;
}

void amd_iommu_setup_domain_device(
    struct domain *domain, struct amd_iommu *iommu, int requestor_id)
{
    void *dte;
    u64 root_ptr;
    unsigned long flags;
    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    BUG_ON( !hd->root_table||!hd->paging_mode );

    root_ptr = (u64)virt_to_maddr(hd->root_table);
    dte = iommu->dev_table.buffer +
        (requestor_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

    if ( !amd_iommu_is_dte_page_translation_valid((u32 *)dte) )
    {
        spin_lock_irqsave(&iommu->lock, flags); 

        amd_iommu_set_dev_table_entry(
            (u32 *)dte,
            root_ptr, hd->domain_id, hd->paging_mode);
        invalidate_dev_table_entry(iommu, requestor_id);
        flush_command_buffer(iommu);
        dprintk(XENLOG_INFO, "AMD IOMMU: Set DTE req_id:%x, "
                "root_ptr:%"PRIx64", domain_id:%d, paging_mode:%d\n",
                requestor_id, root_ptr, hd->domain_id, hd->paging_mode);

        spin_unlock_irqrestore(&iommu->lock, flags);
    }
}

void __init amd_iommu_setup_dom0_devices(void)
{
    struct hvm_iommu *hd = domain_hvm_iommu(dom0);
    struct amd_iommu *iommu;
    struct pci_dev *pdev;
    int bus, dev, func;
    u32 l;
    int req_id, bdf;

    for ( bus = 0; bus < 256; bus++ )
    {
        for ( dev = 0; dev < 32; dev++ )
        {
            for ( func = 0; func < 8; func++ )
            {
                l = read_pci_config(bus, dev, func, PCI_VENDOR_ID);
                /* some broken boards return 0 or ~0 if a slot is empty: */
                if ( l == 0xffffffff || l == 0x00000000 ||
                     l == 0x0000ffff || l == 0xffff0000 )
                    continue;

                pdev = xmalloc(struct pci_dev);
                pdev->bus = bus;
                pdev->devfn = PCI_DEVFN(dev, func);
                list_add_tail(&pdev->list, &hd->pdev_list);

                bdf = (bus << 8) | pdev->devfn;
                req_id = requestor_id_from_bdf(bdf);
                iommu = find_iommu_for_device(bus, pdev->devfn);

                if ( iommu )
                    amd_iommu_setup_domain_device(dom0, iommu, req_id);
            }
        }
    }
}

int amd_iommu_detect(void)
{
    unsigned long i;

    if ( !enable_amd_iommu )
    {
        printk("AMD IOMMU: Disabled\n");
        return 0;
    }

    INIT_LIST_HEAD(&amd_iommu_head);

    if ( scan_for_iommu(iommu_detect_callback) != 0 )
    {
        dprintk(XENLOG_ERR, "AMD IOMMU: Error detection\n");
        goto error_out;
    }

    if ( !iommu_found() )
    {
        printk("AMD IOMMU: Not found!\n");
        return 0;
    }

    if ( amd_iommu_init() != 0 )
    {
        dprintk(XENLOG_ERR, "AMD IOMMU: Error initialization\n");
        goto error_out;
    }

    if ( iommu_domain_init(dom0) != 0 )
        goto error_out;

    /* setup 1:1 page table for dom0 */
    for ( i = 0; i < max_page; i++ )
        amd_iommu_map_page(dom0, i, i);

    amd_iommu_setup_dom0_devices();
    return 0;

 error_out:
    detect_cleanup();
    return -ENODEV;

}

static int allocate_domain_resources(struct hvm_iommu *hd)
{
    /* allocate root table */
    unsigned long flags;

    spin_lock_irqsave(&hd->mapping_lock, flags);
    if ( !hd->root_table )
    {
        hd->root_table = (void *)alloc_xenheap_page();
        if ( !hd->root_table )
            goto error_out;
        memset((u8*)hd->root_table, 0, PAGE_SIZE);
    }
    spin_unlock_irqrestore(&hd->mapping_lock, flags);

    return 0;
 error_out:
    spin_unlock_irqrestore(&hd->mapping_lock, flags);
    return -ENOMEM;
}

static int get_paging_mode(unsigned long entries)
{
    int level = 1;

    BUG_ON ( !max_page );

    if ( entries > max_page )
        entries = max_page;

    while ( entries > PTE_PER_TABLE_SIZE )
    {
        entries = PTE_PER_TABLE_ALIGN(entries) >> PTE_PER_TABLE_SHIFT;
        ++level;
        if ( level > 6 )
            return -ENOMEM;
    }

    dprintk(XENLOG_INFO, "AMD IOMMU: paging mode = %d\n", level);

    return level;
}

int amd_iommu_domain_init(struct domain *domain)
{
    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    /* allocate page directroy */
    if ( allocate_domain_resources(hd) != 0 )
    {
        deallocate_domain_resources(hd);
        return -ENOMEM;
    }

    if ( is_hvm_domain(domain) )
        hd->paging_mode = IOMMU_PAGE_TABLE_LEVEL_4;
    else
        hd->paging_mode = get_paging_mode(max_page);

    hd->domain_id = domain->domain_id;

    return 0;
}

static void amd_iommu_disable_domain_device(
    struct domain *domain, struct amd_iommu *iommu, u16 requestor_id)
{
    void *dte;
    unsigned long flags;

    dte = iommu->dev_table.buffer +
        (requestor_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

    if ( amd_iommu_is_dte_page_translation_valid((u32 *)dte) )
    {
        spin_lock_irqsave(&iommu->lock, flags); 
        memset (dte, 0, IOMMU_DEV_TABLE_ENTRY_SIZE);
        invalidate_dev_table_entry(iommu, requestor_id);
        flush_command_buffer(iommu);
        dprintk(XENLOG_INFO , "AMD IOMMU: disable DTE 0x%x,"
                " domain_id:%d, paging_mode:%d\n",
                requestor_id,  domain_hvm_iommu(domain)->domain_id,
                domain_hvm_iommu(domain)->paging_mode);
        spin_unlock_irqrestore(&iommu->lock, flags);
    }
}

extern void pdev_flr(u8 bus, u8 devfn);

static int reassign_device( struct domain *source, struct domain *target,
                            u8 bus, u8 devfn)
{
    struct hvm_iommu *source_hd = domain_hvm_iommu(source);
    struct hvm_iommu *target_hd = domain_hvm_iommu(target);
    struct pci_dev *pdev;
    struct amd_iommu *iommu;
    int req_id, bdf;
    unsigned long flags;

    for_each_pdev( source, pdev )
    {
        if ( (pdev->bus != bus) || (pdev->devfn != devfn) )
            continue;

        pdev->bus = bus;
        pdev->devfn = devfn;

        bdf = (bus << 8) | devfn;
        req_id = requestor_id_from_bdf(bdf);
        iommu = find_iommu_for_device(bus, devfn);

        if ( iommu )
        {
            amd_iommu_disable_domain_device(source, iommu, req_id);
            /* Move pci device from the source domain to target domain. */
            spin_lock_irqsave(&source_hd->iommu_list_lock, flags);
            spin_lock_irqsave(&target_hd->iommu_list_lock, flags);
            list_move(&pdev->list, &target_hd->pdev_list);
            spin_unlock_irqrestore(&target_hd->iommu_list_lock, flags);
            spin_unlock_irqrestore(&source_hd->iommu_list_lock, flags);

            amd_iommu_setup_domain_device(target, iommu, req_id);
            gdprintk(XENLOG_INFO ,
                     "AMD IOMMU: reassign %x:%x.%x domain %d -> domain %d\n",
                     bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
                     source->domain_id, target->domain_id);
        }
        else
        {
            gdprintk(XENLOG_ERR , "AMD IOMMU: fail to find iommu."
                     " %x:%x.%x cannot be assigned to domain %d\n", 
                     bus, PCI_SLOT(devfn), PCI_FUNC(devfn), target->domain_id);
            return -ENODEV;
        }

        break;
    }
    return 0;
}

int amd_iommu_assign_device(struct domain *d, u8 bus, u8 devfn)
{
    pdev_flr(bus, devfn);
    return reassign_device(dom0, d, bus, devfn);
}

static void release_domain_devices(struct domain *d)
{
    struct hvm_iommu *hd  = domain_hvm_iommu(d);
    struct pci_dev *pdev;

    while ( !list_empty(&hd->pdev_list) )
    {
        pdev = list_entry(hd->pdev_list.next, typeof(*pdev), list);
        pdev_flr(pdev->bus, pdev->devfn);
        gdprintk(XENLOG_INFO ,
                 "AMD IOMMU: release devices %x:%x.%x\n",
                 pdev->bus, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
        reassign_device(d, dom0, pdev->bus, pdev->devfn);
    }
}

static void deallocate_next_page_table(void *table, unsigned long index,
                                       int level)
{
    unsigned long next_index;
    void *next_table, *pde;
    int next_level;

    pde = table + (index * IOMMU_PAGE_TABLE_ENTRY_SIZE);
    next_table = amd_iommu_get_vptr_from_page_table_entry((u32 *)pde);

    if ( next_table )
    {
        next_level = level - 1;
        if ( next_level > 1 )
        {
            next_index = 0;
            do
            {
                deallocate_next_page_table(next_table,
                                           next_index, next_level);
                ++next_index;
            } while (next_index < PTE_PER_TABLE_SIZE);
        }

        free_xenheap_page(next_table);
    }
}

static void deallocate_iommu_page_tables(struct domain *d)
{
    unsigned long index;
    struct hvm_iommu *hd  = domain_hvm_iommu(d);

    if ( hd ->root_table )
    {
        index = 0;
        do
        {
            deallocate_next_page_table(hd->root_table,
                                       index, hd->paging_mode);
            ++index;
        } while ( index < PTE_PER_TABLE_SIZE );

        free_xenheap_page(hd ->root_table);
    }

    hd ->root_table = NULL;
}

void amd_iommu_domain_destroy(struct domain *d)
{
    if ( !amd_iommu_enabled )
        return;

    deallocate_iommu_page_tables(d);
    release_domain_devices(d);
}

struct iommu_ops amd_iommu_ops = {
    .init = amd_iommu_domain_init,
    .assign_device  = amd_iommu_assign_device,
    .teardown = amd_iommu_domain_destroy,
    .map_page = amd_iommu_map_page,
    .unmap_page = amd_iommu_unmap_page,
};
