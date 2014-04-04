/*
 * Kernel image loading.
 *
 * Copyright (C) 2011 Citrix Systems, Inc.
 */
#ifndef __ARCH_ARM_KERNEL_H__
#define __ARCH_ARM_KERNEL_H__

#include <xen/libelf.h>
#include <xen/device_tree.h>

struct kernel_info {
#ifdef CONFIG_ARM_64
    enum domain_type type;
#endif

    void *fdt; /* flat device tree */
    paddr_t unassigned_mem; /* RAM not (yet) assigned to a bank */
    struct dt_mem_info mem;

    /* kernel entry point */
    paddr_t entry;

    /* boot blob load addresses */
    paddr_t dtb_paddr;
    paddr_t initrd_paddr;

    /* loader to use for this kernel */
    void (*load)(struct kernel_info *info);
    /* loader specific state */
    union {
        struct {
            paddr_t kernel_addr;
            paddr_t load_addr;
            paddr_t len;
        } zimage;

        struct {
            struct elf_binary elf;
            struct elf_dom_parms parms;
            unsigned kernel_order;
            void *kernel_img;
        } elf;
    };
};

int kernel_prepare(struct kernel_info *info);
void kernel_load(struct kernel_info *info);

#endif /* #ifdef __ARCH_ARM_KERNEL_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
