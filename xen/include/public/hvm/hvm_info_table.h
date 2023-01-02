/* SPDX-License-Identifier: MIT */
/******************************************************************************
 * hvm/hvm_info_table.h
 *
 * HVM parameter and information table, written into guest memory map.
 *
 * Copyright (c) 2006, Keir Fraser
 */

#ifndef __XEN_PUBLIC_HVM_HVM_INFO_TABLE_H__
#define __XEN_PUBLIC_HVM_HVM_INFO_TABLE_H__

#define HVM_INFO_PFN         0x09F
#define HVM_INFO_OFFSET      0x800
#define HVM_INFO_PADDR       ((HVM_INFO_PFN << 12) + HVM_INFO_OFFSET)

/* Maximum we can support with current vLAPIC ID mapping. */
#define HVM_MAX_VCPUS        128

/*
 * In some cases SMP HVM guests may require knowledge of Xen's idea of vCPU ids
 * for their vCPUs. For example, HYPERVISOR_vcpu_op and some EVTCHNOP_*
 * hypercalls take vcpu id as a parameter. It is valid for HVM guests to assume
 * that Xen's vCPU id always equals to ACPI (not APIC!) id in MADT table which
 * is always present for SMP guests.
 */

struct hvm_info_table {
    char        signature[8]; /* "HVM INFO" */
    uint32_t    length;
    uint8_t     checksum;

    /* Should firmware build APIC descriptors (APIC MADT / MP BIOS)? */
    uint8_t     apic_mode;

    /* How many CPUs does this domain have? */
    uint32_t    nr_vcpus;

    /*
     * MEMORY MAP provided by HVM domain builder.
     * Notes:
     *  1. page_to_phys(x) = x << 12
     *  2. If a field is zero, the corresponding range does not exist.
     */
    /*
     *  0x0 to page_to_phys(low_mem_pgend)-1:
     *    RAM below 4GB (except for VGA hole 0xA0000-0xBFFFF)
     */
    uint32_t    low_mem_pgend;
    /*
     *  page_to_phys(reserved_mem_pgstart) to 0xFFFFFFFF:
     *    Reserved for special memory mappings
     */
    uint32_t    reserved_mem_pgstart;
    /*
     *  0x100000000 to page_to_phys(high_mem_pgend)-1:
     *    RAM above 4GB
     */
    uint32_t    high_mem_pgend;

    /* Bitmap of which CPUs are online at boot time. */
    uint8_t     vcpu_online[(HVM_MAX_VCPUS + 7)/8];
};

#endif /* __XEN_PUBLIC_HVM_HVM_INFO_TABLE_H__ */
