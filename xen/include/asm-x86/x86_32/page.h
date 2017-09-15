
#ifndef __X86_32_PAGE_H__
#define __X86_32_PAGE_H__

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define PAGE_SHIFT              L1_PAGETABLE_SHIFT
#define SUPERPAGE_SHIFT         L2_PAGETABLE_SHIFT
#define ROOT_PAGETABLE_SHIFT    L3_PAGETABLE_SHIFT

#define PAGETABLE_ORDER         9
#define L1_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L3_PAGETABLE_ENTRIES    4
#define ROOT_PAGETABLE_ENTRIES  L3_PAGETABLE_ENTRIES
#define SUPERPAGE_ORDER         PAGETABLE_ORDER

/*
 * Architecturally, physical addresses may be up to 52 bits. However, the
 * page-frame number (pfn) of a 52-bit address will not fit into a 32-bit
 * word. Instead we treat bits 44-51 of a pte as flag bits which are never
 * allowed to be set by a guest kernel. This 'limits' us to addressing 16TB
 * of physical memory on a 32-bit PAE system.
 */
#define PADDR_BITS              44
#define PADDR_MASK              ((1ULL << PADDR_BITS)-1)

#define __PAGE_OFFSET           (0xFF000000)
#define __XEN_VIRT_START        __PAGE_OFFSET

#define VADDR_BITS              32
#define VADDR_MASK              (~0UL)

#define is_canonical_address(x) 1

/* Given a virtual address, get an entry offset into a linear page table. */
#define l1_linear_offset(_a) ((_a) >> L1_PAGETABLE_SHIFT)
#define l2_linear_offset(_a) ((_a) >> L2_PAGETABLE_SHIFT)

#ifndef __ASSEMBLY__

#include <xen/config.h>
#include <asm/types.h>

#define __mfn_valid(mfn)        ({                                            \
    unsigned long __m_f_n = (mfn);                                            \
    likely(__m_f_n < max_page) &&                                             \
    likely(test_bit(pfn_to_pdx(__m_f_n) / PDX_GROUP_COUNT, pdx_group_valid)); \
})

#define max_pdx                 max_page
#define pfn_to_pdx(pfn)         (pfn)
#define pdx_to_pfn(pdx)         (pdx)
#define virt_to_pdx(va)         virt_to_mfn(va)
#define pdx_to_virt(pdx)        mfn_to_virt(pdx)

#define pfn_to_sdx(pfn)         ((pfn)>>(SUPERPAGE_SHIFT-PAGE_SHIFT))
#define sdx_to_pfn(sdx)         ((sdx)<<(SUPERPAGE_SHIFT-PAGE_SHIFT))

static inline unsigned long __virt_to_maddr(unsigned long va)
{
    ASSERT(va >= DIRECTMAP_VIRT_START && va < DIRECTMAP_VIRT_END);
    return va - DIRECTMAP_VIRT_START;
}

static inline void *__maddr_to_virt(unsigned long ma)
{
    ASSERT(ma < DIRECTMAP_VIRT_END - DIRECTMAP_VIRT_START);
    return (void *)(ma + DIRECTMAP_VIRT_START);
}

/* read access (should only be used for debug printk's) */
typedef u64 intpte_t;
#define PRIpte "016llx"

typedef struct { intpte_t l1; } l1_pgentry_t;
typedef struct { intpte_t l2; } l2_pgentry_t;
typedef struct { intpte_t l3; } l3_pgentry_t;
typedef l3_pgentry_t root_pgentry_t;

extern unsigned int PAGE_HYPERVISOR;
extern unsigned int PAGE_HYPERVISOR_NOCACHE;

#endif

#define pte_read_atomic(ptep)       atomic_read64(ptep)
#define pte_write_atomic(ptep, pte) atomic_write64(ptep, pte)
#define pte_write(ptep, pte) do {                             \
    u32 *__ptep_words = (u32 *)(ptep);                        \
    atomic_write32(&__ptep_words[0], 0);                      \
    wmb();                                                    \
    atomic_write32(&__ptep_words[1], (pte) >> 32);            \
    wmb();                                                    \
    atomic_write32(&__ptep_words[0], (pte) >>  0);            \
} while ( 0 )

/* root table */
#define root_get_pfn              l3e_get_pfn
#define root_get_flags            l3e_get_flags
#define root_get_intpte           l3e_get_intpte
#define root_empty                l3e_empty
#define root_from_paddr           l3e_from_paddr
#define PGT_root_page_table       PGT_l3_page_table

/* misc */
#define is_guest_l1_slot(s)    (1)
#define is_guest_l2_slot(d,t,s)                                            \
    ( !((t) & PGT_pae_xen_l2) ||                                           \
      ((s) < (L2_PAGETABLE_FIRST_XEN_SLOT & (L2_PAGETABLE_ENTRIES - 1))) )
#define is_guest_l3_slot(s)    (1)

/*
 * PTE pfn and flags:
 *  32-bit pfn   = (pte[43:12])
 *  32-bit flags = (pte[63:44],pte[11:0])
 */

#define _PAGE_AVAIL_HIGH 0

#define _PAGE_NX_BIT (1U<<31)
#define _PAGE_NX     (cpu_has_nx ? _PAGE_NX_BIT : 0)

/* Extract flags into 32-bit integer, or turn 32-bit flags into a pte mask. */
#define get_pte_flags(x) (((int)((x) >> 32) & ~0xFFF) | ((int)(x) & 0xFFF))
#define put_pte_flags(x) (((intpte_t)((x) & ~0xFFF) << 32) | ((x) & 0xFFF))

/*
 * Bit 12 of a 24-bit flag mask. This corresponds to bit 52 of a pte.
 * This is needed to distinguish between user and kernel PTEs since _PAGE_USER
 * is asserted for both.
 */
#define _PAGE_GUEST_KERNEL (1U<<12)
/*
 * Disallow unused flag bits plus PAT/PSE, PCD, PWT and GLOBAL.
 * Permit the NX bit if the hardware supports it.
 */
#define BASE_DISALLOW_MASK (0xFFFFF198U & ~_PAGE_NX)

#define L1_DISALLOW_MASK (BASE_DISALLOW_MASK | _PAGE_GNTTAB)
#define L2_DISALLOW_MASK (unlikely(opt_allow_superpage) \
                          ? BASE_DISALLOW_MASK & ~_PAGE_PSE \
                          : BASE_DISALLOW_MASK)
#define L3_DISALLOW_MASK 0xFFFFF1FEU /* must-be-zero */

/*
 * Bit 30 of a 32-bit flag mask!  This is not any bit of a real pte,
 * and is only used for signalling in variables that contain flags.
 */
#define _PAGE_INVALID_BIT (1U<<30)

#endif /* __X86_32_PAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
