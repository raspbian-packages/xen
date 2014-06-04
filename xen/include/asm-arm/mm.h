#ifndef __ARCH_ARM_MM__
#define __ARCH_ARM_MM__

#include <xen/config.h>
#include <xen/kernel.h>
#include <asm/page.h>
#include <public/xen.h>
#include <xen/domain_page.h>

/* Align Xen to a 2 MiB boundary. */
#define XEN_PADDR_ALIGN (1 << 21)

/*
 * Per-page-frame information.
 *
 * Every architecture must ensure the following:
 *  1. 'struct page_info' contains a 'struct page_list_entry list'.
 *  2. Provide a PFN_ORDER() macro for accessing the order of a free page.
 */
#define PFN_ORDER(_pfn) ((_pfn)->v.free.order)

struct page_info
{
    /* Each frame can be threaded onto a doubly-linked list. */
    struct page_list_entry list;

    /* Reference count and various PGC_xxx flags and fields. */
    unsigned long count_info;

    /* Context-dependent fields follow... */
    union {
        /* Page is in use: ((count_info & PGC_count_mask) != 0). */
        struct {
            /* Type reference count and various PGT_xxx flags and fields. */
            unsigned long type_info;
        } inuse;
        /* Page is on a free list: ((count_info & PGC_count_mask) == 0). */
        struct {
            /* Do TLBs need flushing for safety before next page use? */
            bool_t need_tlbflush;
        } free;

    } u;

    union {
        /* Page is in use, but not as a shadow. */
        struct {
            /* Owner of this page (zero if page is anonymous). */
            struct domain *domain;
        } inuse;

        /* Page is on a free list. */
        struct {
            /* Order-size of the free chunk this page is the head of. */
            unsigned int order;
        } free;

    } v;

    union {
        /*
         * Timestamp from 'TLB clock', used to avoid extra safety flushes.
         * Only valid for: a) free pages, and b) pages with zero type count
         */
        u32 tlbflush_timestamp;
    };
    u64 pad;
};

#define PG_shift(idx)   (BITS_PER_LONG - (idx))
#define PG_mask(x, idx) (x ## UL << PG_shift(idx))

#define PGT_none          PG_mask(0, 4)  /* no special uses of this page   */
#define PGT_writable_page PG_mask(7, 4)  /* has writable mappings?         */
#define PGT_type_mask     PG_mask(15, 4) /* Bits 28-31 or 60-63.           */

 /* Owning guest has pinned this page to its current type? */
#define _PGT_pinned       PG_shift(5)
#define PGT_pinned        PG_mask(1, 5)

 /* Has this page been validated for use as its current type? */
#define _PGT_validated    PG_shift(6)
#define PGT_validated     PG_mask(1, 6)

 /* Count of uses of this frame as its current type. */
#define PGT_count_width   PG_shift(9)
#define PGT_count_mask    ((1UL<<PGT_count_width)-1)

 /* Cleared when the owning guest 'frees' this page. */
#define _PGC_allocated    PG_shift(1)
#define PGC_allocated     PG_mask(1, 1)
  /* Page is Xen heap? */
#define _PGC_xen_heap     PG_shift(2)
#define PGC_xen_heap      PG_mask(1, 2)
/* ... */
/* Page is broken? */
#define _PGC_broken       PG_shift(7)
#define PGC_broken        PG_mask(1, 7)
 /* Mutually-exclusive page states: { inuse, offlining, offlined, free }. */
#define PGC_state         PG_mask(3, 9)
#define PGC_state_inuse   PG_mask(0, 9)
#define PGC_state_offlining PG_mask(1, 9)
#define PGC_state_offlined PG_mask(2, 9)
#define PGC_state_free    PG_mask(3, 9)
#define page_state_is(pg, st) (((pg)->count_info&PGC_state) == PGC_state_##st)

/* Count of references to this frame. */
#define PGC_count_width   PG_shift(9)
#define PGC_count_mask    ((1UL<<PGC_count_width)-1)

extern unsigned long xenheap_mfn_start, xenheap_mfn_end;
extern unsigned long xenheap_virt_end;

#ifdef CONFIG_ARM_32
#define is_xen_heap_page(page) is_xen_heap_mfn(page_to_mfn(page))
#define is_xen_heap_mfn(mfn) ({                                 \
    unsigned long _mfn = (mfn);                                 \
    (_mfn >= xenheap_mfn_start && _mfn < xenheap_mfn_end);      \
})
#else
#define is_xen_heap_page(page) ((page)->count_info & PGC_xen_heap)
#define is_xen_heap_mfn(mfn) \
    (mfn_valid(mfn) && is_xen_heap_page(__mfn_to_page(mfn)))
#endif

#define is_xen_fixed_mfn(mfn)                                   \
    ((pfn_to_paddr(mfn) >= virt_to_maddr(&_start)) &&       \
     (pfn_to_paddr(mfn) <= virt_to_maddr(&_end)))

#define page_get_owner(_p)    (_p)->v.inuse.domain
#define page_set_owner(_p,_d) ((_p)->v.inuse.domain = (_d))

#define maddr_get_owner(ma)   (page_get_owner(maddr_to_page((ma))))

#define XENSHARE_writable 0
#define XENSHARE_readonly 1
extern void share_xen_page_with_guest(
    struct page_info *page, struct domain *d, int readonly);
extern void share_xen_page_with_privileged_guests(
    struct page_info *page, int readonly);

#define frame_table ((struct page_info *)FRAMETABLE_VIRT_START)
/* MFN of the first page in the frame table. */
extern unsigned long frametable_base_mfn;

extern unsigned long max_page;
extern unsigned long total_pages;

/* Boot-time pagetable setup */
extern void setup_pagetables(unsigned long boot_phys_offset, paddr_t xen_paddr);
/* Remove early mappings */
extern void remove_early_mappings(void);
/* Allocate and initialise pagetables for a secondary CPU. Sets init_ttbr to the
 * new page table */
extern int __cpuinit init_secondary_pagetables(int cpu);
/* Switch secondary CPUS to its own pagetables and finalise MMU setup */
extern void __cpuinit mmu_init_secondary_cpu(void);
/* Second stage paging setup, to be called on all CPUs */
extern void __cpuinit setup_virt_paging(void);
/* Set up the xenheap: up to 1GB of contiguous, always-mapped memory.
 * Base must be 32MB aligned and size a multiple of 32MB. */
extern void setup_xenheap_mappings(unsigned long base_mfn, unsigned long nr_mfns);
/* Map a frame table to cover physical addresses ps through pe */
extern void setup_frametable_mappings(paddr_t ps, paddr_t pe);
/* Map a 4k page in a fixmap entry */
extern void set_fixmap(unsigned map, unsigned long mfn, unsigned attributes);
/* Remove a mapping from a fixmap entry */
extern void clear_fixmap(unsigned map);
/* map a physical range in virtual memory */
void __iomem *ioremap_attr(paddr_t start, size_t len, unsigned attributes);

static inline void __iomem *ioremap_nocache(paddr_t start, size_t len)
{
    return ioremap_attr(start, len, PAGE_HYPERVISOR_NOCACHE);
}

static inline void __iomem *ioremap_cache(paddr_t start, size_t len)
{
    return ioremap_attr(start, len, PAGE_HYPERVISOR);
}

static inline void __iomem *ioremap_wc(paddr_t start, size_t len)
{
    return ioremap_attr(start, len, PAGE_HYPERVISOR_WC);
}

#define mfn_valid(mfn)        ({                                              \
    unsigned long __m_f_n = (mfn);                                            \
    likely(__m_f_n >= frametable_base_mfn && __m_f_n < max_page);             \
})

#define max_pdx                 max_page
#define pfn_to_pdx(pfn)         (pfn)
#define pdx_to_pfn(pdx)         (pdx)
#define virt_to_pdx(va)         virt_to_mfn(va)
#define pdx_to_virt(pdx)        mfn_to_virt(pdx)

/* Convert between machine frame numbers and page-info structures. */
#define mfn_to_page(mfn)  (frame_table + (pfn_to_pdx(mfn) - frametable_base_mfn))
#define page_to_mfn(pg)   pdx_to_pfn((unsigned long)((pg) - frame_table) + frametable_base_mfn)
#define __page_to_mfn(pg)  page_to_mfn(pg)
#define __mfn_to_page(mfn) mfn_to_page(mfn)

/* Convert between machine addresses and page-info structures. */
#define maddr_to_page(ma) __mfn_to_page((ma) >> PAGE_SHIFT)
#define page_to_maddr(pg) ((paddr_t)__page_to_mfn(pg) << PAGE_SHIFT)

/* Convert between frame number and address formats.  */
#define pfn_to_paddr(pfn) ((paddr_t)(pfn) << PAGE_SHIFT)
#define paddr_to_pfn(pa)  ((unsigned long)((pa) >> PAGE_SHIFT))
#define paddr_to_pdx(pa)    pfn_to_pdx(paddr_to_pfn(pa))


static inline paddr_t __virt_to_maddr(vaddr_t va)
{
    uint64_t par = va_to_par(va);
    return (par & PADDR_MASK & PAGE_MASK) | (va & ~PAGE_MASK);
}
#define virt_to_maddr(va)   __virt_to_maddr((vaddr_t)(va))

#ifdef CONFIG_ARM_32
static inline void *maddr_to_virt(paddr_t ma)
{
    ASSERT(is_xen_heap_mfn(ma >> PAGE_SHIFT));
    ma -= pfn_to_paddr(xenheap_mfn_start);
    return (void *)(unsigned long) ma + XENHEAP_VIRT_START;
}
#else
static inline void *maddr_to_virt(paddr_t ma)
{
    ASSERT((ma >> PAGE_SHIFT) < (DIRECTMAP_SIZE >> PAGE_SHIFT));
    ma -= pfn_to_paddr(xenheap_mfn_start);
    return (void *)(unsigned long) ma + DIRECTMAP_VIRT_START;
}
#endif

static inline int gvirt_to_maddr(vaddr_t va, paddr_t *pa, unsigned int flags)
{
    uint64_t par = gva_to_ma_par(va, flags);
    if ( par & PAR_F )
        return -EFAULT;
    *pa = (par & PADDR_MASK & PAGE_MASK) | ((unsigned long) va & ~PAGE_MASK);
    return 0;
}

/* Convert between Xen-heap virtual addresses and machine addresses. */
#define __pa(x)             (virt_to_maddr(x))
#define __va(x)             (maddr_to_virt(x))

/* Convert between Xen-heap virtual addresses and machine frame numbers. */
#define virt_to_mfn(va)   (virt_to_maddr(va) >> PAGE_SHIFT)
#define mfn_to_virt(mfn)  (maddr_to_virt((paddr_t)(mfn) << PAGE_SHIFT))


/* Convert between Xen-heap virtual addresses and page-info structures. */
static inline struct page_info *virt_to_page(const void *v)
{
    unsigned long va = (unsigned long)v;
    ASSERT(va >= XENHEAP_VIRT_START);
    ASSERT(va < xenheap_virt_end);

    return frame_table
        + ((va - XENHEAP_VIRT_START) >> PAGE_SHIFT)
        + xenheap_mfn_start
        - frametable_base_mfn;
}

static inline void *page_to_virt(const struct page_info *pg)
{
    return mfn_to_virt(page_to_mfn(pg));
}

struct domain *page_get_owner_and_reference(struct page_info *page);
void put_page(struct page_info *page);
int  get_page(struct page_info *page, struct domain *domain);

/*
 * The MPT (machine->physical mapping table) is an array of word-sized
 * values, indexed on machine frame number. It is expected that guest OSes
 * will use it to store a "physical" frame number to give the appearance of
 * contiguous (or near contiguous) physical memory.
 */
#undef  machine_to_phys_mapping
#define machine_to_phys_mapping  ((unsigned long *)RDWR_MPT_VIRT_START)
#define INVALID_M2P_ENTRY        (~0UL)
#define VALID_M2P(_e)            (!((_e) & (1UL<<(BITS_PER_LONG-1))))
#define SHARED_M2P_ENTRY         (~0UL - 1UL)
#define SHARED_M2P(_e)           ((_e) == SHARED_M2P_ENTRY)

#define _set_gpfn_from_mfn(mfn, pfn) ({                        \
    struct domain *d = page_get_owner(__mfn_to_page(mfn));     \
    if(d && (d == dom_cow))                                    \
        machine_to_phys_mapping[(mfn)] = SHARED_M2P_ENTRY;     \
    else                                                       \
        machine_to_phys_mapping[(mfn)] = (pfn);                \
    })

static inline void put_gfn(struct domain *d, unsigned long gfn) {}
static inline void mem_event_cleanup(struct domain *d) {}
static inline int relinquish_shared_pages(struct domain *d)
{
    return 0;
}

#define INVALID_MFN             (~0UL)

/* Xen always owns P2M on ARM */
#define set_gpfn_from_mfn(mfn, pfn) do { (void) (mfn), (void)(pfn); } while (0)
#define mfn_to_gmfn(_d, mfn)  (mfn)


/* Arch-specific portion of memory_op hypercall. */
long arch_memory_op(int op, XEN_GUEST_HANDLE_PARAM(void) arg);

int steal_page(
    struct domain *d, struct page_info *page, unsigned int memflags);
int donate_page(
    struct domain *d, struct page_info *page, unsigned int memflags);

#define domain_set_alloc_bitsize(d) ((void)0)
#define domain_clamp_alloc_bitsize(d, b) (b)

unsigned long domain_get_maximum_gpfn(struct domain *d);

extern struct domain *dom_xen, *dom_io, *dom_cow;

#define memguard_init(_s)              (_s)
#define memguard_guard_stack(_p)       ((void)0)
#define memguard_guard_range(_p,_l)    ((void)0)
#define memguard_unguard_range(_p,_l)  ((void)0)

/* Release all __init and __initdata ranges to be reused */
void free_init_memory(void);

int guest_physmap_mark_populate_on_demand(struct domain *d, unsigned long gfn,
                                          unsigned int order);

extern void put_page_type(struct page_info *page);
static inline void put_page_and_type(struct page_info *page)
{
    put_page_type(page);
    put_page(page);
}

void clear_and_clean_page(struct page_info *page);

#endif /*  __ARCH_ARM_MM__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
