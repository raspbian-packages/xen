/******************************************************************************
 * include/asm-x86/paging.h
 *
 * Common interface for paging support
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang) 
 * Parts of this code are Copyright (c) 2006 by XenSource Inc.
 * Parts of this code are Copyright (c) 2006 by Michael A Fetterman
 * Parts based on earlier work by Michael A Fetterman, Ian Pratt et al.
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _XEN_PAGING_H
#define _XEN_PAGING_H

#include <xen/mm.h>
#include <public/domctl.h>
#include <xen/sched.h>
#include <xen/perfc.h>
#include <xen/domain_page.h>
#include <asm/flushtlb.h>
#include <asm/domain.h>

/*****************************************************************************
 * Macros to tell which paging mode a domain is in */

#define PG_SH_shift    20
#define PG_HAP_shift   21
#define PG_SHF_shift   22
/* We're in one of the shadow modes */
#ifdef CONFIG_SHADOW_PAGING
#define PG_SH_enable   (1U << PG_SH_shift)
#define PG_SH_forced   (1U << PG_SHF_shift)
#else
#define PG_SH_enable   0
#define PG_SH_forced   0
#endif
#ifdef CONFIG_HVM
#define PG_HAP_enable  (1U << PG_HAP_shift)
#else
#define PG_HAP_enable  0
#endif

/* common paging mode bits */
#define PG_mode_shift  10 
#ifdef CONFIG_HVM
/* Refcounts based on shadow tables instead of guest tables */
#define PG_refcounts   (XEN_DOMCTL_SHADOW_ENABLE_REFCOUNT << PG_mode_shift)
/* Xen does p2m translation, not guest */
#define PG_translate   (XEN_DOMCTL_SHADOW_ENABLE_TRANSLATE << PG_mode_shift)
/* Xen does not steal address space from the domain for its own booking;
 * requires VT or similar mechanisms */
#define PG_external    (XEN_DOMCTL_SHADOW_ENABLE_EXTERNAL << PG_mode_shift)
#else
#define PG_refcounts   0
#define PG_translate   0
#define PG_external    0
#endif
/* Enable log dirty mode */
#define PG_log_dirty   (XEN_DOMCTL_SHADOW_ENABLE_LOG_DIRTY << PG_mode_shift)

/* All paging modes. */
#define PG_MASK (PG_refcounts | PG_log_dirty | PG_translate | PG_external)

#define paging_mode_enabled(_d)   (!!(_d)->arch.paging.mode)
#define paging_mode_shadow(_d)    (!!((_d)->arch.paging.mode & PG_SH_enable))
#define paging_mode_sh_forced(_d) (!!((_d)->arch.paging.mode & PG_SH_forced))
#define paging_mode_hap(_d)       (!!((_d)->arch.paging.mode & PG_HAP_enable))

#define paging_mode_refcounts(_d) (!!((_d)->arch.paging.mode & PG_refcounts))
#define paging_mode_log_dirty(_d) (!!((_d)->arch.paging.mode & PG_log_dirty))
#define paging_mode_translate(_d) (!!((_d)->arch.paging.mode & PG_translate))
#define paging_mode_external(_d)  (!!((_d)->arch.paging.mode & PG_external))

/* flags used for paging debug */
#define PAGING_DEBUG_LOGDIRTY 0

/*****************************************************************************
 * Mode-specific entry points into the shadow code.  
 *
 * These shouldn't be used directly by callers; rather use the functions
 * below which will indirect through this table as appropriate. */

struct shadow_paging_mode {
#ifdef CONFIG_SHADOW_PAGING
    void          (*detach_old_tables     )(struct vcpu *v);
#ifdef CONFIG_PV
    bool          (*write_guest_entry     )(struct vcpu *v, intpte_t *p,
                                            intpte_t new, mfn_t gmfn);
    bool          (*cmpxchg_guest_entry   )(struct vcpu *v, intpte_t *p,
                                            intpte_t *old, intpte_t new,
                                            mfn_t gmfn);
#endif
#ifdef CONFIG_HVM
    mfn_t         (*make_monitor_table    )(struct vcpu *v);
    void          (*destroy_monitor_table )(struct vcpu *v, mfn_t mmfn);
    int           (*guess_wrmap           )(struct vcpu *v, 
                                            unsigned long vaddr, mfn_t gmfn);
    void          (*pagetable_dying       )(paddr_t gpa);
    void          (*trace_emul_write_val  )(const void *ptr, unsigned long vaddr,
                                            const void *src, unsigned int bytes);
#endif
#endif
    /* For outsiders to tell what mode we're in */
    unsigned int shadow_levels;
};


/************************************************/
/*        common paging interface               */
/************************************************/
struct paging_mode {
    int           (*page_fault            )(struct vcpu *v, unsigned long va,
                                            struct cpu_user_regs *regs);
    bool          (*invlpg                )(struct vcpu *v,
                                            unsigned long linear);
    unsigned long (*gva_to_gfn            )(struct vcpu *v,
                                            struct p2m_domain *p2m,
                                            unsigned long va,
                                            uint32_t *pfec);
    unsigned long (*p2m_ga_to_gfn         )(struct vcpu *v,
                                            struct p2m_domain *p2m,
                                            unsigned long cr3,
                                            paddr_t ga, uint32_t *pfec,
                                            unsigned int *page_order);
    void          (*update_cr3            )(struct vcpu *v, int do_locking,
                                            bool noflush);
    void          (*update_paging_modes   )(struct vcpu *v);
    int           (*write_p2m_entry       )(struct p2m_domain *p2m,
                                            unsigned long gfn,
                                            l1_pgentry_t *p, l1_pgentry_t new,
                                            unsigned int level);
    bool          (*flush_tlb             )(bool (*flush_vcpu)(void *ctxt,
                                                               struct vcpu *v),
                                            void *ctxt);

    unsigned int guest_levels;

    /* paging support extension */
    struct shadow_paging_mode shadow;
};

/*****************************************************************************
 * Log dirty code */

/* get the dirty bitmap for a specific range of pfns */
void paging_log_dirty_range(struct domain *d,
                            unsigned long begin_pfn,
                            unsigned long nr,
                            uint8_t *dirty_bitmap);

/* log dirty initialization */
void paging_log_dirty_init(struct domain *d, const struct log_dirty_ops *ops);

/* mark a page as dirty */
void paging_mark_dirty(struct domain *d, mfn_t gmfn);
/* mark a page as dirty with taking guest pfn as parameter */
void paging_mark_pfn_dirty(struct domain *d, pfn_t pfn);

/* is this guest page dirty? 
 * This is called from inside paging code, with the paging lock held. */
int paging_mfn_is_dirty(struct domain *d, mfn_t gmfn);

/*
 * Log-dirty radix tree indexing:
 *   All tree nodes are PAGE_SIZE bytes, mapped on-demand.
 *   Leaf nodes are simple bitmaps; 1 bit per guest pfn.
 *   Interior nodes are arrays of LOGDIRTY_NODE_ENTRIES mfns.
 * TODO: Dynamic radix tree height. Most guests will only need 2 levels.
 *       The fourth level is basically unusable on 32-bit Xen.
 * TODO2: Abstract out the radix-tree mechanics?
 */
#define LOGDIRTY_NODE_ENTRIES (1 << PAGETABLE_ORDER)
#define L1_LOGDIRTY_IDX(pfn) (pfn_x(pfn) & ((1 << (PAGE_SHIFT + 3)) - 1))
#define L2_LOGDIRTY_IDX(pfn) ((pfn_x(pfn) >> (PAGE_SHIFT + 3)) & \
                              (LOGDIRTY_NODE_ENTRIES-1))
#define L3_LOGDIRTY_IDX(pfn) ((pfn_x(pfn) >> (PAGE_SHIFT + 3 + PAGETABLE_ORDER)) & \
                              (LOGDIRTY_NODE_ENTRIES-1))
#define L4_LOGDIRTY_IDX(pfn) ((pfn_x(pfn) >> (PAGE_SHIFT + 3 + PAGETABLE_ORDER * 2)) & \
                              (LOGDIRTY_NODE_ENTRIES-1))

/* VRAM dirty tracking support */
struct sh_dirty_vram {
    unsigned long begin_pfn;
    unsigned long end_pfn;
    paddr_t *sl1ma;
    uint8_t *dirty_bitmap;
    s_time_t last_dirty;
};

/*****************************************************************************
 * Entry points into the paging-assistance code */

/* Initialize the paging resource for vcpu struct. It is called by
 * vcpu_initialise() in domain.c */
void paging_vcpu_init(struct vcpu *v);

/* Set up the paging-assistance-specific parts of a domain struct at
 * start of day.  Called for every domain from arch_domain_create() */
int paging_domain_init(struct domain *d);

/* Handler for paging-control ops: operations from user-space to enable
 * and disable ephemeral shadow modes (test mode and log-dirty mode) and
 * manipulate the log-dirty bitmap. */
int paging_domctl(struct domain *d, struct xen_domctl_shadow_op *sc,
                  XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl,
                  bool_t resuming);

/* Helper hypercall for dealing with continuations. */
long paging_domctl_continuation(XEN_GUEST_HANDLE_PARAM(xen_domctl_t));

/* Call when destroying a domain */
int paging_teardown(struct domain *d);

/* Call once all of the references to the domain have gone away */
void paging_final_teardown(struct domain *d);

/* Enable an arbitrary paging-assistance mode.  Call once at domain
 * creation. */
int paging_enable(struct domain *d, u32 mode);

#define paging_get_hostmode(v)		((v)->arch.paging.mode)
#define paging_get_nestedmode(v)	((v)->arch.paging.nestedmode)
const struct paging_mode *paging_get_mode(struct vcpu *v);
void paging_update_nestedmode(struct vcpu *v);

/* Page fault handler
 * Called from pagefault handler in Xen, and from the HVM trap handlers
 * for pagefaults.  Returns 1 if this fault was an artefact of the
 * paging code (and the guest should retry) or 0 if it is not (and the
 * fault should be handled elsewhere or passed to the guest).
 *
 * Note: under shadow paging, this function handles all page faults;
 * however, for hardware-assisted paging, this function handles only 
 * host page faults (i.e. nested page faults). */
static inline int
paging_fault(unsigned long va, struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    return paging_get_hostmode(v)->page_fault(v, va, regs);
}

/* Handle invlpg requests on vcpus. */
void paging_invlpg(struct vcpu *v, unsigned long va);

/*
 * Translate a guest virtual address to the frame number that the
 * *guest* pagetables would map it to.  Returns INVALID_GFN if the guest
 * tables don't map this address for this kind of access.
 * *pfec is used to determine which kind of access this is when
 * walking the tables.  The caller should set the PFEC_page_present bit
 * in *pfec; in the failure case, that bit will be cleared if appropriate.
 *
 * SDM Intel 64 Volume 3, Chapter Paging, PAGE-FAULT EXCEPTIONS:
 * The PFEC_insn_fetch flag is set only when NX or SMEP are enabled.
 */
unsigned long paging_gva_to_gfn(struct vcpu *v,
                                unsigned long va,
                                uint32_t *pfec);

/* Translate a guest address using a particular CR3 value.  This is used
 * to by nested HAP code, to walk the guest-supplied NPT tables as if
 * they were pagetables.
 * Use 'paddr_t' for the guest address so it won't overflow when
 * l1 or l2 guest is in 32bit PAE mode.
 * If the GFN returned is not INVALID_GFN, *page_order gives
 * the size of the superpage (if any) it was found in. */
static inline unsigned long paging_ga_to_gfn_cr3(struct vcpu *v,
                                                 unsigned long cr3,
                                                 paddr_t ga,
                                                 uint32_t *pfec,
                                                 unsigned int *page_order)
{
    struct p2m_domain *p2m = v->domain->arch.p2m;
    return paging_get_hostmode(v)->p2m_ga_to_gfn(v, p2m, cr3, ga, pfec,
        page_order);
}

/* Update all the things that are derived from the guest's CR3.
 * Called when the guest changes CR3; the caller can then use v->arch.cr3
 * as the value to load into the host CR3 to schedule this vcpu */
static inline void paging_update_cr3(struct vcpu *v, bool noflush)
{
    paging_get_hostmode(v)->update_cr3(v, 1, noflush);
}

/* Update all the things that are derived from the guest's CR0/CR3/CR4.
 * Called to initialize paging structures if the paging mode
 * has changed, and when bringing up a VCPU for the first time. */
static inline void paging_update_paging_modes(struct vcpu *v)
{
    paging_get_hostmode(v)->update_paging_modes(v);
}

#ifdef CONFIG_PV

/*
 * Write a new value into the guest pagetable, and update the
 * paging-assistance state appropriately.  Returns false if we page-faulted,
 * true for success.
 */
static inline bool paging_write_guest_entry(
    struct vcpu *v, intpte_t *p, intpte_t new, mfn_t gmfn)
{
#ifdef CONFIG_SHADOW_PAGING
    if ( unlikely(paging_mode_shadow(v->domain)) && paging_get_hostmode(v) )
        return paging_get_hostmode(v)->shadow.write_guest_entry(v, p, new,
                                                                gmfn);
#endif
    return !__copy_to_user(p, &new, sizeof(new));
}


/*
 * Cmpxchg a new value into the guest pagetable, and update the
 * paging-assistance state appropriately.  Returns false if we page-faulted,
 * true if not.  N.B. caller should check the value of "old" to see if the
 * cmpxchg itself was successful.
 */
static inline bool paging_cmpxchg_guest_entry(
    struct vcpu *v, intpte_t *p, intpte_t *old, intpte_t new, mfn_t gmfn)
{
#ifdef CONFIG_SHADOW_PAGING
    if ( unlikely(paging_mode_shadow(v->domain)) && paging_get_hostmode(v) )
        return paging_get_hostmode(v)->shadow.cmpxchg_guest_entry(v, p, old,
                                                                  new, gmfn);
#endif
    return !cmpxchg_user(p, *old, new);
}

#endif /* CONFIG_PV */

/* Helper function that writes a pte in such a way that a concurrent read 
 * never sees a half-written entry that has _PAGE_PRESENT set */
static inline void safe_write_pte(l1_pgentry_t *p, l1_pgentry_t new)
{
    *p = new;
}

/* Atomically write a P2M entry and update the paging-assistance state 
 * appropriately. 
 * Arguments: the domain in question, the GFN whose mapping is being updated, 
 * a pointer to the entry to be written, the MFN in which the entry resides, 
 * the new contents of the entry, and the level in the p2m tree at which 
 * we are writing. */
struct p2m_domain;

int paging_write_p2m_entry(struct p2m_domain *p2m, unsigned long gfn,
                           l1_pgentry_t *p, l1_pgentry_t new,
                           unsigned int level);

/*
 * Called from the guest to indicate that the a process is being
 * torn down and its pagetables will soon be discarded.
 */
void pagetable_dying(paddr_t gpa);

/* Print paging-assistance info to the console */
void paging_dump_domain_info(struct domain *d);
void paging_dump_vcpu_info(struct vcpu *v);

/* Set the pool of shadow pages to the required number of pages.
 * Input might be rounded up to at minimum amount of pages, plus
 * space for the p2m table.
 * Returns 0 for success, non-zero for failure. */
int paging_set_allocation(struct domain *d, unsigned int pages,
                          bool *preempted);

/* Is gfn within maxphysaddr for the domain? */
static inline bool gfn_valid(const struct domain *d, gfn_t gfn)
{
    return !(gfn_x(gfn) >> (d->arch.cpuid->extd.maxphysaddr - PAGE_SHIFT));
}

/* Maxphysaddr supportable by the paging infrastructure. */
static always_inline unsigned int paging_max_paddr_bits(const struct domain *d)
{
    unsigned int bits = paging_mode_hap(d) ? hap_paddr_bits : paddr_bits;

    if ( paging_mode_external(d) )
    {
        if ( !IS_ENABLED(CONFIG_BIGMEM) && paging_mode_shadow(d) )
        {
            /* Shadowed superpages store GFNs in 32-bit page_info fields. */
            bits = min(bits, 32U + PAGE_SHIFT);
        }
        else
        {
            /* Both p2m-ept and p2m-pt only support 4-level page tables. */
            bits = min(bits, 48U);
        }
    }

    return bits;
}

static inline bool paging_flush_tlb(bool (*flush_vcpu)(void *ctxt,
                                                       struct vcpu *v),
                                    void *ctxt)
{
    return paging_get_hostmode(current)->flush_tlb(flush_vcpu, ctxt);
}

#endif /* XEN_PAGING_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
