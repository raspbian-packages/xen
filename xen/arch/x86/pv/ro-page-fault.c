/******************************************************************************
 * arch/x86/pv/ro-page-fault.c
 *
 * Read-only page fault emulation for PV guests
 *
 * Copyright (c) 2002-2005 K A Fraser
 * Copyright (c) 2004 Christian Limpach
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

#include <xen/trace.h>
#include <asm/shadow.h>

#include "emulate.h"
#include "mm.h"

/*********************
 * Writable Pagetables
 */

struct ptwr_emulate_ctxt {
    unsigned long cr2;
    l1_pgentry_t  pte;
};

static int ptwr_emulated_read(enum x86_segment seg, unsigned long offset,
                              void *p_data, unsigned int bytes,
                              struct x86_emulate_ctxt *ctxt)
{
    unsigned int rc = bytes;
    unsigned long addr = offset;

    if ( !__addr_ok(addr) ||
         (rc = __copy_from_user(p_data, (void *)addr, bytes)) )
    {
        x86_emul_pagefault(0, addr + bytes - rc, ctxt);  /* Read fault. */
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

/*
 * p_old being NULL indicates a plain write to occur, while a non-NULL
 * input requests a CMPXCHG-based update.
 */
static int ptwr_emulated_update(unsigned long addr, intpte_t *p_old,
                                intpte_t val, unsigned int bytes,
                                struct x86_emulate_ctxt *ctxt)
{
    mfn_t mfn;
    unsigned long unaligned_addr = addr;
    struct page_info *page;
    l1_pgentry_t pte, ol1e, nl1e, *pl1e;
    intpte_t old = p_old ? *p_old : 0;
    unsigned int offset = 0;
    struct vcpu *v = current;
    struct domain *d = v->domain;
    struct ptwr_emulate_ctxt *ptwr_ctxt = ctxt->data;
    int ret;

    /* Only allow naturally-aligned stores within the original %cr2 page. */
    if ( unlikely(((addr ^ ptwr_ctxt->cr2) & PAGE_MASK) ||
                  (addr & (bytes - 1))) )
    {
        gdprintk(XENLOG_WARNING, "bad access (cr2=%lx, addr=%lx, bytes=%u)\n",
                 ptwr_ctxt->cr2, addr, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    /* Turn a sub-word access into a full-word access. */
    if ( bytes != sizeof(val) )
    {
        intpte_t full;
        unsigned int rc;

        offset = (addr & (sizeof(full) - 1)) * 8;

        /* Align address; read full word. */
        addr &= ~(sizeof(full) - 1);
        if ( (rc = copy_from_user(&full, (void *)addr, sizeof(full))) != 0 )
        {
            x86_emul_pagefault(0, /* Read fault. */
                               addr + sizeof(full) - rc,
                               ctxt);
            return X86EMUL_EXCEPTION;
        }
        /* Mask out bits provided by caller. */
        full &= ~((((intpte_t)1 << (bytes * 8)) - 1) << offset);
        /* Shift the caller value and OR in the missing bits. */
        val  &= (((intpte_t)1 << (bytes * 8)) - 1);
        val <<= offset;
        val  |= full;
        /* Also fill in missing parts of the cmpxchg old value. */
        old  &= (((intpte_t)1 << (bytes * 8)) - 1);
        old <<= offset;
        old  |= full;
    }

    pte  = ptwr_ctxt->pte;
    mfn  = l1e_get_mfn(pte);
    page = mfn_to_page(mfn);

    /* We are looking only for read-only mappings of p.t. pages. */
    ASSERT((l1e_get_flags(pte) & (_PAGE_RW|_PAGE_PRESENT)) == _PAGE_PRESENT);
    ASSERT(mfn_valid(mfn));
    ASSERT((page->u.inuse.type_info & PGT_type_mask) == PGT_l1_page_table);
    ASSERT((page->u.inuse.type_info & PGT_count_mask) != 0);
    ASSERT(page_get_owner(page) == d);

    /* Check the new PTE. */
    nl1e = l1e_from_intpte(val);

    if ( !(l1e_get_flags(nl1e) & _PAGE_PRESENT) )
    {
        if ( pv_l1tf_check_l1e(d, nl1e) )
            return X86EMUL_RETRY;
    }
    else
    {
        switch ( ret = get_page_from_l1e(nl1e, d, d) )
        {
        default:
            if ( !is_pv_32bit_domain(d) || (bytes != 4) ||
                 !(unaligned_addr & 4) || p_old ||
                 !(l1e_get_flags(nl1e) & _PAGE_PRESENT) )
            {
                gdprintk(XENLOG_WARNING, "could not get_page_from_l1e()\n");
                return X86EMUL_UNHANDLEABLE;
            }
            /*
             * If this is an upper-half write to a PAE PTE then we assume that
             * the guest has simply got the two writes the wrong way round. We
             * zap the PRESENT bit on the assumption that the bottom half will
             * be written immediately after we return to the guest.
             */
            gdprintk(XENLOG_DEBUG, "ptwr_emulate: fixing up invalid PAE PTE %"
                     PRIpte"\n", l1e_get_intpte(nl1e));
            l1e_remove_flags(nl1e, _PAGE_PRESENT);
            break;

        case 0:
            break;

        case _PAGE_RW ... _PAGE_RW | PAGE_CACHE_ATTRS:
            ASSERT(!(ret & ~(_PAGE_RW | PAGE_CACHE_ATTRS)));
            l1e_flip_flags(nl1e, ret);
            break;
        }
    }

    nl1e = adjust_guest_l1e(nl1e, d);

    /* Checked successfully: do the update (write or cmpxchg). */
    pl1e = map_domain_page(mfn) + (addr & ~PAGE_MASK);
    if ( p_old )
    {
        ol1e = l1e_from_intpte(old);
        if ( !paging_cmpxchg_guest_entry(v, &l1e_get_intpte(*pl1e),
                                         &old, l1e_get_intpte(nl1e), mfn) )
            ret = X86EMUL_UNHANDLEABLE;
        else if ( l1e_get_intpte(ol1e) == old )
            ret = X86EMUL_OKAY;
        else
        {
            *p_old = old >> offset;
            ret = X86EMUL_CMPXCHG_FAILED;
        }

        if ( ret != X86EMUL_OKAY )
        {
            unmap_domain_page(pl1e);
            put_page_from_l1e(nl1e, d);
            return ret;
        }
    }
    else
    {
        ol1e = *pl1e;
        if ( !UPDATE_ENTRY(l1, pl1e, ol1e, nl1e, mfn, v, 0) )
            BUG();
    }

    trace_ptwr_emulation(addr, nl1e);

    unmap_domain_page(pl1e);

    /* Finally, drop the old PTE. */
    put_page_from_l1e(ol1e, d);

    return X86EMUL_OKAY;
}

static int ptwr_emulated_write(enum x86_segment seg, unsigned long offset,
                               void *p_data, unsigned int bytes,
                               struct x86_emulate_ctxt *ctxt)
{
    intpte_t val = 0;

    if ( (bytes > sizeof(val)) || (bytes & (bytes - 1)) || !bytes )
    {
        gdprintk(XENLOG_WARNING, "bad write size (addr=%lx, bytes=%u)\n",
                 offset, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    memcpy(&val, p_data, bytes);

    return ptwr_emulated_update(offset, NULL, val, bytes, ctxt);
}

static int ptwr_emulated_cmpxchg(enum x86_segment seg, unsigned long offset,
                                 void *p_old, void *p_new, unsigned int bytes,
                                 bool lock, struct x86_emulate_ctxt *ctxt)
{
    intpte_t old = 0, new = 0;
    int rc;

    if ( (bytes > sizeof(new)) || (bytes & (bytes - 1)) )
    {
        gdprintk(XENLOG_WARNING, "bad cmpxchg size (addr=%lx, bytes=%u)\n",
                 offset, bytes);
        return X86EMUL_UNHANDLEABLE;
    }

    memcpy(&old, p_old, bytes);
    memcpy(&new, p_new, bytes);

    rc = ptwr_emulated_update(offset, &old, new, bytes, ctxt);

    memcpy(p_old, &old, bytes);

    return rc;
}

static const struct x86_emulate_ops ptwr_emulate_ops = {
    .read       = ptwr_emulated_read,
    .insn_fetch = ptwr_emulated_read,
    .write      = ptwr_emulated_write,
    .cmpxchg    = ptwr_emulated_cmpxchg,
    .validate   = pv_emul_is_mem_write,
};

/* Write page fault handler: check if guest is trying to modify a PTE. */
static int ptwr_do_page_fault(struct x86_emulate_ctxt *ctxt,
                              unsigned long addr, l1_pgentry_t pte)
{
    struct ptwr_emulate_ctxt ptwr_ctxt = {
        .cr2 = addr,
        .pte = pte,
    };
    struct page_info *page;
    int rc;

    page = get_page_from_mfn(l1e_get_mfn(pte), current->domain);
    if ( !page )
        return X86EMUL_UNHANDLEABLE;

    if ( !page_lock(page) )
    {
        put_page(page);
        return X86EMUL_UNHANDLEABLE;
    }

    if ( (page->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(page);
        put_page(page);
        return X86EMUL_UNHANDLEABLE;
    }

    ctxt->data = &ptwr_ctxt;
    rc = x86_emulate(ctxt, &ptwr_emulate_ops);

    page_unlock(page);
    put_page(page);

    return rc;
}

/*****************************************
 * fault handling for read-only MMIO pages
 */

static const struct x86_emulate_ops mmio_ro_emulate_ops = {
    .read       = x86emul_unhandleable_rw,
    .insn_fetch = ptwr_emulated_read,
    .write      = mmio_ro_emulated_write,
    .validate   = pv_emul_is_mem_write,
};

static const struct x86_emulate_ops mmcfg_intercept_ops = {
    .read       = x86emul_unhandleable_rw,
    .insn_fetch = ptwr_emulated_read,
    .write      = mmcfg_intercept_write,
    .validate   = pv_emul_is_mem_write,
};

/* Check if guest is trying to modify a r/o MMIO page. */
static int mmio_ro_do_page_fault(struct x86_emulate_ctxt *ctxt,
                                 unsigned long addr, l1_pgentry_t pte)
{
    struct mmio_ro_emulate_ctxt mmio_ro_ctxt = { .cr2 = addr };
    mfn_t mfn = l1e_get_mfn(pte);

    if ( mfn_valid(mfn) )
    {
        struct page_info *page = mfn_to_page(mfn);
        const struct domain *owner = page_get_owner_and_reference(page);

        if ( owner )
            put_page(page);
        if ( owner != dom_io )
            return X86EMUL_UNHANDLEABLE;
    }

    ctxt->data = &mmio_ro_ctxt;
    if ( pci_ro_mmcfg_decode(mfn_x(mfn), &mmio_ro_ctxt.seg, &mmio_ro_ctxt.bdf) )
        return x86_emulate(ctxt, &mmcfg_intercept_ops);
    else
        return x86_emulate(ctxt, &mmio_ro_emulate_ops);
}

int pv_ro_page_fault(unsigned long addr, struct cpu_user_regs *regs)
{
    l1_pgentry_t pte;
    const struct domain *currd = current->domain;
    unsigned int addr_size = is_pv_32bit_domain(currd) ? 32 : BITS_PER_LONG;
    struct x86_emulate_ctxt ctxt = {
        .regs      = regs,
        .cpu_policy = currd->arch.cpu_policy,
        .addr_size = addr_size,
        .sp_size   = addr_size,
        .lma       = addr_size > 32,
    };
    int rc;
    bool mmio_ro;

    /* Attempt to read the PTE that maps the VA being accessed. */
    pte = guest_get_eff_l1e(addr);

    /* We are only looking for read-only mappings */
    if ( ((l1e_get_flags(pte) & (_PAGE_PRESENT | _PAGE_RW)) != _PAGE_PRESENT) )
        return 0;

    mmio_ro = is_hardware_domain(currd) &&
              rangeset_contains_singleton(mmio_ro_ranges, l1e_get_pfn(pte));
    if ( mmio_ro )
        rc = mmio_ro_do_page_fault(&ctxt, addr, pte);
    else
        rc = ptwr_do_page_fault(&ctxt, addr, pte);

    switch ( rc )
    {
    case X86EMUL_EXCEPTION:
        /*
         * This emulation covers writes to:
         *  - L1 pagetables.
         *  - MMCFG space or read-only MFNs.
         * We tolerate #PF (from hitting an adjacent page or a successful
         * concurrent pagetable update).  Anything else is an emulation bug,
         * or a guest playing with the instruction stream under Xen's feet.
         */
        if ( ctxt.event.type == X86_EVENTTYPE_HW_EXCEPTION &&
             ctxt.event.vector == TRAP_page_fault )
            pv_inject_event(&ctxt.event);
        else
            gdprintk(XENLOG_WARNING,
                     "Unexpected event (type %u, vector %#x) from emulation\n",
                     ctxt.event.type, ctxt.event.vector);

        /* Fallthrough */
    case X86EMUL_OKAY:
        if ( ctxt.retire.singlestep )
            pv_inject_hw_exception(TRAP_debug, X86_EVENT_NO_EC);

        /* Fallthrough */
    case X86EMUL_RETRY:
        if ( mmio_ro )
            perfc_incr(mmio_ro_emulations);
        else
            perfc_incr(ptwr_emulations);
        return EXCRET_fault_fixed;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
