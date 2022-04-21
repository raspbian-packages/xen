/******************************************************************************
 * arch/x86/pv/emulate.c
 *
 * Common PV emulation code
 *
 * Modifications to Linux original are copyright (c) 2002-2004, K A Fraser
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

#include <xen/guest_access.h>

#include <asm/debugreg.h>

#include "emulate.h"

int pv_emul_read_descriptor(unsigned int sel, const struct vcpu *v,
                            unsigned long *base, unsigned long *limit,
                            unsigned int *ar, bool insn_fetch)
{
    seg_desc_t desc;

    if ( sel < 4 ||
         /*
          * Don't apply the GDT limit here, as the selector may be a Xen
          * provided one. get_unsafe() will fail (without taking further
          * action) for ones falling in the gap between guest populated
          * and Xen ones.
          */
         ((sel & 4) && (sel >> 3) >= v->arch.pv.ldt_ents) )
        desc.b = desc.a = 0;
    else if ( get_unsafe(desc, gdt_ldt_desc_ptr(sel)) )
        return 0;
    if ( !insn_fetch )
        desc.b &= ~_SEGMENT_L;

    *ar = desc.b & 0x00f0ff00;
    if ( !(desc.b & _SEGMENT_L) )
    {
        *base = ((desc.a >> 16) + ((desc.b & 0xff) << 16) +
                 (desc.b & 0xff000000));
        *limit = (desc.a & 0xffff) | (desc.b & 0x000f0000);
        if ( desc.b & _SEGMENT_G )
            *limit = ((*limit + 1) << 12) - 1;
#ifndef NDEBUG
        if ( sel > 3 )
        {
            unsigned int a, l;
            unsigned char valid;

            asm volatile (
                "larl %2,%0 ; setz %1"
                : "=r" (a), "=qm" (valid) : "rm" (sel));
            BUG_ON(valid && ((a & 0x00f0ff00) != *ar));
            asm volatile (
                "lsll %2,%0 ; setz %1"
                : "=r" (l), "=qm" (valid) : "rm" (sel));
            BUG_ON(valid && (l != *limit));
        }
#endif
    }
    else
    {
        *base = 0UL;
        *limit = ~0UL;
    }

    return 1;
}

void pv_emul_instruction_done(struct cpu_user_regs *regs, unsigned long rip)
{
    regs->rip = rip;
    regs->eflags &= ~X86_EFLAGS_RF;
    if ( regs->eflags & X86_EFLAGS_TF )
    {
        current->arch.dr6 |= DR_STEP | DR_STATUS_RESERVED_ONE;
        pv_inject_hw_exception(TRAP_debug, X86_EVENT_NO_EC);
    }
}

uint64_t pv_get_reg(struct vcpu *v, unsigned int reg)
{
    const struct vcpu_msrs *msrs = v->arch.msrs;
    struct domain *d = v->domain;

    ASSERT(v == current || !vcpu_runnable(v));

    switch ( reg )
    {
    case MSR_SPEC_CTRL:
        return msrs->spec_ctrl.raw;

    default:
        printk(XENLOG_G_ERR "%s(%pv, 0x%08x) Bad register\n",
               __func__, v, reg);
        domain_crash(d);
        return 0;
    }
}

void pv_set_reg(struct vcpu *v, unsigned int reg, uint64_t val)
{
    struct vcpu_msrs *msrs = v->arch.msrs;
    struct domain *d = v->domain;

    ASSERT(v == current || !vcpu_runnable(v));

    switch ( reg )
    {
    case MSR_SPEC_CTRL:
        msrs->spec_ctrl.raw = val;
        break;

    default:
        printk(XENLOG_G_ERR "%s(%pv, 0x%08x, 0x%016"PRIx64") Bad register\n",
               __func__, v, reg, val);
        domain_crash(d);
    }
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
