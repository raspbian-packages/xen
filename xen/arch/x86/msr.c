/******************************************************************************
 * arch/x86/msr.c
 *
 * Policy objects for Model-Specific Registers.
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
 *
 * Copyright (c) 2017 Citrix Systems Ltd.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/nospec.h>
#include <xen/sched.h>

#include <asm/cpu-policy.h>
#include <asm/debugreg.h>
#include <asm/hvm/viridian.h>
#include <asm/msr.h>
#include <asm/pv/domain.h>
#include <asm/setup.h>

#include <public/hvm/params.h>

DEFINE_PER_CPU(uint32_t, tsc_aux);

int init_vcpu_msr_policy(struct vcpu *v)
{
    struct vcpu_msrs *msrs = xzalloc(struct vcpu_msrs);

    if ( !msrs )
        return -ENOMEM;

    v->arch.msrs = msrs;

    return 0;
}

int guest_rdmsr(struct vcpu *v, uint32_t msr, uint64_t *val)
{
    const struct vcpu *curr = current;
    const struct domain *d = v->domain;
    const struct cpu_policy *cp = d->arch.cpu_policy;
    const struct vcpu_msrs *msrs = v->arch.msrs;
    int ret = X86EMUL_OKAY;

    switch ( msr )
    {
    case MSR_AMD_PATCHLOADER:
    case MSR_IA32_UCODE_WRITE:
    case MSR_PRED_CMD:
    case MSR_FLUSH_CMD:
        /* Write-only */
    case MSR_TEST_CTRL:
    case MSR_CORE_CAPABILITIES:
    case MSR_TSX_FORCE_ABORT:
    case MSR_TSX_CTRL:
    case MSR_MCU_OPT_CTRL:
    case MSR_RTIT_OUTPUT_BASE ... MSR_RTIT_ADDR_B(7):
    case MSR_RAPL_POWER_UNIT:
    case MSR_PKG_POWER_LIMIT  ... MSR_PKG_POWER_INFO:
    case MSR_DRAM_POWER_LIMIT ... MSR_DRAM_POWER_INFO:
    case MSR_PP0_POWER_LIMIT  ... MSR_PP0_POLICY:
    case MSR_PP1_POWER_LIMIT  ... MSR_PP1_POLICY:
    case MSR_PLATFORM_ENERGY_COUNTER:
    case MSR_PLATFORM_POWER_LIMIT:
    case MSR_U_CET:
    case MSR_S_CET:
    case MSR_PL0_SSP ... MSR_INTERRUPT_SSP_TABLE:
    case MSR_AMD64_LWP_CFG:
    case MSR_AMD64_LWP_CBADDR:
    case MSR_PPIN_CTL:
    case MSR_PPIN:
    case MSR_F15H_CU_POWER ... MSR_F15H_CU_MAX_POWER:
    case MSR_AMD_RAPL_POWER_UNIT ... MSR_AMD_PKG_ENERGY_STATUS:
    case MSR_AMD_PPIN_CTL:
    case MSR_AMD_PPIN:
        /* Not offered to guests. */
        goto gp_fault;

    case MSR_IA32_PLATFORM_ID:
        if ( !(cp->x86_vendor & X86_VENDOR_INTEL) ||
             !(boot_cpu_data.x86_vendor & X86_VENDOR_INTEL) )
            goto gp_fault;
        rdmsrl(MSR_IA32_PLATFORM_ID, *val);
        break;

    case MSR_AMD_PATCHLEVEL:
        BUILD_BUG_ON(MSR_IA32_UCODE_REV != MSR_AMD_PATCHLEVEL);
        /*
         * AMD and Intel use the same MSR for the current microcode version.
         *
         * There is no need to jump through the SDM-provided hoops for Intel.
         * A guest might itself perform the "write 0, CPUID, read" sequence,
         * but servicing the CPUID for the guest typically wont result in
         * actually executing a CPUID instruction.
         *
         * As a guest can't influence the value of this MSR, the value will be
         * from Xen's last microcode load, which can be forwarded straight to
         * the guest.
         */
        if ( !(cp->x86_vendor & (X86_VENDOR_INTEL | X86_VENDOR_AMD)) ||
             !(boot_cpu_data.x86_vendor &
               (X86_VENDOR_INTEL | X86_VENDOR_AMD)) ||
             rdmsr_safe(MSR_AMD_PATCHLEVEL, *val) )
            goto gp_fault;
        break;

    case MSR_SPEC_CTRL:
        if ( !cp->feat.ibrsb && !cp->extd.ibrs )
            goto gp_fault;
        goto get_reg;

    case MSR_INTEL_PLATFORM_INFO:
        *val = cp->platform_info.raw;
        break;

    case MSR_ARCH_CAPABILITIES:
        if ( !cp->feat.arch_caps )
            goto gp_fault;
        *val = cp->arch_caps.raw;
        break;

    case MSR_INTEL_MISC_FEATURES_ENABLES:
        *val = msrs->misc_features_enables.raw;
        break;

        /*
         * These MSRs are not enumerated in CPUID.  They have been around
         * since the Pentium 4, and implemented by other vendors.
         *
         * Some versions of Windows try reading these before setting up a #GP
         * handler, and Linux has several unguarded reads as well.  Provide
         * RAZ semantics, in general, but permit a cpufreq controller dom0 to
         * have full access.
         */
    case MSR_IA32_PERF_STATUS:
    case MSR_IA32_PERF_CTL:
        if ( !(cp->x86_vendor & (X86_VENDOR_INTEL | X86_VENDOR_CENTAUR)) )
            goto gp_fault;

        *val = 0;
        if ( likely(!is_cpufreq_controller(d)) || rdmsr_safe(msr, *val) == 0 )
            break;
        goto gp_fault;

    case MSR_X2APIC_FIRST ... MSR_X2APIC_LAST:
        if ( !is_hvm_domain(d) || v != curr )
            goto gp_fault;

        ret = guest_rdmsr_x2apic(v, msr, val);
        break;

    case MSR_IA32_BNDCFGS:
        if ( !cp->feat.mpx || !is_hvm_domain(d) ||
             !hvm_get_guest_bndcfgs(v, val) )
            goto gp_fault;
        break;

    case MSR_IA32_XSS:
        if ( !cp->xstate.xsaves )
            goto gp_fault;

        *val = msrs->xss.raw;
        break;

    case 0x40000000 ... 0x400001ff:
        if ( is_viridian_domain(d) )
        {
            ret = guest_rdmsr_viridian(v, msr, val);
            break;
        }

        /* Fallthrough. */
    case 0x40000200 ... 0x400002ff:
        ret = guest_rdmsr_xen(v, msr, val);
        break;

    case MSR_TSC_AUX:
        if ( !cp->extd.rdtscp && !cp->feat.rdpid )
            goto gp_fault;

        *val = msrs->tsc_aux;
        break;

    case MSR_AMD64_DR0_ADDRESS_MASK:
    case MSR_AMD64_DR1_ADDRESS_MASK ... MSR_AMD64_DR3_ADDRESS_MASK:
        if ( !cp->extd.dbext )
            goto gp_fault;

        /*
         * In HVM context when we've allowed the guest direct access to debug
         * registers, the value in msrs->dr_mask[] may be stale.  Re-read it
         * out of hardware.
         */
#ifdef CONFIG_HVM
        if ( v == current && is_hvm_domain(d) && v->arch.hvm.flag_dr_dirty )
            rdmsrl(msr, *val);
        else
#endif
            *val = msrs->dr_mask[
                array_index_nospec((msr == MSR_AMD64_DR0_ADDRESS_MASK)
                                   ? 0 : (msr - MSR_AMD64_DR1_ADDRESS_MASK + 1),
                                   ARRAY_SIZE(msrs->dr_mask))];
        break;

        /*
         * TODO: Implement when we have better topology representation.
    case MSR_INTEL_CORE_THREAD_COUNT:
         */
    default:
        return X86EMUL_UNHANDLEABLE;
    }

    /*
     * Interim safety check that functions we dispatch to don't alias "Not yet
     * handled by the new MSR infrastructure".
     */
    ASSERT(ret != X86EMUL_UNHANDLEABLE);

    return ret;

 get_reg: /* Delegate register access to per-vm-type logic. */
    if ( is_pv_domain(d) )
        *val = pv_get_reg(v, msr);
    else
        *val = hvm_get_reg(v, msr);
    return X86EMUL_OKAY;

 gp_fault:
    return X86EMUL_EXCEPTION;
}

/*
 * Caller to confirm that MSR_SPEC_CTRL is available.  Intel and AMD have
 * separate CPUID features for this functionality, but only set will be
 * active.
 */
uint64_t msr_spec_ctrl_valid_bits(const struct cpu_policy *cp)
{
    bool ssbd = cp->feat.ssbd || cp->extd.amd_ssbd;
    bool psfd = cp->feat.intel_psfd || cp->extd.psfd;

    /*
     * Note: SPEC_CTRL_STIBP is specified as safe to use (i.e. ignored)
     * when STIBP isn't enumerated in hardware.
     */
    return (SPEC_CTRL_IBRS | SPEC_CTRL_STIBP |
            (ssbd       ? SPEC_CTRL_SSBD       : 0) |
            (psfd       ? SPEC_CTRL_PSFD       : 0) |
            0);
}

int guest_wrmsr(struct vcpu *v, uint32_t msr, uint64_t val)
{
    const struct vcpu *curr = current;
    struct domain *d = v->domain;
    const struct cpu_policy *cp = d->arch.cpu_policy;
    struct vcpu_msrs *msrs = v->arch.msrs;
    int ret = X86EMUL_OKAY;

    switch ( msr )
    {
        uint64_t rsvd;

    case MSR_IA32_PLATFORM_ID:
    case MSR_CORE_CAPABILITIES:
    case MSR_INTEL_CORE_THREAD_COUNT:
    case MSR_INTEL_PLATFORM_INFO:
    case MSR_ARCH_CAPABILITIES:
    case MSR_IA32_PERF_STATUS:
        /* Read-only */
    case MSR_TEST_CTRL:
    case MSR_TSX_FORCE_ABORT:
    case MSR_TSX_CTRL:
    case MSR_MCU_OPT_CTRL:
    case MSR_RTIT_OUTPUT_BASE ... MSR_RTIT_ADDR_B(7):
    case MSR_RAPL_POWER_UNIT:
    case MSR_PKG_POWER_LIMIT  ... MSR_PKG_POWER_INFO:
    case MSR_DRAM_POWER_LIMIT ... MSR_DRAM_POWER_INFO:
    case MSR_PP0_POWER_LIMIT  ... MSR_PP0_POLICY:
    case MSR_PP1_POWER_LIMIT  ... MSR_PP1_POLICY:
    case MSR_PLATFORM_ENERGY_COUNTER:
    case MSR_PLATFORM_POWER_LIMIT:
    case MSR_U_CET:
    case MSR_S_CET:
    case MSR_PL0_SSP ... MSR_INTERRUPT_SSP_TABLE:
    case MSR_AMD64_LWP_CFG:
    case MSR_AMD64_LWP_CBADDR:
    case MSR_PPIN_CTL:
    case MSR_PPIN:
    case MSR_F15H_CU_POWER ... MSR_F15H_CU_MAX_POWER:
    case MSR_AMD_RAPL_POWER_UNIT ... MSR_AMD_PKG_ENERGY_STATUS:
    case MSR_AMD_PPIN_CTL:
    case MSR_AMD_PPIN:
        /* Not offered to guests. */
        goto gp_fault;

    case MSR_AMD_PATCHLEVEL:
        BUILD_BUG_ON(MSR_IA32_UCODE_REV != MSR_AMD_PATCHLEVEL);
        /*
         * AMD and Intel use the same MSR for the current microcode version.
         *
         * Both document it as read-only.  However Intel also document that,
         * for backwards compatiblity, the OS should write 0 to it before
         * trying to access the current microcode version.
         */
        if ( cp->x86_vendor != X86_VENDOR_INTEL || val != 0 )
            goto gp_fault;
        break;

    case MSR_AMD_PATCHLOADER:
        /*
         * See note on MSR_IA32_UCODE_WRITE below, which may or may not apply
         * to AMD CPUs as well (at least the architectural/CPUID part does).
         */
        if ( is_pv_domain(d) ||
             cp->x86_vendor != X86_VENDOR_AMD )
            goto gp_fault;
        break;

    case MSR_IA32_UCODE_WRITE:
        /*
         * Some versions of Windows at least on certain hardware try to load
         * microcode before setting up an IDT. Therefore we must not inject #GP
         * for such attempts. Also the MSR is architectural and not qualified
         * by any CPUID bit.
         */
        if ( is_pv_domain(d) ||
             cp->x86_vendor != X86_VENDOR_INTEL )
            goto gp_fault;
        break;

    case MSR_SPEC_CTRL:
        if ( (!cp->feat.ibrsb && !cp->extd.ibrs) ||
             (val & ~msr_spec_ctrl_valid_bits(cp)) )
            goto gp_fault;
        goto set_reg;

    case MSR_PRED_CMD:
        if ( !cp->feat.ibrsb && !cp->extd.ibpb )
            goto gp_fault; /* MSR available? */

        rsvd = ~(PRED_CMD_IBPB |
                 (cp->extd.sbpb ? PRED_CMD_SBPB : 0));

        if ( val & rsvd )
            goto gp_fault; /* Rsvd bit set? */

        if ( v == curr )
            wrmsrl(MSR_PRED_CMD, val);
        break;

    case MSR_FLUSH_CMD:
        if ( !cp->feat.l1d_flush )
            goto gp_fault; /* MSR available? */

        if ( val & ~FLUSH_CMD_L1D )
            goto gp_fault; /* Rsvd bit set? */

        if ( v == curr )
            wrmsrl(MSR_FLUSH_CMD, val);
        break;

    case MSR_INTEL_MISC_FEATURES_ENABLES:
    {
        bool old_cpuid_faulting = msrs->misc_features_enables.cpuid_faulting;

        rsvd = ~0ull;
        if ( cp->platform_info.cpuid_faulting )
            rsvd &= ~MSR_MISC_FEATURES_CPUID_FAULTING;

        if ( val & rsvd )
            goto gp_fault;

        msrs->misc_features_enables.raw = val;

        if ( v == curr && is_hvm_domain(d) && cpu_has_cpuid_faulting &&
             (old_cpuid_faulting ^ msrs->misc_features_enables.cpuid_faulting) )
            ctxt_switch_levelling(v);
        break;
    }

        /*
         * This MSR is not enumerated in CPUID.  It has been around since the
         * Pentium 4, and implemented by other vendors.
         *
         * To match the RAZ semantics, implement as write-discard, except for
         * a cpufreq controller dom0 which has full access.
         */
    case MSR_IA32_PERF_CTL:
        if ( !(cp->x86_vendor & (X86_VENDOR_INTEL | X86_VENDOR_CENTAUR)) )
            goto gp_fault;

        if ( likely(!is_cpufreq_controller(d)) || wrmsr_safe(msr, val) == 0 )
            break;
        goto gp_fault;

    case MSR_X2APIC_FIRST ... MSR_X2APIC_LAST:
        if ( !is_hvm_domain(d) || v != curr )
            goto gp_fault;

        ret = guest_wrmsr_x2apic(v, msr, val);
        break;

    case MSR_IA32_BNDCFGS:
        if ( !cp->feat.mpx || !is_hvm_domain(d) ||
             !hvm_set_guest_bndcfgs(v, val) )
            goto gp_fault;
        break;

    case MSR_IA32_XSS:
        if ( !cp->xstate.xsaves )
            goto gp_fault;

        /* No XSS features currently supported for guests */
        if ( val != 0 )
            goto gp_fault;

        msrs->xss.raw = val;
        break;

    case 0x40000000 ... 0x400001ff:
        if ( is_viridian_domain(d) )
        {
            ret = guest_wrmsr_viridian(v, msr, val);
            break;
        }

        /* Fallthrough. */
    case 0x40000200 ... 0x400002ff:
        ret = guest_wrmsr_xen(v, msr, val);
        break;

    case MSR_TSC_AUX:
        if ( !cp->extd.rdtscp && !cp->feat.rdpid )
            goto gp_fault;
        if ( val != (uint32_t)val )
            goto gp_fault;

        msrs->tsc_aux = val;
        if ( v == curr )
            wrmsr_tsc_aux(val);
        break;

    case MSR_AMD64_DR0_ADDRESS_MASK:
    case MSR_AMD64_DR1_ADDRESS_MASK ... MSR_AMD64_DR3_ADDRESS_MASK:
        if ( !cp->extd.dbext || val != (uint32_t)val )
            goto gp_fault;

        msrs->dr_mask[
            array_index_nospec((msr == MSR_AMD64_DR0_ADDRESS_MASK)
                               ? 0 : (msr - MSR_AMD64_DR1_ADDRESS_MASK + 1),
                               ARRAY_SIZE(msrs->dr_mask))] = val;

        if ( v == curr && (curr->arch.dr7 & DR7_ACTIVE_MASK) )
            wrmsrl(msr, val);
        break;

    default:
        return X86EMUL_UNHANDLEABLE;
    }

    /*
     * Interim safety check that functions we dispatch to don't alias "Not yet
     * handled by the new MSR infrastructure".
     */
    ASSERT(ret != X86EMUL_UNHANDLEABLE);

    return ret;

 set_reg: /* Delegate register access to per-vm-type logic. */
    if ( is_pv_domain(d) )
        pv_set_reg(v, msr, val);
    else
        hvm_set_reg(v, msr, val);
    return X86EMUL_OKAY;

 gp_fault:
    return X86EMUL_EXCEPTION;
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
