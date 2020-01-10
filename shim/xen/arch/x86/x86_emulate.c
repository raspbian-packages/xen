/******************************************************************************
 * x86_emulate.c
 * 
 * Wrapper for generic x86 instruction decoder and emulator.
 * 
 * Copyright (c) 2008, Citrix Systems, Inc.
 * 
 * Authors:
 *    Keir Fraser <keir@xen.org>
 */

#include <xen/domain_page.h>
#include <asm/x86_emulate.h>
#include <asm/processor.h> /* current_cpu_info */
#include <asm/xstate.h>
#include <asm/amd.h> /* cpu_has_amd_erratum() */
#include <asm/debugreg.h>

/* Avoid namespace pollution. */
#undef cmpxchg
#undef cpuid
#undef wbinvd

#define r(name) r ## name

#define cpu_has_amd_erratum(nr) \
        cpu_has_amd_erratum(&current_cpu_data, AMD_ERRATUM_##nr)

#define get_stub(stb) ({                                        \
    BUILD_BUG_ON(STUB_BUF_SIZE / 2 < MAX_INST_LEN + 1);         \
    ASSERT(!(stb).ptr);                                         \
    (stb).addr = this_cpu(stubs.addr) + STUB_BUF_SIZE / 2;      \
    memset(((stb).ptr = map_domain_page(_mfn(this_cpu(stubs.mfn)))) +  \
           ((stb).addr & ~PAGE_MASK), 0xcc, STUB_BUF_SIZE / 2);        \
})
#define put_stub(stb) ({                                   \
    if ( (stb).ptr )                                       \
    {                                                      \
        unmap_domain_page((stb).ptr);                      \
        (stb).ptr = NULL;                                  \
    }                                                      \
})

#include "x86_emulate/x86_emulate.c"

/* Called with NULL ctxt in hypercall context. */
int x86emul_read_dr(unsigned int reg, unsigned long *val,
                    struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    /* HVM support requires a bit more plumbing before it will work. */
    ASSERT(is_pv_vcpu(curr));

    switch ( reg )
    {
    case 0 ... 3:
    case 6:
        *val = curr->arch.debugreg[reg];
        break;

    case 7:
        *val = (curr->arch.debugreg[7] |
                curr->arch.debugreg[5]);
        break;

    case 4 ... 5:
        if ( !(curr->arch.pv_vcpu.ctrlreg[4] & X86_CR4_DE) )
        {
            *val = curr->arch.debugreg[reg + 2];
            break;
        }

        /* Fallthrough */
    default:
        if ( ctxt )
            x86_emul_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC, ctxt);

        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int x86emul_write_dr(unsigned int reg, unsigned long val,
                     struct x86_emulate_ctxt *ctxt)
{
    struct vcpu *curr = current;

    /* HVM support requires a bit more plumbing before it will work. */
    ASSERT(is_pv_vcpu(curr));

    switch ( set_debugreg(curr, reg, val) )
    {
    case 0:
        return X86EMUL_OKAY;

    case -ENODEV:
        x86_emul_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC, ctxt);
        return X86EMUL_EXCEPTION;

    default:
        x86_emul_hw_exception(TRAP_gp_fault, 0, ctxt);
        return X86EMUL_EXCEPTION;
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
