#include <xen/sched.h>
#include <asm/processor.h>
#include <asm/cpufeature.h>
#include <asm/vfp.h>

void vfp_save_state(struct vcpu *v)
{
    if ( !cpu_has_fp )
        return;

    asm volatile("stp q0, q1, [%0, #16 * 0]\n\t"
                 "stp q2, q3, [%0, #16 * 2]\n\t"
                 "stp q4, q5, [%0, #16 * 4]\n\t"
                 "stp q6, q7, [%0, #16 * 6]\n\t"
                 "stp q8, q9, [%0, #16 * 8]\n\t"
                 "stp q10, q11, [%0, #16 * 10]\n\t"
                 "stp q12, q13, [%0, #16 * 12]\n\t"
                 "stp q14, q15, [%0, #16 * 14]\n\t"
                 "stp q16, q17, [%0, #16 * 16]\n\t"
                 "stp q18, q19, [%0, #16 * 18]\n\t"
                 "stp q20, q21, [%0, #16 * 20]\n\t"
                 "stp q22, q23, [%0, #16 * 22]\n\t"
                 "stp q24, q25, [%0, #16 * 24]\n\t"
                 "stp q26, q27, [%0, #16 * 26]\n\t"
                 "stp q28, q29, [%0, #16 * 28]\n\t"
                 "stp q30, q31, [%0, #16 * 30]\n\t"
                 :: "r" ((char *)(&v->arch.vfp.fpregs)): "memory");

    v->arch.vfp.fpsr = READ_SYSREG32(FPSR);
    v->arch.vfp.fpcr = READ_SYSREG32(FPCR);
    v->arch.vfp.fpexc32_el2 = READ_SYSREG32(FPEXC32_EL2);
}

void vfp_restore_state(struct vcpu *v)
{
    if ( !cpu_has_fp )
        return;

    asm volatile("ldp q0, q1, [%0, #16 * 0]\n\t"
                 "ldp q2, q3, [%0, #16 * 2]\n\t"
                 "ldp q4, q5, [%0, #16 * 4]\n\t"
                 "ldp q6, q7, [%0, #16 * 6]\n\t"
                 "ldp q8, q9, [%0, #16 * 8]\n\t"
                 "ldp q10, q11, [%0, #16 * 10]\n\t"
                 "ldp q12, q13, [%0, #16 * 12]\n\t"
                 "ldp q14, q15, [%0, #16 * 14]\n\t"
                 "ldp q16, q17, [%0, #16 * 16]\n\t"
                 "ldp q18, q19, [%0, #16 * 18]\n\t"
                 "ldp q20, q21, [%0, #16 * 20]\n\t"
                 "ldp q22, q23, [%0, #16 * 22]\n\t"
                 "ldp q24, q25, [%0, #16 * 24]\n\t"
                 "ldp q26, q27, [%0, #16 * 26]\n\t"
                 "ldp q28, q29, [%0, #16 * 28]\n\t"
                 "ldp q30, q31, [%0, #16 * 30]\n\t"
                 :: "r" ((char *)(&v->arch.vfp.fpregs)): "memory");

    WRITE_SYSREG32(v->arch.vfp.fpsr, FPSR);
    WRITE_SYSREG32(v->arch.vfp.fpcr, FPCR);
    WRITE_SYSREG32(v->arch.vfp.fpexc32_el2, FPEXC32_EL2);
}
