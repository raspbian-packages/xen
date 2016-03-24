/*
 * arch-x86/cpufeatureset.h
 *
 * CPU featureset definitions
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2015, 2016 Citrix Systems, Inc.
 */

/*
 * There are two expected ways of including this header.
 *
 * 1) The "default" case (expected from tools etc).
 *
 * Simply #include <public/arch-x86/cpufeatureset.h>
 *
 * In this circumstance, normal header guards apply and the includer shall get
 * an enumeration in the XEN_X86_FEATURE_xxx namespace.
 *
 * 2) The special case where the includer provides XEN_CPUFEATURE() in scope.
 *
 * In this case, no inclusion guards apply and the caller is responsible for
 * their XEN_CPUFEATURE() being appropriate in the included context.
 */

#ifndef XEN_CPUFEATURE

/*
 * Includer has not provided a custom XEN_CPUFEATURE().  Arrange for normal
 * header guards, an enum and constants in the XEN_X86_FEATURE_xxx namespace.
 */
#ifndef __XEN_PUBLIC_ARCH_X86_CPUFEATURESET_H__
#define __XEN_PUBLIC_ARCH_X86_CPUFEATURESET_H__

#define XEN_CPUFEATURESET_DEFAULT_INCLUDE

#define XEN_CPUFEATURE(name, value) XEN_X86_FEATURE_##name = value,
enum {

#endif /* __XEN_PUBLIC_ARCH_X86_CPUFEATURESET_H__ */
#endif /* !XEN_CPUFEATURE */


#ifdef XEN_CPUFEATURE
/*
 * A featureset is a bitmap of x86 features, represented as a collection of
 * 32bit words.
 *
 * Words are as specified in vendors programming manuals, and shall not
 * contain any synthesied values.  New words may be added to the end of
 * featureset.
 *
 * All featureset words currently originate from leaves specified for the
 * CPUID instruction, but this is not preclude other sources of information.
 */

/*
 * Attribute syntax:
 *
 * Attributes for a particular feature are provided as characters before the
 * first space in the comment immediately following the feature value.
 *
 * Special: '!'
 *   This bit has special properties and is not a straight indication of a
 *   piece of new functionality.  Xen will handle these differently,
 *   and may override toolstack settings completely.
 */

/* Intel-defined CPU features, CPUID level 0x00000001.edx, word 0 */
XEN_CPUFEATURE(FPU,           0*32+ 0) /*   Onboard FPU */
XEN_CPUFEATURE(VME,           0*32+ 1) /*   Virtual Mode Extensions */
XEN_CPUFEATURE(DE,            0*32+ 2) /*   Debugging Extensions */
XEN_CPUFEATURE(PSE,           0*32+ 3) /*   Page Size Extensions */
XEN_CPUFEATURE(TSC,           0*32+ 4) /*   Time Stamp Counter */
XEN_CPUFEATURE(MSR,           0*32+ 5) /*   Model-Specific Registers, RDMSR, WRMSR */
XEN_CPUFEATURE(PAE,           0*32+ 6) /*   Physical Address Extensions */
XEN_CPUFEATURE(MCE,           0*32+ 7) /*   Machine Check Architecture */
XEN_CPUFEATURE(CX8,           0*32+ 8) /*   CMPXCHG8 instruction */
XEN_CPUFEATURE(APIC,          0*32+ 9) /*!  Onboard APIC */
XEN_CPUFEATURE(SEP,           0*32+11) /*   SYSENTER/SYSEXIT */
XEN_CPUFEATURE(MTRR,          0*32+12) /*   Memory Type Range Registers */
XEN_CPUFEATURE(PGE,           0*32+13) /*   Page Global Enable */
XEN_CPUFEATURE(MCA,           0*32+14) /*   Machine Check Architecture */
XEN_CPUFEATURE(CMOV,          0*32+15) /*   CMOV instruction (FCMOVCC and FCOMI too if FPU present) */
XEN_CPUFEATURE(PAT,           0*32+16) /*   Page Attribute Table */
XEN_CPUFEATURE(PSE36,         0*32+17) /*   36-bit PSEs */
XEN_CPUFEATURE(CLFLUSH,       0*32+19) /*   CLFLUSH instruction */
XEN_CPUFEATURE(DS,            0*32+21) /*   Debug Store */
XEN_CPUFEATURE(ACPI,          0*32+22) /*   ACPI via MSR */
XEN_CPUFEATURE(MMX,           0*32+23) /*   Multimedia Extensions */
XEN_CPUFEATURE(FXSR,          0*32+24) /*   FXSAVE and FXRSTOR instructions */
XEN_CPUFEATURE(SSE,           0*32+25) /*   Streaming SIMD Extensions */
XEN_CPUFEATURE(SSE2,          0*32+26) /*   Streaming SIMD Extensions-2 */
XEN_CPUFEATURE(HTT,           0*32+28) /*!  Hyper-Threading Technology */
XEN_CPUFEATURE(TM1,           0*32+29) /*   Thermal Monitor 1 */
XEN_CPUFEATURE(PBE,           0*32+31) /*   Pending Break Enable */

/* Intel-defined CPU features, CPUID level 0x00000001.ecx, word 1 */
XEN_CPUFEATURE(SSE3,          1*32+ 0) /*   Streaming SIMD Extensions-3 */
XEN_CPUFEATURE(PCLMULQDQ,     1*32+ 1) /*   Carry-less mulitplication */
XEN_CPUFEATURE(DTES64,        1*32+ 2) /*   64-bit Debug Store */
XEN_CPUFEATURE(MONITOR,       1*32+ 3) /*   Monitor/Mwait support */
XEN_CPUFEATURE(DSCPL,         1*32+ 4) /*   CPL Qualified Debug Store */
XEN_CPUFEATURE(VMX,           1*32+ 5) /*   Virtual Machine Extensions */
XEN_CPUFEATURE(SMX,           1*32+ 6) /*   Safer Mode Extensions */
XEN_CPUFEATURE(EIST,          1*32+ 7) /*   Enhanced SpeedStep */
XEN_CPUFEATURE(TM2,           1*32+ 8) /*   Thermal Monitor 2 */
XEN_CPUFEATURE(SSSE3,         1*32+ 9) /*   Supplemental Streaming SIMD Extensions-3 */
XEN_CPUFEATURE(FMA,           1*32+12) /*   Fused Multiply Add */
XEN_CPUFEATURE(CX16,          1*32+13) /*   CMPXCHG16B */
XEN_CPUFEATURE(XTPR,          1*32+14) /*   Send Task Priority Messages */
XEN_CPUFEATURE(PDCM,          1*32+15) /*   Perf/Debug Capability MSR */
XEN_CPUFEATURE(PCID,          1*32+17) /*   Process Context ID */
XEN_CPUFEATURE(DCA,           1*32+18) /*   Direct Cache Access */
XEN_CPUFEATURE(SSE4_1,        1*32+19) /*   Streaming SIMD Extensions 4.1 */
XEN_CPUFEATURE(SSE4_2,        1*32+20) /*   Streaming SIMD Extensions 4.2 */
XEN_CPUFEATURE(X2APIC,        1*32+21) /*!  Extended xAPIC */
XEN_CPUFEATURE(MOVBE,         1*32+22) /*   movbe instruction */
XEN_CPUFEATURE(POPCNT,        1*32+23) /*   POPCNT instruction */
XEN_CPUFEATURE(TSC_DEADLINE,  1*32+24) /*   TSC Deadline Timer */
XEN_CPUFEATURE(AESNI,         1*32+25) /*   AES instructions */
XEN_CPUFEATURE(XSAVE,         1*32+26) /*   XSAVE/XRSTOR/XSETBV/XGETBV */
XEN_CPUFEATURE(OSXSAVE,       1*32+27) /*!  OSXSAVE */
XEN_CPUFEATURE(AVX,           1*32+28) /*   Advanced Vector Extensions */
XEN_CPUFEATURE(F16C,          1*32+29) /*   Half-precision convert instruction */
XEN_CPUFEATURE(RDRAND,        1*32+30) /*   Digital Random Number Generator */
XEN_CPUFEATURE(HYPERVISOR,    1*32+31) /*!  Running under some hypervisor */

/* AMD-defined CPU features, CPUID level 0x80000001.edx, word 2 */
XEN_CPUFEATURE(SYSCALL,       2*32+11) /*   SYSCALL/SYSRET */
XEN_CPUFEATURE(NX,            2*32+20) /*   Execute Disable */
XEN_CPUFEATURE(MMXEXT,        2*32+22) /*   AMD MMX extensions */
XEN_CPUFEATURE(FFXSR,         2*32+25) /*   FFXSR instruction optimizations */
XEN_CPUFEATURE(PAGE1GB,       2*32+26) /*   1Gb large page support */
XEN_CPUFEATURE(RDTSCP,        2*32+27) /*   RDTSCP */
XEN_CPUFEATURE(LM,            2*32+29) /*   Long Mode (x86-64) */
XEN_CPUFEATURE(3DNOWEXT,      2*32+30) /*   AMD 3DNow! extensions */
XEN_CPUFEATURE(3DNOW,         2*32+31) /*   3DNow! */

/* AMD-defined CPU features, CPUID level 0x80000001.ecx, word 3 */
XEN_CPUFEATURE(LAHF_LM,       3*32+ 0) /*   LAHF/SAHF in long mode */
XEN_CPUFEATURE(CMP_LEGACY,    3*32+ 1) /*!  If yes HyperThreading not valid */
XEN_CPUFEATURE(SVM,           3*32+ 2) /*   Secure virtual machine */
XEN_CPUFEATURE(EXTAPIC,       3*32+ 3) /*   Extended APIC space */
XEN_CPUFEATURE(CR8_LEGACY,    3*32+ 4) /*   CR8 in 32-bit mode */
XEN_CPUFEATURE(ABM,           3*32+ 5) /*   Advanced bit manipulation */
XEN_CPUFEATURE(SSE4A,         3*32+ 6) /*   SSE-4A */
XEN_CPUFEATURE(MISALIGNSSE,   3*32+ 7) /*   Misaligned SSE mode */
XEN_CPUFEATURE(3DNOWPREFETCH, 3*32+ 8) /*   3DNow prefetch instructions */
XEN_CPUFEATURE(OSVW,          3*32+ 9) /*   OS Visible Workaround */
XEN_CPUFEATURE(IBS,           3*32+10) /*   Instruction Based Sampling */
XEN_CPUFEATURE(XOP,           3*32+11) /*   extended AVX instructions */
XEN_CPUFEATURE(SKINIT,        3*32+12) /*   SKINIT/STGI instructions */
XEN_CPUFEATURE(WDT,           3*32+13) /*   Watchdog timer */
XEN_CPUFEATURE(LWP,           3*32+15) /*   Light Weight Profiling */
XEN_CPUFEATURE(FMA4,          3*32+16) /*   4 operands MAC instructions */
XEN_CPUFEATURE(NODEID_MSR,    3*32+19) /*   NodeId MSR */
XEN_CPUFEATURE(TBM,           3*32+21) /*   trailing bit manipulations */
XEN_CPUFEATURE(TOPOEXT,       3*32+22) /*   topology extensions CPUID leafs */
XEN_CPUFEATURE(DBEXT,         3*32+26) /*   data breakpoint extension */
XEN_CPUFEATURE(MONITORX,      3*32+29) /*   MONITOR extension (MONITORX/MWAITX) */

/* Intel-defined CPU features, CPUID level 0x0000000D:1.eax, word 4 */
XEN_CPUFEATURE(XSAVEOPT,      4*32+ 0) /*   XSAVEOPT instruction */
XEN_CPUFEATURE(XSAVEC,        4*32+ 1) /*   XSAVEC/XRSTORC instructions */
XEN_CPUFEATURE(XGETBV1,       4*32+ 2) /*   XGETBV with %ecx=1 */
XEN_CPUFEATURE(XSAVES,        4*32+ 3) /*   XSAVES/XRSTORS instructions */

/* Intel-defined CPU features, CPUID level 0x00000007:0.ebx, word 5 */
XEN_CPUFEATURE(FSGSBASE,      5*32+ 0) /*   {RD,WR}{FS,GS}BASE instructions */
XEN_CPUFEATURE(TSC_ADJUST,    5*32+ 1) /*   TSC_ADJUST MSR available */
XEN_CPUFEATURE(BMI1,          5*32+ 3) /*   1st bit manipulation extensions */
XEN_CPUFEATURE(HLE,           5*32+ 4) /*   Hardware Lock Elision */
XEN_CPUFEATURE(AVX2,          5*32+ 5) /*   AVX2 instructions */
XEN_CPUFEATURE(FDP_EXCP_ONLY, 5*32+ 6) /*!  x87 FDP only updated on exception. */
XEN_CPUFEATURE(SMEP,          5*32+ 7) /*   Supervisor Mode Execution Protection */
XEN_CPUFEATURE(BMI2,          5*32+ 8) /*   2nd bit manipulation extensions */
XEN_CPUFEATURE(ERMS,          5*32+ 9) /*   Enhanced REP MOVSB/STOSB */
XEN_CPUFEATURE(INVPCID,       5*32+10) /*   Invalidate Process Context ID */
XEN_CPUFEATURE(RTM,           5*32+11) /*   Restricted Transactional Memory */
XEN_CPUFEATURE(PQM,           5*32+12) /*   Platform QoS Monitoring */
XEN_CPUFEATURE(NO_FPU_SEL,    5*32+13) /*!  FPU CS/DS stored as zero */
XEN_CPUFEATURE(MPX,           5*32+14) /*   Memory Protection Extensions */
XEN_CPUFEATURE(PQE,           5*32+15) /*   Platform QoS Enforcement */
XEN_CPUFEATURE(RDSEED,        5*32+18) /*   RDSEED instruction */
XEN_CPUFEATURE(ADX,           5*32+19) /*   ADCX, ADOX instructions */
XEN_CPUFEATURE(SMAP,          5*32+20) /*   Supervisor Mode Access Prevention */
XEN_CPUFEATURE(PCOMMIT,       5*32+22) /*   PCOMMIT instruction */
XEN_CPUFEATURE(CLFLUSHOPT,    5*32+23) /*   CLFLUSHOPT instruction */
XEN_CPUFEATURE(CLWB,          5*32+24) /*   CLWB instruction */
XEN_CPUFEATURE(SHA,           5*32+29) /*   SHA1 & SHA256 instructions */

/* Intel-defined CPU features, CPUID level 0x00000007:0.ecx, word 6 */
XEN_CPUFEATURE(PREFETCHWT1,   6*32+ 0) /*   PREFETCHWT1 instruction */
XEN_CPUFEATURE(PKU,           6*32+ 3) /*   Protection Keys for Userspace */
XEN_CPUFEATURE(OSPKE,         6*32+ 4) /*!  OS Protection Keys Enable */

/* AMD-defined CPU features, CPUID level 0x80000007.edx, word 7 */
XEN_CPUFEATURE(ITSC,          7*32+ 8) /*   Invariant TSC */
XEN_CPUFEATURE(EFRO,          7*32+10) /*   APERF/MPERF Read Only interface */

/* AMD-defined CPU features, CPUID level 0x80000008.ebx, word 8 */
XEN_CPUFEATURE(CLZERO,        8*32+ 0) /*   CLZERO instruction */

#endif /* XEN_CPUFEATURE */

/* Clean up from a default include.  Close the enum (for C). */
#ifdef XEN_CPUFEATURESET_DEFAULT_INCLUDE
#undef XEN_CPUFEATURESET_DEFAULT_INCLUDE
#undef XEN_CPUFEATURE
};

#endif /* XEN_CPUFEATURESET_DEFAULT_INCLUDE */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
