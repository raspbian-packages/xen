#ifndef __ASM_SMP_H
#define __ASM_SMP_H

#ifndef __ASSEMBLY__
#include <xen/config.h>
#include <xen/cpumask.h>
#include <xen/device_tree.h>
#include <asm/current.h>
#endif

DECLARE_PER_CPU(cpumask_var_t, cpu_sibling_mask);
DECLARE_PER_CPU(cpumask_var_t, cpu_core_mask);

#define cpu_is_offline(cpu) unlikely(!cpu_online(cpu))

#define raw_smp_processor_id() (get_processor_id())

extern void stop_cpu(void);

/* Bring the non-boot CPUs up to paging and ready to enter C.  
 * Must be called after Xen is relocated but before the original copy of
 * .text gets overwritten. */
extern void
make_cpus_ready(unsigned int max_cpus, unsigned long boot_phys_offset);

extern int arch_smp_init(void);
extern int arch_cpu_init(int cpu, struct dt_device_node *dn);
extern int arch_cpu_up(int cpu);

/* Secondary CPU entry point */
extern void init_secondary(void);

extern void smp_clear_cpu_maps (void);
extern int smp_get_max_cpus (void);
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
