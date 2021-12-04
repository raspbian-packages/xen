#ifndef __ASM_SOFTIRQ_H__
#define __ASM_SOFTIRQ_H__

#define NMI_SOFTIRQ            (NR_COMMON_SOFTIRQS + 0)
#define TIME_CALIBRATE_SOFTIRQ (NR_COMMON_SOFTIRQS + 1)
#define VCPU_KICK_SOFTIRQ      (NR_COMMON_SOFTIRQS + 2)

#define MACHINE_CHECK_SOFTIRQ  (NR_COMMON_SOFTIRQS + 3)
#define HVM_DPCI_SOFTIRQ       (NR_COMMON_SOFTIRQS + 4)
#define NR_ARCH_SOFTIRQS       5

bool arch_skip_send_event_check(unsigned int cpu);

#endif /* __ASM_SOFTIRQ_H__ */
