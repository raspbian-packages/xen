#include <xen/config.h>
#include <asm/cpufeature.h>
#include <asm/cpuerrata.h>

#define MIDR_RANGE(model, min, max)     \
    .matches = is_affected_midr_range,  \
    .midr_model = model,                \
    .midr_range_min = min,              \
    .midr_range_max = max

static bool_t __maybe_unused
is_affected_midr_range(const struct arm_cpu_capabilities *entry)
{
    return MIDR_IS_CPU_MODEL_RANGE(boot_cpu_data.midr.bits, entry->midr_model,
                                   entry->midr_range_min,
                                   entry->midr_range_max);
}

static const struct arm_cpu_capabilities arm_errata[] = {
#if defined(CONFIG_ARM64_ERRATUM_827319) || \
    defined(CONFIG_ARM64_ERRATUM_824069)
    {
        /* Cortex-A53 r0p[012] */
        .desc = "ARM errata 827319, 824069",
        .capability = ARM64_WORKAROUND_CLEAN_CACHE,
        MIDR_RANGE(MIDR_CORTEX_A53, 0x00, 0x02),
    },
#endif
#ifdef CONFIG_ARM64_ERRATUM_819472
    {
        /* Cortex-A53 r0[01] */
        .desc = "ARM erratum 819472",
        .capability = ARM64_WORKAROUND_CLEAN_CACHE,
        MIDR_RANGE(MIDR_CORTEX_A53, 0x00, 0x01),
    },
#endif
    {},
};

void check_local_cpu_errata(void)
{
    update_cpu_capabilities(arm_errata, "enabled workaround for");
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
