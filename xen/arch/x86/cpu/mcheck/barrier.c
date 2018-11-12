#include "barrier.h"
#include "util.h"
#include "mce.h"

void mce_barrier_init(struct mce_softirq_barrier *bar)
{
    atomic_set(&bar->val, 0);
    atomic_set(&bar->ingen, 0);
    atomic_set(&bar->outgen, 0);
}

void mce_barrier_dec(struct mce_softirq_barrier *bar)
{
    atomic_inc(&bar->outgen);
    wmb();
    atomic_dec(&bar->val);
}

void mce_barrier_enter(struct mce_softirq_barrier *bar)
{
    int gen;

    if (!mce_broadcast)
        return;
    atomic_inc(&bar->ingen);
    gen = atomic_read(&bar->outgen);
    mb();
    atomic_inc(&bar->val);
    while ( atomic_read(&bar->val) != num_online_cpus() &&
            atomic_read(&bar->outgen) == gen )
    {
            mb();
            mce_panic_check();
    }
}

void mce_barrier_exit(struct mce_softirq_barrier *bar)
{
    int gen;

    if ( !mce_broadcast )
        return;
    atomic_inc(&bar->outgen);
    gen = atomic_read(&bar->ingen);
    mb();
    atomic_dec(&bar->val);
    while ( atomic_read(&bar->val) != 0 &&
            atomic_read(&bar->ingen) == gen )
    {
            mb();
            mce_panic_check();
    }
}

void mce_barrier(struct mce_softirq_barrier *bar)
{
    mce_barrier_enter(bar);
    mce_barrier_exit(bar);
}
