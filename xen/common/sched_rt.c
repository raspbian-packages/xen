/*****************************************************************************
 * Preemptive Global Earliest Deadline First  (EDF) scheduler for Xen
 * EDF scheduling is a real-time scheduling algorithm used in embedded field.
 *
 * by Sisu Xi, 2013, Washington University in Saint Louis
 * Meng Xu, 2014-2016, University of Pennsylvania
 *
 * Conversion toward event driven model by Tianyang Chen
 * and Dagaen Golomb, 2016, University of Pennsylvania
 *
 * based on the code of credit Scheduler
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/delay.h>
#include <xen/event.h>
#include <xen/time.h>
#include <xen/timer.h>
#include <xen/perfc.h>
#include <xen/sched-if.h>
#include <xen/softirq.h>
#include <asm/atomic.h>
#include <xen/errno.h>
#include <xen/trace.h>
#include <xen/cpu.h>
#include <xen/keyhandler.h>
#include <xen/trace.h>
#include <xen/err.h>
#include <xen/guest_access.h>

/*
 * TODO:
 *
 * Migration compensation and resist like credit2 to better use cache;
 * Lock Holder Problem, using yield?
 * Self switch problem: VCPUs of the same domain may preempt each other;
 */

/*
 * Design:
 *
 * This scheduler follows the Preemptive Global Earliest Deadline First (EDF)
 * theory in real-time field.
 * At any scheduling point, the VCPU with earlier deadline has higher priority.
 * The scheduler always picks highest priority VCPU to run on a feasible PCPU.
 * A PCPU is feasible if the VCPU can run on this PCPU and (the PCPU is idle or
 * has a lower-priority VCPU running on it.)
 *
 * Each VCPU has a dedicated period and budget.
 * The deadline of a VCPU is at the end of each period;
 * A VCPU has its budget replenished at the beginning of each period;
 * While scheduled, a VCPU burns its budget.
 * The VCPU needs to finish its budget before its deadline in each period;
 * The VCPU discards its unused budget at the end of each period.
 * If a VCPU runs out of budget in a period, it has to wait until next period.
 *
 * Each VCPU is implemented as a deferable server.
 * When a VCPU has a task running on it, its budget is continuously burned;
 * When a VCPU has no task but with budget left, its budget is preserved.
 *
 * Queue scheme:
 * A global runqueue and a global depletedqueue for each CPU pool.
 * The runqueue holds all runnable VCPUs with budget, sorted by deadline;
 * The depletedqueue holds all VCPUs without budget, unsorted;
 *
 * Note: cpumask and cpupool is supported.
 */

/*
 * Locking:
 * A global system lock is used to protect the RunQ and DepletedQ.
 * The global lock is referenced by schedule_data.schedule_lock
 * from all physical cpus.
 *
 * The lock is already grabbed when calling wake/sleep/schedule/ functions
 * in schedule.c
 *
 * The functions involes RunQ and needs to grab locks are:
 *    vcpu_insert, vcpu_remove, context_saved, __runq_insert
 */


/*
 * Default parameters:
 * Period and budget in default is 10 and 4 ms, respectively
 */
#define RTDS_DEFAULT_PERIOD     (MICROSECS(10000))
#define RTDS_DEFAULT_BUDGET     (MICROSECS(4000))

/*
 * Max period: max delta of time type, because period is added to the time
 * a vcpu activates, so this must not overflow.
 * Min period: 10 us, considering the scheduling overhead (when period is
 * too low, scheduling is invoked too frequently, causing high overhead).
 */
#define RTDS_MAX_PERIOD     (STIME_DELTA_MAX)
#define RTDS_MIN_PERIOD     (MICROSECS(10))

/*
 * Min budget: 10 us, considering the scheduling overhead (when budget is
 * consumed too fast, scheduling is invoked too frequently, causing
 * high overhead).
 */
#define RTDS_MIN_BUDGET     (MICROSECS(10))

#define UPDATE_LIMIT_SHIFT      10

/*
 * Flags
 */
/*
 * RTDS_scheduled: Is this vcpu either running on, or context-switching off,
 * a phyiscal cpu?
 * + Accessed only with global lock held.
 * + Set when chosen as next in rt_schedule().
 * + Cleared after context switch has been saved in rt_context_saved()
 * + Checked in vcpu_wake to see if we can add to the Runqueue, or if we should
 *   set RTDS_delayed_runq_add
 * + Checked to be false in runq_insert.
 */
#define __RTDS_scheduled            1
#define RTDS_scheduled (1<<__RTDS_scheduled)
/*
 * RTDS_delayed_runq_add: Do we need to add this to the RunQ/DepletedQ
 * once it's done being context switching out?
 * + Set when scheduling out in rt_schedule() if prev is runable
 * + Set in rt_vcpu_wake if it finds RTDS_scheduled set
 * + Read in rt_context_saved(). If set, it adds prev to the Runqueue/DepletedQ
 *   and clears the bit.
 */
#define __RTDS_delayed_runq_add     2
#define RTDS_delayed_runq_add (1<<__RTDS_delayed_runq_add)

/*
 * RTDS_depleted: Does this vcp run out of budget?
 * This flag is
 * + set in burn_budget() if a vcpu has zero budget left;
 * + cleared and checked in the repenishment handler,
 *   for the vcpus that are being replenished.
 */
#define __RTDS_depleted     3
#define RTDS_depleted (1<<__RTDS_depleted)

/*
 * rt tracing events ("only" 512 available!). Check
 * include/public/trace.h for more details.
 */
#define TRC_RTDS_TICKLE           TRC_SCHED_CLASS_EVT(RTDS, 1)
#define TRC_RTDS_RUNQ_PICK        TRC_SCHED_CLASS_EVT(RTDS, 2)
#define TRC_RTDS_BUDGET_BURN      TRC_SCHED_CLASS_EVT(RTDS, 3)
#define TRC_RTDS_BUDGET_REPLENISH TRC_SCHED_CLASS_EVT(RTDS, 4)
#define TRC_RTDS_SCHED_TASKLET    TRC_SCHED_CLASS_EVT(RTDS, 5)

 /*
  * Useful to avoid too many cpumask_var_t on the stack.
  */
static cpumask_var_t *_cpumask_scratch;
#define cpumask_scratch _cpumask_scratch[smp_processor_id()]

/*
 * We want to only allocate the _cpumask_scratch array the first time an
 * instance of this scheduler is used, and avoid reallocating and leaking
 * the old one when more instance are activated inside new cpupools. We
 * also want to get rid of it when the last instance is de-inited.
 *
 * So we (sort of) reference count the number of initialized instances. This
 * does not need to happen via atomic_t refcounters, as it only happens either
 * during boot, or under the protection of the cpupool_lock spinlock.
 */
static unsigned int nr_rt_ops;

static void repl_timer_handler(void *data);

/*
 * Systme-wide private data, include global RunQueue/DepletedQ
 * Global lock is referenced by schedule_data.schedule_lock from all
 * physical cpus. It can be grabbed via vcpu_schedule_lock_irq()
 */
struct rt_private {
    spinlock_t lock;            /* the global coarse grand lock */
    struct list_head sdom;      /* list of availalbe domains, used for dump */
    struct list_head runq;      /* ordered list of runnable vcpus */
    struct list_head depletedq; /* unordered list of depleted vcpus */
    struct list_head replq;     /* ordered list of vcpus that need replenishment */
    cpumask_t tickled;          /* cpus been tickled */
    struct timer *repl_timer;   /* replenishment timer */
};

/*
 * Virtual CPU
 */
struct rt_vcpu {
    struct list_head q_elem;    /* on the runq/depletedq list */
    struct list_head replq_elem; /* on the replenishment events list */

    /* Up-pointers */
    struct rt_dom *sdom;
    struct vcpu *vcpu;

    /* VCPU parameters, in nanoseconds */
    s_time_t period;
    s_time_t budget;

    /* VCPU current infomation in nanosecond */
    s_time_t cur_budget;        /* current budget */
    s_time_t last_start;        /* last start time */
    s_time_t cur_deadline;      /* current deadline for EDF */

    unsigned flags;             /* mark __RTDS_scheduled, etc.. */
};

/*
 * Domain
 */
struct rt_dom {
    struct list_head sdom_elem; /* link list on rt_priv */
    struct domain *dom;         /* pointer to upper domain */
};

/*
 * Useful inline functions
 */
static inline struct rt_private *rt_priv(const struct scheduler *ops)
{
    return ops->sched_data;
}

static inline struct rt_vcpu *rt_vcpu(const struct vcpu *vcpu)
{
    return vcpu->sched_priv;
}

static inline struct rt_dom *rt_dom(const struct domain *dom)
{
    return dom->sched_priv;
}

static inline struct list_head *rt_runq(const struct scheduler *ops)
{
    return &rt_priv(ops)->runq;
}

static inline struct list_head *rt_depletedq(const struct scheduler *ops)
{
    return &rt_priv(ops)->depletedq;
}

static inline struct list_head *rt_replq(const struct scheduler *ops)
{
    return &rt_priv(ops)->replq;
}

/*
 * Helper functions for manipulating the runqueue, the depleted queue,
 * and the replenishment events queue.
 */
static int
__vcpu_on_q(const struct rt_vcpu *svc)
{
   return !list_empty(&svc->q_elem);
}

static struct rt_vcpu *
__q_elem(struct list_head *elem)
{
    return list_entry(elem, struct rt_vcpu, q_elem);
}

static struct rt_vcpu *
replq_elem(struct list_head *elem)
{
    return list_entry(elem, struct rt_vcpu, replq_elem);
}

static int
vcpu_on_replq(const struct rt_vcpu *svc)
{
    return !list_empty(&svc->replq_elem);
}

/*
 * Debug related code, dump vcpu/cpu information
 */
static void
rt_dump_vcpu(const struct scheduler *ops, const struct rt_vcpu *svc)
{
    cpumask_t *cpupool_mask, *mask;

    ASSERT(svc != NULL);
    /* idle vcpu */
    if( svc->sdom == NULL )
    {
        printk("\n");
        return;
    }

    /*
     * We can't just use 'cpumask_scratch' because the dumping can
     * happen from a pCPU outside of this scheduler's cpupool, and
     * hence it's not right to use the pCPU's scratch mask (which
     * may even not exist!). On the other hand, it is safe to use
     * svc->vcpu->processor's own scratch space, since we hold the
     * runqueue lock.
     */
    mask = _cpumask_scratch[svc->vcpu->processor];

    cpupool_mask = cpupool_domain_cpumask(svc->vcpu->domain);
    cpumask_and(mask, cpupool_mask, svc->vcpu->cpu_hard_affinity);
    cpulist_scnprintf(keyhandler_scratch, sizeof(keyhandler_scratch), mask);
    printk("[%5d.%-2u] cpu %u, (%"PRI_stime", %"PRI_stime"),"
           " cur_b=%"PRI_stime" cur_d=%"PRI_stime" last_start=%"PRI_stime"\n"
           " \t\t onQ=%d runnable=%d flags=%x effective hard_affinity=%s\n",
            svc->vcpu->domain->domain_id,
            svc->vcpu->vcpu_id,
            svc->vcpu->processor,
            svc->period,
            svc->budget,
            svc->cur_budget,
            svc->cur_deadline,
            svc->last_start,
            __vcpu_on_q(svc),
            vcpu_runnable(svc->vcpu),
            svc->flags,
            keyhandler_scratch);
}

static void
rt_dump_pcpu(const struct scheduler *ops, int cpu)
{
    struct rt_private *prv = rt_priv(ops);
    unsigned long flags;

    spin_lock_irqsave(&prv->lock, flags);
    rt_dump_vcpu(ops, rt_vcpu(curr_on_cpu(cpu)));
    spin_unlock_irqrestore(&prv->lock, flags);
}

static void
rt_dump(const struct scheduler *ops)
{
    struct list_head *runq, *depletedq, *replq, *iter;
    struct rt_private *prv = rt_priv(ops);
    struct rt_vcpu *svc;
    struct rt_dom *sdom;
    unsigned long flags;

    spin_lock_irqsave(&prv->lock, flags);

    if ( list_empty(&prv->sdom) )
        goto out;

    runq = rt_runq(ops);
    depletedq = rt_depletedq(ops);
    replq = rt_replq(ops);

    printk("Global RunQueue info:\n");
    list_for_each( iter, runq )
    {
        svc = __q_elem(iter);
        rt_dump_vcpu(ops, svc);
    }

    printk("Global DepletedQueue info:\n");
    list_for_each( iter, depletedq )
    {
        svc = __q_elem(iter);
        rt_dump_vcpu(ops, svc);
    }

    printk("Global Replenishment Events info:\n");
    list_for_each( iter, replq )
    {
        svc = replq_elem(iter);
        rt_dump_vcpu(ops, svc);
    }

    printk("Domain info:\n");
    list_for_each( iter, &prv->sdom )
    {
        struct vcpu *v;

        sdom = list_entry(iter, struct rt_dom, sdom_elem);
        printk("\tdomain: %d\n", sdom->dom->domain_id);

        for_each_vcpu ( sdom->dom, v )
        {
            svc = rt_vcpu(v);
            rt_dump_vcpu(ops, svc);
        }
    }

 out:
    spin_unlock_irqrestore(&prv->lock, flags);
}

/*
 * update deadline and budget when now >= cur_deadline
 * it need to be updated to the deadline of the current period
 */
static void
rt_update_deadline(s_time_t now, struct rt_vcpu *svc)
{
    ASSERT(now >= svc->cur_deadline);
    ASSERT(svc->period != 0);

    if ( svc->cur_deadline + (svc->period << UPDATE_LIMIT_SHIFT) > now )
    {
        do
            svc->cur_deadline += svc->period;
        while ( svc->cur_deadline <= now );
    }
    else
    {
        long count = ((now - svc->cur_deadline) / svc->period) + 1;
        svc->cur_deadline += count * svc->period;
    }

    svc->cur_budget = svc->budget;

    /* TRACE */
    {
        struct __packed {
            unsigned vcpu:16, dom:16;
            uint64_t cur_deadline, cur_budget;
        } d;
        d.dom = svc->vcpu->domain->domain_id;
        d.vcpu = svc->vcpu->vcpu_id;
        d.cur_deadline = (uint64_t) svc->cur_deadline;
        d.cur_budget = (uint64_t) svc->cur_budget;
        trace_var(TRC_RTDS_BUDGET_REPLENISH, 1,
                  sizeof(d),
                  (unsigned char *) &d);
    }

    return;
}

/*
 * Helpers for removing and inserting a vcpu in a queue
 * that is being kept ordered by the vcpus' deadlines (as EDF
 * mandates).
 *
 * For callers' convenience, the vcpu removing helper returns
 * true if the vcpu removed was the one at the front of the
 * queue; similarly, the inserting helper returns true if the
 * inserted ended at the front of the queue (i.e., in both
 * cases, if the vcpu with the earliest deadline is what we
 * are dealing with).
 */
static inline bool_t
deadline_queue_remove(struct list_head *queue, struct list_head *elem)
{
    int pos = 0;

    if ( queue->next != elem )
        pos = 1;

    list_del_init(elem);
    return !pos;
}

static inline bool_t
deadline_queue_insert(struct rt_vcpu * (*qelem)(struct list_head *),
                      struct rt_vcpu *svc, struct list_head *elem,
                      struct list_head *queue)
{
    struct list_head *iter;
    int pos = 0;

    list_for_each ( iter, queue )
    {
        struct rt_vcpu * iter_svc = (*qelem)(iter);
        if ( svc->cur_deadline <= iter_svc->cur_deadline )
            break;
        pos++;
    }
    list_add_tail(elem, iter);
    return !pos;
}
#define deadline_runq_insert(...) \
  deadline_queue_insert(&__q_elem, ##__VA_ARGS__)
#define deadline_replq_insert(...) \
  deadline_queue_insert(&replq_elem, ##__VA_ARGS__)

static inline void
__q_remove(struct rt_vcpu *svc)
{
    ASSERT( __vcpu_on_q(svc) );
    list_del_init(&svc->q_elem);
}

static inline void
replq_remove(const struct scheduler *ops, struct rt_vcpu *svc)
{
    struct rt_private *prv = rt_priv(ops);
    struct list_head *replq = rt_replq(ops);

    ASSERT( vcpu_on_replq(svc) );

    if ( deadline_queue_remove(replq, &svc->replq_elem) )
    {
        /*
         * The replenishment timer needs to be set to fire when a
         * replenishment for the vcpu at the front of the replenishment
         * queue is due. If it is such vcpu that we just removed, we may
         * need to reprogram the timer.
         */
        if ( !list_empty(replq) )
        {
            struct rt_vcpu *svc_next = replq_elem(replq->next);
            set_timer(prv->repl_timer, svc_next->cur_deadline);
        }
        else
            stop_timer(prv->repl_timer);
    }
}

/*
 * Insert svc with budget in RunQ according to EDF:
 * vcpus with smaller deadlines go first.
 * Insert svc without budget in DepletedQ unsorted;
 */
static void
__runq_insert(const struct scheduler *ops, struct rt_vcpu *svc)
{
    struct rt_private *prv = rt_priv(ops);
    struct list_head *runq = rt_runq(ops);

    ASSERT( spin_is_locked(&prv->lock) );
    ASSERT( !__vcpu_on_q(svc) );
    ASSERT( vcpu_on_replq(svc) );

    /* add svc to runq if svc still has budget */
    if ( svc->cur_budget > 0 )
        deadline_runq_insert(svc, &svc->q_elem, runq);
    else
        list_add(&svc->q_elem, &prv->depletedq);
}

static void
replq_insert(const struct scheduler *ops, struct rt_vcpu *svc)
{
    struct list_head *replq = rt_replq(ops);
    struct rt_private *prv = rt_priv(ops);

    ASSERT( !vcpu_on_replq(svc) );

    /*
     * The timer may be re-programmed if svc is inserted
     * at the front of the event list.
     */
    if ( deadline_replq_insert(svc, &svc->replq_elem, replq) )
        set_timer(prv->repl_timer, svc->cur_deadline);
}

/*
 * Removes and re-inserts an event to the replenishment queue.
 * The aim is to update its position inside the queue, as its
 * deadline (and hence its replenishment time) could have
 * changed.
 */
static void
replq_reinsert(const struct scheduler *ops, struct rt_vcpu *svc)
{
    struct list_head *replq = rt_replq(ops);
    struct rt_vcpu *rearm_svc = svc;
    bool_t rearm = 0;

    ASSERT( vcpu_on_replq(svc) );

    /*
     * If svc was at the front of the replenishment queue, we certainly
     * need to re-program the timer, and we want to use the deadline of
     * the vcpu which is now at the front of the queue (which may still
     * be svc or not).
     *
     * We may also need to re-program, if svc has been put at the front
     * of the replenishment queue when being re-inserted.
     */
    if ( deadline_queue_remove(replq, &svc->replq_elem) )
    {
        deadline_replq_insert(svc, &svc->replq_elem, replq);
        rearm_svc = replq_elem(replq->next);
        rearm = 1;
    }
    else
        rearm = deadline_replq_insert(svc, &svc->replq_elem, replq);

    if ( rearm )
        set_timer(rt_priv(ops)->repl_timer, rearm_svc->cur_deadline);
}

/*
 * Init/Free related code
 */
static int
rt_init(struct scheduler *ops)
{
    struct rt_private *prv = xzalloc(struct rt_private);

    printk("Initializing RTDS scheduler\n"
           "WARNING: This is experimental software in development.\n"
           "Use at your own risk.\n");

    if ( prv == NULL )
        return -ENOMEM;

    ASSERT( _cpumask_scratch == NULL || nr_rt_ops > 0 );

    if ( !_cpumask_scratch )
    {
        _cpumask_scratch = xmalloc_array(cpumask_var_t, nr_cpu_ids);
        if ( !_cpumask_scratch )
            goto no_mem;
    }
    nr_rt_ops++;

    spin_lock_init(&prv->lock);
    INIT_LIST_HEAD(&prv->sdom);
    INIT_LIST_HEAD(&prv->runq);
    INIT_LIST_HEAD(&prv->depletedq);
    INIT_LIST_HEAD(&prv->replq);

    cpumask_clear(&prv->tickled);

    ops->sched_data = prv;

    /*
     * The timer initialization will happen later when
     * the first pcpu is added to this pool in alloc_pdata.
     */
    prv->repl_timer = NULL;

    return 0;

 no_mem:
    xfree(prv);
    return -ENOMEM;
}

static void
rt_deinit(struct scheduler *ops)
{
    struct rt_private *prv = rt_priv(ops);

    ASSERT( _cpumask_scratch && nr_rt_ops > 0 );

    if ( (--nr_rt_ops) == 0 )
    {
        xfree(_cpumask_scratch);
        _cpumask_scratch = NULL;
    }

    kill_timer(prv->repl_timer);
    xfree(prv->repl_timer);

    ops->sched_data = NULL;
    xfree(prv);
}

/*
 * Point per_cpu spinlock to the global system lock;
 * All cpu have same global system lock
 */
static void *
rt_alloc_pdata(const struct scheduler *ops, int cpu)
{
    struct rt_private *prv = rt_priv(ops);
    spinlock_t *old_lock;
    unsigned long flags;

    /* Move the scheduler lock to our global runqueue lock.  */
    old_lock = pcpu_schedule_lock_irqsave(cpu, &flags);

    per_cpu(schedule_data, cpu).schedule_lock = &prv->lock;

    /* _Not_ pcpu_schedule_unlock(): per_cpu().schedule_lock changed! */
    spin_unlock_irqrestore(old_lock, flags);

    if ( !alloc_cpumask_var(&_cpumask_scratch[cpu]) )
        return ERR_PTR(-ENOMEM);

    if ( prv->repl_timer == NULL )
    {
        /* Allocate the timer on the first cpu of this pool. */
        prv->repl_timer = xzalloc(struct timer);

        if ( prv->repl_timer == NULL )
            return ERR_PTR(-ENOMEM);

        init_timer(prv->repl_timer, repl_timer_handler, (void *)ops, cpu);
    }

    return NULL;
}

static void
rt_free_pdata(const struct scheduler *ops, void *pcpu, int cpu)
{
    struct rt_private *prv = rt_priv(ops);
    struct schedule_data *sd = &per_cpu(schedule_data, cpu);
    unsigned long flags;

    spin_lock_irqsave(&prv->lock, flags);

    /* Move spinlock back to the default lock */
    ASSERT(sd->schedule_lock == &prv->lock);
    ASSERT(!spin_is_locked(&sd->_lock));
    sd->schedule_lock = &sd->_lock;

    spin_unlock_irqrestore(&prv->lock, flags);

    free_cpumask_var(_cpumask_scratch[cpu]);
}

static void *
rt_alloc_domdata(const struct scheduler *ops, struct domain *dom)
{
    unsigned long flags;
    struct rt_dom *sdom;
    struct rt_private * prv = rt_priv(ops);

    sdom = xzalloc(struct rt_dom);
    if ( sdom == NULL )
        return NULL;

    INIT_LIST_HEAD(&sdom->sdom_elem);
    sdom->dom = dom;

    /* spinlock here to insert the dom */
    spin_lock_irqsave(&prv->lock, flags);
    list_add_tail(&sdom->sdom_elem, &(prv->sdom));
    spin_unlock_irqrestore(&prv->lock, flags);

    return sdom;
}

static void
rt_free_domdata(const struct scheduler *ops, void *data)
{
    unsigned long flags;
    struct rt_dom *sdom = data;
    struct rt_private *prv = rt_priv(ops);

    spin_lock_irqsave(&prv->lock, flags);
    list_del_init(&sdom->sdom_elem);
    spin_unlock_irqrestore(&prv->lock, flags);
    xfree(data);
}

static int
rt_dom_init(const struct scheduler *ops, struct domain *dom)
{
    struct rt_dom *sdom;

    /* IDLE Domain does not link on rt_private */
    if ( is_idle_domain(dom) )
        return 0;

    sdom = rt_alloc_domdata(ops, dom);
    if ( sdom == NULL )
        return -ENOMEM;

    dom->sched_priv = sdom;

    return 0;
}

static void
rt_dom_destroy(const struct scheduler *ops, struct domain *dom)
{
    rt_free_domdata(ops, rt_dom(dom));
}

static void *
rt_alloc_vdata(const struct scheduler *ops, struct vcpu *vc, void *dd)
{
    struct rt_vcpu *svc;

    /* Allocate per-VCPU info */
    svc = xzalloc(struct rt_vcpu);
    if ( svc == NULL )
        return NULL;

    INIT_LIST_HEAD(&svc->q_elem);
    INIT_LIST_HEAD(&svc->replq_elem);
    svc->flags = 0U;
    svc->sdom = dd;
    svc->vcpu = vc;
    svc->last_start = 0;

    svc->period = RTDS_DEFAULT_PERIOD;
    if ( !is_idle_vcpu(vc) )
        svc->budget = RTDS_DEFAULT_BUDGET;

    SCHED_STAT_CRANK(vcpu_alloc);

    return svc;
}

static void
rt_free_vdata(const struct scheduler *ops, void *priv)
{
    struct rt_vcpu *svc = priv;

    xfree(svc);
}

/*
 * It is called in sched_move_domain() and sched_init_vcpu
 * in schedule.c.
 * When move a domain to a new cpupool.
 * It inserts vcpus of moving domain to the scheduler's RunQ in
 * dest. cpupool.
 */
static void
rt_vcpu_insert(const struct scheduler *ops, struct vcpu *vc)
{
    struct rt_vcpu *svc = rt_vcpu(vc);
    s_time_t now = NOW();
    spinlock_t *lock;

    BUG_ON( is_idle_vcpu(vc) );

    lock = vcpu_schedule_lock_irq(vc);
    if ( now >= svc->cur_deadline )
        rt_update_deadline(now, svc);

    if ( !__vcpu_on_q(svc) && vcpu_runnable(vc) )
    {
        replq_insert(ops, svc);

        if ( !vc->is_running )
            __runq_insert(ops, svc);
    }
    vcpu_schedule_unlock_irq(lock, vc);

    SCHED_STAT_CRANK(vcpu_insert);
}

/*
 * Remove rt_vcpu svc from the old scheduler in source cpupool.
 */
static void
rt_vcpu_remove(const struct scheduler *ops, struct vcpu *vc)
{
    struct rt_vcpu * const svc = rt_vcpu(vc);
    struct rt_dom * const sdom = svc->sdom;
    spinlock_t *lock;

    SCHED_STAT_CRANK(vcpu_remove);

    BUG_ON( sdom == NULL );

    lock = vcpu_schedule_lock_irq(vc);
    if ( __vcpu_on_q(svc) )
        __q_remove(svc);

    if ( vcpu_on_replq(svc) )
        replq_remove(ops,svc);

    vcpu_schedule_unlock_irq(lock, vc);
}

/*
 * Pick a valid CPU for the vcpu vc
 * Valid CPU of a vcpu is intesection of vcpu's affinity
 * and available cpus
 */
static int
rt_cpu_pick(const struct scheduler *ops, struct vcpu *vc)
{
    cpumask_t cpus;
    cpumask_t *online;
    int cpu;

    online = cpupool_domain_cpumask(vc->domain);
    cpumask_and(&cpus, online, vc->cpu_hard_affinity);

    cpu = cpumask_test_cpu(vc->processor, &cpus)
            ? vc->processor
            : cpumask_cycle(vc->processor, &cpus);
    ASSERT( !cpumask_empty(&cpus) && cpumask_test_cpu(cpu, &cpus) );

    return cpu;
}

/*
 * Burn budget in nanosecond granularity
 */
static void
burn_budget(const struct scheduler *ops, struct rt_vcpu *svc, s_time_t now)
{
    s_time_t delta;

    /* don't burn budget for idle VCPU */
    if ( is_idle_vcpu(svc->vcpu) )
        return;

    /* burn at nanoseconds level */
    delta = now - svc->last_start;
    /*
     * delta < 0 only happens in nested virtualization;
     * TODO: how should we handle delta < 0 in a better way?
     */
    if ( delta < 0 )
    {
        printk("%s, ATTENTION: now is behind last_start! delta=%"PRI_stime"\n",
                __func__, delta);
        svc->last_start = now;
        return;
    }

    svc->cur_budget -= delta;

    if ( svc->cur_budget <= 0 )
    {
        svc->cur_budget = 0;
        set_bit(__RTDS_depleted, &svc->flags);
    }

    /* TRACE */
    {
        struct __packed {
            unsigned vcpu:16, dom:16;
            uint64_t cur_budget;
            int delta;
        } d;
        d.dom = svc->vcpu->domain->domain_id;
        d.vcpu = svc->vcpu->vcpu_id;
        d.cur_budget = (uint64_t) svc->cur_budget;
        d.delta = delta;
        trace_var(TRC_RTDS_BUDGET_BURN, 1,
                  sizeof(d),
                  (unsigned char *) &d);
    }
}

/*
 * RunQ is sorted. Pick first one within cpumask. If no one, return NULL
 * lock is grabbed before calling this function
 */
static struct rt_vcpu *
__runq_pick(const struct scheduler *ops, const cpumask_t *mask)
{
    struct list_head *runq = rt_runq(ops);
    struct list_head *iter;
    struct rt_vcpu *svc = NULL;
    struct rt_vcpu *iter_svc = NULL;
    cpumask_t cpu_common;
    cpumask_t *online;

    list_for_each(iter, runq)
    {
        iter_svc = __q_elem(iter);

        /* mask cpu_hard_affinity & cpupool & mask */
        online = cpupool_domain_cpumask(iter_svc->vcpu->domain);
        cpumask_and(&cpu_common, online, iter_svc->vcpu->cpu_hard_affinity);
        cpumask_and(&cpu_common, mask, &cpu_common);
        if ( cpumask_empty(&cpu_common) )
            continue;

        ASSERT( iter_svc->cur_budget > 0 );

        svc = iter_svc;
        break;
    }

    /* TRACE */
    {
        if( svc != NULL )
        {
            struct __packed {
                unsigned vcpu:16, dom:16;
                uint64_t cur_deadline, cur_budget;
            } d;
            d.dom = svc->vcpu->domain->domain_id;
            d.vcpu = svc->vcpu->vcpu_id;
            d.cur_deadline = (uint64_t) svc->cur_deadline;
            d.cur_budget = (uint64_t) svc->cur_budget;
            trace_var(TRC_RTDS_RUNQ_PICK, 1,
                      sizeof(d),
                      (unsigned char *) &d);
        }
    }

    return svc;
}

/*
 * schedule function for rt scheduler.
 * The lock is already grabbed in schedule.c, no need to lock here
 */
static struct task_slice
rt_schedule(const struct scheduler *ops, s_time_t now, bool_t tasklet_work_scheduled)
{
    const int cpu = smp_processor_id();
    struct rt_private *prv = rt_priv(ops);
    struct rt_vcpu *const scurr = rt_vcpu(current);
    struct rt_vcpu *snext = NULL;
    struct task_slice ret = { .migrated = 0 };

    /* clear ticked bit now that we've been scheduled */
    cpumask_clear_cpu(cpu, &prv->tickled);

    /* burn_budget would return for IDLE VCPU */
    burn_budget(ops, scurr, now);

    if ( tasklet_work_scheduled )
    {
        trace_var(TRC_RTDS_SCHED_TASKLET, 1, 0,  NULL);
        snext = rt_vcpu(idle_vcpu[cpu]);
    }
    else
    {
        snext = __runq_pick(ops, cpumask_of(cpu));
        if ( snext == NULL )
            snext = rt_vcpu(idle_vcpu[cpu]);

        /* if scurr has higher priority and budget, still pick scurr */
        if ( !is_idle_vcpu(current) &&
             vcpu_runnable(current) &&
             scurr->cur_budget > 0 &&
             ( is_idle_vcpu(snext->vcpu) ||
               scurr->cur_deadline <= snext->cur_deadline ) )
            snext = scurr;
    }

    if ( snext != scurr &&
         !is_idle_vcpu(current) &&
         vcpu_runnable(current) )
        set_bit(__RTDS_delayed_runq_add, &scurr->flags);

    snext->last_start = now;
    ret.time =  -1; /* if an idle vcpu is picked */
    if ( !is_idle_vcpu(snext->vcpu) )
    {
        if ( snext != scurr )
        {
            __q_remove(snext);
            set_bit(__RTDS_scheduled, &snext->flags);
        }
        if ( snext->vcpu->processor != cpu )
        {
            snext->vcpu->processor = cpu;
            ret.migrated = 1;
        }
        ret.time = snext->cur_budget; /* invoke the scheduler next time */
    }
    ret.task = snext->vcpu;

    return ret;
}

/*
 * Remove VCPU from RunQ
 * The lock is already grabbed in schedule.c, no need to lock here
 */
static void
rt_vcpu_sleep(const struct scheduler *ops, struct vcpu *vc)
{
    struct rt_vcpu * const svc = rt_vcpu(vc);

    BUG_ON( is_idle_vcpu(vc) );
    SCHED_STAT_CRANK(vcpu_sleep);

    if ( curr_on_cpu(vc->processor) == vc )
        cpu_raise_softirq(vc->processor, SCHEDULE_SOFTIRQ);
    else if ( __vcpu_on_q(svc) )
    {
        __q_remove(svc);
        replq_remove(ops, svc);
    }
    else if ( svc->flags & RTDS_delayed_runq_add )
        clear_bit(__RTDS_delayed_runq_add, &svc->flags);
}

/*
 * Pick a cpu where to run a vcpu,
 * possibly kicking out the vcpu running there
 * Called by wake() and context_saved()
 * We have a running candidate here, the kick logic is:
 * Among all the cpus that are within the cpu affinity
 * 1) if the new->cpu is idle, kick it. This could benefit cache hit
 * 2) if there are any idle vcpu, kick it.
 * 3) now all pcpus are busy;
 *    among all the running vcpus, pick lowest priority one
 *    if snext has higher priority, kick it.
 *
 * TODO:
 * 1) what if these two vcpus belongs to the same domain?
 *    replace a vcpu belonging to the same domain introduces more overhead
 *
 * lock is grabbed before calling this function
 */
static void
runq_tickle(const struct scheduler *ops, struct rt_vcpu *new)
{
    struct rt_private *prv = rt_priv(ops);
    struct rt_vcpu *latest_deadline_vcpu = NULL; /* lowest priority */
    struct rt_vcpu *iter_svc;
    struct vcpu *iter_vc;
    int cpu = 0, cpu_to_tickle = 0;
    cpumask_t not_tickled;
    cpumask_t *online;

    if ( new == NULL || is_idle_vcpu(new->vcpu) )
        return;

    online = cpupool_domain_cpumask(new->vcpu->domain);
    cpumask_and(&not_tickled, online, new->vcpu->cpu_hard_affinity);
    cpumask_andnot(&not_tickled, &not_tickled, &prv->tickled);

    /* 1) if new's previous cpu is idle, kick it for cache benefit */
    if ( is_idle_vcpu(curr_on_cpu(new->vcpu->processor)) )
    {
        cpu_to_tickle = new->vcpu->processor;
        goto out;
    }

    /* 2) if there are any idle pcpu, kick it */
    /* The same loop also find the one with lowest priority */
    for_each_cpu(cpu, &not_tickled)
    {
        iter_vc = curr_on_cpu(cpu);
        if ( is_idle_vcpu(iter_vc) )
        {
            cpu_to_tickle = cpu;
            goto out;
        }
        iter_svc = rt_vcpu(iter_vc);
        if ( latest_deadline_vcpu == NULL ||
             iter_svc->cur_deadline > latest_deadline_vcpu->cur_deadline )
            latest_deadline_vcpu = iter_svc;
    }

    /* 3) candicate has higher priority, kick out lowest priority vcpu */
    if ( latest_deadline_vcpu != NULL &&
         new->cur_deadline < latest_deadline_vcpu->cur_deadline )
    {
        cpu_to_tickle = latest_deadline_vcpu->vcpu->processor;
        goto out;
    }

    /* didn't tickle any cpu */
    SCHED_STAT_CRANK(tickle_idlers_none);
    return;
out:
    /* TRACE */
    {
        struct {
            unsigned cpu:16, pad:16;
        } d;
        d.cpu = cpu_to_tickle;
        d.pad = 0;
        trace_var(TRC_RTDS_TICKLE, 1,
                  sizeof(d),
                  (unsigned char *)&d);
    }

    cpumask_set_cpu(cpu_to_tickle, &prv->tickled);
    SCHED_STAT_CRANK(tickle_idlers_some);
    cpu_raise_softirq(cpu_to_tickle, SCHEDULE_SOFTIRQ);
    return;
}

/*
 * Should always wake up runnable vcpu, put it back to RunQ.
 * Check priority to raise interrupt
 * The lock is already grabbed in schedule.c, no need to lock here
 * TODO: what if these two vcpus belongs to the same domain?
 */
static void
rt_vcpu_wake(const struct scheduler *ops, struct vcpu *vc)
{
    struct rt_vcpu * const svc = rt_vcpu(vc);
    s_time_t now = NOW();
    bool_t missed;

    BUG_ON( is_idle_vcpu(vc) );

    if ( unlikely(curr_on_cpu(vc->processor) == vc) )
    {
        SCHED_STAT_CRANK(vcpu_wake_running);
        return;
    }

    /* on RunQ/DepletedQ, just update info is ok */
    if ( unlikely(__vcpu_on_q(svc)) )
    {
        SCHED_STAT_CRANK(vcpu_wake_onrunq);
        return;
    }

    if ( likely(vcpu_runnable(vc)) )
        SCHED_STAT_CRANK(vcpu_wake_runnable);
    else
        SCHED_STAT_CRANK(vcpu_wake_not_runnable);

    /*
     * If a deadline passed while svc was asleep/blocked, we need new
     * scheduling parameters (a new deadline and full budget).
     */

    missed = ( now >= svc->cur_deadline );
    if ( missed )
        rt_update_deadline(now, svc);

    /*
     * If context hasn't been saved for this vcpu yet, we can't put it on
     * the run-queue/depleted-queue. Instead, we set the appropriate flag,
     * the vcpu will be put back on queue after the context has been saved
     * (in rt_context_save()).
     */
    if ( unlikely(svc->flags & RTDS_scheduled) )
    {
        set_bit(__RTDS_delayed_runq_add, &svc->flags);
        /*
         * The vcpu is waking up already, and we didn't even had the time to
         * remove its next replenishment event from the replenishment queue
         * when it blocked! No big deal. If we did not miss the deadline in
         * the meantime, let's just leave it there. If we did, let's remove it
         * and queue a new one (to occur at our new deadline).
         */
        if ( missed )
           replq_reinsert(ops, svc);
        return;
    }

    /* Replenishment event got cancelled when we blocked. Add it back. */
    replq_insert(ops, svc);
    /* insert svc to runq/depletedq because svc is not in queue now */
    __runq_insert(ops, svc);

    runq_tickle(ops, svc);
}

/*
 * scurr has finished context switch, insert it back to the RunQ,
 * and then pick the highest priority vcpu from runq to run
 */
static void
rt_context_saved(const struct scheduler *ops, struct vcpu *vc)
{
    struct rt_vcpu *svc = rt_vcpu(vc);
    spinlock_t *lock = vcpu_schedule_lock_irq(vc);

    clear_bit(__RTDS_scheduled, &svc->flags);
    /* not insert idle vcpu to runq */
    if ( is_idle_vcpu(vc) )
        goto out;

    if ( test_and_clear_bit(__RTDS_delayed_runq_add, &svc->flags) &&
         likely(vcpu_runnable(vc)) )
    {
        __runq_insert(ops, svc);
        runq_tickle(ops, svc);
    }
    else
        replq_remove(ops, svc);

out:
    vcpu_schedule_unlock_irq(lock, vc);
}

/*
 * set/get each vcpu info of each domain
 */
static int
rt_dom_cntl(
    const struct scheduler *ops,
    struct domain *d,
    struct xen_domctl_scheduler_op *op)
{
    struct rt_private *prv = rt_priv(ops);
    struct rt_vcpu *svc;
    struct vcpu *v;
    unsigned long flags;
    int rc = 0;
    xen_domctl_schedparam_vcpu_t local_sched;
    s_time_t period, budget;
    uint32_t index = 0;

    switch ( op->cmd )
    {
    case XEN_DOMCTL_SCHEDOP_getinfo:
        /* Return the default parameters. */
        op->u.rtds.period = RTDS_DEFAULT_PERIOD / MICROSECS(1);
        op->u.rtds.budget = RTDS_DEFAULT_BUDGET / MICROSECS(1);
        break;
    case XEN_DOMCTL_SCHEDOP_putinfo:
        if ( op->u.rtds.period == 0 || op->u.rtds.budget == 0 )
        {
            rc = -EINVAL;
            break;
        }
        spin_lock_irqsave(&prv->lock, flags);
        for_each_vcpu ( d, v )
        {
            svc = rt_vcpu(v);
            svc->period = MICROSECS(op->u.rtds.period); /* transfer to nanosec */
            svc->budget = MICROSECS(op->u.rtds.budget);
        }
        spin_unlock_irqrestore(&prv->lock, flags);
        break;
    case XEN_DOMCTL_SCHEDOP_getvcpuinfo:
    case XEN_DOMCTL_SCHEDOP_putvcpuinfo:
        while ( index < op->u.v.nr_vcpus )
        {
            if ( copy_from_guest_offset(&local_sched,
                                        op->u.v.vcpus, index, 1) )
            {
                rc = -EFAULT;
                break;
            }
            if ( local_sched.vcpuid >= d->max_vcpus ||
                 d->vcpu[local_sched.vcpuid] == NULL )
            {
                rc = -EINVAL;
                break;
            }

            if ( op->cmd == XEN_DOMCTL_SCHEDOP_getvcpuinfo )
            {
                spin_lock_irqsave(&prv->lock, flags);
                svc = rt_vcpu(d->vcpu[local_sched.vcpuid]);
                local_sched.u.rtds.budget = svc->budget / MICROSECS(1);
                local_sched.u.rtds.period = svc->period / MICROSECS(1);
                spin_unlock_irqrestore(&prv->lock, flags);

                if ( copy_to_guest_offset(op->u.v.vcpus, index,
                                          &local_sched, 1) )
                {
                    rc = -EFAULT;
                    break;
                }
            }
            else
            {
                period = MICROSECS(local_sched.u.rtds.period);
                budget = MICROSECS(local_sched.u.rtds.budget);
                if ( period > RTDS_MAX_PERIOD || budget < RTDS_MIN_BUDGET ||
                     budget > period || period < RTDS_MIN_PERIOD )
                {
                    rc = -EINVAL;
                    break;
                }

                spin_lock_irqsave(&prv->lock, flags);
                svc = rt_vcpu(d->vcpu[local_sched.vcpuid]);
                svc->period = period;
                svc->budget = budget;
                spin_unlock_irqrestore(&prv->lock, flags);
            }
            /* Process a most 64 vCPUs without checking for preemptions. */
            if ( (++index > 63) && hypercall_preempt_check() )
                break;
        }
        if ( !rc )
            /* notify upper caller how many vcpus have been processed. */
            op->u.v.nr_vcpus = index;
        break;
    }

    return rc;
}

/*
 * The replenishment timer handler picks vcpus
 * from the replq and does the actual replenishment.
 */
static void repl_timer_handler(void *data){
    s_time_t now = NOW();
    struct scheduler *ops = data;
    struct rt_private *prv = rt_priv(ops);
    struct list_head *replq = rt_replq(ops);
    struct list_head *runq = rt_runq(ops);
    struct timer *repl_timer = prv->repl_timer;
    struct list_head *iter, *tmp;
    struct rt_vcpu *svc;
    LIST_HEAD(tmp_replq);

    spin_lock_irq(&prv->lock);

    /*
     * Do the replenishment and move replenished vcpus
     * to the temporary list to tickle.
     * If svc is on run queue, we need to put it at
     * the correct place since its deadline changes.
     */
    list_for_each_safe ( iter, tmp, replq )
    {
        svc = replq_elem(iter);

        if ( now < svc->cur_deadline )
            break;

        list_del(&svc->replq_elem);
        rt_update_deadline(now, svc);
        list_add(&svc->replq_elem, &tmp_replq);

        if ( __vcpu_on_q(svc) )
        {
            __q_remove(svc);
            __runq_insert(ops, svc);
        }
    }

    /*
     * Iterate through the list of updated vcpus.
     * If an updated vcpu is running, tickle the head of the
     * runqueue if it has a higher priority.
     * If an updated vcpu was depleted and on the runqueue, tickle it.
     * Finally, reinsert the vcpus back to replenishement events list.
     */
    list_for_each_safe ( iter, tmp, &tmp_replq )
    {
        svc = replq_elem(iter);

        if ( curr_on_cpu(svc->vcpu->processor) == svc->vcpu &&
             !list_empty(runq) )
        {
            struct rt_vcpu *next_on_runq = __q_elem(runq->next);

            if ( svc->cur_deadline > next_on_runq->cur_deadline )
                runq_tickle(ops, next_on_runq);
        }
        else if ( __vcpu_on_q(svc) &&
                  test_and_clear_bit(__RTDS_depleted, &svc->flags) )
            runq_tickle(ops, svc);

        list_del(&svc->replq_elem);
        deadline_replq_insert(svc, &svc->replq_elem, replq);
    }

    /*
     * If there are vcpus left in the replenishment event list,
     * set the next replenishment to happen at the deadline of
     * the one in the front.
     */
    if ( !list_empty(replq) )
        set_timer(repl_timer, replq_elem(replq->next)->cur_deadline);

    spin_unlock_irq(&prv->lock);
}

static const struct scheduler sched_rtds_def = {
    .name           = "SMP RTDS Scheduler",
    .opt_name       = "rtds",
    .sched_id       = XEN_SCHEDULER_RTDS,
    .sched_data     = NULL,

    .dump_cpu_state = rt_dump_pcpu,
    .dump_settings  = rt_dump,
    .init           = rt_init,
    .deinit         = rt_deinit,
    .alloc_pdata    = rt_alloc_pdata,
    .free_pdata     = rt_free_pdata,
    .alloc_domdata  = rt_alloc_domdata,
    .free_domdata   = rt_free_domdata,
    .init_domain    = rt_dom_init,
    .destroy_domain = rt_dom_destroy,
    .alloc_vdata    = rt_alloc_vdata,
    .free_vdata     = rt_free_vdata,
    .insert_vcpu    = rt_vcpu_insert,
    .remove_vcpu    = rt_vcpu_remove,

    .adjust         = rt_dom_cntl,

    .pick_cpu       = rt_cpu_pick,
    .do_schedule    = rt_schedule,
    .sleep          = rt_vcpu_sleep,
    .wake           = rt_vcpu_wake,
    .context_saved  = rt_context_saved,
};

REGISTER_SCHEDULER(sched_rtds_def);
