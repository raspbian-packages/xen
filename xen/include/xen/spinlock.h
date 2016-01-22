#ifndef __SPINLOCK_H__
#define __SPINLOCK_H__

#include <asm/system.h>
#include <asm/spinlock.h>
#include <asm/types.h>
#include <xen/percpu.h>

#ifndef NDEBUG
struct lock_debug {
    int irq_safe; /* +1: IRQ-safe; 0: not IRQ-safe; -1: don't know yet */
};
#define _LOCK_DEBUG { -1 }
void spin_debug_enable(void);
void spin_debug_disable(void);
#else
struct lock_debug { };
#define _LOCK_DEBUG { }
#define spin_debug_enable() ((void)0)
#define spin_debug_disable() ((void)0)
#endif

#ifdef LOCK_PROFILE

#include <public/sysctl.h>

/*
    lock profiling on:

    Global locks which should be subject to profiling must be declared via
    DEFINE_SPINLOCK.

    For locks in structures further measures are necessary:
    - the structure definition must include a profile_head with exactly this
      name:

      struct lock_profile_qhead   profile_head;

    - the single locks which are subject to profiling have to be initialized
      via

      spin_lock_init_prof(ptr, lock);

      with ptr being the main structure pointer and lock the spinlock field

    - each structure has to be added to profiling with

      lock_profile_register_struct(type, ptr, idx, print);

      with:
        type:  something like LOCKPROF_TYPE_PERDOM
        ptr:   pointer to the structure
        idx:   index of that structure, e.g. domid
        print: descriptive string like "domain"

    - removing of a structure is done via

      lock_profile_deregister_struct(type, ptr);
*/

struct spinlock;

struct lock_profile {
    struct lock_profile *next;       /* forward link */
    char                *name;       /* lock name */
    struct spinlock     *lock;       /* the lock itself */
    u64                 lock_cnt;    /* # of complete locking ops */
    u64                 block_cnt;   /* # of complete wait for lock */
    s64                 time_hold;   /* cumulated lock time */
    s64                 time_block;  /* cumulated wait time */
    s64                 time_locked; /* system time of last locking */
};

struct lock_profile_qhead {
    struct lock_profile_qhead *head_q; /* next head of this type */
    struct lock_profile       *elem_q; /* first element in q */
    int32_t                   idx;     /* index for printout */
};

#define _LOCK_PROFILE(name) { 0, #name, &name, 0, 0, 0, 0, 0 }
#define _LOCK_PROFILE_PTR(name)                                               \
    static struct lock_profile *__lock_profile_##name                         \
    __used_section(".lockprofile.data") =                                     \
    &__lock_profile_data_##name
#define _SPIN_LOCK_UNLOCKED(x) { { 0 }, SPINLOCK_NO_CPU, 0, _LOCK_DEBUG, x }
#define SPIN_LOCK_UNLOCKED _SPIN_LOCK_UNLOCKED(NULL)
#define DEFINE_SPINLOCK(l)                                                    \
    spinlock_t l = _SPIN_LOCK_UNLOCKED(NULL);                                 \
    static struct lock_profile __lock_profile_data_##l = _LOCK_PROFILE(l);    \
    _LOCK_PROFILE_PTR(l)

#define spin_lock_init_prof(s, l)                                             \
    do {                                                                      \
        struct lock_profile *prof;                                            \
        prof = xzalloc(struct lock_profile);                                  \
        if (!prof) break;                                                     \
        prof->name = #l;                                                      \
        prof->lock = &(s)->l;                                                 \
        (s)->l = (spinlock_t)_SPIN_LOCK_UNLOCKED(prof);                       \
        prof->next = (s)->profile_head.elem_q;                                \
        (s)->profile_head.elem_q = prof;                                      \
    } while(0)

void _lock_profile_register_struct(
    int32_t, struct lock_profile_qhead *, int32_t, char *);
void _lock_profile_deregister_struct(int32_t, struct lock_profile_qhead *);

#define lock_profile_register_struct(type, ptr, idx, print)                   \
    _lock_profile_register_struct(type, &((ptr)->profile_head), idx, print)
#define lock_profile_deregister_struct(type, ptr)                             \
    _lock_profile_deregister_struct(type, &((ptr)->profile_head))

extern int spinlock_profile_control(xen_sysctl_lockprof_op_t *pc);
extern void spinlock_profile_printall(unsigned char key);
extern void spinlock_profile_reset(unsigned char key);

#else

struct lock_profile_qhead { };

#define SPIN_LOCK_UNLOCKED { { 0 }, SPINLOCK_NO_CPU, 0, _LOCK_DEBUG }
#define DEFINE_SPINLOCK(l) spinlock_t l = SPIN_LOCK_UNLOCKED

#define spin_lock_init_prof(s, l) spin_lock_init(&((s)->l))
#define lock_profile_register_struct(type, ptr, idx, print)
#define lock_profile_deregister_struct(type, ptr)

#endif

typedef union {
    u32 head_tail;
    struct {
        u16 head;
        u16 tail;
    };
} spinlock_tickets_t;

#define SPINLOCK_TICKET_INC { .head_tail = 0x10000, }

typedef struct spinlock {
    spinlock_tickets_t tickets;
    u16 recurse_cpu:12;
#define SPINLOCK_NO_CPU 0xfffu
    u16 recurse_cnt:4;
#define SPINLOCK_MAX_RECURSE 0xfu
    struct lock_debug debug;
#ifdef LOCK_PROFILE
    struct lock_profile *profile;
#endif
} spinlock_t;


#define spin_lock_init(l) (*(l) = (spinlock_t)SPIN_LOCK_UNLOCKED)

typedef struct {
    volatile uint32_t lock;
    struct lock_debug debug;
} rwlock_t;

#define RW_WRITE_FLAG (1u<<31)

#define RW_LOCK_UNLOCKED { 0, _LOCK_DEBUG }
#define DEFINE_RWLOCK(l) rwlock_t l = RW_LOCK_UNLOCKED
#define rwlock_init(l) (*(l) = (rwlock_t)RW_LOCK_UNLOCKED)

void _spin_lock(spinlock_t *lock);
void _spin_lock_irq(spinlock_t *lock);
unsigned long _spin_lock_irqsave(spinlock_t *lock);

void _spin_unlock(spinlock_t *lock);
void _spin_unlock_irq(spinlock_t *lock);
void _spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags);

int _spin_is_locked(spinlock_t *lock);
int _spin_trylock(spinlock_t *lock);
void _spin_barrier(spinlock_t *lock);

int _spin_trylock_recursive(spinlock_t *lock);
void _spin_lock_recursive(spinlock_t *lock);
void _spin_unlock_recursive(spinlock_t *lock);

void _read_lock(rwlock_t *lock);
void _read_lock_irq(rwlock_t *lock);
unsigned long _read_lock_irqsave(rwlock_t *lock);

void _read_unlock(rwlock_t *lock);
void _read_unlock_irq(rwlock_t *lock);
void _read_unlock_irqrestore(rwlock_t *lock, unsigned long flags);
int _read_trylock(rwlock_t *lock);

void _write_lock(rwlock_t *lock);
void _write_lock_irq(rwlock_t *lock);
unsigned long _write_lock_irqsave(rwlock_t *lock);
int _write_trylock(rwlock_t *lock);

void _write_unlock(rwlock_t *lock);
void _write_unlock_irq(rwlock_t *lock);
void _write_unlock_irqrestore(rwlock_t *lock, unsigned long flags);

int _rw_is_locked(rwlock_t *lock);
int _rw_is_write_locked(rwlock_t *lock);

#define spin_lock(l)                  _spin_lock(l)
#define spin_lock_irq(l)              _spin_lock_irq(l)
#define spin_lock_irqsave(l, f)                                 \
    ({                                                          \
        BUILD_BUG_ON(sizeof(f) != sizeof(unsigned long));       \
        ((f) = _spin_lock_irqsave(l));                          \
    })

#define spin_unlock(l)                _spin_unlock(l)
#define spin_unlock_irq(l)            _spin_unlock_irq(l)
#define spin_unlock_irqrestore(l, f)  _spin_unlock_irqrestore(l, f)

#define spin_is_locked(l)             _spin_is_locked(l)
#define spin_trylock(l)               _spin_trylock(l)

#define spin_trylock_irqsave(lock, flags)       \
({                                              \
    local_irq_save(flags);                      \
    spin_trylock(lock) ?                        \
    1 : ({ local_irq_restore(flags); 0; });     \
})

/* Ensure a lock is quiescent between two critical operations. */
#define spin_barrier(l)               _spin_barrier(l)

/*
 * spin_[un]lock_recursive(): Use these forms when the lock can (safely!) be
 * reentered recursively on the same CPU. All critical regions that may form
 * part of a recursively-nested set must be protected by these forms. If there
 * are any critical regions that cannot form part of such a set, they can use
 * standard spin_[un]lock().
 */
#define spin_trylock_recursive(l)     _spin_trylock_recursive(l)
#define spin_lock_recursive(l)        _spin_lock_recursive(l)
#define spin_unlock_recursive(l)      _spin_unlock_recursive(l)

#define read_lock(l)                  _read_lock(l)
#define read_lock_irq(l)              _read_lock_irq(l)
#define read_lock_irqsave(l, f)                                 \
    ({                                                          \
        BUILD_BUG_ON(sizeof(f) != sizeof(unsigned long));       \
        ((f) = _read_lock_irqsave(l));                          \
    })

#define read_unlock(l)                _read_unlock(l)
#define read_unlock_irq(l)            _read_unlock_irq(l)
#define read_unlock_irqrestore(l, f)  _read_unlock_irqrestore(l, f)
#define read_trylock(l)               _read_trylock(l)

#define write_lock(l)                 _write_lock(l)
#define write_lock_irq(l)             _write_lock_irq(l)
#define write_lock_irqsave(l, f)                                \
    ({                                                          \
        BUILD_BUG_ON(sizeof(f) != sizeof(unsigned long));       \
        ((f) = _write_lock_irqsave(l));                         \
    })
#define write_trylock(l)              _write_trylock(l)

#define write_unlock(l)               _write_unlock(l)
#define write_unlock_irq(l)           _write_unlock_irq(l)
#define write_unlock_irqrestore(l, f) _write_unlock_irqrestore(l, f)

#define rw_is_locked(l)               _rw_is_locked(l)
#define rw_is_write_locked(l)         _rw_is_write_locked(l)

typedef struct percpu_rwlock percpu_rwlock_t;

struct percpu_rwlock {
    rwlock_t            rwlock;
    bool_t              writer_activating;
#ifndef NDEBUG
    percpu_rwlock_t     **percpu_owner;
#endif
};

#ifndef NDEBUG
#define PERCPU_RW_LOCK_UNLOCKED(owner) { RW_LOCK_UNLOCKED, 0, owner }
static inline void _percpu_rwlock_owner_check(percpu_rwlock_t **per_cpudata,
                                         percpu_rwlock_t *percpu_rwlock)
{
    ASSERT(per_cpudata == percpu_rwlock->percpu_owner);
}
#else
#define PERCPU_RW_LOCK_UNLOCKED(owner) { RW_LOCK_UNLOCKED, 0 }
#define _percpu_rwlock_owner_check(data, lock) ((void)0)
#endif

#define DEFINE_PERCPU_RWLOCK_RESOURCE(l, owner) \
    percpu_rwlock_t l = PERCPU_RW_LOCK_UNLOCKED(&get_per_cpu_var(owner))
#define percpu_rwlock_resource_init(l, owner) \
    (*(l) = (percpu_rwlock_t)PERCPU_RW_LOCK_UNLOCKED(&get_per_cpu_var(owner)))

static inline void _percpu_read_lock(percpu_rwlock_t **per_cpudata,
                                         percpu_rwlock_t *percpu_rwlock)
{
    /* Validate the correct per_cpudata variable has been provided. */
    _percpu_rwlock_owner_check(per_cpudata, percpu_rwlock);

    /* We cannot support recursion on the same lock. */
    ASSERT(this_cpu_ptr(per_cpudata) != percpu_rwlock);
    /* 
     * Detect using a second percpu_rwlock_t simulatenously and fallback
     * to standard read_lock.
     */
    if ( unlikely(this_cpu_ptr(per_cpudata) != NULL ) )
    {
        read_lock(&percpu_rwlock->rwlock);
        return;
    }

    /* Indicate this cpu is reading. */
    this_cpu_ptr(per_cpudata) = percpu_rwlock;
    smp_mb();
    /* Check if a writer is waiting. */
    if ( unlikely(percpu_rwlock->writer_activating) )
    {
        /* Let the waiting writer know we aren't holding the lock. */
        this_cpu_ptr(per_cpudata) = NULL;
        /* Wait using the read lock to keep the lock fair. */
        read_lock(&percpu_rwlock->rwlock);
        /* Set the per CPU data again and continue. */
        this_cpu_ptr(per_cpudata) = percpu_rwlock;
        /* Drop the read lock because we don't need it anymore. */
        read_unlock(&percpu_rwlock->rwlock);
    }
}

static inline void _percpu_read_unlock(percpu_rwlock_t **per_cpudata,
                percpu_rwlock_t *percpu_rwlock)
{
    /* Validate the correct per_cpudata variable has been provided. */
    _percpu_rwlock_owner_check(per_cpudata, percpu_rwlock);

    /* Verify the read lock was taken for this lock */
    ASSERT(this_cpu_ptr(per_cpudata) != NULL);
    /* 
     * Detect using a second percpu_rwlock_t simulatenously and fallback
     * to standard read_unlock.
     */
    if ( unlikely(this_cpu_ptr(per_cpudata) != percpu_rwlock ) )
    {
        read_unlock(&percpu_rwlock->rwlock);
        return;
    }
    this_cpu_ptr(per_cpudata) = NULL;
    smp_wmb();
}

/* Don't inline percpu write lock as it's a complex function. */
void _percpu_write_lock(percpu_rwlock_t **per_cpudata,
                        percpu_rwlock_t *percpu_rwlock);

static inline void _percpu_write_unlock(percpu_rwlock_t **per_cpudata,
                percpu_rwlock_t *percpu_rwlock)
{
    /* Validate the correct per_cpudata variable has been provided. */
    _percpu_rwlock_owner_check(per_cpudata, percpu_rwlock);

    ASSERT(percpu_rwlock->writer_activating);
    percpu_rwlock->writer_activating = 0;
    write_unlock(&percpu_rwlock->rwlock);
}

#define percpu_rw_is_write_locked(l)         _rw_is_write_locked(&((l)->rwlock))

#define percpu_read_lock(percpu, lock) \
    _percpu_read_lock(&get_per_cpu_var(percpu), lock)
#define percpu_read_unlock(percpu, lock) \
    _percpu_read_unlock(&get_per_cpu_var(percpu), lock)
#define percpu_write_lock(percpu, lock) \
    _percpu_write_lock(&get_per_cpu_var(percpu), lock)
#define percpu_write_unlock(percpu, lock) \
    _percpu_write_unlock(&get_per_cpu_var(percpu), lock)

#define DEFINE_PERCPU_RWLOCK_GLOBAL(name) DEFINE_PER_CPU(percpu_rwlock_t *, \
                                                         name)
#define DECLARE_PERCPU_RWLOCK_GLOBAL(name) DECLARE_PER_CPU(percpu_rwlock_t *, \
                                                         name)

#endif /* __SPINLOCK_H__ */
