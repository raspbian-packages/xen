/******************************************************************************
 * arch/x86/mm/mm-locks.h
 *
 * Spinlocks used by the code in arch/x86/mm.
 *
 * Copyright (c) 2011 Citrix Systems, inc. 
 * Copyright (c) 2007 Advanced Micro Devices (Wei Huang)
 * Copyright (c) 2006-2007 XenSource Inc.
 * Copyright (c) 2006 Michael A Fetterman
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _MM_LOCKS_H
#define _MM_LOCKS_H

/* Per-CPU variable for enforcing the lock ordering */
DECLARE_PER_CPU(int, mm_lock_level);
#define __get_lock_level()  (this_cpu(mm_lock_level))


static inline void mm_lock_init(mm_lock_t *l)
{
    spin_lock_init(&l->lock);
    l->locker = -1;
    l->locker_function = "nobody";
    l->unlock_level = 0;
}

static inline int mm_locked_by_me(mm_lock_t *l) 
{
    return (l->lock.recurse_cpu == current->processor);
}

/* If you see this crash, the numbers printed are lines in this file 
 * where the offending locks are declared. */
#define __check_lock_level(l)                           \
do {                                                    \
    if ( unlikely(__get_lock_level() > (l)) )           \
    {                                                   \
        printk("mm locking order violation: %i > %i\n", \
               __get_lock_level(), (l));                \
        BUG();                                          \
    }                                                   \
} while(0)

#define __set_lock_level(l)         \
do {                                \
    __get_lock_level() = (l);       \
} while(0)



static inline void _mm_lock(mm_lock_t *l, const char *func, int level, int rec)
{
    /* If you see this crash, the numbers printed are lines in this file 
     * where the offending locks are declared. */
    if ( unlikely(this_cpu(mm_lock_level) > level) )
        panic("mm locking order violation: %i > %i\n", 
              this_cpu(mm_lock_level), level);
    spin_lock_recursive(&l->lock);
    if ( l->lock.recurse_cnt == 1 )
    {
        l->locker_function = func;
        l->unlock_level = this_cpu(mm_lock_level);
    }
    else if ( (unlikely(!rec)) )
        panic("mm lock already held by %s\n", l->locker_function);
    this_cpu(mm_lock_level) = level;
}
/* This wrapper uses the line number to express the locking order below */
#define declare_mm_lock(name)                                                 \
    static inline void mm_lock_##name(mm_lock_t *l, const char *func, int rec)\
    { _mm_lock(l, func, __LINE__, rec); }
/* These capture the name of the calling function */
#define mm_lock(name, l) mm_lock_##name(l, __func__, 0)
#define mm_lock_recursive(name, l) mm_lock_##name(l, __func__, 1)

static inline void mm_unlock(mm_lock_t *l)
{
    if ( l->lock.recurse_cnt == 1 )
    {
        l->locker_function = "nobody";
        this_cpu(mm_lock_level) = l->unlock_level;
    }
    spin_unlock_recursive(&l->lock);
}

/************************************************************************
 *                                                                      *
 * To avoid deadlocks, these locks _MUST_ be taken in the order they're *
 * declared in this file.  The locking functions will enforce this.     *
 *                                                                      *
 ************************************************************************/

/* Page-sharing lock (global) 
 *
 * A single global lock that protects the memory-sharing code's
 * hash tables. */

declare_mm_lock(shr)
#define shr_lock()         mm_lock(shr, &shr_lock)
#define shr_unlock()       mm_unlock(&shr_lock)
#define shr_locked_by_me() mm_locked_by_me(&shr_lock)

/* Nested P2M lock (per-domain)
 *
 * A per-domain lock that protects some of the nested p2m datastructures.
 * TODO: find out exactly what needs to be covered by this lock */

declare_mm_lock(nestedp2m)
#define nestedp2m_lock(d)   mm_lock(nestedp2m, &(d)->arch.nested_p2m_lock)
#define nestedp2m_unlock(d) mm_unlock(&(d)->arch.nested_p2m_lock)

/* P2M lock (per-p2m-table)
 * 
 * This protects all updates to the p2m table.  Updates are expected to
 * be safe against concurrent reads, which do *not* require the lock. */

declare_mm_lock(p2m)
#define p2m_lock(p)           mm_lock(p2m, &(p)->lock)
#define p2m_lock_recursive(p) mm_lock_recursive(p2m, &(p)->lock)
#define p2m_unlock(p)         mm_unlock(&(p)->lock)
#define p2m_locked_by_me(p)   mm_locked_by_me(&(p)->lock)
#define gfn_lock(p,g,o)       p2m_lock(p)
#define gfn_unlock(p,g,o)     p2m_unlock(p)


/* Paging lock (per-domain)
 *
 * For shadow pagetables, this lock protects
 *   - all changes to shadow page table pages
 *   - the shadow hash table
 *   - the shadow page allocator 
 *   - all changes to guest page table pages
 *   - all changes to the page_info->tlbflush_timestamp
 *   - the page_info->count fields on shadow pages 
 * 
 * For HAP, it protects the NPT/EPT tables and mode changes. 
 * 
 * It also protects the log-dirty bitmap from concurrent accesses (and
 * teardowns, etc). */

declare_mm_lock(paging)
#define paging_lock(d)         mm_lock(paging, &(d)->arch.paging.lock)
#define paging_lock_recursive(d) \
                    mm_lock_recursive(paging, &(d)->arch.paging.lock)
#define paging_unlock(d)       mm_unlock(&(d)->arch.paging.lock)
#define paging_locked_by_me(d) mm_locked_by_me(&(d)->arch.paging.lock)


static inline void mm_write_unlock(mm_rwlock_t *l)
{
    if ( --(l->recurse_count) != 0 )
        return;
    l->locker = -1;
    l->locker_function = "nobody";
    __set_lock_level(l->unlock_level);
    write_unlock(&l->lock);
}
   
static inline void _mm_read_lock(mm_rwlock_t *l, int level)
{
    __check_lock_level(level);
    read_lock(&l->lock);
    /* There's nowhere to store the per-CPU unlock level so we can't
     * set the lock level. */
}

static inline void mm_read_unlock(mm_rwlock_t *l)
{
    read_unlock(&l->lock);
}

/* This wrapper uses the line number to express the locking order below */
#define declare_mm_lock(name)                                                 \
    static inline void mm_lock_##name(mm_lock_t *l, const char *func, int rec)\
    { _mm_lock(l, func, __LINE__, rec); }
#define declare_mm_rwlock(name)                                               \
    static inline void mm_write_lock_##name(mm_rwlock_t *l, const char *func) \
    { _mm_write_lock(l, func, __LINE__); }                                    \
    static inline void mm_read_lock_##name(mm_rwlock_t *l)                    \
    { _mm_read_lock(l, __LINE__); }
/* These capture the name of the calling function */
#define mm_lock(name, l) mm_lock_##name(l, __func__, 0)
#define mm_lock_recursive(name, l) mm_lock_##name(l, __func__, 1)
#define mm_write_lock(name, l) mm_write_lock_##name(l, __func__)
#define mm_read_lock(name, l) mm_read_lock_##name(l)



     
#endif /* _MM_LOCKS_H */
