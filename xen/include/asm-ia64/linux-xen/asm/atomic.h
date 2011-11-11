#ifndef _ASM_IA64_ATOMIC_H
#define _ASM_IA64_ATOMIC_H

/*
 * Atomic operations that C can't guarantee us.  Useful for
 * resource counting etc..
 *
 * NOTE: don't mess with the types below!  The "unsigned long" and
 * "int" types were carefully placed so as to ensure proper operation
 * of the macros.
 *
 * Copyright (C) 1998, 1999, 2002-2003 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 */
#include <linux/types.h>

#include <asm/intrinsics.h>

/*
 * On IA-64, counter must always be volatile to ensure that that the
 * memory accesses are ordered.
 */
typedef struct { volatile __s32 counter; } atomic_t;
typedef struct { volatile __s64 counter; } atomic64_t;

#ifndef XEN

#define ATOMIC_INIT(i)		((atomic_t) { (i) })
#define ATOMIC64_INIT(i)	((atomic64_t) { (i) })

#define atomic_read(v)		((v)->counter)
#define atomic64_read(v)	((v)->counter)

#define atomic_set(v,i)		(((v)->counter) = (i))
#define atomic64_set(v,i)	(((v)->counter) = (i))

#else

#define ATOMIC_INIT(i)		{ (i) }
#define ATOMIC64_INIT(i)	{ (i) }

#define build_atomic_read(tag, type) \
static inline type atomic_read##tag(const volatile type *addr) \
{ \
	type ret; \
	asm volatile("ld%2.acq %0 = %1" \
		     : "=r" (ret) \
		     : "m" (*addr), "i" (sizeof(type))); \
	return ret; \
}

#define build_atomic_write(tag, type) \
static inline void atomic_write##tag(volatile type *addr, type val) \
{ \
	asm volatile("st%2.rel %0 = %1" \
		     : "=m" (*addr) \
		     : "r" (val), "i" (sizeof(type))); \
}

build_atomic_read(8, uint8_t)
build_atomic_read(16, uint16_t)
build_atomic_read(32, uint32_t)
build_atomic_read(64, uint64_t)
build_atomic_read(_int, int)
build_atomic_read(_long, long)

build_atomic_write(8, uint8_t)
build_atomic_write(16, uint16_t)
build_atomic_write(32, uint32_t)
build_atomic_write(64, uint64_t)
build_atomic_write(_int, int)
build_atomic_write(_long, long)

#define _atomic_read(v)		((v).counter)
#define _atomic64_read(v)	((v).counter)
#define atomic_read(v)		atomic_read_int(&((v)->counter))
#define atomic64_read(v)	atomic_read_long(&((v)->counter))

#define _atomic_set(v,i)	(((v).counter) = (i))
#define _atomic64_set(v,i)	(((v).counter) = (i))
#define atomic_set(v,i)		atomic_write_int(&((v)->counter), i)
#define atomic64_set(v,l)	atomic_write_long(&((v)->counter), l)

#endif

static __inline__ int
ia64_atomic_add (int i, atomic_t *v)
{
	__s32 old, new;
	CMPXCHG_BUGCHECK_DECL

	do {
		CMPXCHG_BUGCHECK(v);
		old = atomic_read(v);
		new = old + i;
	} while (ia64_cmpxchg(acq, v, old, new, sizeof(atomic_t)) != old);
	return new;
}

static __inline__ int
ia64_atomic64_add (__s64 i, atomic64_t *v)
{
	__s64 old, new;
	CMPXCHG_BUGCHECK_DECL

	do {
		CMPXCHG_BUGCHECK(v);
		old = atomic64_read(v);
		new = old + i;
	} while (ia64_cmpxchg(acq, v, old, new, sizeof(atomic64_t)) != old);
	return new;
}

static __inline__ int
ia64_atomic_sub (int i, atomic_t *v)
{
	__s32 old, new;
	CMPXCHG_BUGCHECK_DECL

	do {
		CMPXCHG_BUGCHECK(v);
		old = atomic_read(v);
		new = old - i;
	} while (ia64_cmpxchg(acq, v, old, new, sizeof(atomic_t)) != old);
	return new;
}

static __inline__ int
ia64_atomic64_sub (__s64 i, atomic64_t *v)
{
	__s64 old, new;
	CMPXCHG_BUGCHECK_DECL

	do {
		CMPXCHG_BUGCHECK(v);
		old = atomic64_read(v);
		new = old - i;
	} while (ia64_cmpxchg(acq, v, old, new, sizeof(atomic64_t)) != old);
	return new;
}

#define atomic_add_return(i,v)						\
({									\
	int __ia64_aar_i = (i);						\
	(__builtin_constant_p(i)					\
	 && (   (__ia64_aar_i ==  1) || (__ia64_aar_i ==   4)		\
	     || (__ia64_aar_i ==  8) || (__ia64_aar_i ==  16)		\
	     || (__ia64_aar_i == -1) || (__ia64_aar_i ==  -4)		\
	     || (__ia64_aar_i == -8) || (__ia64_aar_i == -16)))		\
		? ia64_fetch_and_add(__ia64_aar_i, &(v)->counter)	\
		: ia64_atomic_add(__ia64_aar_i, v);			\
})

#define atomic64_add_return(i,v)					\
({									\
	long __ia64_aar_i = (i);					\
	(__builtin_constant_p(i)					\
	 && (   (__ia64_aar_i ==  1) || (__ia64_aar_i ==   4)		\
	     || (__ia64_aar_i ==  8) || (__ia64_aar_i ==  16)		\
	     || (__ia64_aar_i == -1) || (__ia64_aar_i ==  -4)		\
	     || (__ia64_aar_i == -8) || (__ia64_aar_i == -16)))		\
		? ia64_fetch_and_add(__ia64_aar_i, &(v)->counter)	\
		: ia64_atomic64_add(__ia64_aar_i, v);			\
})

/*
 * Atomically add I to V and return TRUE if the resulting value is
 * negative.
 */
static __inline__ int
atomic_add_negative (int i, atomic_t *v)
{
	return atomic_add_return(i, v) < 0;
}

static __inline__ int
atomic64_add_negative (__s64 i, atomic64_t *v)
{
	return atomic64_add_return(i, v) < 0;
}

#define atomic_sub_return(i,v)						\
({									\
	int __ia64_asr_i = (i);						\
	(__builtin_constant_p(i)					\
	 && (   (__ia64_asr_i ==   1) || (__ia64_asr_i ==   4)		\
	     || (__ia64_asr_i ==   8) || (__ia64_asr_i ==  16)		\
	     || (__ia64_asr_i ==  -1) || (__ia64_asr_i ==  -4)		\
	     || (__ia64_asr_i ==  -8) || (__ia64_asr_i == -16)))	\
		? ia64_fetch_and_add(-__ia64_asr_i, &(v)->counter)	\
		: ia64_atomic_sub(__ia64_asr_i, v);			\
})

#define atomic64_sub_return(i,v)					\
({									\
	long __ia64_asr_i = (i);					\
	(__builtin_constant_p(i)					\
	 && (   (__ia64_asr_i ==   1) || (__ia64_asr_i ==   4)		\
	     || (__ia64_asr_i ==   8) || (__ia64_asr_i ==  16)		\
	     || (__ia64_asr_i ==  -1) || (__ia64_asr_i ==  -4)		\
	     || (__ia64_asr_i ==  -8) || (__ia64_asr_i == -16)))	\
		? ia64_fetch_and_add(-__ia64_asr_i, &(v)->counter)	\
		: ia64_atomic64_sub(__ia64_asr_i, v);			\
})

#define atomic_dec_return(v)		atomic_sub_return(1, (v))
#define atomic_inc_return(v)		atomic_add_return(1, (v))
#define atomic64_dec_return(v)		atomic64_sub_return(1, (v))
#define atomic64_inc_return(v)		atomic64_add_return(1, (v))

#define atomic_sub_and_test(i,v)	(atomic_sub_return((i), (v)) == 0)
#define atomic_dec_and_test(v)		(atomic_sub_return(1, (v)) == 0)
#define atomic_inc_and_test(v)		(atomic_add_return(1, (v)) == 0)
#define atomic64_sub_and_test(i,v)	(atomic64_sub_return((i), (v)) == 0)
#define atomic64_dec_and_test(v)	(atomic64_sub_return(1, (v)) == 0)
#define atomic64_inc_and_test(v)	(atomic64_add_return(1, (v)) == 0)

#define atomic_add(i,v)			atomic_add_return((i), (v))
#define atomic_sub(i,v)			atomic_sub_return((i), (v))
#define atomic_inc(v)			atomic_add(1, (v))
#define atomic_dec(v)			atomic_sub(1, (v))

#define atomic64_add(i,v)		atomic64_add_return((i), (v))
#define atomic64_sub(i,v)		atomic64_sub_return((i), (v))
#define atomic64_inc(v)			atomic64_add(1, (v))
#define atomic64_dec(v)			atomic64_sub(1, (v))

/* Atomic operations are already serializing */
#define smp_mb__before_atomic_dec()	barrier()
#define smp_mb__after_atomic_dec()	barrier()
#define smp_mb__before_atomic_inc()	barrier()
#define smp_mb__after_atomic_inc()	barrier()

#endif /* _ASM_IA64_ATOMIC_H */
