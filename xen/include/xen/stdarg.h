#ifndef __XEN_STDARG_H__
#define __XEN_STDARG_H__

#ifdef __GNUC__
#  define __GNUC_PREREQ__(x, y)                                       \
      ((__GNUC__ == (x) && __GNUC_MINOR__ >= (y)) ||                  \
       (__GNUC__ > (x)))
#else
#  define __GNUC_PREREQ__(x, y)   0
#endif

#if !__GNUC_PREREQ__(4, 5)
#  define __builtin_va_start(ap, last)    __builtin_stdarg_start((ap), (last))
#endif

typedef __builtin_va_list va_list;
#define va_start(ap, last)    __builtin_va_start((ap), (last))
#define va_end(ap)            __builtin_va_end(ap)
#define va_arg                __builtin_va_arg

#endif /* __XEN_STDARG_H__ */
