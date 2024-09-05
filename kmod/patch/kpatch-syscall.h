#ifndef __KPATCH_SYSCALL_H_
#define __KPATCH_SYSCALL_H_

#include "kpatch-macros.h"

/*
 * These kpatch-specific syscall definition macros can be used for patching a
 * syscall.
 *
 * Attempting to patch a syscall typically results in an error, due to a
 * missing fentry hook in the inner __do_sys##name() function.  The fentry hook
 * is missing because of the 'inline' annotation, which invokes 'notrace'.
 *
 * These macros are copied almost verbatim from the kernel, the main difference
 * being a 'kpatch' prefix added to the __do_sys##name() function name.  This
 * causes kpatch-build to treat it as a new function (due to
 * its new name), and its caller __se_sys##name() function is inlined by its own
 * caller __x64_sys##name() function, which has an fentry hook.  Since the
 * kpatch versions do not provide SYSCALL_METADATA, specifically entries in the
 * __syscalls_metadata and _ftrace_events sections, provide dummy values in
 * these sections and instruct kpatch-build to ignore changes to them.
 *
 * To patch a syscall, just replace the use of the SYSCALL_DEFINE1 (or similar)
 * macro with the "KPATCH_" prefixed version.
 */

#define KPATCH_SYSCALL_METADATA(sname)					\
	static struct syscall_metadata __used				\
	  __section("__syscalls_metadata")			 	\
	  *__p_syscall_meta_##sname = NULL;				\
	KPATCH_IGNORE_SECTION("__syscalls_metadata");			\
									\
	static struct trace_event_call __used				\
	  __section("_ftrace_events")					\
	  *__event_enter_##sname = NULL;				\
	KPATCH_IGNORE_SECTION("_ftrace_events")

#define KPATCH_SYSCALL_DEFINE1(name, ...) KPATCH_SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define KPATCH_SYSCALL_DEFINE2(name, ...) KPATCH_SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define KPATCH_SYSCALL_DEFINE3(name, ...) KPATCH_SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define KPATCH_SYSCALL_DEFINE4(name, ...) KPATCH_SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define KPATCH_SYSCALL_DEFINE5(name, ...) KPATCH_SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define KPATCH_SYSCALL_DEFINE6(name, ...) KPATCH_SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)

#define KPATCH_SYSCALL_DEFINEx(x, sname, ...)				\
	KPATCH_SYSCALL_METADATA(sname);					\
	__KPATCH_SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

#ifdef CONFIG_X86_64

/* arch/x86/include/asm/syscall_wrapper.h versions */

# if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)

#  define __KPATCH_SYSCALL_DEFINEx(x, name, ...)			\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	__X64_SYS_STUBx(x, name, __VA_ARGS__)				\
	__IA32_SYS_STUBx(x, name, __VA_ARGS__)				\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __kpatch_do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

# elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)

#  define __KPATCH_SYSCALL_DEFINEx(x, name, ...)			\
	asmlinkage long __x64_sys##name(const struct pt_regs *regs);	\
	ALLOW_ERROR_INJECTION(__x64_sys##name, ERRNO);			\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	asmlinkage long __x64_sys##name(const struct pt_regs *regs)	\
	{								\
		return __se_sys##name(SC_X86_64_REGS_TO_ARGS(x,__VA_ARGS__));\
	}								\
	__IA32_SYS_STUBx(x, name, __VA_ARGS__)				\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __kpatch_do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

# endif /* LINUX_VERSION_CODE */

#elif defined(CONFIG_S390)

/* arch/s390/include/asm/syscall_wrapper.h versions */
# if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)

#define __KPATCH_S390_SYS_STUBx(x, name, ...)                                          \
	long __s390_sys##name(struct pt_regs *regs);                            \
	ALLOW_ERROR_INJECTION(__s390_sys##name, ERRNO);                         \
	static inline long ___se_sys##name(__MAP(x, __SC_LONG, __VA_ARGS__));   \
	long __s390_sys##name(struct pt_regs *regs)                             \
	{                                                                       \
		return ___se_sys##name(SC_S390_REGS_TO_ARGS(x, __VA_ARGS__));   \
	}                                                                       \
	static inline long ___se_sys##name(__MAP(x, __SC_LONG, __VA_ARGS__))    \
	{                                                                       \
		__MAP(x, __SC_TEST, __VA_ARGS__);                               \
		return __kpatch_do_sys##name(__MAP(x, __SC_COMPAT_CAST, __VA_ARGS__)); \
	}

#define __KPATCH_SYSCALL_DEFINEx(x, name, ...)					\
       long __s390x_sys##name(struct pt_regs *regs);                           \
       ALLOW_ERROR_INJECTION(__s390x_sys##name, ERRNO);                        \
       static inline long __se_sys##name(__MAP(x, __SC_LONG, __VA_ARGS__));    \
       static inline long __kpatch_do_sys##name(__MAP(x, __SC_DECL, __VA_ARGS__));    \
       __KPATCH_S390_SYS_STUBx(x, name, __VA_ARGS__);                                 \
       long __s390x_sys##name(struct pt_regs *regs)                            \
       {                                                                       \
               return __se_sys##name(SC_S390_REGS_TO_ARGS(x, __VA_ARGS__));    \
       }                                                                       \
       static inline long __se_sys##name(__MAP(x, __SC_LONG, __VA_ARGS__))     \
       {                                                                       \
               __MAP(x, __SC_TEST, __VA_ARGS__);                               \
               return __kpatch_do_sys##name(__MAP(x, __SC_CAST, __VA_ARGS__));        \
       }                                                                       \
       static inline long __kpatch_do_sys##name(__MAP(x, __SC_DECL, __VA_ARGS__))
# else

#define __KPATCH_S390_SYS_STUBx(x, name, ...)					\
	long __s390_sys##name(struct pt_regs *regs);				\
	ALLOW_ERROR_INJECTION(__s390_sys##name, ERRNO);				\
	long __s390_sys##name(struct pt_regs *regs)				\
	{									\
		long ret = __kpatch_do_sys##name(SYSCALL_PT_ARGS(x, regs,	\
			__SC_COMPAT_CAST, __MAP(x, __SC_TYPE, __VA_ARGS__)));	\
		__MAP(x,__SC_TEST,__VA_ARGS__);					\
		return ret;							\
	}

#define __KPATCH_SYSCALL_DEFINEx(x, name, ...)						\
	__diag_push();									\
	__diag_ignore(GCC, 8, "-Wattribute-alias",					\
		      "Type aliasing is used to sanitize syscall arguments");		\
	long __s390x_sys##name(struct pt_regs *regs)					\
		__attribute__((alias(__stringify(__se_sys##name))));			\
	ALLOW_ERROR_INJECTION(__s390x_sys##name, ERRNO);				\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));	\
	long __se_sys##name(struct pt_regs *regs);					\
	__KPATCH_S390_SYS_STUBx(x, name, __VA_ARGS__)					\
	long __se_sys##name(struct pt_regs *regs)					\
	{										\
		long ret = __kpatch_do_sys##name(SYSCALL_PT_ARGS(x, regs,		\
				    __SC_CAST, __MAP(x, __SC_TYPE, __VA_ARGS__)));	\
		__MAP(x,__SC_TEST,__VA_ARGS__);						\
		return ret;								\
	}										\
	__diag_pop();									\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

#endif /* LINUX_VERSION_CODE */

#elif defined(CONFIG_PPC64)

/* arch/powerpc/include/asm/syscall_wrapper.h versions */

# if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)

#  define __KPATCH_SYSCALL_DEFINEx(x, name, ...)			\
	long sys##name(const struct pt_regs *regs);			\
	ALLOW_ERROR_INJECTION(sys##name, ERRNO);			\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));		\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	__attribute__((optimize("-fno-optimize-sibling-calls")))		\
	long sys##name(const struct pt_regs *regs)			\
	{									\
		return __se_sys##name(SC_POWERPC_REGS_TO_ARGS(x,__VA_ARGS__));	\
	}									\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))		\
	{									\
		long ret = __kpatch_do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);					\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));		\
		return ret;							\
	}									\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

# endif /* LINUX_VERSION_CODE */

#elif defined(CONFIG_ARM64)

/* arm64/include/asm/syscall_wrapper.h versions */

#define SC_ARM64_REGS_TO_ARGS(x, ...)       \
  __MAP(x,__SC_ARGS         \
        ,,regs->regs[0],,regs->regs[1],,regs->regs[2] \
        ,,regs->regs[3],,regs->regs[4],,regs->regs[5])

#define __KPATCH_SYSCALL_DEFINEx(x, name, ...)           \
  asmlinkage long __arm64_sys##name(const struct pt_regs *regs);    \
  ALLOW_ERROR_INJECTION(__arm64_sys##name, ERRNO);      \
  static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));   \
  static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));  \
  asmlinkage long __arm64_sys##name(const struct pt_regs *regs)   \
  {                 \
    return __se_sys##name(SC_ARM64_REGS_TO_ARGS(x,__VA_ARGS__));  \
  }                 \
  static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))    \
  {                 \
    long ret = __kpatch_do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));  \
    __MAP(x,__SC_TEST,__VA_ARGS__);         \
    __PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));   \
    return ret;             \
  }                 \
  static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

#endif /* which arch */


#ifndef __KPATCH_SYSCALL_DEFINEx

/* include/linux/syscalls.h versions */

# if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#  define __KPATCH_SYSCALL_DEFINEx(x, name, ...)			\
	__diag_push();							\
	__diag_ignore(GCC, 8, "-Wattribute-alias",			\
		      "Type aliasing is used to sanitize syscall arguments");\
	asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))	\
		__attribute__((alias(__stringify(__se_sys##name))));	\
	ALLOW_ERROR_INJECTION(sys##name, ERRNO);			\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	asmlinkage long __attribute__((optimize("-fno-optimize-sibling-calls")))\
			__se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __kpatch_do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	__diag_pop();							\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

# elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#  define __KPATCH_SYSCALL_DEFINEx(x, name, ...)			\
	asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))	\
		__attribute__((alias(__stringify(__se_sys##name))));	\
	ALLOW_ERROR_INJECTION(sys##name, ERRNO);			\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	asmlinkage long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __kpatch_do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	static inline long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

# else
#  define __KPATCH_SYSCALL_DEFINEx(x, name, ...)			\
	asmlinkage long sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))	\
		__attribute__((alias(__stringify(SyS##name))));		\
	static inline long __kpatch_SYSC##name(__MAP(x,__SC_DECL,__VA_ARGS__));	\
	asmlinkage long SyS##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	asmlinkage long SyS##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{								\
		long ret = __kpatch_SYSC##name(__MAP(x,__SC_CAST,__VA_ARGS__));	\
		__MAP(x,__SC_TEST,__VA_ARGS__);				\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));	\
		return ret;						\
	}								\
	static inline long __kpatch_SYSC##name(__MAP(x,__SC_DECL,__VA_ARGS__))

# endif

#endif /* __KPATCH_SYSCALL_DEFINEx */

#endif /* __KPATCH_SYSCALL_H_ */
