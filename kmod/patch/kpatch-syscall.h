#ifndef __KPATCH_SYSCALL_H_
#define __KPATCH_SYSCALL_H_

#include "kpatch-macros.h"

#define KPATCH_IGNORE_SYSCALL_SECTIONS					\
	KPATCH_IGNORE_SECTION("__syscalls_metadata");			\
	KPATCH_IGNORE_SECTION("_ftrace_events")

#define KPATCH_SYSCALL_DEFINE1(name, ...) KPATCH_SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define KPATCH_SYSCALL_DEFINE2(name, ...) KPATCH_SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define KPATCH_SYSCALL_DEFINE3(name, ...) KPATCH_SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define KPATCH_SYSCALL_DEFINE4(name, ...) KPATCH_SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define KPATCH_SYSCALL_DEFINE5(name, ...) KPATCH_SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define KPATCH_SYSCALL_DEFINE6(name, ...) KPATCH_SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)

#ifdef __x86_64__

#define KPATCH_SYSCALL_DEFINEx(x, sname, ...)				\
	KPATCH_IGNORE_SYSCALL_SECTIONS;					\
	__KPATCH_SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

#define __KPATCH_SYSCALL_DEFINEx(x, name, ...)				\
	asmlinkage long __x64_sys##name(const struct pt_regs *regs);	\
	ALLOW_ERROR_INJECTION(__x64_sys##name, ERRNO);			\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	static long __kpatch_do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
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

#else /* !__x86_64__ */

#define KPATCH_SYSCALL_DEFINEx(x, sname, ...) SYSCALL_DEFINEx(x, sname, __VA_ARGS__)

#endif /* __x86_64__ */

#endif /* __KPATCH_SYSCALL_H_ */
