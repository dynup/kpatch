#ifndef MACHINE_H
#define MACHINE_H

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define ARCH_BIG_ENDIAN 1
#else
#define ARCH_BIG_ENDIAN 0
#endif


enum bitness {
	ARCH_LP32,
	ARCH_X32,
	ARCH_LP64,
	ARCH_LLP64,
};

#ifdef __LP64__
#define ARCH_M64_DEFAULT ARCH_LP64
#elif defined(__x86_64__) || defined(__x86_64)
#define ARCH_M64_DEFAULT ARCH_X32
#else
#define ARCH_M64_DEFAULT ARCH_LP32
#endif


enum machine {
	MACH_ARM,	MACH_ARM64,
	MACH_I386,	MACH_X86_64,
	MACH_MIPS32,	MACH_MIPS64,
	MACH_PPC32,	MACH_PPC64,
	MACH_RISCV32,	MACH_RISCV64,
	MACH_SPARC32,	MACH_SPARC64,
	MACH_S390,	MACH_S390X,
	MACH_ALPHA,
	MACH_BFIN,
	MACH_H8300,
	MACH_M68K,
	MACH_MICROBLAZE,
	MACH_NDS32,
	MACH_NIOS2,
	MACH_OPENRISC,
	MACH_SH,
	MACH_XTENSA,
	MACH_UNKNOWN
};

#if defined(__aarch64__)
#define MACH_NATIVE	MACH_ARM64
#elif defined(__alpha__) || defined(__alpha)
#define	MACH_NATIVE	MACH_ALPHA
#elif defined(__arm__)
#define	MACH_NATIVE	MACH_ARM
#elif defined(__x86_64__) || defined(__x86_64)
#define	MACH_NATIVE	MACH_X86_64
#elif defined(__i386__) || defined(__i386)
#define	MACH_NATIVE	MACH_I386
#elif defined(__mips64__) || (defined(__mips) && __mips == 64)
#define	MACH_NATIVE	MACH_MIPS64
#elif defined(__mips__) || defined(__mips)
#define	MACH_NATIVE	MACH_MIPS32
#elif defined(__powerpc64__) || defined(__ppc64__)
#define	MACH_NATIVE	MACH_PPC64
#elif defined(__powerpc__) || defined(__powerpc) || defined(__ppc__)
#define	MACH_NATIVE	MACH_PPC32
#elif defined(__riscv) && (__riscv_xlen == 64)
#define	MACH_NATIVE	MACH_RISCV64
#elif defined(__riscv) && (__riscv_xlen == 32)
#define	MACH_NATIVE	MACH_RISCV32
#elif defined(__sparc_v9__) || defined(__sparcv9)
#define	MACH_NATIVE	MACH_SPARC64
#elif defined(__sparc__) || defined(__sparc)
#define	MACH_NATIVE	MACH_SPARC32
#elif defined(__m68k__)
#define MACH_NATIVE	MACH_M68K
#elif defined(__s390x__) || defined(__zarch__)
#define MACH_NATIVE	MACH_S390X
#elif defined(__s390__)
#define MACH_NATIVE	MACH_S390
#else
#define MACH_NATIVE	MACH_UNKNOWN
#endif


enum fp_abi {
	FP_ABI_HARD,
	FP_ABI_SOFT,
	FP_ABI_HYBRID,
};

#if defined(__ARM_PCS_VFP)
#define FP_ABI_NATIVE		FP_ABI_HARD
#elif defined(__ARM_PCS) && !defined(__SOFTFP__)
#define FP_ABI_NATIVE		FP_ABI_HYBRID
#else
#define FP_ABI_NATIVE		FP_ABI_SOFT
#endif


enum {
	OS_UNKNOWN,
	OS_NONE,
	OS_UNIX,
	OS_CYGWIN,
	OS_DARWIN,
	OS_FREEBSD,
	OS_LINUX,
	OS_NETBSD,
	OS_OPENBSD,
	OS_SUNOS,
};

#if defined(__CYGWIN__)
#define OS_NATIVE	OS_CYGWIN
#elif defined(__APPLE__)
#define OS_NATIVE	OS_DARWIN
#elif defined(__FreeBSD__)
#define OS_NATIVE	OS_FREEBSD
#elif defined(__linux__) || defined(__linux)
#define OS_NATIVE	OS_LINUX
#elif defined(__NetBSD__)
#define OS_NATIVE	OS_NETBSD
#elif defined(__OpenBSD__)
#define OS_NATIVE	OS_OPENBSD
#elif defined(__sun__) || defined(__sun)
#define OS_NATIVE	OS_SUNOS
#elif defined(__unix__) || defined(__unix)
#define OS_NATIVE	OS_UNIX
#else
#define OS_NATIVE	OS_UNKNOWN
#endif

#endif
