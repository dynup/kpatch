#include <stdio.h>
#include <string.h>

#include "symbol.h"
#include "target.h"
#include "machine.h"

struct symbol *ptrdiff_ctype;
struct symbol *intptr_ctype;
struct symbol *uintptr_ctype;
struct symbol *size_t_ctype = &ulong_ctype;
struct symbol *ssize_t_ctype = &long_ctype;
struct symbol *intmax_ctype = &long_ctype;
struct symbol *uintmax_ctype = &ulong_ctype;
struct symbol *int64_ctype = &long_ctype;
struct symbol *uint64_ctype = &ulong_ctype;
struct symbol *int32_ctype = &int_ctype;
struct symbol *uint32_ctype = &uint_ctype;
struct symbol *wchar_ctype = &int_ctype;
struct symbol *wint_ctype = &uint_ctype;
struct symbol *least8_ctype = &schar_ctype;
struct symbol *uleast8_ctype = &uchar_ctype;
struct symbol *least16_ctype = &short_ctype;
struct symbol *uleast16_ctype = &ushort_ctype;
struct symbol *least32_ctype = &int_ctype;
struct symbol *uleast32_ctype = &uint_ctype;
struct symbol *least64_ctype = &llong_ctype;
struct symbol *uleast64_ctype = &ullong_ctype;
struct symbol *fast8_ctype = &schar_ctype;
struct symbol *ufast8_ctype = &uchar_ctype;
struct symbol *fast16_ctype = &long_ctype;
struct symbol *ufast16_ctype = &ulong_ctype;
struct symbol *fast32_ctype = &long_ctype;
struct symbol *ufast32_ctype = &ulong_ctype;
struct symbol *fast64_ctype = &long_ctype;
struct symbol *ufast64_ctype = &ulong_ctype;
struct symbol *sig_atomic_ctype = &int_ctype;

/*
 * For "__attribute__((aligned))"
 */
int max_alignment = 16;

/*
 * Integer data types
 */
int bits_in_bool = 1;
int bits_in_char = 8;
int bits_in_short = 16;
int bits_in_int = 32;
int bits_in_long = 64;
int bits_in_longlong = 64;
int bits_in_longlonglong = 128;

int max_int_alignment = 8;

/*
 * Floating point data types
 */
int bits_in_float = 32;
int bits_in_double = 64;
int bits_in_longdouble = 128;

int max_fp_alignment = 16;

/*
 * Pointer data type
 */
int bits_in_pointer = 64;
int pointer_alignment = 8;

/*
 * Enum data types
 */
int bits_in_enum = 32;
int enum_alignment = 4;


static const struct target *targets[] = {
	[MACH_ALPHA] =		&target_alpha,
	[MACH_ARM] =		&target_arm,
	[MACH_ARM64] =		&target_arm64,
	[MACH_BFIN] =		&target_bfin,
	[MACH_H8300] =		&target_h8300,
	[MACH_I386] =		&target_i386,
	[MACH_M68K] =		&target_m68k,
	[MACH_MICROBLAZE] =	&target_microblaze,
	[MACH_MIPS32] =		&target_mips32,
	[MACH_MIPS64] =		&target_mips64,
	[MACH_NDS32] =		&target_nds32,
	[MACH_NIOS2] =		&target_nios2,
	[MACH_OPENRISC] =	&target_openrisc,
	[MACH_PPC32] =		&target_ppc32,
	[MACH_PPC64] =		&target_ppc64,
	[MACH_RISCV32] =	&target_riscv32,
	[MACH_RISCV64] =	&target_riscv64,
	[MACH_S390] =		&target_s390,
	[MACH_S390X] =		&target_s390x,
	[MACH_SH] =		&target_sh,
	[MACH_SPARC32] =	&target_sparc32,
	[MACH_SPARC64] =	&target_sparc64,
	[MACH_X86_64] =		&target_x86_64,
	[MACH_XTENSA] =		&target_xtensa,
	[MACH_UNKNOWN] =	&target_default,
};
const struct target *arch_target = &target_default;

enum machine target_parse(const char *name)
{
	static const struct arch {
		const char *name;
		enum machine mach;
		char bits;
	} archs[] = {
		{ "alpha",	MACH_ALPHA,	64, },
		{ "aarch64",	MACH_ARM64,	64, },
		{ "arm64",	MACH_ARM64,	64, },
		{ "arm",	MACH_ARM,	32, },
		{ "bfin",	MACH_BFIN,	32, },
		{ "h8300",	MACH_H8300,	32, },
		{ "i386",	MACH_I386,	32, },
		{ "m68k",	MACH_M68K,	32, },
		{ "microblaze",	MACH_MICROBLAZE,32, },
		{ "mips",	MACH_MIPS32,	0,  },
		{ "nds32",	MACH_NDS32,	32, },
		{ "nios2",	MACH_NIOS2,	32, },
		{ "openrisc",	MACH_OPENRISC,	32, },
		{ "powerpc",	MACH_PPC32,	0,  },
		{ "ppc",	MACH_PPC32,	0,  },
		{ "riscv",	MACH_RISCV32,	0,  },
		{ "s390x",	MACH_S390X,	64, },
		{ "s390",	MACH_S390,	32, },
		{ "sparc",	MACH_SPARC32,	0,  },
		{ "x86_64",	MACH_X86_64,	64, },
		{ "x86-64",	MACH_X86_64,	64, },
		{ "sh",		MACH_SH,	32, },
		{ "xtensa",	MACH_XTENSA,	32, },
		{ NULL },
	};
	const struct arch *p;

	for (p = &archs[0]; p->name; p++) {
		size_t len = strlen(p->name);
		if (strncmp(p->name, name, len) == 0) {
			enum machine mach = p->mach;
			const char *suf = name + len;
			int bits = p->bits;

			if (bits == 0) {
				if (!strcmp(suf, "") || !strcmp(suf, "32")) {
					;
				} else if (!strcmp(suf, "64")) {
					mach += 1;
				} else {
					die("invalid architecture: %s", name);
				}
			} else {
				if (strcmp(suf, ""))
					die("invalid architecture: %s", name);
			}

			return mach;
		}
	}

	return MACH_UNKNOWN;
}

void target_os(const char *name)
{
	static const struct os {
		const char *name;
		int os;
	} oses[] = {
		{ "cygwin",	OS_CYGWIN },
		{ "darwin",	OS_DARWIN },
		{ "freebsd",	OS_FREEBSD },
		{ "linux",	OS_LINUX },
		{ "native",	OS_NATIVE, },
		{ "netbsd",	OS_NETBSD },
		{ "none",	OS_NONE },
		{ "openbsd",	OS_OPENBSD },
		{ "sunos",	OS_SUNOS },
		{ "unix",	OS_UNIX },
		{ NULL },
	}, *p;

	for (p = &oses[0]; p->name; p++) {
		if (!strcmp(p->name, name)) {
			arch_os = p->os;
			return;
		}
	}

	die("invalid os: %s", name);
}


void target_config(enum machine mach)
{
	const struct target *target = targets[mach];

	arch_target = target;
	arch_m64 = target->bitness;
	arch_big_endian = target->big_endian;

	funsigned_char = target->unsigned_char;
}


void target_init(void)
{
	const struct target *target = arch_target;

	switch (arch_m64) {
	case ARCH_X32:
		if (target->target_x32bit)
			target = target->target_x32bit;
		goto case_32bit;

	case ARCH_LP32:
		max_int_alignment = 4;
		if (target->target_32bit)
			target = target->target_32bit;
		/* fallthrough */
	case_32bit:
		bits_in_long = 32;
		bits_in_pointer = 32;
		pointer_alignment = 4;
		size_t_ctype = &uint_ctype;
		ssize_t_ctype = &int_ctype;
		int64_ctype = &llong_ctype;
		uint64_ctype = &ullong_ctype;
		intmax_ctype = &llong_ctype;
		uintmax_ctype = &ullong_ctype;
		fast64_ctype = &llong_ctype;
		ufast64_ctype = &ullong_ctype;
		break;

	case ARCH_LLP64:
		bits_in_long = 32;
		size_t_ctype = &ullong_ctype;
		ssize_t_ctype = &llong_ctype;
		int64_ctype = &llong_ctype;
		uint64_ctype = &ullong_ctype;
		intmax_ctype = &llong_ctype;
		uintmax_ctype = &ullong_ctype;
		/* fallthrough */
	case ARCH_LP64:
		if (target->target_64bit)
			target = target->target_64bit;
		break;
	}
	arch_target = target;

	if (fpie > fpic)
		fpic = fpie;

	if (target->wchar)
		wchar_ctype = target->wchar;
	if (target->wint)
		wint_ctype = target->wint;
	if (target->bits_in_longdouble)
		bits_in_longdouble = target->bits_in_longdouble;
	if (target->max_fp_alignment)
		max_fp_alignment = target->max_fp_alignment;

	if (target->init)
		target->init(target);

	if (arch_msize_long || target->size_t_long) {
		size_t_ctype = &ulong_ctype;
		ssize_t_ctype = &long_ctype;
	}
	if (fshort_wchar)
		wchar_ctype = &ushort_ctype;
}
