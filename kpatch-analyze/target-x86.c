#include "symbol.h"
#include "target.h"
#include "machine.h"
#include "builtin.h"


static void predefine_i386(const struct target *self)
{
	predefine("__i386__", 1, "1");
	predefine("__i386", 1, "1");
	predefine_nostd("i386");
}

static void predefine_x86_64(const struct target *self)
{
	predefine("__x86_64__", 1, "1");
	predefine("__x86_64", 1, "1");
	predefine("__amd64__", 1, "1");
	predefine("__amd64", 1, "1");
}


static void init_x86_common(const struct target *target)
{
	switch (arch_os) {
	case OS_CYGWIN:
		wchar_ctype = &ushort_ctype;
		break;
	case OS_FREEBSD:
		wint_ctype = &int_ctype;
		break;
	case OS_OPENBSD:
		size_t_ctype = &ulong_ctype;
		ssize_t_ctype = &long_ctype;
		wchar_ctype = &int_ctype;
		wint_ctype = &int_ctype;
		fast16_ctype = &short_ctype;
		ufast16_ctype = &ushort_ctype;
		break;
	}
}

static const struct builtin_fn builtins_x86_common[] = {
	{ "__builtin_ia32_pause", &void_ctype, 0, },
	{ }
};


static void init_i386(const struct target *target)
{
	fast16_ctype = &int_ctype;
	ufast16_ctype = &uint_ctype;
	fast32_ctype = &int_ctype;
	ufast32_ctype = &uint_ctype;

	init_x86_common(target);
}

const struct target target_i386 = {
	.mach = MACH_I386,
	.bitness = ARCH_LP32,
	.big_endian = 0,
	.unsigned_char = 0,

	.wchar = &long_ctype,
	.bits_in_longdouble = 96,
	.max_fp_alignment = 4,

	.target_64bit = &target_x86_64,

	.init = init_i386,
	.predefine = predefine_i386,
	.builtins = builtins_x86_common,
};


static void init_x86_x32(const struct target *target)
{
	init_x86_common(target);

	max_int_alignment = 8;

	fast16_ctype = &int_ctype;
	ufast16_ctype = &uint_ctype;
	fast32_ctype = &int_ctype;
	ufast32_ctype = &uint_ctype;
	wchar_ctype = &long_ctype;
}

static const struct target target_x86_x32 = {
	.mach = MACH_X86_64,
	.bitness = ARCH_X32,
	.big_endian = 0,
	.unsigned_char = 0,
	.has_int128 = 1,

	.bits_in_longdouble = 128,
	.max_fp_alignment = 16,

	.target_32bit = &target_i386,
	.target_64bit = &target_x86_64,

	.init = init_x86_x32,
	.predefine = predefine_x86_64,
};


static void init_x86_64(const struct target *target)
{
	init_x86_common(target);

	switch (arch_os) {
	case OS_CYGWIN:
		break;
	case OS_DARWIN:
		int64_ctype = &llong_ctype;
		uint64_ctype = &ullong_ctype;
		wint_ctype = &int_ctype;
		fast16_ctype = &short_ctype;
		ufast16_ctype = &ushort_ctype;
		fast32_ctype = &int_ctype;
		ufast32_ctype = &uint_ctype;
		fast64_ctype = &llong_ctype;
		ufast64_ctype = &ullong_ctype;
		break;
	case OS_FREEBSD:
		fast16_ctype = &short_ctype;
		ufast16_ctype = &ushort_ctype;
		fast32_ctype = &int_ctype;
		ufast32_ctype = &uint_ctype;
		break;
	case OS_NETBSD:
		fast8_ctype = &int_ctype;
		ufast8_ctype = &uint_ctype;
		fast16_ctype = &int_ctype;
		ufast16_ctype = &uint_ctype;
		fast32_ctype = &int_ctype;
		ufast32_ctype = &uint_ctype;
		wint_ctype = &int_ctype;
		break;
	case OS_OPENBSD:
		fast32_ctype = &int_ctype;
		ufast32_ctype = &uint_ctype;
		int64_ctype = &llong_ctype;
		uint64_ctype = &ullong_ctype;
		intmax_ctype = &llong_ctype;
		uintmax_ctype = &ullong_ctype;
		least64_ctype = &long_ctype;
		uleast64_ctype = &ulong_ctype;
		break;
	}
}

const struct target target_x86_64 = {
	.mach = MACH_X86_64,
	.bitness = ARCH_LP64,
	.big_endian = 0,
	.unsigned_char = 0,
	.has_int128 = 1,

	.bits_in_longdouble = 128,
	.max_fp_alignment = 16,

	.target_32bit = &target_i386,
	.target_x32bit = &target_x86_x32,

	.init = init_x86_64,
	.predefine = predefine_x86_64,
	.builtins = builtins_x86_common,
};
