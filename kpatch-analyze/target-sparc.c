#include "symbol.h"
#include "target.h"
#include "machine.h"


static int sparc_version;

static void predefine_sparc(const struct target *self)
{
	predefine("__sparc__", 1, "1");
	predefine("__sparc", 1, "1");
	predefine_nostd("sparc");

	predefine_weak("__sparc_v%d__", sparc_version);
	predefine_weak("__sparcv%d__", sparc_version);
	predefine_weak("__sparcv%d", sparc_version);
}


static void init_sparc32(const struct target *target)
{
	fast16_ctype = &int_ctype;
	ufast16_ctype = &uint_ctype;
	fast32_ctype = &int_ctype;
	ufast32_ctype = &uint_ctype;

	if (!sparc_version)
		sparc_version = 8;

	if (arch_os == OS_SUNOS) {
		wint_ctype = &long_ctype;
		wchar_ctype = &long_ctype;

		bits_in_longdouble = 128;
		max_fp_alignment = 16;

		funsigned_char = 0;
	}
}

static void predefine_sparc32(const struct target *self)
{
	predefine_sparc(self);
}

const struct target target_sparc32 = {
	.mach = MACH_SPARC32,
	.bitness = ARCH_LP32,
	.big_endian = 1,
	.unsigned_char = 0,

	.bits_in_longdouble = 64,
	.max_fp_alignment = 8,

	.init = init_sparc32,
	.target_64bit = &target_sparc64,

	.predefine = predefine_sparc32,
};


static void init_sparc64(const struct target *target)
{
	if (!sparc_version)
		sparc_version = 9;
}

static void predefine_sparc64(const struct target *self)
{
	predefine("__sparc64__", 1, "1");
	predefine("__arch64__", 1, "1");

	predefine_sparc(self);
}

const struct target target_sparc64 = {
	.mach = MACH_SPARC64,
	.bitness = ARCH_LP64,
	.big_endian = 1,
	.unsigned_char = 0,
	.has_int128 = 1,

	.target_32bit = &target_sparc32,

	.init = init_sparc64,
	.predefine = predefine_sparc64,
};
