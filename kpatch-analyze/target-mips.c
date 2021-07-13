#include "symbol.h"
#include "target.h"
#include "machine.h"


static void predefine_mips(const struct target *self)
{
	predefine("__mips__", 1, "1");
	predefine("__mips", 1, "%d", ptr_ctype.bit_size);
	predefine("_MIPS_SZINT", 1, "%d", int_ctype.bit_size);
	predefine("_MIPS_SZLONG", 1, "%d", long_ctype.bit_size);
	predefine("_MIPS_SZPTR", 1, "%d", ptr_ctype.bit_size);

	if (arch_big_endian) {
		predefine("_MIPSEB", 1, "1");
		predefine("__MIPSEB", 1, "1");
		predefine("__MIPSEB__", 1, "1");
	} else {
		predefine("_MIPSEL", 1, "1");
		predefine("__MIPSEL", 1, "1");
		predefine("__MIPSEL__", 1, "1");
	}
}


static void predefine_mips32(const struct target *self)
{
	predefine_mips(self);
}

const struct target target_mips32 = {
	.mach = MACH_MIPS32,
	.bitness = ARCH_LP32,
	.big_endian = 1,
	.unsigned_char = 0,

	.bits_in_longdouble = 64,
	.max_fp_alignment = 8,

	.target_64bit = &target_mips64,

	.predefine = predefine_mips32,
};


static void predefine_mips64(const struct target *self)
{
	predefine("__mips64", 1, "64");

	predefine_mips(self);
}

const struct target target_mips64 = {
	.mach = MACH_MIPS64,
	.bitness = ARCH_LP64,
	.big_endian = 1,
	.unsigned_char = 0,
	.has_int128 = 1,

	.target_32bit = &target_mips32,

	.predefine = predefine_mips64,
};
