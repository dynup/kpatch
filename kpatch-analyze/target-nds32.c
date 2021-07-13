#include "symbol.h"
#include "target.h"
#include "machine.h"


static void init_nds32(const struct target *self)
{
	fast16_ctype = &int_ctype;
	ufast16_ctype = &uint_ctype;
	fast32_ctype = &int_ctype;
	ufast32_ctype = &uint_ctype;

	wchar_ctype = &uint_ctype;
}

static void predefine_nds32(const struct target *self)
{
	predefine("__NDS32__", 1, "1");
	predefine("__nds32__", 1, "1");

	predefine_weak("__NDS32_E%c__", arch_big_endian ? 'B' : 'L');
}

const struct target target_nds32 = {
	.mach = MACH_NDS32,
	.bitness = ARCH_LP32,
	.big_endian = false,

	.bits_in_longdouble = 64,

	.init = init_nds32,
	.predefine = predefine_nds32,
};
