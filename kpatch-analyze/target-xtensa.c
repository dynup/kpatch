#include "symbol.h"
#include "target.h"
#include "machine.h"


static void init_xtensa(const struct target *self)
{
	fast16_ctype = &int_ctype;
	ufast16_ctype = &uint_ctype;
	fast32_ctype = &int_ctype;
	ufast32_ctype = &uint_ctype;

	wchar_ctype = &long_ctype;
}

static void predefine_xtensa(const struct target *self)
{
	predefine("__XTENSA__", 1, "1");
	predefine("__xtensa__", 1, "1");
}

const struct target target_xtensa = {
	.mach = MACH_XTENSA,
	.bitness = ARCH_LP32,
	.big_endian = true,

	.bits_in_longdouble = 64,

	.init = init_xtensa,
	.predefine = predefine_xtensa,
};
