#include "symbol.h"
#include "target.h"
#include "machine.h"


static void init_sh(const struct target *self)
{
	int64_ctype = &llong_ctype;
	uint64_ctype = &ullong_ctype;
	intptr_ctype = &int_ctype;
	uintptr_ctype = &uint_ctype;

	fast16_ctype = &int_ctype;
	ufast16_ctype = &uint_ctype;
	fast32_ctype = &int_ctype;
	ufast32_ctype = &uint_ctype;

	wchar_ctype = &long_ctype;
}

static void predefine_sh(const struct target *self)
{
	predefine_weak("__SH4__");
	predefine_weak("__sh__");
}

const struct target target_sh = {
	.mach = MACH_SH,
	.bitness = ARCH_LP32,
	.big_endian = false,

	.bits_in_longdouble = 64,

	.init = init_sh,
	.predefine = predefine_sh,
};
