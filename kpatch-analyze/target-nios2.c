#include "symbol.h"
#include "target.h"
#include "machine.h"
#include "builtin.h"


static void init_nios2(const struct target *self)
{
	fast16_ctype = &int_ctype;
	ufast16_ctype = &uint_ctype;
	fast32_ctype = &int_ctype;
	ufast32_ctype = &uint_ctype;
}

static void predefine_nios2(const struct target *self)
{
	predefine("__NIOS2", 1, "1");
	predefine("__NIOS2__", 1, "1");
	predefine("__nios2", 1, "1");
	predefine("__nios2__", 1, "1");

	if (arch_big_endian) {
		predefine("__nios2_big_endian", 1, "1");
		predefine("__nios2_big_endian__", 1, "1");
	} else {
		predefine("__nios2_little_endian", 1, "1");
		predefine("__nios2_little_endian__", 1, "1");
	}
}

static const struct builtin_fn builtins_nios2[] = {
	{ "__builtin_rdctl", &int_ctype, 0, { &int_ctype }},
	{ "__builtin_wrctl", &void_ctype, 0, { &int_ctype, &int_ctype }},
	{ "__builtin_custom_ini", &int_ctype, 0, { &int_ctype }},
	{ }
};

const struct target target_nios2 = {
	.mach = MACH_NIOS2,
	.bitness = ARCH_LP32,

	.bits_in_longdouble = 64,

	.init = init_nios2,
	.predefine = predefine_nios2,
	.builtins = builtins_nios2,
};
