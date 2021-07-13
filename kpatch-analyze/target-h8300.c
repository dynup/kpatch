#include "symbol.h"
#include "target.h"
#include "machine.h"


static void init_h8300(const struct target *self)
{
	intptr_ctype = &int_ctype;
	uintptr_ctype = &uint_ctype;
	ssize_t_ctype = &long_ctype;
	size_t_ctype = &ulong_ctype;
	wchar_ctype = &ushort_ctype;

	fast16_ctype = &int_ctype;
	ufast16_ctype = &uint_ctype;
	fast32_ctype = &int_ctype;
	ufast32_ctype = &uint_ctype;
}

static void predefine_h8300(const struct target *self)
{
	predefine("__H8300H__", 1, "1");
}

const struct target target_h8300 = {
	.mach = MACH_H8300,
	.bitness = ARCH_LP32,
	.big_endian = true,

	.bits_in_longdouble = 64,

	.init = init_h8300,
	.predefine = predefine_h8300,
};
