#include "symbol.h"
#include "target.h"
#include "machine.h"
#include "builtin.h"


static void predefine_bfin(const struct target *self)
{
	predefine("__BFIN__", 1, "1");
	predefine("__bfin__", 1, "1");
}

static const struct builtin_fn builtins_bfin[] = {
	{ "__builtin_bfin_csync", &void_ctype, 0 },
	{ "__builtin_bfin_ssync", &void_ctype, 0 },
	{ "__builtin_bfin_norm_fr1x32", &int_ctype, 0, { &int_ctype }},
	{ }
};

const struct target target_bfin = {
	.mach = MACH_BFIN,
	.bitness = ARCH_LP32,

	.predefine = predefine_bfin,
	.builtins = builtins_bfin,
};
