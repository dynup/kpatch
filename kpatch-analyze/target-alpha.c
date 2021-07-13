#include "symbol.h"
#include "target.h"
#include "machine.h"
#include "builtin.h"


static void predefine_alpha(const struct target *self)
{
	predefine("__alpha__", 1, "1");
	predefine("__alpha", 1, "1");
}

static const struct builtin_fn builtins_alpha[] = {
	{ "__builtin_alpha_cmpbge", &long_ctype, 0, { &long_ctype, &long_ctype }},
	{ "__builtin_alpha_extbl", &long_ctype, 0, { &long_ctype, &long_ctype }},
	{ "__builtin_alpha_extwl", &long_ctype, 0, { &long_ctype, &long_ctype }},
	{ "__builtin_alpha_insbl", &long_ctype, 0, { &long_ctype, &long_ctype }},
	{ "__builtin_alpha_inslh", &long_ctype, 0, { &long_ctype, &long_ctype }},
	{ "__builtin_alpha_insql", &long_ctype, 0, { &long_ctype, &long_ctype }},
	{ "__builtin_alpha_inswl", &long_ctype, 0, { &long_ctype, &long_ctype }},
	{ }
};

const struct target target_alpha = {
	.mach = MACH_ALPHA,
	.bitness = ARCH_LP64,
	.has_int128 = 1,

	.bits_in_longdouble = 64,

	.predefine = predefine_alpha,
	.builtins = builtins_alpha,
};
