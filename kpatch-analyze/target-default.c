#include "symbol.h"
#include "target.h"
#include "machine.h"


const struct target target_default = {
	.mach = MACH_UNKNOWN,
	.bitness = ARCH_LP64,
	.big_endian = 0,
	.unsigned_char = 0,
};
