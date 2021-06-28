#include "lib.h"
#include "symbol.h"
#include "target.h"
#include "machine.h"
#include <string.h>

#define RISCV_32BIT	(1 << 0)
#define RISCV_64BIT	(1 << 1)
#define RISCV_MUL	(1 << 2)
#define RISCV_DIV	(1 << 3)
#define RISCV_ATOMIC	(1 << 4)
#define RISCV_FLOAT	(1 << 5)
#define RISCV_DOUBLE	(1 << 6)
#define RISCV_FDIV	(1 << 7)
#define RISCV_COMP	(1 << 8)
#define RISCV_EMBD	(1 << 9)
#define RISCV_FPU	(RISCV_FLOAT|RISCV_DOUBLE|RISCV_FDIV)
#define RISCV_GENERIC	(RISCV_MUL|RISCV_DIV|RISCV_ATOMIC|RISCV_FPU)

static unsigned int riscv_flags;

static void parse_march_riscv(const char *arg)
{
	static struct {
		const char *pattern;
		unsigned int flags;
	} basic_sets[] = {
		{ "rv32i",	RISCV_32BIT },
		{ "rv32e",	RISCV_32BIT|RISCV_EMBD },
		{ "rv32g",	RISCV_32BIT|RISCV_GENERIC },
		{ "rv64i",	RISCV_64BIT },
		{ "rv64g",	RISCV_64BIT|RISCV_GENERIC },
	}, extensions[] = {
		{ "m",		RISCV_MUL|RISCV_DIV },
		{ "a",		RISCV_ATOMIC },
		{ "f",		RISCV_FLOAT|RISCV_FDIV },
		{ "d",		RISCV_DOUBLE|RISCV_FDIV },
		{ "g",		RISCV_GENERIC },
		{ "q",		0 },
		{ "l",		0 },
		{ "c",		RISCV_COMP },
		{ "b",		0 },
		{ "j",		0 },
		{ "t",		0 },
		{ "p",		0 },
		{ "v",		0 },
		{ "n",		0 },
		{ "h",		0 },
		{ "s",		0 },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(basic_sets); i++) {
		const char *pat = basic_sets[i].pattern;
		size_t len = strlen(pat);

		if (!strncmp(arg, pat, len)) {
			riscv_flags |= basic_sets[i].flags;
			arg += len;
			goto ext;
		}
	}
	die("invalid argument to '-march': '%s'\n", arg);

ext:
	for (i = 0; i < ARRAY_SIZE(extensions); i++) {
		const char *pat = extensions[i].pattern;
		size_t len = strlen(pat);

		if (!strncmp(arg, pat, len)) {
			riscv_flags |= extensions[i].flags;
			arg += len;
		}
	}
	if (arg[0])
		die("invalid argument to '-march': '%s'\n", arg);
}

static void init_riscv(const struct target *self)
{
	if (arch_cmodel == CMODEL_UNKNOWN)
		arch_cmodel = CMODEL_MEDLOW;
	if (fpic)
		arch_cmodel = CMODEL_PIC;

	if (riscv_flags == 0)
		riscv_flags = self->flags;
}

static void init_riscv32(const struct target *self)
{
	fast16_ctype = &int_ctype;
	ufast16_ctype = &uint_ctype;
	fast32_ctype = &int_ctype;
	ufast32_ctype = &uint_ctype;

	init_riscv(self);
}

static void predefine_riscv(const struct target *self)
{
	static const char *cmodels[CMODEL_LAST] = {
		[CMODEL_MEDANY] = "medany",
		[CMODEL_MEDLOW] = "medlow",
		[CMODEL_PIC]    = "pic",
	};
	const char *cmodel = cmodels[arch_cmodel];

	predefine("__riscv", 1, "1");
	predefine("__riscv_xlen", 1, "%d", ptr_ctype.bit_size);

	if (riscv_flags & RISCV_ATOMIC)
		predefine("__riscv_atomic", 1, "1");
	if (riscv_flags & RISCV_COMP)
		predefine("__riscv_compressed", 1, "1");
	if (riscv_flags & RISCV_DIV)
		predefine("__riscv_div", 1, "1");
	if (riscv_flags & RISCV_EMBD)
		predefine("__riscv_32e", 1, "1");
	if (riscv_flags & RISCV_FPU)
		predefine("__riscv_flen", 1, "%d", (riscv_flags & RISCV_DOUBLE) ? 64 : 32);
	if (riscv_flags & RISCV_FDIV)
		predefine("__riscv_fdiv", 1, "1");
	if (riscv_flags & RISCV_FDIV)
		predefine("__riscv_fsqrt", 1, "1");
	if (riscv_flags & RISCV_MUL)
		predefine("__riscv_mul", 1, "1");
	if ((riscv_flags & RISCV_MUL) && (riscv_flags & RISCV_DIV))
		predefine("__riscv_muldiv", 1, "1");

	if (cmodel)
		predefine_strong("__riscv_cmodel_%s", cmodel);
}

const struct target target_riscv32 = {
	.mach = MACH_RISCV32,
	.bitness = ARCH_LP32,
	.big_endian = 0,
	.unsigned_char = 1,
	.flags = RISCV_32BIT|RISCV_GENERIC|RISCV_COMP,

	.target_64bit = &target_riscv64,

	.init = init_riscv32,
	.predefine = predefine_riscv,
	.parse_march = parse_march_riscv,
};

const struct target target_riscv64 = {
	.mach = MACH_RISCV64,
	.bitness = ARCH_LP64,
	.big_endian = 0,
	.unsigned_char = 1,
	.has_int128 = 1,
	.flags = RISCV_64BIT|RISCV_GENERIC|RISCV_COMP,

	.target_32bit = &target_riscv32,

	.init = init_riscv,
	.predefine = predefine_riscv,
	.parse_march = parse_march_riscv,
};
