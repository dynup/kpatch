#include "symbol.h"
#include "target.h"
#include "machine.h"
#include "expression.h"


static void init_s390(const struct target *self)
{
	intptr_ctype = &int_ctype;
	uintptr_ctype = &uint_ctype;

	fast16_ctype = &int_ctype;
	ufast16_ctype = &uint_ctype;
	fast32_ctype = &int_ctype;
	ufast32_ctype = &uint_ctype;
}

static void predefine_s390(const struct target *self)
{
	predefine("__s390__", 1, "1");
}

static const char *asm_constraint_s390(struct asm_operand *op, int c, const char *str)
{
	switch (c) {
	case 'R': case 'S': case 'T':
		op->is_memory = true;
		break;
	}
	return str;
}

const struct target target_s390 = {
	.mach = MACH_S390,
	.bitness = ARCH_LP32,
	.big_endian = 1,
	.unsigned_char = 1,
	.size_t_long = 1,

	.bits_in_longdouble = 64,
	.max_fp_alignment = 8,

	.target_64bit = &target_s390x,

	.init = init_s390,
	.predefine = predefine_s390,
	.asm_constraint = asm_constraint_s390,
};


static void predefine_s390x(const struct target *self)
{
	predefine("__zarch__", 1, "1");
	predefine("__s390x__", 1, "1");

	predefine_s390(self);
}

const struct target target_s390x = {
	.mach = MACH_S390X,
	.bitness = ARCH_LP64,
	.big_endian = 1,
	.unsigned_char = 1,
	.has_int128 = 1,

	.bits_in_longdouble = 64,
	.max_fp_alignment = 8,

	.target_32bit = &target_s390,

	.predefine = predefine_s390x,
	.asm_constraint = asm_constraint_s390,
};
