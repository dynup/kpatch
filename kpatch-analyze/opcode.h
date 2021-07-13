#ifndef OPCODE_H
#define OPCODE_H

#include "symbol.h"

enum opcode {
#define OPCODE(OP,NG,SW,SG,TF,N,FL)  OP_##OP,
#define OPCODE_RANGE(OP,S,E)	OP_##OP = OP_##S, OP_##OP##_END = OP_##E,
#include "opcode.def"
#undef  OPCODE
#undef  OPCODE_RANGE
	OP_LAST,			/* keep this one last! */
};

extern const struct opcode_table {
	int	negate:8;
	int	swap:8;
	int	sign:8;
	int	to_float:8;
	unsigned int arity:2;
	unsigned int :6;
	unsigned int flags:8;
#define			OPF_NONE	0
#define			OPF_TARGET	(1 << 0)
#define			OPF_COMMU	(1 << 1)
#define			OPF_ASSOC	(1 << 2)
#define			OPF_UNOP	(1 << 3)
#define			OPF_BINOP	(1 << 4)
#define			OPF_COMPARE	(1 << 5)
#define			OPF_SIGNED	(1 << 6)
#define			OPF_UNSIGNED	(1 << 7)
} opcode_table[];


static inline int opcode_negate(int opcode)
{
	return opcode_table[opcode].negate;
}

static inline int opcode_swap(int opcode)
{
	return opcode_table[opcode].swap;
}

static inline int opcode_float(int opcode, struct symbol *type)
{
	if (!type || !is_float_type(type))
		return opcode;
	return opcode_table[opcode].to_float;
}

#endif
