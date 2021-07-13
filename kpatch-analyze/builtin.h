#ifndef _BUILTIN_H_
#define _BUILTIN_H_

#include "symbol.h"

struct builtin_fn {
	const char *name;
	struct symbol *ret_type;
	unsigned int variadic:1;
	struct symbol *args[6];
	struct symbol *_args_null_tail;
	struct symbol_op *op;
};

void declare_builtins(int stream, const struct builtin_fn tbl[]);

extern struct symbol_op generic_int_op;

#endif
