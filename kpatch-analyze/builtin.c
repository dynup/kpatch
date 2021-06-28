/*
 * builtin evaluation & expansion.
 *
 * Copyright (C) 2003 Transmeta Corp.
 *               2003-2004 Linus Torvalds
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "builtin.h"
#include "expression.h"
#include "evaluate.h"
#include "expand.h"
#include "symbol.h"
#include "compat/bswap.h"
#include <stdarg.h>

#define dyntype incomplete_ctype
static bool is_dynamic_type(struct symbol *t)
{
	if (t->type == SYM_NODE)
		t = t->ctype.base_type;
	return t == &dyntype;
}

static int evaluate_to_int_const_expr(struct expression *expr)
{
	expr->ctype = &int_ctype;
	expr->flags |= CEF_SET_ICE;
	return 1;
}

static int evaluate_pure_unop(struct expression *expr)
{
	struct expression *arg = first_expression(expr->args);
	int flags = arg->flags;

	/*
	 * Allow such functions with a constant integer expression
	 * argument to be treated as a *constant* integer.
	 * This allow us to use them in switch() { case ...:
	 */
	flags |= (flags & CEF_ICE) ? CEF_SET_INT : 0;
	expr->flags = flags;
	return 1;
}

/*
 * eval_args - check the number of arguments and evaluate them.
 */
static int eval_args(struct expression *expr, int n)
{
	struct expression *arg;
	struct symbol *sym;
	const char *msg;
	int rc = 1;

	FOR_EACH_PTR(expr->args, arg) {
		if (n-- == 0) {
			msg = "too many arguments";
			goto error;
		}
		if (!evaluate_expression(arg))
			rc = 0;
	} END_FOR_EACH_PTR(arg);
	if (n > 0) {
		msg = "not enough arguments";
		goto error;
	}
	return rc;

error:
	sym = expr->fn->ctype;
	expression_error(expr, "%s for %s", msg, show_ident(sym->ident));
	return 0;
}

static int args_prototype(struct expression *expr)
{
	struct symbol *fntype = expr->fn->ctype->ctype.base_type;
	int n = symbol_list_size(fntype->arguments);
	return eval_args(expr, n);
}

static int args_triadic(struct expression *expr)
{
	return eval_args(expr, 3);
}

static int evaluate_choose(struct expression *expr)
{
	struct expression_list *list = expr->args;
	struct expression *arg, *args[3];
	int n = 0;

	/* there will be exactly 3; we'd already verified that */
	FOR_EACH_PTR(list, arg) {
		args[n++] = arg;
	} END_FOR_EACH_PTR(arg);

	*expr = get_expression_value(args[0]) ? *args[1] : *args[2];

	return 1;
}

static int expand_expect(struct expression *expr, int cost)
{
	struct expression *arg = first_ptr_list((struct ptr_list *) expr->args);

	if (arg)
		*expr = *arg;
	return 0;
}

/*
 * __builtin_warning() has type "int" and always returns 1,
 * so that you can use it in conditionals or whatever
 */
static int expand_warning(struct expression *expr, int cost)
{
	struct expression *arg;
	struct expression_list *arglist = expr->args;

	FOR_EACH_PTR (arglist, arg) {
		/*
		 * Constant strings get printed out as a warning. By the
		 * time we get here, the EXPR_STRING has been fully 
		 * evaluated, so by now it's an anonymous symbol with a
		 * string initializer.
		 *
		 * Just for the heck of it, allow any constant string
		 * symbol.
		 */
		if (arg->type == EXPR_SYMBOL) {
			struct symbol *sym = arg->symbol;
			if (sym->initializer && sym->initializer->type == EXPR_STRING) {
				struct string *string = sym->initializer->string;
				warning(expr->pos, "%*s", string->length-1, string->data);
			}
			continue;
		}

		/*
		 * Any other argument is a conditional. If it's
		 * non-constant, or it is false, we exit and do
		 * not print any warning.
		 */
		if (arg->type != EXPR_VALUE)
			goto out;
		if (!arg->value)
			goto out;
	} END_FOR_EACH_PTR(arg);
out:
	expr->type = EXPR_VALUE;
	expr->value = 1;
	expr->taint = 0;
	return 0;
}

/* The arguments are constant if the cost of all of them is zero */
static int expand_constant_p(struct expression *expr, int cost)
{
	expr->type = EXPR_VALUE;
	expr->value = !cost;
	expr->taint = 0;
	return 0;
}

/* The arguments are safe, if their cost is less than SIDE_EFFECTS */
static int expand_safe_p(struct expression *expr, int cost)
{
	expr->type = EXPR_VALUE;
	expr->value = (cost < SIDE_EFFECTS);
	expr->taint = 0;
	return 0;
}

static struct symbol_op constant_p_op = {
	.evaluate = evaluate_to_int_const_expr,
	.expand = expand_constant_p
};

static struct symbol_op safe_p_op = {
	.evaluate = evaluate_to_int_const_expr,
	.expand = expand_safe_p
};

static struct symbol_op warning_op = {
	.evaluate = evaluate_to_int_const_expr,
	.expand = expand_warning
};

static struct symbol_op expect_op = {
	.expand = expand_expect
};

static struct symbol_op choose_op = {
	.args = args_triadic,
	.evaluate = evaluate_choose,
};

/* The argument is constant and valid if the cost is zero */
static int expand_bswap(struct expression *expr, int cost)
{
	struct expression *arg;
	long long val;

	if (cost)
		return cost;

	/* the arguments number & type have already been checked */
	arg = first_expression(expr->args);
	val = get_expression_value_silent(arg);
	switch (expr->ctype->bit_size) {
	case 16: expr->value = bswap16(val); break;
	case 32: expr->value = bswap32(val); break;
	case 64: expr->value = bswap64(val); break;
	default: /* impossible error */
		return SIDE_EFFECTS;
	}

	expr->type = EXPR_VALUE;
	expr->taint = 0;
	return 0;
}

static struct symbol_op bswap_op = {
	.evaluate = evaluate_pure_unop,
	.expand = expand_bswap,
};


#define EXPAND_FINDBIT(name)					\
static int expand_##name(struct expression *expr, int cost)	\
{								\
	struct expression *arg;					\
	long long val;						\
								\
	if (cost)						\
		return cost;					\
								\
	arg = first_expression(expr->args);			\
	val = get_expression_value_silent(arg);			\
	switch (arg->ctype->bit_size) {				\
	case sizeof(int) * 8:					\
		val = __builtin_##name(val); break;		\
	case sizeof(long long) * 8:				\
		val = __builtin_##name##ll(val); break;		\
	default: /* impossible error */				\
		return SIDE_EFFECTS;				\
	}							\
								\
	expr->value = val;					\
	expr->type = EXPR_VALUE;				\
	expr->taint = 0;					\
	return 0;						\
}								\
								\
static struct symbol_op name##_op = {				\
	.evaluate = evaluate_pure_unop,				\
	.expand = expand_##name,				\
}

EXPAND_FINDBIT(clz);
EXPAND_FINDBIT(ctz);
EXPAND_FINDBIT(clrsb);
EXPAND_FINDBIT(ffs);
EXPAND_FINDBIT(parity);
EXPAND_FINDBIT(popcount);

static int evaluate_fp_unop(struct expression *expr)
{
	struct expression *arg;

	if (!eval_args(expr, 1))
		return 0;

	arg = first_expression(expr->args);
	if (!is_float_type(arg->ctype)) {
		expression_error(expr, "non-floating-point argument in call to %s()",
			show_ident(expr->fn->ctype->ident));
		return 0;
	}
	return 1;
}

static struct symbol_op fp_unop_op = {
	.evaluate = evaluate_fp_unop,
};


static int expand_isdigit(struct expression *expr, int cost)
{
	struct expression *arg = first_expression(expr->args);
	long long val = get_expression_value_silent(arg);

	if (cost)
		return cost;

	expr->value = (val >= '0') && (val <= '9');
	expr->type = EXPR_VALUE;
	expr->taint = 0;
	return 0;
}

static struct symbol_op isdigit_op = {
	.evaluate = evaluate_pure_unop,
	.expand = expand_isdigit,
};


static int evaluate_overflow_gen(struct expression *expr, int ptr)
{
	struct expression *arg;
	int n = 0;

	/* there will be exactly 3; we'd already verified that */
	FOR_EACH_PTR(expr->args, arg) {
		struct symbol *type;

		n++;
		if (!arg || !(type = arg->ctype))
			return 0;
		// 1st & 2nd args must be a basic integer type
		// 3rd arg must be a pointer to such a type.
		if (n == 3 && ptr) {
			if (type->type == SYM_NODE)
				type = type->ctype.base_type;
			if (!type)
				return 0;
			if (type->type != SYM_PTR)
				goto err;
			type = type->ctype.base_type;
			if (!type)
				return 0;
		}
		if (type->type == SYM_NODE)
			type = type->ctype.base_type;
		if (!type)
			return 0;
		if (type->ctype.base_type != &int_type || type == &bool_ctype)
			goto err;
	} END_FOR_EACH_PTR(arg);

	// the builtin returns a bool
	expr->ctype = &bool_ctype;
	return 1;

err:
	sparse_error(arg->pos, "invalid type for argument %d:", n);
	info(arg->pos, "        %s", show_typename(arg->ctype));
	expr->ctype = &bad_ctype;
	return 0;
}

static int evaluate_overflow(struct expression *expr)
{
	return evaluate_overflow_gen(expr, 1);
}

static struct symbol_op overflow_op = {
	.args = args_triadic,
	.evaluate = evaluate_overflow,
};

static int evaluate_overflow_p(struct expression *expr)
{
	return evaluate_overflow_gen(expr, 0);
}

static struct symbol_op overflow_p_op = {
	.args = args_triadic,
	.evaluate = evaluate_overflow_p,
};


///
// Evaluate the arguments of 'generic' integer operators.
//
// Parameters with a complete type are used like in a normal prototype.
// The first parameter with a 'dynamic' type will be consider
// as polymorphic and for each calls will be instancied with the type
// of its effective argument.
// The next dynamic parameters will the use this polymorphic type.
// This allows to declare functions with some parameters having
// a type variably defined at call time:
//	int foo(int, T, T);
static int evaluate_generic_int_op(struct expression *expr)
{
	struct symbol *fntype = expr->fn->ctype->ctype.base_type;
	struct symbol_list *types = NULL;
	struct symbol *ctype = NULL;
	struct expression *arg;
	struct symbol *t;
	int n = 0;

	PREPARE_PTR_LIST(fntype->arguments, t);
	FOR_EACH_PTR(expr->args, arg) {
		n++;

		if (!is_dynamic_type(t)) {
			;
		} else if (!ctype) {
			// first 'dynamic' type, check that it's an integer
			t = arg->ctype;
			if (!t)
				return 0;
			if (t->type == SYM_NODE)
				t = t->ctype.base_type;
			if (!t)
				return 0;
			if (t->ctype.base_type != &int_type)
				goto err;

			// next 'dynamic' arguments will use this type
			ctype = t;
		} else {
			// use the previous 'dynamic' type
			t = ctype;
		}
		add_ptr_list(&types, t);
		NEXT_PTR_LIST(t);
	} END_FOR_EACH_PTR(arg);
	FINISH_PTR_LIST(t);
	return evaluate_arguments(types, expr->args);

err:
	sparse_error(arg->pos, "non-integer type for argument %d:", n);
	info(arg->pos, "        %s", show_typename(arg->ctype));
	expr->ctype = &bad_ctype;
	return 0;
}

struct symbol_op generic_int_op = {
	.args = args_prototype,
	.evaluate = evaluate_generic_int_op,
};


static int eval_atomic_common(struct expression *expr)
{
	struct symbol *fntype = expr->fn->ctype->ctype.base_type;
	struct symbol_list *types = NULL;
	struct symbol *ctype = NULL;
	struct symbol *t;
	struct expression *arg;
	int n = 0;

	// The number of arguments has already be verified.
	// The first arg must be a pointer to an integral type.
	PREPARE_PTR_LIST(fntype->arguments, t);
	FOR_EACH_PTR(expr->args, arg) {
		struct symbol *ptrtype = NULL;

		if (++n == 1) {
			t = arg->ctype;
			if (!t)
				return 0;
			if (t->type == SYM_NODE)
				t = t->ctype.base_type;
			if (!t)
				return 0;
			if (t->type != SYM_PTR)
				goto err;
			ptrtype = t;
			t = t->ctype.base_type;
			if (!t)
				return 0;
			if (t->type == SYM_NODE)
				t = t->ctype.base_type;
			if (!t)
				return 0;
			if (t->type != SYM_PTR && t->ctype.base_type != &int_type)
				goto err;
			ctype = t;
			t = ptrtype;
		} else if (is_dynamic_type(t)) {
			t = ctype;
		} else if (t == &ptr_ctype) {
			t = ptrtype;
		}
		add_ptr_list(&types, t);
		NEXT_PTR_LIST(t);
	} END_FOR_EACH_PTR(arg);
	FINISH_PTR_LIST(t);

	if (!expr->ctype)	// set the return type, if needed
		expr->ctype = ctype;
	return evaluate_arguments(types, expr->args);

err:
	sparse_error(arg->pos, "invalid type for argument %d:", n);
	info(arg->pos, "        %s", show_typename(arg->ctype));
	expr->ctype = &bad_ctype;
	return 0;
}

static struct symbol_op atomic_op = {
	.args = args_prototype,
	.evaluate = eval_atomic_common,
};


///
// expand __builtin_object_size()
//
// :note: type 1 and type 3 are not supported because the
//	needed information isn't available after evaluation.
static int expand_object_size(struct expression *expr, int cost)
{
	struct expression *arg = first_expression(expr->args);
	int type = get_expression_value_silent(ptr_list_nth(expr->args, 1));
	unsigned long val = -1, off = 0;

	while (arg) {
		switch (arg->type) {
		case EXPR_IMPLIED_CAST:
		case EXPR_CAST:
			// ignore those
			arg = arg->cast_expression;
			continue;
		case EXPR_BINOP:
			// a constant add is (maybe) an offset
			if (!arg->right || arg->op != '+' || arg->right->type != EXPR_VALUE)
				break;
			off += arg->right->value;
			arg = arg->left;
			continue;
		case EXPR_PREOP:
			// a deref is just intermediate variable
			// and so the offset needs to be zeroed.
			if (arg->op == '*') {
				arg = arg->unop;
				off = 0;
				switch (arg->type) {
				case EXPR_SYMBOL:
					arg = arg->symbol->initializer;
					continue;
				default:
					break;
				}
			}
			break;
		case EXPR_SYMBOL:
			// the symbol we're looking after
			val = bits_to_bytes(arg->symbol->bit_size);
			break;
		case EXPR_CALL:
			// use alloc_size() attribute but only after linearization.
			return UNSAFE;
		default:
			break;
		}
		break;
	}

	if (val == -1)
		val = (type & 2) ? 0 : val;
	else if (type & 1)
		return UNSAFE;
	else
		val -= off;

	expr->flags |= CEF_SET_ICE;
	expr->type = EXPR_VALUE;
	expr->value = val;
	expr->taint = 0;
	return 0;
}

static struct symbol_op object_size_op = {
	.expand = expand_object_size,
};

/*
 * Builtin functions
 */
static struct symbol size_t_alias;

static struct symbol *get_ctype(struct symbol *sym)
{
	if (sym == &size_t_alias)
		return size_t_ctype;
	return sym;
}

static void declare_builtin(int stream, const struct builtin_fn *entry)
{
	struct symbol *sym = create_symbol(stream, entry->name, SYM_NODE, NS_SYMBOL);
	struct symbol *fun = alloc_symbol(sym->pos, SYM_FN);
	struct symbol *arg;
	int i;

	sym->ctype.base_type = fun;
	sym->ctype.modifiers = MOD_TOPLEVEL;
	sym->builtin = 1;
	sym->op = entry->op;

	fun->ctype.base_type = get_ctype(entry->ret_type);
	fun->variadic = entry->variadic;

	for (i = 0; (arg = entry->args[i]); i++) {
		struct symbol *anode = alloc_symbol(sym->pos, SYM_NODE);
		anode->ctype.base_type = get_ctype(arg);
		add_symbol(&fun->arguments, anode);
	}
}

void declare_builtins(int stream, const struct builtin_fn tbl[])
{
	if (!tbl)
		return;

	while (tbl->name)
		declare_builtin(stream, tbl++);
}

static const struct builtin_fn builtins_common[] = {
#define size_t_ctype	&size_t_alias
#define va_list_ctype	&ptr_ctype
#define vol_ptr		&volatile_ptr_ctype
	{ "__atomic_add_fetch", NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_always_lock_free", &bool_ctype, 0, { size_t_ctype, vol_ptr }},
	{ "__atomic_and_fetch", NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_clear", &void_ctype, 0, { &volatile_bool_ptr_ctype, &int_ctype }},
	{ "__atomic_compare_exchange", &bool_ctype, 0, { vol_ptr, &ptr_ctype, &ptr_ctype, &bool_ctype, &int_ctype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_compare_exchange_n", &bool_ctype, 0, { vol_ptr, &ptr_ctype, &dyntype, &bool_ctype, &int_ctype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_exchange", &void_ctype, 0, { vol_ptr, &ptr_ctype, &ptr_ctype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_exchange_n", NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_fetch_add", NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_fetch_and", NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_fetch_nand",NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_fetch_or",  NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_fetch_sub", NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_fetch_xor", NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_is_lock_free", &bool_ctype, 0, { size_t_ctype, vol_ptr }},
	{ "__atomic_load", &void_ctype, 0, { vol_ptr, &ptr_ctype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_load_n", NULL, 0, { vol_ptr, &int_ctype }, .op = &atomic_op },
	{ "__atomic_nand_fetch",NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_or_fetch",  NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_signal_fence", &void_ctype, 0, { &int_ctype }},
	{ "__atomic_store", &void_ctype, 0, { vol_ptr, &ptr_ctype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_store_n", &void_ctype, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_sub_fetch", NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__atomic_test_and_set", &bool_ctype, 0, { vol_ptr, &int_ctype }},
	{ "__atomic_thread_fence", &void_ctype, 0, { &int_ctype }},
	{ "__atomic_xor_fetch", NULL, 0, { vol_ptr, &dyntype, &int_ctype }, .op = &atomic_op },
	{ "__builtin_choose_expr", NULL, 1, .op = &choose_op },
	{ "__builtin_constant_p", NULL, 1, .op = &constant_p_op },
	{ "__builtin_expect", &long_ctype, 0, { &long_ctype ,&long_ctype }, .op = &expect_op },
	{ "__builtin_safe_p", NULL, 1, .op = &safe_p_op },
	{ "__builtin_warning", NULL, 1, .op = &warning_op },

	{ "__builtin_abort", &void_ctype, 0 },
	{ "__builtin_abs", &int_ctype , 0, { &int_ctype }},
	{ "__builtin_add_overflow", &bool_ctype, 1, .op = &overflow_op },
	{ "__builtin_add_overflow_p", &bool_ctype, 1, .op = &overflow_p_op },
	{ "__builtin_alloca", &ptr_ctype, 0, { size_t_ctype }},
	{ "__builtin_bcmp", &int_ctype , 0, { &const_ptr_ctype, &const_ptr_ctype, size_t_ctype }},
	{ "__builtin_bcopy", &void_ctype, 0, { &const_ptr_ctype, &ptr_ctype, size_t_ctype }},
	{ "__builtin_bswap16", &ushort_ctype, 0, { &ushort_ctype }, .op = &bswap_op },
	{ "__builtin_bswap32", &uint_ctype, 0, { &uint_ctype }, .op = &bswap_op },
	{ "__builtin_bswap64", &ullong_ctype, 0, { &ullong_ctype }, .op = &bswap_op },
	{ "__builtin_bzero", &void_ctype, 0, { &ptr_ctype, size_t_ctype }},
	{ "__builtin_calloc", &ptr_ctype, 0, { size_t_ctype, size_t_ctype }},
	{ "__builtin_clrsb", &int_ctype, 0, { &int_ctype }, .op = &clrsb_op },
	{ "__builtin_clrsbl", &int_ctype, 0, { &long_ctype }, .op = &clrsb_op },
	{ "__builtin_clrsbll", &int_ctype, 0, { &llong_ctype }, .op = &clrsb_op },
	{ "__builtin_clz", &int_ctype, 0, { &int_ctype }, .op = &clz_op },
	{ "__builtin_clzl", &int_ctype, 0, { &long_ctype }, .op = &clz_op },
	{ "__builtin_clzll", &int_ctype, 0, { &llong_ctype }, .op = &clz_op },
	{ "__builtin_ctz", &int_ctype, 0, { &int_ctype }, .op = &ctz_op },
	{ "__builtin_ctzl", &int_ctype, 0, { &long_ctype }, .op = &ctz_op },
	{ "__builtin_ctzll", &int_ctype, 0, { &llong_ctype }, .op = &ctz_op },
	{ "__builtin_exit", &void_ctype, 0, { &int_ctype }},
	{ "__builtin_extract_return_addr", &ptr_ctype, 0, { &ptr_ctype }},
	{ "__builtin_fabs", &double_ctype, 0, { &double_ctype }},
	{ "__builtin_ffs", &int_ctype, 0, { &int_ctype }, .op = &ffs_op },
	{ "__builtin_ffsl", &int_ctype, 0, { &long_ctype }, .op = &ffs_op },
	{ "__builtin_ffsll", &int_ctype, 0, { &llong_ctype }, .op = &ffs_op },
	{ "__builtin_fma", &double_ctype, 0, { &double_ctype, &double_ctype, &double_ctype }},
	{ "__builtin_fmaf", &float_ctype, 0, { &float_ctype, &float_ctype, &float_ctype }},
	{ "__builtin_fmal", &ldouble_ctype, 0, { &ldouble_ctype, &ldouble_ctype, &ldouble_ctype }},
	{ "__builtin_frame_address", &ptr_ctype, 0, { &uint_ctype }},
	{ "__builtin_free", &void_ctype, 0, { &ptr_ctype }},
	{ "__builtin_huge_val", &double_ctype, 0 },
	{ "__builtin_huge_valf", &float_ctype, 0 },
	{ "__builtin_huge_vall", &ldouble_ctype, 0 },
	{ "__builtin_index", &string_ctype, 0, { &const_string_ctype, &int_ctype }},
	{ "__builtin_inf", &double_ctype, 0 },
	{ "__builtin_inff", &float_ctype, 0 },
	{ "__builtin_infl", &ldouble_ctype, 0 },
	{ "__builtin_isdigit", &int_ctype, 0, { &int_ctype }, .op = &isdigit_op },
	{ "__builtin_isfinite", &int_ctype, 1, .op = &fp_unop_op },
	{ "__builtin_isgreater", &int_ctype, 0, { &float_ctype, &float_ctype }},
	{ "__builtin_isgreaterequal", &int_ctype, 0, { &float_ctype, &float_ctype }},
	{ "__builtin_isinf", &int_ctype, 1, .op = &fp_unop_op },
	{ "__builtin_isinf_sign", &int_ctype, 1, .op = &fp_unop_op },
	{ "__builtin_isless", &int_ctype, 0, { &float_ctype, &float_ctype }},
	{ "__builtin_islessequal", &int_ctype, 0, { &float_ctype, &float_ctype }},
	{ "__builtin_islessgreater", &int_ctype, 0, { &float_ctype, &float_ctype }},
	{ "__builtin_isnan", &int_ctype, 1, .op = &fp_unop_op },
	{ "__builtin_isnormal", &int_ctype, 1, .op = &fp_unop_op },
	{ "__builtin_isunordered", &int_ctype, 0, { &float_ctype, &float_ctype }},
	{ "__builtin_labs", &long_ctype, 0, { &long_ctype }},
	{ "__builtin_llabs", &llong_ctype, 0, { &llong_ctype }},
	{ "__builtin_malloc", &ptr_ctype, 0, { size_t_ctype }},
	{ "__builtin_memchr", &ptr_ctype, 0, { &const_ptr_ctype, &int_ctype, size_t_ctype }},
	{ "__builtin_memcmp", &int_ctype, 0, { &const_ptr_ctype, &const_ptr_ctype, size_t_ctype }},
	{ "__builtin_memcpy", &ptr_ctype, 0, { &ptr_ctype, &const_ptr_ctype, size_t_ctype }},
	{ "__builtin_memmove", &ptr_ctype, 0, { &ptr_ctype, &const_ptr_ctype, size_t_ctype }},
	{ "__builtin_mempcpy", &ptr_ctype, 0, { &ptr_ctype, &const_ptr_ctype, size_t_ctype }},
	{ "__builtin_memset", &ptr_ctype, 0, { &ptr_ctype, &int_ctype, size_t_ctype }},
	{ "__builtin_mul_overflow", &bool_ctype, 1, .op = &overflow_op },
	{ "__builtin_mul_overflow_p", &bool_ctype, 1, .op = &overflow_p_op },
	{ "__builtin_nan", &double_ctype, 0, { &const_string_ctype }},
	{ "__builtin_nanf", &float_ctype, 0, { &const_string_ctype }},
	{ "__builtin_nanl", &ldouble_ctype, 0, { &const_string_ctype }},
	{ "__builtin_object_size", size_t_ctype, 0, { &const_ptr_ctype, &int_ctype }, .op = &object_size_op},
	{ "__builtin_parity", &int_ctype, 0, { &uint_ctype }, .op = &parity_op },
	{ "__builtin_parityl", &int_ctype, 0, { &ulong_ctype }, .op = &parity_op },
	{ "__builtin_parityll", &int_ctype, 0, { &ullong_ctype }, .op = &parity_op },
	{ "__builtin_popcount", &int_ctype, 0, { &uint_ctype }, .op = &popcount_op },
	{ "__builtin_popcountl", &int_ctype, 0, { &ulong_ctype }, .op = &popcount_op },
	{ "__builtin_popcountll", &int_ctype, 0, { &ullong_ctype }, .op = &popcount_op },
	{ "__builtin_prefetch", &void_ctype, 1, { &const_ptr_ctype }},
	{ "__builtin_printf", &int_ctype, 1, { &const_string_ctype }},
	{ "__builtin_puts", &int_ctype, 0, { &const_string_ctype }},
	{ "__builtin_realloc", &ptr_ctype, 0, { &ptr_ctype, size_t_ctype }},
	{ "__builtin_return_address", &ptr_ctype, 0, { &uint_ctype }},
	{ "__builtin_rindex", &string_ctype, 0, { &const_string_ctype, &int_ctype }},
	{ "__builtin_sadd_overflow", &bool_ctype, 0, { &int_ctype, &int_ctype, &int_ptr_ctype }},
	{ "__builtin_saddl_overflow", &bool_ctype, 0, { &long_ctype, &long_ctype, &long_ptr_ctype }},
	{ "__builtin_saddll_overflow", &bool_ctype, 0, { &llong_ctype, &llong_ctype, &llong_ptr_ctype }},
	{ "__builtin_signbit", &int_ctype, 1 , .op = &fp_unop_op },
	{ "__builtin_smul_overflow", &bool_ctype, 0, { &int_ctype, &int_ctype, &int_ptr_ctype }},
	{ "__builtin_smull_overflow", &bool_ctype, 0, { &long_ctype, &long_ctype, &long_ptr_ctype }},
	{ "__builtin_smulll_overflow", &bool_ctype, 0, { &llong_ctype, &llong_ctype, &llong_ptr_ctype }},
	{ "__builtin_snprintf", &int_ctype, 1, { &string_ctype, size_t_ctype, &const_string_ctype }},
	{ "__builtin_sprintf", &int_ctype, 1, { &string_ctype, &const_string_ctype }},
	{ "__builtin_ssub_overflow", &bool_ctype, 0, { &int_ctype, &int_ctype, &int_ptr_ctype }},
	{ "__builtin_ssubl_overflow", &bool_ctype, 0, { &long_ctype, &long_ctype, &long_ptr_ctype }},
	{ "__builtin_ssubll_overflow", &bool_ctype, 0, { &llong_ctype, &llong_ctype, &llong_ptr_ctype }},
	{ "__builtin_stpcpy", &string_ctype, 0, { &const_string_ctype, &const_string_ctype }},
	{ "__builtin_stpncpy", &string_ctype, 0, { &const_string_ctype, &const_string_ctype, size_t_ctype }},
	{ "__builtin_strcasecmp", &int_ctype, 0, { &const_string_ctype, &const_string_ctype }},
	{ "__builtin_strcasestr", &string_ctype, 0, { &const_string_ctype, &const_string_ctype }},
	{ "__builtin_strcat", &string_ctype, 0, { &string_ctype, &const_string_ctype }},
	{ "__builtin_strchr", &string_ctype, 0, { &const_string_ctype, &int_ctype }},
	{ "__builtin_strcmp", &int_ctype, 0, { &const_string_ctype, &const_string_ctype }},
	{ "__builtin_strcpy", &string_ctype, 0, { &string_ctype, &const_string_ctype }},
	{ "__builtin_strcspn", size_t_ctype, 0, { &const_string_ctype, &const_string_ctype }},
	{ "__builtin_strdup", &string_ctype, 0, { &const_string_ctype }},
	{ "__builtin_strlen", size_t_ctype, 0, { &const_string_ctype }},
	{ "__builtin_strncasecmp", &int_ctype, 0, { &const_string_ctype, &const_string_ctype, size_t_ctype }},
	{ "__builtin_strncat", &string_ctype, 0, { &string_ctype, &const_string_ctype, size_t_ctype }},
	{ "__builtin_strncmp", &int_ctype, 0, { &const_string_ctype, &const_string_ctype, size_t_ctype }},
	{ "__builtin_strncpy", &string_ctype, 0, { &string_ctype, &const_string_ctype, size_t_ctype }},
	{ "__builtin_strndup", &string_ctype, 0, { &const_string_ctype, size_t_ctype }},
	{ "__builtin_strnstr", &string_ctype, 0, { &const_string_ctype, &const_string_ctype, size_t_ctype }},
	{ "__builtin_strpbrk", &string_ctype, 0, { &const_string_ctype, &const_string_ctype }},
	{ "__builtin_strrchr", &string_ctype, 0, { &const_string_ctype, &int_ctype }},
	{ "__builtin_strspn", size_t_ctype, 0, { &const_string_ctype, &const_string_ctype }},
	{ "__builtin_strstr", &string_ctype, 0, { &const_string_ctype, &const_string_ctype }},
	{ "__builtin_sub_overflow", &bool_ctype, 1, .op = &overflow_op },
	{ "__builtin_sub_overflow_p", &bool_ctype, 1, .op = &overflow_p_op },
	{ "__builtin_trap", &void_ctype, 0 },
	{ "__builtin_uadd_overflow", &bool_ctype, 0, { &uint_ctype, &uint_ctype, &uint_ptr_ctype }},
	{ "__builtin_uaddl_overflow", &bool_ctype, 0, { &ulong_ctype, &ulong_ctype, &ulong_ptr_ctype }},
	{ "__builtin_uaddll_overflow", &bool_ctype, 0, { &ullong_ctype, &ullong_ctype, &ullong_ptr_ctype }},
	{ "__builtin_umul_overflow", &bool_ctype, 0, { &uint_ctype, &uint_ctype, &uint_ptr_ctype }},
	{ "__builtin_umull_overflow", &bool_ctype, 0, { &ulong_ctype, &ulong_ctype, &ulong_ptr_ctype }},
	{ "__builtin_umulll_overflow", &bool_ctype, 0, { &ullong_ctype, &ullong_ctype, &ullong_ptr_ctype }},
	{ "__builtin_unreachable", &void_ctype, 0 },
	{ "__builtin_usub_overflow", &bool_ctype, 0, { &uint_ctype, &uint_ctype, &uint_ptr_ctype }},
	{ "__builtin_usubl_overflow", &bool_ctype, 0, { &ulong_ctype, &ulong_ctype, &ulong_ptr_ctype }},
	{ "__builtin_usubll_overflow", &bool_ctype, 0, { &ullong_ctype, &ullong_ctype, &ullong_ptr_ctype }},
	{ "__builtin_va_arg_pack_len", size_t_ctype, 0 },
	{ "__builtin_vprintf", &int_ctype, 0, { &const_string_ctype, va_list_ctype }},
	{ "__builtin_vsnprintf", &int_ctype, 0, { &string_ctype, size_t_ctype, &const_string_ctype, va_list_ctype }},
	{ "__builtin_vsprintf", &int_ctype, 0, { &string_ctype, &const_string_ctype, va_list_ctype }},

	{ "__builtin___memcpy_chk", &ptr_ctype, 0, { &ptr_ctype, &const_ptr_ctype, size_t_ctype, size_t_ctype }},
	{ "__builtin___memmove_chk", &ptr_ctype, 0, { &ptr_ctype, &const_ptr_ctype, size_t_ctype, size_t_ctype }},
	{ "__builtin___mempcpy_chk", &ptr_ctype, 0, { &ptr_ctype, &const_ptr_ctype, size_t_ctype, size_t_ctype }},
	{ "__builtin___memset_chk", &ptr_ctype, 0, { &ptr_ctype, &int_ctype, size_t_ctype, size_t_ctype }},
	{ "__builtin___snprintf_chk", &int_ctype, 1, { &string_ctype, size_t_ctype, &int_ctype , size_t_ctype, &const_string_ctype }},
	{ "__builtin___sprintf_chk", &int_ctype, 1, { &string_ctype, &int_ctype, size_t_ctype, &const_string_ctype }},
	{ "__builtin___stpcpy_chk", &string_ctype, 0, { &string_ctype, &const_string_ctype, size_t_ctype }},
	{ "__builtin___strcat_chk", &string_ctype, 0, { &string_ctype, &const_string_ctype, size_t_ctype }},
	{ "__builtin___strcpy_chk", &string_ctype, 0, { &string_ctype, &const_string_ctype, size_t_ctype }},
	{ "__builtin___strncat_chk", &string_ctype, 0, { &string_ctype, &const_string_ctype, size_t_ctype, size_t_ctype }},
	{ "__builtin___strncpy_chk", &string_ctype, 0, { &string_ctype, &const_string_ctype, size_t_ctype, size_t_ctype }},
	{ "__builtin___vsnprintf_chk", &int_ctype, 0, { &string_ctype, size_t_ctype, &int_ctype, size_t_ctype, &const_string_ctype, va_list_ctype }},
	{ "__builtin___vsprintf_chk", &int_ctype, 0, { &string_ctype, &int_ctype, size_t_ctype, &const_string_ctype, va_list_ctype }},

	{ "__sync_add_and_fetch", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_and_and_fetch", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_bool_compare_and_swap", &bool_ctype, 1, { vol_ptr, &dyntype, &dyntype }, .op = &atomic_op},
	{ "__sync_fetch_and_add", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_fetch_and_and", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_fetch_and_nand", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_fetch_and_or", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_fetch_and_sub", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_fetch_and_xor", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_lock_release", &void_ctype, 1, { vol_ptr }, .op = &atomic_op },
	{ "__sync_lock_test_and_set", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_nand_and_fetch", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_or_and_fetch", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_sub_and_fetch", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },
	{ "__sync_synchronize", &void_ctype, 1 },
	{ "__sync_val_compare_and_swap", NULL, 1, { vol_ptr, &dyntype, &dyntype }, .op = &atomic_op },
	{ "__sync_xor_and_fetch", NULL, 1, { vol_ptr, &dyntype }, .op = &atomic_op },

	{ }
};

void init_builtins(int stream)
{
	declare_builtins(stream, builtins_common);
	declare_builtins(stream, arch_target->builtins);
	init_linearized_builtins(stream);
}
