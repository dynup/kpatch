/*
 * Stupid C parser, version 1e-6.
 *
 * Let's see how hard this is to do.
 *
 * Copyright (C) 2003 Transmeta Corp.
 *               2003-2004 Linus Torvalds
 * Copyright (C) 2004 Christopher Li
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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include "lib.h"
#include "allocate.h"
#include "token.h"
#include "parse.h"
#include "symbol.h"
#include "scope.h"
#include "expression.h"
#include "target.h"

static struct symbol_list **function_symbol_list;
struct symbol_list *function_computed_target_list;
struct statement_list *function_computed_goto_list;

static struct token *statement(struct token *token, struct statement **tree);
static struct token *handle_attributes(struct token *token, struct decl_state *ctx);

typedef struct token *declarator_t(struct token *, struct symbol *, struct decl_state *);
static declarator_t
	struct_specifier, union_specifier, enum_specifier,
	attribute_specifier, typeof_specifier,
	storage_specifier, thread_specifier;
static declarator_t generic_qualifier;
static declarator_t autotype_specifier;

static struct token *parse_if_statement(struct token *token, struct statement *stmt);
static struct token *parse_return_statement(struct token *token, struct statement *stmt);
static struct token *parse_loop_iterator(struct token *token, struct statement *stmt);
static struct token *parse_default_statement(struct token *token, struct statement *stmt);
static struct token *parse_case_statement(struct token *token, struct statement *stmt);
static struct token *parse_switch_statement(struct token *token, struct statement *stmt);
static struct token *parse_for_statement(struct token *token, struct statement *stmt);
static struct token *parse_while_statement(struct token *token, struct statement *stmt);
static struct token *parse_do_statement(struct token *token, struct statement *stmt);
static struct token *parse_goto_statement(struct token *token, struct statement *stmt);
static struct token *parse_context_statement(struct token *token, struct statement *stmt);
static struct token *parse_range_statement(struct token *token, struct statement *stmt);
static struct token *parse_asm_statement(struct token *token, struct statement *stmt);
static struct token *toplevel_asm_declaration(struct token *token, struct symbol_list **list);
static struct token *parse_static_assert(struct token *token, struct symbol_list **unused);

typedef struct token *attr_t(struct token *, struct symbol *,
			     struct decl_state *);

static attr_t
	attribute_packed, attribute_aligned, attribute_modifier,
	attribute_function,
	attribute_bitwise,
	attribute_address_space, attribute_context,
	attribute_designated_init,
	attribute_transparent_union, ignore_attribute,
	attribute_mode, attribute_force;

typedef struct symbol *to_mode_t(struct symbol *);

static to_mode_t
	to_QI_mode, to_HI_mode, to_SI_mode, to_DI_mode, to_TI_mode;
static to_mode_t to_pointer_mode, to_word_mode;

enum {
	Set_T = 1,
	Set_S = 2,
	Set_Char = 4,
	Set_Int = 8,
	Set_Double = 16,
	Set_Float = 32,
	Set_Signed = 64,
	Set_Unsigned = 128,
	Set_Short = 256,
	Set_Long = 512,
	Set_Vlong = 1024,
	Set_Int128 = 2048,
	Set_Any = Set_T | Set_Short | Set_Long | Set_Signed | Set_Unsigned
};

enum {
	CInt = 0, CSInt, CUInt, CReal,
};

static void asm_modifier(struct token *token, unsigned long *mods, unsigned long mod)
{
	if (*mods & mod)
		warning(token->pos, "duplicated asm modifier");
	*mods |= mod;
}

static struct symbol_op typedef_op = {
	.type = KW_MODIFIER,
	.declarator = storage_specifier,
};

static struct symbol_op inline_op = {
	.type = KW_MODIFIER,
	.declarator = generic_qualifier,
	.asm_modifier = asm_modifier,
};

static struct symbol_op noreturn_op = {
	.type = KW_MODIFIER,
	.declarator = generic_qualifier,
};

static declarator_t alignas_specifier;
static struct symbol_op alignas_op = {
	.type = KW_MODIFIER,
	.declarator = alignas_specifier,
};

static struct symbol_op auto_op = {
	.type = KW_MODIFIER,
	.declarator = storage_specifier,
};

static struct symbol_op register_op = {
	.type = KW_MODIFIER,
	.declarator = storage_specifier,
};

static struct symbol_op static_op = {
	.type = KW_MODIFIER|KW_STATIC,
	.declarator = storage_specifier,
};

static struct symbol_op extern_op = {
	.type = KW_MODIFIER,
	.declarator = storage_specifier,
};

static struct symbol_op thread_op = {
	.type = KW_MODIFIER,
	.declarator = thread_specifier,
};

static struct symbol_op const_op = {
	.type = KW_QUALIFIER,
	.declarator = generic_qualifier,
};

static struct symbol_op volatile_op = {
	.type = KW_QUALIFIER,
	.declarator = generic_qualifier,
	.asm_modifier = asm_modifier,
};

static struct symbol_op restrict_op = {
	.type = KW_QUALIFIER,
	.declarator = generic_qualifier,
};

static struct symbol_op atomic_op = {
	.type = KW_QUALIFIER,
	.declarator = generic_qualifier,
};

static struct symbol_op typeof_op = {
	.type = KW_SPECIFIER,
	.declarator = typeof_specifier,
	.test = Set_Any,
	.set = Set_S|Set_T,
};

static struct symbol_op autotype_op = {
	.type = KW_SPECIFIER,
	.declarator = autotype_specifier,
	.test = Set_Any,
	.set = Set_S|Set_T,
};

static struct symbol_op attribute_op = {
	.type = KW_ATTRIBUTE,
	.declarator = attribute_specifier,
};

static struct symbol_op struct_op = {
	.type = KW_SPECIFIER,
	.declarator = struct_specifier,
	.test = Set_Any,
	.set = Set_S|Set_T,
};

static struct symbol_op union_op = {
	.type = KW_SPECIFIER,
	.declarator = union_specifier,
	.test = Set_Any,
	.set = Set_S|Set_T,
};

static struct symbol_op enum_op = {
	.type = KW_SPECIFIER,
	.declarator = enum_specifier,
	.test = Set_Any,
	.set = Set_S|Set_T,
};

static struct symbol_op spec_op = {
	.type = KW_SPECIFIER | KW_EXACT,
	.test = Set_Any,
	.set = Set_S|Set_T,
};

static struct symbol_op char_op = {
	.type = KW_SPECIFIER,
	.test = Set_T|Set_Long|Set_Short,
	.set = Set_T|Set_Char,
	.class = CInt,
};

static struct symbol_op int_op = {
	.type = KW_SPECIFIER,
	.test = Set_T,
	.set = Set_T|Set_Int,
};

static struct symbol_op double_op = {
	.type = KW_SPECIFIER,
	.test = Set_T|Set_Signed|Set_Unsigned|Set_Short|Set_Vlong,
	.set = Set_T|Set_Double,
	.class = CReal,
};

static struct symbol_op float_op = {
	.type = KW_SPECIFIER,
	.test = Set_T|Set_Signed|Set_Unsigned|Set_Short|Set_Long,
	.set = Set_T|Set_Float,
	.class = CReal,
};

static struct symbol_op short_op = {
	.type = KW_SPECIFIER,
	.test = Set_S|Set_Char|Set_Float|Set_Double|Set_Long|Set_Short,
	.set = Set_Short,
};

static struct symbol_op signed_op = {
	.type = KW_SPECIFIER,
	.test = Set_S|Set_Float|Set_Double|Set_Signed|Set_Unsigned,
	.set = Set_Signed,
	.class = CSInt,
};

static struct symbol_op unsigned_op = {
	.type = KW_SPECIFIER,
	.test = Set_S|Set_Float|Set_Double|Set_Signed|Set_Unsigned,
	.set = Set_Unsigned,
	.class = CUInt,
};

static struct symbol_op long_op = {
	.type = KW_SPECIFIER,
	.test = Set_S|Set_Char|Set_Float|Set_Short|Set_Vlong,
	.set = Set_Long,
};

static struct symbol_op int128_op = {
	.type = KW_SPECIFIER,
	.test = Set_S|Set_T|Set_Char|Set_Short|Set_Int|Set_Float|Set_Double|Set_Long|Set_Vlong|Set_Int128,
	.set =  Set_T|Set_Int128|Set_Vlong,
	.class = CInt,
};

static struct symbol_op if_op = {
	.statement = parse_if_statement,
};

static struct symbol_op return_op = {
	.statement = parse_return_statement,
};

static struct symbol_op loop_iter_op = {
	.statement = parse_loop_iterator,
};

static struct symbol_op default_op = {
	.statement = parse_default_statement,
};

static struct symbol_op case_op = {
	.statement = parse_case_statement,
};

static struct symbol_op switch_op = {
	.statement = parse_switch_statement,
};

static struct symbol_op for_op = {
	.statement = parse_for_statement,
};

static struct symbol_op while_op = {
	.statement = parse_while_statement,
};

static struct symbol_op do_op = {
	.statement = parse_do_statement,
};

static struct symbol_op goto_op = {
	.statement = parse_goto_statement,
};

static struct symbol_op __context___op = {
	.statement = parse_context_statement,
	.attribute = attribute_context,
};

static struct symbol_op range_op = {
	.statement = parse_range_statement,
};

static struct symbol_op asm_op = {
	.type = KW_ASM,
	.statement = parse_asm_statement,
	.toplevel = toplevel_asm_declaration,
};

static struct symbol_op static_assert_op = {
	.toplevel = parse_static_assert,
};

static struct symbol_op packed_op = {
	.attribute = attribute_packed,
};

static struct symbol_op aligned_op = {
	.attribute = attribute_aligned,
};

static struct symbol_op attr_mod_op = {
	.attribute = attribute_modifier,
};

static struct symbol_op attr_fun_op = {
	.attribute = attribute_function,
};

static struct symbol_op attr_bitwise_op = {
	.attribute = attribute_bitwise,
};

static struct symbol_op attr_force_op = {
	.attribute = attribute_force,
};

static struct symbol_op address_space_op = {
	.attribute = attribute_address_space,
};

static struct symbol_op mode_op = {
	.attribute = attribute_mode,
};

static struct symbol_op context_op = {
	.attribute = attribute_context,
};

static struct symbol_op designated_init_op = {
	.attribute = attribute_designated_init,
};

static struct symbol_op transparent_union_op = {
	.attribute = attribute_transparent_union,
};

static struct symbol_op ignore_attr_op = {
	.attribute = ignore_attribute,
};

static struct symbol_op mode_QI_op = {
	.type = KW_MODE,
	.to_mode = to_QI_mode
};

static struct symbol_op mode_HI_op = {
	.type = KW_MODE,
	.to_mode = to_HI_mode
};

static struct symbol_op mode_SI_op = {
	.type = KW_MODE,
	.to_mode = to_SI_mode
};

static struct symbol_op mode_DI_op = {
	.type = KW_MODE,
	.to_mode = to_DI_mode
};

static struct symbol_op mode_TI_op = {
	.type = KW_MODE,
	.to_mode = to_TI_mode
};

static struct symbol_op mode_pointer_op = {
	.type = KW_MODE,
	.to_mode = to_pointer_mode
};

static struct symbol_op mode_word_op = {
	.type = KW_MODE,
	.to_mode = to_word_mode
};

/*
 * Define the keyword and their effects.
 * The entries in the 'typedef' and put in NS_TYPEDEF and
 * are automatically set as reserved keyword while the ones
 * in the 'keyword' table are just put in NS_KEYWORD.
 *
 * The entries are added via the 3 macros:
 *   N() for entries with "name" only,
 *   D() for entries with "name" & "__name__",
 *   A() for entries with "name", "__name" & "__name__",
 *   U() for entries with "__name" & "__name__".
 */
static struct init_keyword {
	const char *name;
	struct symbol_op *op;
	struct symbol *type;
	unsigned long mods;
} typedefs[] = {
#define N(I, O,...)	{ I, O,##__VA_ARGS__ }
#define D(I, O,...)	N(I,O,##__VA_ARGS__ ),		\
			N("__" I "__",O,##__VA_ARGS__)
#define A(I, O,...)	N(I,O,##__VA_ARGS__ ),		\
			N("__" I,O,##__VA_ARGS__),	\
			N("__" I "__",O,##__VA_ARGS__)
#define U(I, O,...)	N("__" I,O,##__VA_ARGS__),	\
			N("__" I "__",O,##__VA_ARGS__)
	/* Storage classes */
	N("auto",		&auto_op,	.mods = MOD_AUTO),
	N("register",		&register_op,	.mods = MOD_REGISTER),
	N("static",		&static_op,	.mods = MOD_STATIC),
	N("extern",		&extern_op,	.mods = MOD_EXTERN),
	N("__thread",		&thread_op),
	N("_Thread_local",	&thread_op),

	A("inline",		&inline_op,	.mods = MOD_INLINE),

	/* Typedef ... */
	N("typedef",		&typedef_op,	.mods = MOD_USERTYPE),
	A("typeof",		&typeof_op),
	N("__auto_type",	&autotype_op),

	/* Type qualifiers */
	A("const",		&const_op,	.mods = MOD_CONST),
	A("volatile",		&volatile_op,	.mods = MOD_VOLATILE),
	A("restrict",		&restrict_op,	.mods = MOD_RESTRICT),

	N("_Atomic",		&atomic_op,	.mods = MOD_ATOMIC),
	N("_Noreturn",		&noreturn_op,	.mods = MOD_NORETURN),
	N("_Alignas",		&alignas_op),

	U("attribute",		&attribute_op),

	/* Type specifiers */
	N("struct",		&struct_op),
	N("union",		&union_op),
	N("enum",		&enum_op),

	N("void",		&spec_op,	.type = &void_ctype),
	N("char",		&char_op),
	N("short",		&short_op),
	N("int",		&int_op),
	N("long",		&long_op),
	N("float",		&float_op),
	N("double",		&double_op),
	A("signed",		&signed_op),
	N("unsigned",		&unsigned_op),
	N("__int128",		&int128_op),
	N("_Bool",		&spec_op,	.type = &bool_ctype),

	/* Predeclared types */
	N("__builtin_va_list",	&spec_op,	.type = &ptr_ctype),
	N("__builtin_ms_va_list",&spec_op,	.type = &ptr_ctype),
	N("__int128_t",		&spec_op,	.type = &sint128_ctype),
	N("__uint128_t",	&spec_op,	.type = &uint128_ctype),
	N("_Float32",		&spec_op,	.type = &float32_ctype),
	N("_Float32x",		&spec_op,	.type = &float32x_ctype),
	N("_Float64",		&spec_op,	.type = &float64_ctype),
	N("_Float64x",		&spec_op,	.type = &float64x_ctype),
	N("_Float128",		&spec_op,	.type = &float128_ctype),
}, keywords[] = {
	/* Statements */
	N("if",			&if_op),
	N("return",		&return_op),
	N("break",		&loop_iter_op),
	N("continue",		&loop_iter_op),
	N("default",		&default_op),
	N("case",		&case_op),
	N("switch",		&switch_op),
	N("for",		&for_op),
	N("while",		&while_op),
	N("do",			&do_op),
	N("goto",		&goto_op),
	A("asm",		&asm_op),
	N("context",		&context_op),
	N("__context__",	&__context___op),
	N("__range__",		&range_op),
	N("_Static_assert",	&static_assert_op),

	/* Attributes */
	D("packed",		&packed_op),
	D("aligned",		&aligned_op),
	D("nocast",		&attr_mod_op,		.mods = MOD_NOCAST),
	D("noderef",		&attr_mod_op,		.mods = MOD_NODEREF),
	D("safe",		&attr_mod_op,		.mods = MOD_SAFE),
	D("unused",		&attr_mod_op,		.mods = MOD_UNUSED),
	D("externally_visible",	&attr_mod_op,		.mods = MOD_EXT_VISIBLE),
	D("force",		&attr_force_op),
	D("bitwise",		&attr_bitwise_op,	.mods = MOD_BITWISE),
	D("address_space",	&address_space_op),
	D("designated_init",	&designated_init_op),
	D("transparent_union",	&transparent_union_op),
	D("noreturn",		&attr_fun_op,		.mods = MOD_NORETURN),
	D("pure",		&attr_fun_op,		.mods = MOD_PURE),
	A("const",		&attr_fun_op,		.mods = MOD_PURE),
	D("gnu_inline",		&attr_fun_op,		.mods = MOD_GNU_INLINE),
	D("no_instrument_function",	&attr_fun_op,	.mods = MOD_NOTRACE),
	A("__section(.init.text)",	&attr_fun_op,		.mods = MOD_INIT),

	/* Modes */
	D("mode",		&mode_op),
	D("QI",			&mode_QI_op),
	D("HI",			&mode_HI_op),
	D("SI",			&mode_SI_op),
	D("DI",			&mode_DI_op),
	D("TI",			&mode_TI_op),
	D("byte",		&mode_QI_op),
	D("pointer",		&mode_pointer_op),
	D("word",		&mode_word_op),
};


static const char *ignored_attributes[] = {

#define GCC_ATTR(x)		\
	STRINGIFY(x), 		\
	STRINGIFY(__##x##__),

#include "gcc-attr-list.h"

#undef GCC_ATTR

	"bounded",
	"__bounded__",
	"__noclone",
	"__nonnull",
	"__nothrow",
};


static void init_keyword(int stream, struct init_keyword *kw, enum namespace ns)
{
	struct symbol *sym = create_symbol(stream, kw->name, SYM_KEYWORD, ns);
	sym->ident->keyword = 1;
	sym->ident->reserved |= (ns == NS_TYPEDEF);
	sym->ctype.modifiers = kw->mods;
	sym->ctype.base_type = kw->type;
	sym->op = kw->op;
}

void init_parser(int stream)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(typedefs); i++)
		init_keyword(stream, &typedefs[i], NS_TYPEDEF);
	for (i = 0; i < ARRAY_SIZE(keywords); i++)
		init_keyword(stream, &keywords[i], NS_KEYWORD);

	for (i = 0; i < ARRAY_SIZE(ignored_attributes); i++) {
		const char * name = ignored_attributes[i];
		struct symbol *sym = create_symbol(stream, name, SYM_KEYWORD,
						   NS_KEYWORD);
		if (!sym->op) {
			sym->ident->keyword = 1;
			sym->op = &ignore_attr_op;
		}
	}
}


static struct token *skip_to(struct token *token, int op)
{
	while (!match_op(token, op) && !eof_token(token))
		token = token->next;
	return token;
}

static struct token bad_token = { .pos.type = TOKEN_BAD };
struct token *expect(struct token *token, int op, const char *where)
{
	if (!match_op(token, op)) {
		if (token != &bad_token) {
			bad_token.next = token;
			sparse_error(token->pos, "Expected %s %s", show_special(op), where);
			sparse_error(token->pos, "got %s", show_token(token));
		}
		if (op == ';')
			return skip_to(token, op);
		return &bad_token;
	}
	return token->next;
}

///
// issue an error message on new parsing errors
// @token: the current token
// @errmsg: the error message
// If the current token is from a previous error, an error message
// has already been issued, so nothing more is done.
// Otherwise, @errmsg is displayed followed by the current token.
static void unexpected(struct token *token, const char *errmsg)
{
	if (token == &bad_token)
		return;
	sparse_error(token->pos, "%s", errmsg);
	sparse_error(token->pos, "got %s", show_token(token));
}

// Add a symbol to the list of function-local symbols
static void fn_local_symbol(struct symbol *sym)
{
	if (function_symbol_list)
		add_symbol(function_symbol_list, sym);
}

struct statement *alloc_statement(struct position pos, int type)
{
	struct statement *stmt = __alloc_statement(0);
	stmt->type = type;
	stmt->pos = pos;
	return stmt;
}

static struct token *struct_declaration_list(struct token *token, struct symbol_list **list);

static void apply_ctype(struct position pos, struct ctype *dst, struct ctype *src);

static void apply_modifiers(struct position pos, struct decl_state *ctx)
{
	struct symbol *ctype;
	if (!ctx->mode)
		return;
	ctype = ctx->mode->to_mode(ctx->ctype.base_type);
	if (!ctype)
		sparse_error(pos, "don't know how to apply mode to %s",
				show_typename(ctx->ctype.base_type));
	else
		ctx->ctype.base_type = ctype;
	
}

static struct symbol * alloc_indirect_symbol(struct position pos, struct ctype *ctype, int type)
{
	struct symbol *sym = alloc_symbol(pos, type);

	sym->ctype.base_type = ctype->base_type;
	sym->ctype.modifiers = ctype->modifiers;

	ctype->base_type = sym;
	ctype->modifiers = 0;
	return sym;
}

/*
 * NOTE! NS_LABEL is not just a different namespace,
 * it also ends up using function scope instead of the
 * regular symbol scope.
 */
struct symbol *label_symbol(struct token *token, int used)
{
	struct symbol *sym = lookup_symbol(token->ident, NS_LABEL);
	if (!sym) {
		sym = alloc_symbol(token->pos, SYM_LABEL);
		bind_symbol(sym, token->ident, NS_LABEL);
		if (used)
			sym->used = 1;
		fn_local_symbol(sym);
	}
	return sym;
}

static struct token *struct_union_enum_specifier(enum type type,
	struct token *token, struct decl_state *ctx,
	struct token *(*parse)(struct token *, struct symbol *))
{
	struct decl_state attr = { };
	struct symbol *sym;
	struct position *repos;

	token = handle_attributes(token, &attr);
	if (token_type(token) == TOKEN_IDENT) {
		sym = lookup_symbol(token->ident, NS_STRUCT);
		if (!sym ||
		    (is_outer_scope(sym->scope) &&
		     (match_op(token->next,';') || match_op(token->next,'{')))) {
			// Either a new symbol, or else an out-of-scope
			// symbol being redefined.
			sym = alloc_symbol(token->pos, type);
			bind_symbol(sym, token->ident, NS_STRUCT);
		}
		if (sym->type != type)
			error_die(token->pos, "invalid tag applied to %s", show_typename (sym));
		ctx->ctype.base_type = sym;
		repos = &token->pos;
		token = token->next;
		if (!match_op(token, '{'))
			return token;

		// The following test is actually wrong for empty
		// structs, but (1) they are not C99, (2) gcc does
		// the same thing, and (3) it's easier.
		if (sym->symbol_list)
			error_die(token->pos, "redefinition of %s", show_typename (sym));
		sym->pos = *repos;

		// Mark the structure as needing re-examination
		sym->examined = 0;
	} else if (match_op(token, '{')) {
		// private struct/union/enum type
		sym = alloc_symbol(token->pos, type);
		set_current_scope(sym);		// used by dissect
		ctx->ctype.base_type = sym;
	} else {
		sparse_error(token->pos, "expected declaration");
		ctx->ctype.base_type = &bad_ctype;
		return token;
	}

	token = parse(token->next, sym);
	token = expect(token, '}', "at end of specifier");
	attr.ctype.base_type = sym;
	token = handle_attributes(token, &attr);
	apply_ctype(token->pos, &sym->ctype, &attr.ctype);
	sym->packed = attr.packed;

	sym->endpos = token->pos;

	return token;
}

static struct token *parse_struct_declaration(struct token *token, struct symbol *sym)
{
	struct symbol *field, *last = NULL;
	struct token *res;
	res = struct_declaration_list(token, &sym->symbol_list);
	FOR_EACH_PTR(sym->symbol_list, field) {
		if (!field->ident) {
			struct symbol *base = field->ctype.base_type;
			if (base && base->type == SYM_BITFIELD)
				continue;
		}
		if (last)
			last->next_subobject = field;
		last = field;
	} END_FOR_EACH_PTR(field);
	return res;
}

static struct token *parse_union_declaration(struct token *token, struct symbol *sym)
{
	return struct_declaration_list(token, &sym->symbol_list);
}

static struct token *struct_specifier(struct token *token, struct symbol *sym, struct decl_state *ctx)
{
	return struct_union_enum_specifier(SYM_STRUCT, token, ctx, parse_struct_declaration);
}

static struct token *union_specifier(struct token *token, struct symbol *sym, struct decl_state *ctx)
{
	return struct_union_enum_specifier(SYM_UNION, token, ctx, parse_union_declaration);
}

///
// safe right shift
//
// This allow to use a shift amount as big (or bigger)
// than the width of the value to be shifted, in which case
// the result is, of course, 0.
static unsigned long long rshift(unsigned long long val, unsigned int n)
{
	if (n >= (sizeof(val) * 8))
		return 0;
	return val >> n;
}

struct range {
	long long		neg;
	unsigned long long	pos;
};

static void update_range(struct range *range, unsigned long long uval, struct symbol *vtype)
{
	long long sval = uval;

	if (is_signed_type(vtype) && (sval < 0)) {
		if (sval < range->neg)
			range->neg = sval;
	} else {
		if (uval > range->pos)
			range->pos = uval;
	}
}

static int type_is_ok(struct symbol *type, struct range range)
{
	int shift = type->bit_size;
	int is_unsigned = type->ctype.modifiers & MOD_UNSIGNED;

	if (!is_unsigned)
		shift--;
	if (rshift(range.pos, shift))
		return 0;
	if (range.neg == 0)
		return 1;
	if (is_unsigned)
		return 0;
	if (rshift(~range.neg, shift))
		return 0;
	return 1;
}

static struct range type_range(struct symbol *type)
{
	struct range range;
	unsigned int size = type->bit_size;
	unsigned long long max;
	long long min;

	if (is_signed_type(type)) {
		min = sign_bit(size);
		max = min - 1;
	} else {
		min = 0;
		max = bits_mask(size);
	}

	range.pos = max;
	range.neg = min;
	return range;
}

static int val_in_range(struct range *range, long long sval, struct symbol *vtype)
{
	unsigned long long uval = sval;

	if (is_signed_type(vtype) && (sval < 0))
		return range->neg <= sval;
	else
		return uval <= range->pos;
}

static void cast_enum_list(struct symbol_list *list, struct symbol *base_type)
{
	struct range irange = type_range(&int_ctype);
	struct symbol *sym;

	FOR_EACH_PTR(list, sym) {
		struct expression *expr = sym->initializer;
		struct symbol *ctype;
		long long val;
		if (expr->type != EXPR_VALUE)
			continue;
		ctype = expr->ctype;
		val = get_expression_value(expr);
		if (is_int_type(ctype) && val_in_range(&irange, val, ctype)) {
			expr->ctype = &int_ctype;
			continue;
		}
		cast_value(expr, base_type, expr, ctype);
		expr->ctype = base_type;
	} END_FOR_EACH_PTR(sym);
}

static struct token *parse_enum_declaration(struct token *token, struct symbol *parent)
{
	unsigned long long lastval = 0;
	struct symbol *ctype = NULL, *base_type = NULL;
	struct range range = { };
	int mix_bitwise = 0;

	parent->examined = 1;
	parent->ctype.base_type = &int_ctype;
	while (token_type(token) == TOKEN_IDENT) {
		struct expression *expr = NULL;
		struct token *next = token->next;
		struct decl_state ctx = { };
		struct symbol *sym;

		// FIXME: only 'deprecated' should be accepted
		next = handle_attributes(next, &ctx);

		if (match_op(next, '=')) {
			next = constant_expression(next->next, &expr);
			lastval = get_expression_value(expr);
			ctype = &void_ctype;
			if (expr && expr->ctype)
				ctype = expr->ctype;
		} else if (!ctype) {
			ctype = &int_ctype;
		} else if (is_int_type(ctype)) {
			lastval++;
		} else {
			error_die(token->pos, "can't increment the last enum member");
		}

		if (!expr) {
			expr = alloc_expression(token->pos, EXPR_VALUE);
			expr->value = lastval;
			expr->ctype = ctype;
		}

		sym = alloc_symbol(token->pos, SYM_NODE);
		bind_symbol(sym, token->ident, NS_SYMBOL);
		sym->ctype.modifiers &= ~MOD_ADDRESSABLE;
		sym->initializer = expr;
		sym->enum_member = 1;
		sym->ctype.base_type = parent;
		add_ptr_list(&parent->symbol_list, sym);

		if (base_type != &bad_ctype) {
			if (ctype->type == SYM_NODE)
				ctype = ctype->ctype.base_type;
			if (ctype->type == SYM_ENUM) {
				if (ctype == parent)
					ctype = base_type;
				else 
					ctype = ctype->ctype.base_type;
			}
			/*
			 * base_type rules:
			 *  - if all enums are of the same type, then
			 *    the base_type is that type (two first
			 *    cases)
			 *  - if enums are of different types, they
			 *    all have to be integer types, and the
			 *    base type is at least "int_ctype".
			 *  - otherwise the base_type is "bad_ctype".
			 */
			if (!base_type || ctype == &bad_ctype) {
				base_type = ctype;
			} else if (ctype == base_type) {
				/* nothing */
			} else if (is_int_type(base_type) && is_int_type(ctype)) {
				base_type = &int_ctype;
			} else if (is_restricted_type(base_type) != is_restricted_type(ctype)) {
				if (!mix_bitwise++) {
					warning(expr->pos, "mixed bitwiseness");
				}
			} else if (is_restricted_type(base_type) && base_type != ctype) {
				sparse_error(expr->pos, "incompatible restricted type");
				info(expr->pos, "   expected: %s", show_typename(base_type));
				info(expr->pos, "        got: %s", show_typename(ctype));
				base_type = &bad_ctype;
			} else if (base_type != &bad_ctype) {
				sparse_error(token->pos, "bad enum definition");
				base_type = &bad_ctype;
			}
			parent->ctype.base_type = base_type;
		}
		if (is_int_type(base_type)) {
			update_range(&range, lastval, ctype);
		}
		token = next;

		sym->endpos = token->pos;

		if (!match_op(token, ','))
			break;
		token = token->next;
	}
	if (!base_type) {
		sparse_error(token->pos, "empty enum definition");
		base_type = &bad_ctype;
	}
	else if (!is_int_type(base_type))
		;
	else if (type_is_ok(&uint_ctype, range))
		base_type = &uint_ctype;
	else if (type_is_ok(&int_ctype, range))
		base_type = &int_ctype;
	else if (type_is_ok(&ulong_ctype, range))
		base_type = &ulong_ctype;
	else if (type_is_ok(&long_ctype, range))
		base_type = &long_ctype;
	else if (type_is_ok(&ullong_ctype, range))
		base_type = &ullong_ctype;
	else if (type_is_ok(&llong_ctype, range))
		base_type = &llong_ctype;
	else
		base_type = &bad_ctype;
	parent->ctype.base_type = base_type;
	parent->ctype.modifiers |= (base_type->ctype.modifiers & MOD_UNSIGNED);
	parent->examined = 0;

	if (mix_bitwise)
		return token;
	cast_enum_list(parent->symbol_list, base_type);

	return token;
}

static struct token *enum_specifier(struct token *token, struct symbol *sym, struct decl_state *ctx)
{
	struct token *ret = struct_union_enum_specifier(SYM_ENUM, token, ctx, parse_enum_declaration);
	struct ctype *ctype = &ctx->ctype.base_type->ctype;

	if (!ctype->base_type)
		ctype->base_type = &incomplete_ctype;

	return ret;
}

static struct token *typeof_specifier(struct token *token, struct symbol *sym, struct decl_state *ctx)
{

	if (!match_op(token, '(')) {
		sparse_error(token->pos, "expected '(' after typeof");
		return token;
	}
	if (lookup_type(token->next)) {
		struct symbol *sym;
		token = typename(token->next, &sym, NULL);
		ctx->ctype.base_type = sym->ctype.base_type;
		apply_ctype(token->pos, &ctx->ctype, &sym->ctype);
	} else {
		struct symbol *typeof_sym = alloc_symbol(token->pos, SYM_TYPEOF);
		token = parse_expression(token->next, &typeof_sym->initializer);

		typeof_sym->endpos = token->pos;
		if (!typeof_sym->initializer) {
			sparse_error(token->pos, "expected expression after the '(' token");
			typeof_sym = &bad_ctype;
		}
		ctx->ctype.base_type = typeof_sym;
	}
	return expect(token, ')', "after typeof");
}

static struct token *autotype_specifier(struct token *token, struct symbol *sym, struct decl_state *ctx)
{
	ctx->ctype.base_type = &autotype_ctype;
	ctx->autotype = 1;
	return token;
}

static struct token *ignore_attribute(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	struct expression *expr = NULL;
	if (match_op(token, '('))
		token = parens_expression(token, &expr, "in attribute");
	return token;
}

static struct token *attribute_packed(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	if (!ctx->ctype.alignment) {
		ctx->ctype.alignment = 1;
		ctx->packed = 1;
	}
	return token;
}

static struct token *attribute_aligned(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	int alignment = max_alignment;
	struct expression *expr = NULL;

	if (match_op(token, '(')) {
		token = parens_expression(token, &expr, "in attribute");
		if (expr)
			alignment = const_expression_value(expr);
	}
	if (alignment & (alignment-1)) {
		warning(token->pos, "I don't like non-power-of-2 alignments");
		return token;
	} else if (alignment > ctx->ctype.alignment)
		ctx->ctype.alignment = alignment;
	return token;
}

static void apply_mod(struct position *pos, unsigned long *mods, unsigned long mod)
{
	if (*mods & mod & ~MOD_DUP_OK)
		warning(*pos, "duplicate %s", modifier_name(mod));
	*mods |= mod;
}

static void apply_qualifier(struct position *pos, struct ctype *ctx, unsigned long qual)
{
	apply_mod(pos, &ctx->modifiers, qual);
}

static struct token *attribute_modifier(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	apply_mod(&token->pos, &ctx->ctype.modifiers, attr->ctype.modifiers);
	return token;
}

static struct token *attribute_function(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	apply_mod(&token->pos, &ctx->f_modifiers, attr->ctype.modifiers);
	return token;
}

static struct token *attribute_bitwise(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	if (Wbitwise)
		attribute_modifier(token, attr, ctx);
	return token;
}

static struct ident *numerical_address_space(int asn)
{
	char buff[32];

	if (!asn)
		return NULL;
	sprintf(buff, "<asn:%d>", asn);
	return built_in_ident(buff);
}

static struct token *attribute_address_space(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	struct expression *expr = NULL;
	struct ident *as = NULL;
	struct token *next;

	token = expect(token, '(', "after address_space attribute");
	switch (token_type(token)) {
	case TOKEN_NUMBER:
		next = primary_expression(token, &expr);
		if (expr->type != EXPR_VALUE)
			goto invalid;
		as = numerical_address_space(expr->value);
		break;
	case TOKEN_IDENT:
		next = token->next;
		as = token->ident;
		break;
	default:
		next = token->next;
	invalid:
		as = NULL;
		warning(token->pos, "invalid address space name");
	}

	if (Waddress_space && as) {
		if (ctx->ctype.as)
			sparse_error(token->pos,
				     "multiple address spaces given: %s & %s",
				     show_as(ctx->ctype.as), show_as(as));
		ctx->ctype.as = as;
	}
	token = expect(next, ')', "after address_space attribute");
	return token;
}

static struct symbol *to_QI_mode(struct symbol *ctype)
{
	if (ctype->ctype.base_type != &int_type)
		return NULL;
	if (ctype == &char_ctype)
		return ctype;
	return ctype->ctype.modifiers & MOD_UNSIGNED ? &uchar_ctype
						     : &schar_ctype;
}

static struct symbol *to_HI_mode(struct symbol *ctype)
{
	if (ctype->ctype.base_type != &int_type)
		return NULL;
	return ctype->ctype.modifiers & MOD_UNSIGNED ? &ushort_ctype
						     : &sshort_ctype;
}

static struct symbol *to_SI_mode(struct symbol *ctype)
{
	if (ctype->ctype.base_type != &int_type)
		return NULL;
	return ctype->ctype.modifiers & MOD_UNSIGNED ? &uint_ctype
						     : &sint_ctype;
}

static struct symbol *to_DI_mode(struct symbol *ctype)
{
	if (ctype->ctype.base_type != &int_type)
		return NULL;
	return ctype->ctype.modifiers & MOD_UNSIGNED ? &ullong_ctype
						     : &sllong_ctype;
}

static struct symbol *to_TI_mode(struct symbol *ctype)
{
	if (ctype->ctype.base_type != &int_type)
		return NULL;
	return ctype->ctype.modifiers & MOD_UNSIGNED ? &uint128_ctype
						     : &sint128_ctype;
}

static struct symbol *to_pointer_mode(struct symbol *ctype)
{
	if (ctype->ctype.base_type != &int_type)
		return NULL;
	return ctype->ctype.modifiers & MOD_UNSIGNED ? uintptr_ctype
						     :  intptr_ctype;
}

static struct symbol *to_word_mode(struct symbol *ctype)
{
	if (ctype->ctype.base_type != &int_type)
		return NULL;
	return ctype->ctype.modifiers & MOD_UNSIGNED ? &ulong_ctype
						     : &slong_ctype;
}

static struct token *attribute_mode(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	token = expect(token, '(', "after mode attribute");
	if (token_type(token) == TOKEN_IDENT) {
		struct symbol *mode = lookup_keyword(token->ident, NS_KEYWORD);
		if (mode && mode->op->type & KW_MODE)
			ctx->mode = mode->op;
		else
			sparse_error(token->pos, "unknown mode attribute %s", show_ident(token->ident));
		token = token->next;
	} else
		sparse_error(token->pos, "expect attribute mode symbol\n");
	token = expect(token, ')', "after mode attribute");
	return token;
}

static struct token *attribute_context(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	struct context *context = alloc_context();
	struct expression *args[3];
	int idx = 0;

	token = expect(token, '(', "after context attribute");
	token = conditional_expression(token, &args[0]);
	token = expect(token, ',', "after context 1st argument");
	token = conditional_expression(token, &args[1]);
	if (match_op(token, ',')) {
		token = token->next;
		token = conditional_expression(token, &args[2]);
		token = expect(token, ')', "after context 3rd argument");
		context->context = args[0];
		idx++;
	} else {
		token = expect(token, ')', "after context 2nd argument");
	}
	context->in =  get_expression_value(args[idx++]);
	context->out = get_expression_value(args[idx++]);
	add_ptr_list(&ctx->ctype.contexts, context);
	return token;
}

static struct token *attribute_designated_init(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	if (ctx->ctype.base_type && ctx->ctype.base_type->type == SYM_STRUCT)
		ctx->ctype.base_type->designated_init = 1;
	else
		warning(token->pos, "attribute designated_init applied to non-structure type");
	return token;
}

static struct token *attribute_transparent_union(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	if (Wtransparent_union)
		warning(token->pos, "attribute __transparent_union__");

	if (ctx->ctype.base_type && ctx->ctype.base_type->type == SYM_UNION)
		ctx->ctype.base_type->transparent_union = 1;
	else
		warning(token->pos, "attribute __transparent_union__ applied to non-union type");
	return token;
}

static struct token *recover_unknown_attribute(struct token *token)
{
	struct expression *expr = NULL;

	if (Wunknown_attribute)
		warning(token->pos, "unknown attribute '%s'", show_ident(token->ident));
	token = token->next;
	if (match_op(token, '('))
		token = parens_expression(token, &expr, "in attribute");
	return token;
}

static struct token *attribute_specifier(struct token *token, struct symbol *sym, struct decl_state *ctx)
{
	token = expect(token, '(', "after attribute");
	token = expect(token, '(', "after attribute");

	while (token_type(token) == TOKEN_IDENT) {
		struct symbol *attr = lookup_keyword(token->ident, NS_KEYWORD);
		if (attr && attr->op->attribute)
			token = attr->op->attribute(token->next, attr, ctx);
		else
			token = recover_unknown_attribute(token);

		if (!match_op(token, ','))
			break;
		token = token->next;
	}

	token = expect(token, ')', "after attribute");
	token = expect(token, ')', "after attribute");
	return token;
}

static unsigned long decl_modifiers(struct decl_state *ctx)
{
	unsigned long mods = ctx->ctype.modifiers & MOD_DECLARE;
	ctx->ctype.modifiers &= ~MOD_DECLARE;
	return ctx->storage_class | mods;
}

static struct token *storage_specifier(struct token *next, struct symbol *sym, struct decl_state *ctx)
{
	int is_tls = ctx->ctype.modifiers & MOD_TLS;
	unsigned long class = sym->ctype.modifiers;
	const char *storage = modifier_name(class);

	/* __thread can be used alone, or with extern or static */
	if (is_tls && (class & ~(MOD_STATIC|MOD_EXTERN)))
		sparse_error(next->pos, "__thread cannot be used with '%s'", storage);
	else if (!ctx->storage_class)
		ctx->storage_class = class;
	else if (ctx->storage_class == class)
		sparse_error(next->pos, "duplicate %s", storage);
	else
		sparse_error(next->pos, "multiple storage classes");
	return next;
}

static struct token *thread_specifier(struct token *next, struct symbol *sym, struct decl_state *ctx)
{
	/* This GCC extension can be used alone, or with extern or static */
	if (!(ctx->storage_class & ~(MOD_STATIC|MOD_EXTERN))) {
		apply_qualifier(&next->pos, &ctx->ctype, MOD_TLS);
	} else {
		sparse_error(next->pos, "__thread cannot be used with '%s'",
			modifier_name(ctx->storage_class));
	}

	return next;
}

static struct token *attribute_force(struct token *token, struct symbol *attr, struct decl_state *ctx)
{
	ctx->forced = 1;
	return token;
}

static struct token *alignas_specifier(struct token *token, struct symbol *sym, struct decl_state *ctx)
{
	int alignment = 0;

	if (!match_op(token, '(')) {
		sparse_error(token->pos, "expected '(' after _Alignas");
		return token;
	}
	if (lookup_type(token->next)) {
		struct symbol *sym = NULL;
		token = typename(token->next, &sym, NULL);
		sym = examine_symbol_type(sym);
		alignment = sym->ctype.alignment;
		token = expect(token, ')', "after _Alignas(...");
	} else {
		struct expression *expr = NULL;
		token = parens_expression(token, &expr, "after _Alignas");
		if (!expr)
			return token;
		alignment = const_expression_value(expr);
	}

	if (alignment < 0) {
		warning(token->pos, "non-positive alignment");
		return token;
	}
	if (alignment & (alignment-1)) {
		warning(token->pos, "non-power-of-2 alignment");
		return token;
	}
	if (alignment > ctx->ctype.alignment)
		ctx->ctype.alignment = alignment;
	return token;
}

static struct token *generic_qualifier(struct token *next, struct symbol *sym, struct decl_state *ctx)
{
	apply_qualifier(&next->pos, &ctx->ctype, sym->ctype.modifiers);
	return next;
}

static void apply_ctype(struct position pos, struct ctype *dst, struct ctype *src)
{
	unsigned long mod = src->modifiers;

	if (mod)
		apply_qualifier(&pos, dst, mod);

	/* Context */
	concat_ptr_list((struct ptr_list *)src->contexts,
	                (struct ptr_list **)&dst->contexts);

	/* Alignment */
	if (src->alignment > dst->alignment)
		dst->alignment = src->alignment;

	/* Address space */
	if (src->as)
		dst->as = src->as;
}

static void specifier_conflict(struct position pos, int what, struct ident *new)
{
	const char *old;
	if (what & (Set_S | Set_T))
		goto Catch_all;
	if (what & Set_Char)
		old = "char";
	else if (what & Set_Double)
		old = "double";
	else if (what & Set_Float)
		old = "float";
	else if (what & Set_Signed)
		old = "signed";
	else if (what & Set_Unsigned)
		old = "unsigned";
	else if (what & Set_Short)
		old = "short";
	else if (what & Set_Long)
		old = "long";
	else
		old = "long long";
	sparse_error(pos, "impossible combination of type specifiers: %s %s",
			old, show_ident(new));
	return;

Catch_all:
	sparse_error(pos, "two or more data types in declaration specifiers");
}

static struct symbol * const int_types[] =
	{&char_ctype, &short_ctype, &int_ctype, &long_ctype, &llong_ctype, &int128_ctype};
static struct symbol * const signed_types[] =
	{&schar_ctype, &sshort_ctype, &sint_ctype, &slong_ctype, &sllong_ctype,
	 &sint128_ctype};
static struct symbol * const unsigned_types[] =
	{&uchar_ctype, &ushort_ctype, &uint_ctype, &ulong_ctype, &ullong_ctype,
	 &uint128_ctype};
static struct symbol * const real_types[] =
	{&float_ctype, &double_ctype, &ldouble_ctype};
static struct symbol * const * const types[] = {
	[CInt]  = int_types + 2,
	[CSInt] = signed_types + 2,
	[CUInt] = unsigned_types + 2,
	[CReal] = real_types + 1,
};

struct symbol *ctype_integer(int size, int want_unsigned)
{
	return types[want_unsigned ? CUInt : CInt][size];
}

static struct token *handle_qualifiers(struct token *t, struct decl_state *ctx)
{
	while (token_type(t) == TOKEN_IDENT) {
		struct symbol *s = lookup_keyword(t->ident, NS_TYPEDEF);
		if (!s)
			break;
		if (!(s->op->type & (KW_ATTRIBUTE | KW_QUALIFIER)))
			break;
		t = t->next;
		if (s->op->declarator)
			t = s->op->declarator(t, s, ctx);
	}
	return t;
}

static struct token *declaration_specifiers(struct token *token, struct decl_state *ctx)
{
	int seen = 0;
	int class = CInt;
	int rank = 0;

	while (token_type(token) == TOKEN_IDENT) {
		struct symbol *s = lookup_symbol(token->ident,
						 NS_TYPEDEF | NS_SYMBOL);
		if (!s || !(s->namespace & NS_TYPEDEF))
			break;
		if (s->type != SYM_KEYWORD) {
			if (seen & Set_Any)
				break;
			seen |= Set_S | Set_T;
			ctx->ctype.base_type = s->ctype.base_type;
			apply_ctype(token->pos, &ctx->ctype, &s->ctype);
			token = token->next;
			continue;
		}
		if (s->op->type & KW_SPECIFIER) {
			if (seen & s->op->test) {
				specifier_conflict(token->pos,
						   seen & s->op->test,
						   token->ident);
				break;
			}
			seen |= s->op->set;
			class += s->op->class;
			if (s->op->set & Set_Int128)
				rank = 3;
			else if (s->op->set & Set_Char)
				rank = -2;
			if (s->op->set & (Set_Short|Set_Float)) {
				rank = -1;
			} else if (s->op->set & Set_Long && rank++) {
				if (class == CReal) {
					specifier_conflict(token->pos,
							   Set_Vlong,
							   &double_ident);
					break;
				}
				seen |= Set_Vlong;
			}
		}
		token = token->next;
		if (s->op->declarator)	// Note: this eats attributes
			token = s->op->declarator(token, s, ctx);
		if (s->op->type & KW_EXACT) {
			ctx->ctype.base_type = s->ctype.base_type;
			ctx->ctype.modifiers |= s->ctype.modifiers;
		}
	}

	if (!(seen & Set_S)) {	/* not set explicitly? */
		struct symbol *base = &incomplete_ctype;
		if (seen & Set_Any)
			base = types[class][rank];
		ctx->ctype.base_type = base;
	}

	if (ctx->ctype.modifiers & MOD_BITWISE) {
		struct symbol *type;
		ctx->ctype.modifiers &= ~MOD_BITWISE;
		if (!is_int_type(ctx->ctype.base_type)) {
			sparse_error(token->pos, "invalid modifier");
			return token;
		}
		type = alloc_symbol(token->pos, SYM_BASETYPE);
		*type = *ctx->ctype.base_type;
		type->ctype.modifiers &= ~MOD_SPECIFIER;
		type->ctype.base_type = ctx->ctype.base_type;
		type->type = SYM_RESTRICT;
		ctx->ctype.base_type = type;
		create_fouled(type);
	}
	return token;
}

static struct token *abstract_array_declarator(struct token *token, struct symbol *sym)
{
	struct expression *expr = NULL;
	int has_static = 0;

	while (token_type(token) == TOKEN_IDENT) {
		struct symbol *sym = lookup_keyword(token->ident, NS_TYPEDEF);
		if (!sym || !(sym->op->type & (KW_STATIC|KW_QUALIFIER)))
			break;
		if (has_static && (sym->op->type & KW_STATIC))
			sparse_error(token->pos, "duplicate array static declarator");
		has_static |= (sym->op->type & KW_STATIC);
		token = token->next;
	}
	if (match_op(token, '*') && match_op(token->next, ']')) {
		// FIXME: '[*]' is treated like '[]'
		token = token->next;
	} else {
		token = assignment_expression(token, &expr);
	}
	sym->array_size = expr;
	return token;
}

static struct token *parameter_type_list(struct token *, struct symbol *);
static struct token *identifier_list(struct token *, struct symbol *);
static struct token *declarator(struct token *token, struct decl_state *ctx);

static struct token *handle_asm_name(struct token *token, struct decl_state *ctx)
{
	struct expression *expr;
	struct symbol *keyword;

	if (token_type(token) != TOKEN_IDENT)
		return token;
	keyword = lookup_keyword(token->ident, NS_KEYWORD);
	if (!keyword)
		return token;
	if (!(keyword->op->type & KW_ASM))
		return token;

	token = token->next;
	token = expect(token, '(', "after asm");
	token = string_expression(token, &expr, "asm name");
	token = expect(token, ')', "after asm");
	return token;
}

///
// test if @token is '__attribute__' (or one of its variant)
static bool match_attribute(struct token *token)
{
	struct symbol *sym;

	if (token_type(token) != TOKEN_IDENT)
		return false;
	sym = lookup_keyword(token->ident, NS_TYPEDEF);
	if (!sym || !sym->op)
		return false;
	return sym->op->type & KW_ATTRIBUTE;
}

static struct token *skip_attribute(struct token *token)
{
	token = token->next;
	if (match_op(token, '(')) {
		int depth = 1;
		token = token->next;
		while (depth && !eof_token(token)) {
			if (token_type(token) == TOKEN_SPECIAL) {
				if (token->special == '(')
					depth++;
				else if (token->special == ')')
					depth--;
			}
			token = token->next;
		}
	}
	return token;
}

static struct token *skip_attributes(struct token *token)
{
	while (match_attribute(token)) {
		token = expect(token->next, '(', "after attribute");
		token = expect(token, '(', "after attribute");
		while (token_type(token) == TOKEN_IDENT) {
			token = skip_attribute(token);
			if (!match_op(token, ','))
				break;
			token = token->next;
		}
		token = expect(token, ')', "after attribute");
		token = expect(token, ')', "after attribute");
	}
	return token;
}

static struct token *handle_attributes(struct token *token, struct decl_state *ctx)
{
	while (match_attribute(token))
		token = attribute_specifier(token->next, NULL, ctx);
	return token;
}

static int is_nested(struct token *token, struct token **p,
		    int prefer_abstract)
{
	/*
	 * This can be either a parameter list or a grouping.
	 * For the direct (non-abstract) case, we know if must be
	 * a parameter list if we already saw the identifier.
	 * For the abstract case, we know if must be a parameter
	 * list if it is empty or starts with a type.
	 */
	struct token *next = token->next;

	*p = next = skip_attributes(next);

	if (token_type(next) == TOKEN_IDENT) {
		if (lookup_type(next))
			return !prefer_abstract;
		return 1;
	}

	if (match_op(next, ')') || match_op(next, SPECIAL_ELLIPSIS))
		return 0;

	return 1;
}

enum kind {
	Empty, K_R, Proto, Bad_Func,
};

static enum kind which_func(struct token *token,
			    struct ident **n,
			    int prefer_abstract)
{
	struct token *next = token->next;

	if (token_type(next) == TOKEN_IDENT) {
		if (lookup_type(next))
			return Proto;
		/* identifier list not in definition; complain */
		if (prefer_abstract)
			warning(token->pos,
				"identifier list not in definition");
		return K_R;
	}

	if (token_type(next) != TOKEN_SPECIAL)
		return Bad_Func;

	if (next->special == ')') {
		/* don't complain about those */
		if (!n || match_op(next->next, ';') || match_op(next->next, ','))
			return Empty;
		if (Wstrict_prototypes)
			warning(next->pos,
				"non-ANSI function declaration of function '%s'",
				show_ident(*n));
		return Empty;
	}

	if (next->special == SPECIAL_ELLIPSIS) {
		warning(next->pos,
			"variadic functions must have one named argument");
		return Proto;
	}

	return Bad_Func;
}

static struct token *direct_declarator(struct token *token, struct decl_state *ctx)
{
	struct ctype *ctype = &ctx->ctype;
	struct token *next;
	struct ident **p = ctx->ident;

	if (ctx->ident && token_type(token) == TOKEN_IDENT) {
		*ctx->ident = token->ident;
		token = token->next;
	} else if (match_op(token, '(') &&
	    is_nested(token, &next, ctx->prefer_abstract)) {
		struct symbol *base_type = ctype->base_type;
		if (token->next != next)
			next = handle_attributes(token->next, ctx);
		token = declarator(next, ctx);
		token = expect(token, ')', "in nested declarator");
		while (ctype->base_type != base_type)
			ctype = &ctype->base_type->ctype;
		p = NULL;
	}

	if (match_op(token, '(')) {
		enum kind kind = which_func(token, p, ctx->prefer_abstract);
		struct symbol *fn;
		fn = alloc_indirect_symbol(token->pos, ctype, SYM_FN);
		ctype->modifiers |= ctx->f_modifiers;
		token = token->next;
		if (kind == K_R)
			token = identifier_list(token, fn);
		else if (kind == Proto)
			token = parameter_type_list(token, fn);
		token = expect(token, ')', "in function declarator");
		fn->endpos = token->pos;
		return token;
	}

	while (match_op(token, '[')) {
		struct symbol *array;
		array = alloc_indirect_symbol(token->pos, ctype, SYM_ARRAY);
		token = abstract_array_declarator(token->next, array);
		token = expect(token, ']', "in abstract_array_declarator");
		array->endpos = token->pos;
		ctype = &array->ctype;
	}
	return token;
}

static struct token *pointer(struct token *token, struct decl_state *ctx)
{
	while (match_op(token,'*')) {
		struct symbol *ptr = alloc_symbol(token->pos, SYM_PTR);
		ptr->ctype.modifiers = ctx->ctype.modifiers;
		ptr->ctype.base_type = ctx->ctype.base_type;
		ptr->ctype.as = ctx->ctype.as;
		ptr->ctype.contexts = ctx->ctype.contexts;
		ctx->ctype.modifiers = 0;
		ctx->ctype.base_type = ptr;
		ctx->ctype.as = NULL;
		ctx->ctype.contexts = NULL;
		ctx->ctype.alignment = 0;

		token = handle_qualifiers(token->next, ctx);
		ctx->ctype.base_type->endpos = token->pos;
	}
	return token;
}

static struct token *declarator(struct token *token, struct decl_state *ctx)
{
	token = pointer(token, ctx);
	return direct_declarator(token, ctx);
}

static struct token *handle_bitfield(struct token *token, struct decl_state *ctx)
{
	struct ctype *ctype = &ctx->ctype;
	struct expression *expr;
	struct symbol *bitfield;
	long long width;

	if (ctype->base_type != &int_type && !is_int_type(ctype->base_type)) {
		sparse_error(token->pos, "invalid bitfield specifier for type %s.",
			show_typename(ctype->base_type));
		// Parse this to recover gracefully.
		return conditional_expression(token->next, &expr);
	}

	bitfield = alloc_indirect_symbol(token->pos, ctype, SYM_BITFIELD);
	token = conditional_expression(token->next, &expr);
	width = const_expression_value(expr);
	bitfield->bit_size = width;

	if (width < 0 || width > INT_MAX || (*ctx->ident && width == 0)) {
		sparse_error(token->pos, "bitfield '%s' has invalid width (%lld)",
			show_ident(*ctx->ident), width);
		width = -1;
	} else if (*ctx->ident) {
		struct symbol *base_type = bitfield->ctype.base_type;
		struct symbol *bitfield_type = base_type == &int_type ? bitfield : base_type;
		int is_signed = !(bitfield_type->ctype.modifiers & MOD_UNSIGNED);
		if (Wone_bit_signed_bitfield && width == 1 && is_signed) {
			// Valid values are either {-1;0} or {0}, depending on integer
			// representation.  The latter makes for very efficient code...
			sparse_error(token->pos, "dubious one-bit signed bitfield");
		}
		if (Wdefault_bitfield_sign &&
		    bitfield_type->type != SYM_ENUM &&
		    !(bitfield_type->ctype.modifiers & MOD_EXPLICITLY_SIGNED) &&
		    is_signed) {
			// The sign of bitfields is unspecified by default.
			warning(token->pos, "dubious bitfield without explicit `signed' or `unsigned'");
		}
	}
	bitfield->bit_size = width;
	bitfield->endpos = token->pos;
	bitfield->ident = *ctx->ident;
	return token;
}

static struct token *declaration_list(struct token *token, struct symbol_list **list)
{
	struct decl_state ctx = {.prefer_abstract = 0};
	struct ctype saved;
	unsigned long mod;

	token = declaration_specifiers(token, &ctx);
	mod = decl_modifiers(&ctx);
	saved = ctx.ctype;
	for (;;) {
		struct symbol *decl = alloc_symbol(token->pos, SYM_NODE);
		ctx.ident = &decl->ident;

		token = declarator(token, &ctx);
		if (match_op(token, ':'))
			token = handle_bitfield(token, &ctx);

		token = handle_attributes(token, &ctx);
		apply_modifiers(token->pos, &ctx);

		decl->ctype = ctx.ctype;
		decl->ctype.modifiers |= mod;
		decl->endpos = token->pos;
		add_symbol(list, decl);
		if (!match_op(token, ','))
			break;
		token = token->next;
		ctx.ctype = saved;
	}
	return token;
}

static struct token *struct_declaration_list(struct token *token, struct symbol_list **list)
{
	while (!match_op(token, '}')) {
		if (match_ident(token, &_Static_assert_ident)) {
			token = parse_static_assert(token, NULL);
			continue;
		}
		if (!match_op(token, ';'))
			token = declaration_list(token, list);
		if (!match_op(token, ';')) {
			sparse_error(token->pos, "expected ; at end of declaration");
			break;
		}
		token = token->next;
	}
	return token;
}

static struct token *parameter_declaration(struct token *token, struct symbol *sym)
{
	struct decl_state ctx = {.prefer_abstract = 1};

	token = declaration_specifiers(token, &ctx);
	ctx.ident = &sym->ident;
	token = declarator(token, &ctx);
	token = handle_attributes(token, &ctx);
	apply_modifiers(token->pos, &ctx);
	sym->ctype = ctx.ctype;
	sym->ctype.modifiers |= decl_modifiers(&ctx);
	sym->endpos = token->pos;
	sym->forced_arg = ctx.forced;
	return token;
}

struct token *typename(struct token *token, struct symbol **p, int *forced)
{
	struct decl_state ctx = {.prefer_abstract = 1};
	unsigned long class;
	struct symbol *sym = alloc_symbol(token->pos, SYM_NODE);
	*p = sym;
	token = declaration_specifiers(token, &ctx);
	token = declarator(token, &ctx);
	apply_modifiers(token->pos, &ctx);
	sym->ctype = ctx.ctype;
	sym->endpos = token->pos;
	class = ctx.storage_class;
	if (forced)
		*forced = ctx.forced;
	if (class)
		warning(sym->pos, "storage class in typename (%s%s)",
			modifier_string(class), show_typename(sym));
	return token;
}

static struct token *expression_statement(struct token *token, struct expression **tree)
{
	token = parse_expression(token, tree);
	return expect(token, ';', "at end of statement");
}

static struct token *parse_asm_operands(struct token *token, struct statement *stmt,
	struct asm_operand_list **inout)
{
	/* Allow empty operands */
	if (match_op(token->next, ':') || match_op(token->next, ')'))
		return token->next;
	do {
		struct asm_operand *op = __alloc_asm_operand(0);
		if (match_op(token->next, '[') &&
		    token_type(token->next->next) == TOKEN_IDENT &&
		    match_op(token->next->next->next, ']')) {
			op->name = token->next->next->ident;
			token = token->next->next->next;
		}
		token = token->next;
		token = string_expression(token, &op->constraint, "asm constraint");
		token = parens_expression(token, &op->expr, "in asm parameter");
		add_ptr_list(inout, op);
	} while (match_op(token, ','));
	return token;
}

static struct token *parse_asm_clobbers(struct token *token, struct statement *stmt,
	struct expression_list **clobbers)
{
	struct expression *expr;

	do {
		token = primary_expression(token->next, &expr);
		if (expr)
			add_expression(clobbers, expr);
	} while (match_op(token, ','));
	return token;
}

static struct token *parse_asm_labels(struct token *token, struct statement *stmt,
		        struct symbol_list **labels)
{
	struct symbol *label;

	do {
		token = token->next; /* skip ':' and ',' */
		if (token_type(token) != TOKEN_IDENT)
			return token;
		label = label_symbol(token, 1);
		add_symbol(labels, label);
		token = token->next;
	} while (match_op(token, ','));
	return token;
}

static struct token *parse_asm_statement(struct token *token, struct statement *stmt)
{
	unsigned long mods = 0;

	token = token->next;
	stmt->type = STMT_ASM;
	while (token_type(token) == TOKEN_IDENT) {
		struct symbol *s = lookup_keyword(token->ident, NS_TYPEDEF);
		if (s && s->op->asm_modifier)
			s->op->asm_modifier(token, &mods, s->ctype.modifiers);
		else if (token->ident == &goto_ident)
			asm_modifier(token, &mods, MOD_ASM_GOTO);
		token = token->next;
	}
	token = expect(token, '(', "after asm");
	token = string_expression(token, &stmt->asm_string, "inline asm");
	if (match_op(token, ':'))
		token = parse_asm_operands(token, stmt, &stmt->asm_outputs);
	if (match_op(token, ':'))
		token = parse_asm_operands(token, stmt, &stmt->asm_inputs);
	if (match_op(token, ':'))
		token = parse_asm_clobbers(token, stmt, &stmt->asm_clobbers);
	if (match_op(token, ':') && (mods & MOD_ASM_GOTO))
		token = parse_asm_labels(token, stmt, &stmt->asm_labels);
	token = expect(token, ')', "after asm");
	return expect(token, ';', "at end of asm-statement");
}

static struct token *parse_static_assert(struct token *token, struct symbol_list **unused)
{
	struct expression *cond = NULL, *message = NULL;

	token = expect(token->next, '(', "after _Static_assert");
	token = constant_expression(token, &cond);
	if (!cond)
		sparse_error(token->pos, "Expected constant expression");
	if (match_op(token, ',')) {
		token = token->next;
		token = string_expression(token, &message, "_Static_assert()");
		if (!message)
			cond = NULL;
	}
	token = expect(token, ')', "after diagnostic message in _Static_assert");
	token = expect(token, ';', "after _Static_assert()");

	if (cond && !const_expression_value(cond) && cond->type == EXPR_VALUE) {
		const char *sep = "", *msg = "";

		if (message) {
			sep = ": ";
			msg = show_string(message->string);
		}
		sparse_error(cond->pos, "static assertion failed%s%s", sep, msg);
	}

	return token;
}

/* Make a statement out of an expression */
static struct statement *make_statement(struct expression *expr)
{
	struct statement *stmt;

	if (!expr)
		return NULL;
	stmt = alloc_statement(expr->pos, STMT_EXPRESSION);
	stmt->expression = expr;
	return stmt;
}

/*
 * All iterators have two symbols associated with them:
 * the "continue" and "break" symbols, which are targets
 * for continue and break statements respectively.
 *
 * They are in a special name-space, but they follow
 * all the normal visibility rules, so nested iterators
 * automatically work right.
 */
static void start_iterator(struct statement *stmt)
{
	struct symbol *cont, *brk;

	start_block_scope();
	cont = alloc_symbol(stmt->pos, SYM_NODE);
	bind_symbol(cont, &continue_ident, NS_ITERATOR);
	brk = alloc_symbol(stmt->pos, SYM_NODE);
	bind_symbol(brk, &break_ident, NS_ITERATOR);

	stmt->type = STMT_ITERATOR;
	stmt->iterator_break = brk;
	stmt->iterator_continue = cont;
	fn_local_symbol(brk);
	fn_local_symbol(cont);
}

static void end_iterator(struct statement *stmt)
{
	end_block_scope();
}

static struct statement *start_function(struct symbol *sym)
{
	struct symbol *ret;
	struct statement *stmt = alloc_statement(sym->pos, STMT_COMPOUND);

	start_function_scope();
	ret = alloc_symbol(sym->pos, SYM_NODE);
	ret->ctype = sym->ctype.base_type->ctype;
	ret->ctype.modifiers &= ~(MOD_STORAGE | MOD_QUALIFIER | MOD_TLS | MOD_ACCESS | MOD_NOCAST | MOD_NODEREF);
	ret->ctype.modifiers |= (MOD_AUTO | MOD_REGISTER);
	bind_symbol(ret, &return_ident, NS_ITERATOR);
	stmt->ret = ret;
	fn_local_symbol(ret);

	// Currently parsed symbol for __func__/__FUNCTION__/__PRETTY_FUNCTION__
	current_fn = sym;

	return stmt;
}

static void end_function(struct symbol *sym)
{
	current_fn = NULL;
	end_function_scope();
}

/*
 * A "switch()" statement, like an iterator, has a
 * the "break" symbol associated with it. It works
 * exactly like the iterator break - it's the target
 * for any break-statements in scope, and means that
 * "break" handling doesn't even need to know whether
 * it's breaking out of an iterator or a switch.
 *
 * In addition, the "case" symbol is a marker for the
 * case/default statements to find the switch statement
 * that they are associated with.
 */
static void start_switch(struct statement *stmt)
{
	struct symbol *brk, *switch_case;

	start_block_scope();
	brk = alloc_symbol(stmt->pos, SYM_NODE);
	bind_symbol(brk, &break_ident, NS_ITERATOR);

	switch_case = alloc_symbol(stmt->pos, SYM_NODE);
	bind_symbol(switch_case, &case_ident, NS_ITERATOR);
	switch_case->stmt = stmt;

	stmt->type = STMT_SWITCH;
	stmt->switch_break = brk;
	stmt->switch_case = switch_case;

	fn_local_symbol(brk);
	fn_local_symbol(switch_case);
}

static void end_switch(struct statement *stmt)
{
	if (!stmt->switch_case->symbol_list)
		warning(stmt->pos, "switch with no cases");
	end_block_scope();
}

static void add_case_statement(struct statement *stmt)
{
	struct symbol *target = lookup_symbol(&case_ident, NS_ITERATOR);
	struct symbol *sym;

	if (!target) {
		sparse_error(stmt->pos, "not in switch scope");
		stmt->type = STMT_NONE;
		return;
	}
	sym = alloc_symbol(stmt->pos, SYM_NODE);
	add_symbol(&target->symbol_list, sym);
	sym->stmt = stmt;
	stmt->case_label = sym;
	fn_local_symbol(sym);
}

static struct token *parse_return_statement(struct token *token, struct statement *stmt)
{
	struct symbol *target = lookup_symbol(&return_ident, NS_ITERATOR);

	if (!target)
		error_die(token->pos, "internal error: return without a function target");
	stmt->type = STMT_RETURN;
	stmt->ret_target = target;
	return expression_statement(token->next, &stmt->ret_value);
}

static void validate_for_loop_decl(struct symbol *sym)
{
	unsigned long storage = sym->ctype.modifiers & MOD_STORAGE;

	if (storage & ~(MOD_AUTO | MOD_REGISTER)) {
		const char *name = show_ident(sym->ident);
		sparse_error(sym->pos, "non-local var '%s' in for-loop initializer", name);
		sym->ctype.modifiers &= ~MOD_STORAGE;
	}
}

static struct token *parse_for_statement(struct token *token, struct statement *stmt)
{
	struct symbol_list *syms;
	struct expression *e1, *e2, *e3;
	struct statement *iterator;

	start_iterator(stmt);
	token = expect(token->next, '(', "after 'for'");

	syms = NULL;
	e1 = NULL;
	/* C99 variable declaration? */
	if (lookup_type(token)) {
		token = external_declaration(token, &syms, validate_for_loop_decl);
	} else {
		token = parse_expression(token, &e1);
		token = expect(token, ';', "in 'for'");
	}
	token = parse_expression(token, &e2);
	token = expect(token, ';', "in 'for'");
	token = parse_expression(token, &e3);
	token = expect(token, ')', "in 'for'");
	token = statement(token, &iterator);

	stmt->iterator_syms = syms;
	stmt->iterator_pre_statement = make_statement(e1);
	stmt->iterator_pre_condition = e2;
	stmt->iterator_post_statement = make_statement(e3);
	stmt->iterator_post_condition = NULL;
	stmt->iterator_statement = iterator;
	end_iterator(stmt);

	return token;
}

static struct token *parse_while_statement(struct token *token, struct statement *stmt)
{
	struct expression *expr;
	struct statement *iterator;

	start_iterator(stmt);
	token = parens_expression(token->next, &expr, "after 'while'");
	token = statement(token, &iterator);

	stmt->iterator_pre_condition = expr;
	stmt->iterator_post_condition = NULL;
	stmt->iterator_statement = iterator;
	end_iterator(stmt);

	return token;
}

static struct token *parse_do_statement(struct token *token, struct statement *stmt)
{
	struct expression *expr;
	struct statement *iterator;

	start_iterator(stmt);
	token = statement(token->next, &iterator);
	if (token_type(token) == TOKEN_IDENT && token->ident == &while_ident)
		token = token->next;
	else
		sparse_error(token->pos, "expected 'while' after 'do'");
	token = parens_expression(token, &expr, "after 'do-while'");

	stmt->iterator_post_condition = expr;
	stmt->iterator_statement = iterator;
	end_iterator(stmt);

	if (iterator && iterator->type != STMT_COMPOUND && Wdo_while)
		warning(iterator->pos, "do-while statement is not a compound statement");

	return expect(token, ';', "after statement");
}

static struct token *parse_if_statement(struct token *token, struct statement *stmt)
{
	stmt->type = STMT_IF;
	token = parens_expression(token->next, &stmt->if_conditional, "after if");
	token = statement(token, &stmt->if_true);
	if (token_type(token) != TOKEN_IDENT)
		return token;
	if (token->ident != &else_ident)
		return token;
	return statement(token->next, &stmt->if_false);
}

static inline struct token *case_statement(struct token *token, struct statement *stmt)
{
	stmt->type = STMT_CASE;
	token = expect(token, ':', "after default/case");
	add_case_statement(stmt);
	return statement(token, &stmt->case_statement);
}

static struct token *parse_case_statement(struct token *token, struct statement *stmt)
{
	token = parse_expression(token->next, &stmt->case_expression);
	if (match_op(token, SPECIAL_ELLIPSIS))
		token = parse_expression(token->next, &stmt->case_to);
	return case_statement(token, stmt);
}

static struct token *parse_default_statement(struct token *token, struct statement *stmt)
{
	return case_statement(token->next, stmt);
}

static struct token *parse_loop_iterator(struct token *token, struct statement *stmt)
{
	struct symbol *target = lookup_symbol(token->ident, NS_ITERATOR);
	stmt->type = STMT_GOTO;
	stmt->goto_label = target;
	if (!target)
		sparse_error(stmt->pos, "break/continue not in iterator scope");
	return expect(token->next, ';', "at end of statement");
}

static struct token *parse_switch_statement(struct token *token, struct statement *stmt)
{
	stmt->type = STMT_SWITCH;
	start_switch(stmt);
	token = parens_expression(token->next, &stmt->switch_expression, "after 'switch'");
	token = statement(token, &stmt->switch_statement);
	end_switch(stmt);
	return token;
}

static void warn_label_usage(struct position def, struct position use, struct ident *ident)
{
	const char *id = show_ident(ident);
	sparse_error(use, "label '%s' used outside statement expression", id);
	info(def, "   label '%s' defined here", id);
	current_fn->bogus_linear = 1;
}

void check_label_usage(struct symbol *label, struct position use_pos)
{
	struct statement *def = label->stmt;

	if (def) {
		if (!is_in_scope(def->label_scope, label_scope))
			warn_label_usage(def->pos, use_pos, label->ident);
	} else if (!label->label_scope) {
		label->label_scope = label_scope;
		label->label_pos = use_pos;
	}
}

static struct token *parse_goto_statement(struct token *token, struct statement *stmt)
{
	stmt->type = STMT_GOTO;
	token = token->next;
	if (match_op(token, '*')) {
		token = parse_expression(token->next, &stmt->goto_expression);
		add_statement(&function_computed_goto_list, stmt);
	} else if (token_type(token) == TOKEN_IDENT) {
		struct symbol *label = label_symbol(token, 1);
		stmt->goto_label = label;
		check_label_usage(label, stmt->pos);
		token = token->next;
	} else {
		sparse_error(token->pos, "Expected identifier or goto expression");
	}
	return expect(token, ';', "at end of statement");
}

static struct token *parse_context_statement(struct token *token, struct statement *stmt)
{
	stmt->type = STMT_CONTEXT;
	token = token->next;
	token = expect(token, '(', "after __context__ statement");
	token = assignment_expression(token, &stmt->expression);
	if (!stmt->expression)
		unexpected(token, "expression expected after '('");
	if (match_op(token, ',')) {
		token = token->next;
		stmt->context = stmt->expression;
		token = assignment_expression(token, &stmt->expression);
		if (!stmt->expression)
			unexpected(token, "expression expected after ','");
	}
	token = expect(token, ')', "at end of __context__ statement");
	return expect(token, ';', "at end of statement");
}

static struct token *parse_range_statement(struct token *token, struct statement *stmt)
{
	stmt->type = STMT_RANGE;
	token = token->next;
	token = expect(token, '(', "after __range__ statement");
	token = assignment_expression(token, &stmt->range_expression);
	token = expect(token, ',', "after range expression");
	token = assignment_expression(token, &stmt->range_low);
	token = expect(token, ',', "after low range");
	token = assignment_expression(token, &stmt->range_high);
	token = expect(token, ')', "after range statement");
	return expect(token, ';', "after range statement");
}

static struct token *handle_label_attributes(struct token *token, struct symbol *label)
{
	struct decl_state ctx = { };

	token = handle_attributes(token, &ctx);
	label->label_modifiers = ctx.ctype.modifiers;
	return token;
}

static struct token *statement(struct token *token, struct statement **tree)
{
	struct statement *stmt = alloc_statement(token->pos, STMT_NONE);

	*tree = stmt;
	if (token_type(token) == TOKEN_IDENT) {
		struct symbol *s = lookup_keyword(token->ident, NS_KEYWORD);
		if (s && s->op->statement)
			return s->op->statement(token, stmt);

		if (match_op(token->next, ':')) {
			struct symbol *s = label_symbol(token, 0);
			token = handle_label_attributes(token->next->next, s);
			if (s->stmt) {
				sparse_error(stmt->pos, "label '%s' redefined", show_ident(s->ident));
				// skip the label to avoid multiple definitions
				return statement(token, tree);
			}
			stmt->type = STMT_LABEL;
			stmt->label_identifier = s;
			stmt->label_scope = label_scope;
			if (s->label_scope) {
				if (!is_in_scope(label_scope, s->label_scope))
					warn_label_usage(stmt->pos, s->label_pos, s->ident);
			}
			s->stmt = stmt;
			if (match_op(token, '}')) {
				warning(token->pos, "statement expected after label");
				stmt->label_statement = alloc_statement(token->pos, STMT_NONE);
				return token;
			}
			return statement(token, &stmt->label_statement);
		}
	}

	if (match_op(token, '{')) {
		token = compound_statement(token->next, stmt);
		return expect(token, '}', "at end of compound statement");
	}
			
	stmt->type = STMT_EXPRESSION;
	return expression_statement(token, &stmt->expression);
}

/* gcc extension - __label__ ident-list; in the beginning of compound stmt */
static struct token *label_statement(struct token *token)
{
	while (token_type(token) == TOKEN_IDENT) {
		struct symbol *sym = alloc_symbol(token->pos, SYM_LABEL);
		/* it's block-scope, but we want label namespace */
		bind_symbol_with_scope(sym, token->ident, NS_LABEL, block_scope);
		fn_local_symbol(sym);
		token = token->next;
		if (!match_op(token, ','))
			break;
		token = token->next;
	}
	return expect(token, ';', "at end of label declaration");
}

static struct token * statement_list(struct token *token, struct statement_list **list)
{
	int seen_statement = 0;
	while (token_type(token) == TOKEN_IDENT &&
	       token->ident == &__label___ident)
		token = label_statement(token->next);
	for (;;) {
		struct statement * stmt;
		if (eof_token(token))
			break;
		if (match_op(token, '}'))
			break;
		if (match_ident(token, &_Static_assert_ident)) {
			token = parse_static_assert(token, NULL);
			continue;
		}
		if (lookup_type(token)) {
			if (seen_statement) {
				warning(token->pos, "mixing declarations and code");
				seen_statement = 0;
			}
			stmt = alloc_statement(token->pos, STMT_DECLARATION);
			token = external_declaration(token, &stmt->declaration, NULL);
		} else {
			seen_statement = Wdeclarationafterstatement;
			token = statement(token, &stmt);
		}
		add_statement(list, stmt);
	}
	return token;
}

static struct token *identifier_list(struct token *token, struct symbol *fn)
{
	struct symbol_list **list = &fn->arguments;
	for (;;) {
		struct symbol *sym = alloc_symbol(token->pos, SYM_NODE);
		sym->ident = token->ident;
		token = token->next;
		sym->endpos = token->pos;
		sym->ctype.base_type = &incomplete_ctype;
		add_symbol(list, sym);
		if (!match_op(token, ',') ||
		    token_type(token->next) != TOKEN_IDENT ||
		    lookup_type(token->next))
			break;
		token = token->next;
	}
	return token;
}

static struct token *parameter_type_list(struct token *token, struct symbol *fn)
{
	struct symbol_list **list = &fn->arguments;

	for (;;) {
		struct symbol *sym;

		if (match_op(token, SPECIAL_ELLIPSIS)) {
			fn->variadic = 1;
			token = token->next;
			break;
		}

		sym = alloc_symbol(token->pos, SYM_NODE);
		token = parameter_declaration(token, sym);
		if (sym->ctype.base_type == &void_ctype) {
			/* Special case: (void) */
			if (!*list && !sym->ident)
				break;
			warning(token->pos, "void parameter");
		}
		add_symbol(list, sym);
		if (!match_op(token, ','))
			break;
		token = token->next;
	}
	return token;
}

struct token *compound_statement(struct token *token, struct statement *stmt)
{
	stmt->type = STMT_COMPOUND;
	start_block_scope();
	token = statement_list(token, &stmt->stmts);
	end_block_scope();
	return token;
}

static struct expression *identifier_expression(struct token *token)
{
	struct expression *expr = alloc_expression(token->pos, EXPR_IDENTIFIER);
	expr->expr_ident = token->ident;
	return expr;
}

static struct expression *index_expression(struct expression *from, struct expression *to)
{
	int idx_from, idx_to;
	struct expression *expr = alloc_expression(from->pos, EXPR_INDEX);

	idx_from = const_expression_value(from);
	idx_to = idx_from;
	if (to) {
		idx_to = const_expression_value(to);
		if (idx_to < idx_from || idx_from < 0)
			warning(from->pos, "nonsense array initializer index range");
	}
	expr->idx_from = idx_from;
	expr->idx_to = idx_to;
	return expr;
}

static struct token *single_initializer(struct expression **ep, struct token *token)
{
	int expect_equal = 0;
	struct token *next = token->next;
	struct expression **tail = ep;
	int nested;

	*ep = NULL; 

	if ((token_type(token) == TOKEN_IDENT) && match_op(next, ':')) {
		struct expression *expr = identifier_expression(token);
		if (Wold_initializer)
			warning(token->pos, "obsolete struct initializer, use C99 syntax");
		token = initializer(&expr->ident_expression, next->next);
		if (expr->ident_expression)
			*ep = expr;
		return token;
	}

	for (tail = ep, nested = 0; ; nested++, next = token->next) {
		if (match_op(token, '.') && (token_type(next) == TOKEN_IDENT)) {
			struct expression *expr = identifier_expression(next);
			*tail = expr;
			tail = &expr->ident_expression;
			expect_equal = 1;
			token = next->next;
		} else if (match_op(token, '[')) {
			struct expression *from = NULL, *to = NULL, *expr;
			token = constant_expression(token->next, &from);
			if (!from) {
				sparse_error(token->pos, "Expected constant expression");
				break;
			}
			if (match_op(token, SPECIAL_ELLIPSIS))
				token = constant_expression(token->next, &to);
			expr = index_expression(from, to);
			*tail = expr;
			tail = &expr->idx_expression;
			token = expect(token, ']', "at end of initializer index");
			if (nested)
				expect_equal = 1;
		} else {
			break;
		}
	}
	if (nested && !expect_equal) {
		if (!match_op(token, '='))
			warning(token->pos, "obsolete array initializer, use C99 syntax");
		else
			expect_equal = 1;
	}
	if (expect_equal)
		token = expect(token, '=', "at end of initializer index");

	token = initializer(tail, token);
	if (!*tail)
		*ep = NULL;
	return token;
}

static struct token *initializer_list(struct expression_list **list, struct token *token)
{
	struct expression *expr;

	for (;;) {
		token = single_initializer(&expr, token);
		if (!expr)
			break;
		add_expression(list, expr);
		if (!match_op(token, ','))
			break;
		token = token->next;
	}
	return token;
}

struct token *initializer(struct expression **tree, struct token *token)
{
	if (match_op(token, '{')) {
		struct expression *expr = alloc_expression(token->pos, EXPR_INITIALIZER);
		*tree = expr;
		if (!Wuniversal_initializer) {
			struct token *next = token->next;
			// '{ 0 }' is equivalent to '{ }' except for some
			// warnings, like using 0 to initialize a null-pointer.
			if (match_token_zero(next)) {
				if (match_op(next->next, '}'))
					expr->zero_init = 1;
			}
		}

		token = initializer_list(&expr->expr_list, token->next);
		return expect(token, '}', "at end of initializer");
	}
	return assignment_expression(token, tree);
}

static void declare_argument(struct symbol *sym, struct symbol *fn)
{
	if (!sym->ident) {
		sparse_error(sym->pos, "no identifier for function argument");
		return;
	}
	if (sym->ctype.base_type == &incomplete_ctype) {
		sym->ctype.base_type = &int_ctype;

		if (Wimplicit_int) {
			sparse_error(sym->pos, "missing type declaration for parameter '%s'",
				show_ident(sym->ident));
		}
	}
	bind_symbol(sym, sym->ident, NS_SYMBOL);
}

static struct token *parse_function_body(struct token *token, struct symbol *decl,
	struct symbol_list **list)
{
	struct symbol_list **old_symbol_list;
	struct symbol *base_type = decl->ctype.base_type;
	struct statement *stmt, **p;
	struct symbol *prev;
	struct symbol *arg;

	old_symbol_list = function_symbol_list;
	if (decl->ctype.modifiers & MOD_INLINE) {
		function_symbol_list = &decl->inline_symbol_list;
		p = &base_type->inline_stmt;
	} else {
		function_symbol_list = &decl->symbol_list;
		p = &base_type->stmt;
	}
	function_computed_target_list = NULL;
	function_computed_goto_list = NULL;

	if ((decl->ctype.modifiers & (MOD_EXTERN|MOD_INLINE)) == MOD_EXTERN) {
		if (Wexternal_function_has_definition)
			warning(decl->pos, "function '%s' with external linkage has definition", show_ident(decl->ident));
	}
	if (!(decl->ctype.modifiers & MOD_STATIC))
		decl->ctype.modifiers |= MOD_EXTERN;

	stmt = start_function(decl);
	*p = stmt;

	FOR_EACH_PTR (base_type->arguments, arg) {
		declare_argument(arg, base_type);
	} END_FOR_EACH_PTR(arg);

	token = statement_list(token->next, &stmt->stmts);
	end_function(decl);

	if (!(decl->ctype.modifiers & MOD_INLINE))
		add_symbol(list, decl);
	check_declaration(decl);
	decl->definition = decl;
	prev = decl->same_symbol;
	if (prev && prev->definition) {
		warning(decl->pos, "multiple definitions for function '%s'",
			show_ident(decl->ident));
		info(prev->definition->pos, " the previous one is here");
	} else {
		while (prev) {
			rebind_scope(prev, decl->scope);
			prev->definition = decl;
			prev = prev->same_symbol;
		}
	}
	function_symbol_list = old_symbol_list;
	if (function_computed_goto_list) {
		if (!function_computed_target_list)
			warning(decl->pos, "function '%s' has computed goto but no targets?", show_ident(decl->ident));
		else {
			FOR_EACH_PTR(function_computed_goto_list, stmt) {
				stmt->target_list = function_computed_target_list;
			} END_FOR_EACH_PTR(stmt);
		}
	}
	return expect(token, '}', "at end of function");
}

static void promote_k_r_types(struct symbol *arg)
{
	struct symbol *base = arg->ctype.base_type;
	if (base && base->ctype.base_type == &int_type && base->rank < 0) {
		arg->ctype.base_type = &int_ctype;
	}
}

static void apply_k_r_types(struct symbol_list *argtypes, struct symbol *fn)
{
	struct symbol_list *real_args = fn->ctype.base_type->arguments;
	struct symbol *arg;

	FOR_EACH_PTR(real_args, arg) {
		struct symbol *type;

		/* This is quadratic in the number of arguments. We _really_ don't care */
		FOR_EACH_PTR(argtypes, type) {
			if (type->ident == arg->ident)
				goto match;
		} END_FOR_EACH_PTR(type);
		if (Wimplicit_int) {
			warning(arg->pos, "missing type declaration for parameter '%s'",
				show_ident(arg->ident));
		}
		type = alloc_symbol(arg->pos, SYM_NODE);
		type->ident = arg->ident;
		type->ctype.base_type = &int_ctype;
match:
		type->used = 1;
		/* "char" and "short" promote to "int" */
		promote_k_r_types(type);

		arg->ctype = type->ctype;
	} END_FOR_EACH_PTR(arg);

	FOR_EACH_PTR(argtypes, arg) {
		if (!arg->used)
			warning(arg->pos, "nonsensical parameter declaration '%s'", show_ident(arg->ident));
	} END_FOR_EACH_PTR(arg);

}

static struct token *parse_k_r_arguments(struct token *token, struct symbol *decl,
	struct symbol_list **list)
{
	struct symbol_list *args = NULL;

	if (Wold_style_definition)
		warning(token->pos, "non-ANSI definition of function '%s'", show_ident(decl->ident));

	do {
		token = declaration_list(token, &args);
		if (!match_op(token, ';')) {
			sparse_error(token->pos, "expected ';' at end of parameter declaration");
			break;
		}
		token = token->next;
	} while (lookup_type(token));

	apply_k_r_types(args, decl);

	if (!match_op(token, '{')) {
		sparse_error(token->pos, "expected function body");
		return token;
	}
	return parse_function_body(token, decl, list);
}

static struct token *toplevel_asm_declaration(struct token *token, struct symbol_list **list)
{
	struct symbol *anon = alloc_symbol(token->pos, SYM_NODE);
	struct symbol *fn = alloc_symbol(token->pos, SYM_FN);
	struct statement *stmt;

	anon->ctype.base_type = fn;
	stmt = alloc_statement(token->pos, STMT_NONE);
	fn->stmt = stmt;

	token = parse_asm_statement(token, stmt);

	// FIXME: add_symbol(list, anon);
	return token;
}

struct token *external_declaration(struct token *token, struct symbol_list **list,
		validate_decl_t validate_decl)
{
	struct ident *ident = NULL;
	struct symbol *decl;
	struct decl_state ctx = { .ident = &ident };
	struct ctype saved;
	struct symbol *base_type;
	unsigned long mod;
	int is_typedef;

	/* Top-level inline asm or static assertion? */
	if (token_type(token) == TOKEN_IDENT) {
		struct symbol *s = lookup_keyword(token->ident, NS_KEYWORD);
		if (s && s->op->toplevel)
			return s->op->toplevel(token, list);
	}

	/* Parse declaration-specifiers, if any */
	token = declaration_specifiers(token, &ctx);
	mod = decl_modifiers(&ctx);
	decl = alloc_symbol(token->pos, SYM_NODE);
	/* Just a type declaration? */
	if (match_op(token, ';')) {
		apply_modifiers(token->pos, &ctx);
		return token->next;
	}

	saved = ctx.ctype;
	token = declarator(token, &ctx);
	token = handle_asm_name(token, &ctx);
	token = handle_attributes(token, &ctx);
	apply_modifiers(token->pos, &ctx);

	decl->ctype = ctx.ctype;
	decl->ctype.modifiers |= mod;
	decl->endpos = token->pos;

	/* Just a type declaration? */
	if (!ident) {
		warning(token->pos, "missing identifier in declaration");
		return expect(token, ';', "at the end of type declaration");
	}

	/* type define declaration? */
	is_typedef = ctx.storage_class == MOD_USERTYPE;

	/* Typedefs don't have meaningful storage */
	if (is_typedef)
		decl->ctype.modifiers |= MOD_USERTYPE;

	bind_symbol(decl, ident, is_typedef ? NS_TYPEDEF: NS_SYMBOL);

	base_type = decl->ctype.base_type;

	if (is_typedef) {
		if (base_type && !base_type->ident) {
			switch (base_type->type) {
			case SYM_STRUCT:
			case SYM_UNION:
			case SYM_ENUM:
			case SYM_RESTRICT:
				base_type->ident = ident;
				break;
			default:
				break;
			}
		}
	} else if (base_type && base_type->type == SYM_FN) {
		if (base_type->ctype.base_type == &autotype_ctype) {
			sparse_error(decl->pos, "'%s()' has __auto_type return type",
				show_ident(decl->ident));
			base_type->ctype.base_type = &int_ctype;
		}
		if (base_type->ctype.base_type == &incomplete_ctype) {
			warning(decl->pos, "'%s()' has implicit return type",
				show_ident(decl->ident));
			base_type->ctype.base_type = &int_ctype;
		}
		/* apply attributes placed after the declarator */
		decl->ctype.modifiers |= ctx.f_modifiers;

		/* K&R argument declaration? */
		if (lookup_type(token))
			return parse_k_r_arguments(token, decl, list);
		if (match_op(token, '{'))
			return parse_function_body(token, decl, list);

		if (!(decl->ctype.modifiers & MOD_STATIC))
			decl->ctype.modifiers |= MOD_EXTERN;
	} else if (base_type == &void_ctype && !(decl->ctype.modifiers & MOD_EXTERN)) {
		sparse_error(token->pos, "void declaration");
	}
	if (base_type == &incomplete_ctype) {
		warning(decl->pos, "'%s' has implicit type", show_ident(decl->ident));
		decl->ctype.base_type = &int_ctype;;
	}

	for (;;) {
		if (!is_typedef && match_op(token, '=')) {
			struct token *next = token->next;
			token = initializer(&decl->initializer, next);
			if (token == next)
				sparse_error(token->pos, "expression expected before '%s'", show_token(token));
		}
		if (!is_typedef) {
			if (validate_decl)
				validate_decl(decl);

			if (decl->initializer && decl->ctype.modifiers & MOD_EXTERN) {
				warning(decl->pos, "symbol with external linkage has initializer");
				decl->ctype.modifiers &= ~MOD_EXTERN;
			}

			if (!(decl->ctype.modifiers & (MOD_EXTERN | MOD_INLINE))) {
				add_symbol(list, decl);
				fn_local_symbol(decl);
			}
		}
		check_declaration(decl);
		if (decl->same_symbol) {
			decl->definition = decl->same_symbol->definition;
			decl->op = decl->same_symbol->op;
			if (is_typedef) {
				// TODO: handle -std=c89 --pedantic
				check_duplicates(decl);
			}
		}

		if (ctx.autotype) {
			const char *msg = NULL;
			if (decl->ctype.base_type != &autotype_ctype)
				msg = "on non-identifier";
			else if (match_op(token, ','))
				msg = "on declaration list";
			else if (!decl->initializer)
				msg = "without initializer";
			else if (decl->initializer->type == EXPR_SYMBOL &&
				 decl->initializer->symbol == decl)
				msg = "on self-init var";
			if (msg) {
				sparse_error(decl->pos, "__auto_type %s", msg);
				decl->ctype.base_type = &bad_ctype;
			}
		}

		if (!match_op(token, ','))
			break;

		token = token->next;
		ident = NULL;
		decl = alloc_symbol(token->pos, SYM_NODE);
		ctx.ctype = saved;
		token = handle_attributes(token, &ctx);
		token = declarator(token, &ctx);
		token = handle_asm_name(token, &ctx);
		token = handle_attributes(token, &ctx);
		apply_modifiers(token->pos, &ctx);
		decl->ctype = ctx.ctype;
		decl->ctype.modifiers |= mod;
		decl->endpos = token->pos;
		if (!ident) {
			sparse_error(token->pos, "expected identifier name in type definition");
			return token;
		}

		if (is_typedef)
			decl->ctype.modifiers |= MOD_USERTYPE;

		bind_symbol(decl, ident, is_typedef ? NS_TYPEDEF: NS_SYMBOL);

		/* Function declarations are automatically extern unless specifically static */
		base_type = decl->ctype.base_type;
		if (!is_typedef && base_type && base_type->type == SYM_FN) {
			if (!(decl->ctype.modifiers & MOD_STATIC))
				decl->ctype.modifiers |= MOD_EXTERN;
		}
	}
	return expect(token, ';', "at end of declaration");
}
