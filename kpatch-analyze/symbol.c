/*
 * Symbol lookup and handling.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib.h"
#include "allocate.h"
#include "token.h"
#include "parse.h"
#include "symbol.h"
#include "scope.h"
#include "expression.h"
#include "evaluate.h"

#include "target.h"

/*
 * Secondary symbol list for stuff that needs to be output because it
 * was used. 
 */
struct symbol_list *translation_unit_used_list = NULL;

/*
 * If the symbol is an inline symbol, add it to the list of symbols to parse
 */
void access_symbol(struct symbol *sym)
{
	if (sym->ctype.modifiers & MOD_INLINE) {
		if (!sym->accessed) {
			add_symbol(&translation_unit_used_list, sym);
			sym->accessed = 1;
		}
	}
}

struct symbol *lookup_symbol(struct ident *ident, enum namespace ns)
{
	struct symbol *sym;

	for (sym = ident->symbols; sym; sym = sym->next_id) {
		if (sym->namespace & ns) {
			sym->used = 1;
			return sym;
		}
	}
	return NULL;
}

struct context *alloc_context(void)
{
	return __alloc_context(0);
}

struct symbol *alloc_symbol(struct position pos, int type)
{
	struct symbol *sym = __alloc_symbol(0);
	sym->type = type;
	sym->pos = pos;
	sym->endpos.type = 0;
	return sym;
}

struct struct_union_info {
	unsigned long max_align;
	unsigned long bit_size;
	int align_size;
	char has_flex_array;
	bool packed;
	struct symbol *flex_array;
};

/*
 * Unions are fairly easy to lay out ;)
 */
static void lay_out_union(struct symbol *sym, struct struct_union_info *info)
{
	if (sym->bit_size < 0 && is_array_type(sym))
		sparse_error(sym->pos, "flexible array member '%s' in a union", show_ident(sym->ident));

	if (sym->bit_size > info->bit_size)
		info->bit_size = sym->bit_size;

	sym->offset = 0;
}

static int bitfield_base_size(struct symbol *sym)
{
	if (sym->type == SYM_NODE)
		sym = sym->ctype.base_type;
	if (sym->type == SYM_BITFIELD)
		sym = sym->ctype.base_type;
	return sym->bit_size;
}

/*
 * Structures are a bit more interesting to lay out
 */
static void lay_out_struct(struct symbol *sym, struct struct_union_info *info)
{
	unsigned long bit_size, align_bit_mask;
	unsigned long alignment;
	int base_size;

	bit_size = info->bit_size;
	base_size = sym->bit_size; 

	/*
	 * If the member is unsized, either it's a flexible array or
	 * it's invalid and a warning has already been issued.
	 */
	if (base_size < 0) {
		if (!is_array_type(sym))
			return;
		base_size = 0;
		info->flex_array = sym;
	}

	alignment = info->packed ? 1 : sym->ctype.alignment;
	align_bit_mask = bytes_to_bits(alignment) - 1;

	/*
	 * Bitfields have some very special rules..
	 */
	if (is_bitfield_type (sym)) {
		unsigned long bit_offset = bit_size & align_bit_mask;
		int room = bitfield_base_size(sym) - bit_offset;
		// Zero-width fields just fill up the unit.
		int width = base_size ? : (bit_offset ? room : 0);

		if (width > room && !info->packed) {
			bit_size = (bit_size + align_bit_mask) & ~align_bit_mask;
			bit_offset = 0;
		}
		sym->offset = bits_to_bytes(bit_size - bit_offset);
		sym->bit_offset = bit_offset;
		sym->ctype.base_type->bit_offset = bit_offset;
		info->bit_size = bit_size + width;
		// warning (sym->pos, "bitfield: offset=%d:%d  size=:%d", sym->offset, sym->bit_offset, width);

		if (info->packed && sym->type == SYM_NODE)
			sym->packed = 1;
		return;
	}

	/*
	 * Otherwise, just align it right and add it up..
	 */
	bit_size = (bit_size + align_bit_mask) & ~align_bit_mask;
	sym->offset = bits_to_bytes(bit_size);

	info->bit_size = bit_size + base_size;
	// warning (sym->pos, "regular: offset=%d", sym->offset);
}

///
// propagate properties of anonymous structs or unions into their members.
//
// :note: GCC seems to only propagate the qualifiers.
// :note: clang doesn't propagate anything at all.
static void examine_anonymous_member(struct symbol *sym)
{
	unsigned long mod = sym->ctype.modifiers & MOD_QUALIFIER;
	struct symbol *sub;

	if (sym->type == SYM_NODE)
		sym = sym->ctype.base_type;
	if (sym->type != SYM_STRUCT && sym->type != SYM_UNION)
		return;

	FOR_EACH_PTR(sym->symbol_list, sub) {
		assert(sub->type == SYM_NODE);
		sub->ctype.modifiers |= mod;

		// if nested, propagate all the way down
		if (!sub->ident)
			examine_anonymous_member(sub);
	} END_FOR_EACH_PTR(sub);
}

static struct symbol * examine_struct_union_type(struct symbol *sym, int advance)
{
	struct struct_union_info info = {
		.packed = sym->packed,
		.max_align = 1,
		.bit_size = 0,
		.align_size = 1
	};
	unsigned long bit_size, bit_align;
	void (*fn)(struct symbol *, struct struct_union_info *);
	struct symbol *member;

	fn = advance ? lay_out_struct : lay_out_union;
	FOR_EACH_PTR(sym->symbol_list, member) {
		if (member->ctype.base_type == &autotype_ctype) {
			sparse_error(member->pos, "member '%s' has __auto_type", show_ident(member->ident));
			member->ctype.base_type = &incomplete_ctype;
		}
		if (info.flex_array)
			sparse_error(info.flex_array->pos, "flexible array member '%s' is not last", show_ident(info.flex_array->ident));
		examine_symbol_type(member);
		if (!member->ident)
			examine_anonymous_member(member);

		if (member->ctype.alignment > info.max_align && !sym->packed) {
			// Unnamed bitfields do not affect alignment.
			if (member->ident || !is_bitfield_type(member))
				info.max_align = member->ctype.alignment;
		}

		if (has_flexible_array(member))
			info.has_flex_array = 1;
		if (has_flexible_array(member) && Wflexible_array_nested)
			warning(member->pos, "nested flexible array");
		fn(member, &info);
	} END_FOR_EACH_PTR(member);

	if (!sym->ctype.alignment)
		sym->ctype.alignment = info.max_align;
	bit_size = info.bit_size;
	if (info.align_size) {
		bit_align = bytes_to_bits(sym->ctype.alignment)-1;
		bit_size = (bit_size + bit_align) & ~bit_align;
	}
	if (info.flex_array) {
		info.has_flex_array = 1;
	}
	if (info.has_flex_array && (!is_union_type(sym) || Wflexible_array_union))
		sym->has_flex_array = 1;
	sym->bit_size = bit_size;
	return sym;
}

static struct symbol *examine_base_type(struct symbol *sym)
{
	struct symbol *base_type;

	if (sym->ctype.base_type == &autotype_ctype) {
		struct symbol *type = evaluate_expression(sym->initializer);
		if (!type)
			type = &bad_ctype;
		if (is_bitfield_type(type)) {
			warning(sym->pos, "__auto_type on bitfield");
			if (type->type == SYM_NODE)
				type = type->ctype.base_type;
			type = type->ctype.base_type;
		}
		sym->ctype.base_type = type;
	}

	/* Check the base type */
	base_type = examine_symbol_type(sym->ctype.base_type);
	if (!base_type || base_type->type == SYM_PTR)
		return base_type;
	combine_address_space(sym->pos, &sym->ctype.as, base_type->ctype.as);
	sym->ctype.modifiers |= base_type->ctype.modifiers & MOD_PTRINHERIT;
	concat_ptr_list((struct ptr_list *)base_type->ctype.contexts,
			(struct ptr_list **)&sym->ctype.contexts);
	if (base_type->type == SYM_NODE) {
		base_type = base_type->ctype.base_type;
		sym->ctype.base_type = base_type;
		sym->rank = base_type->rank;
	}
	return base_type;
}

static struct symbol * examine_array_type(struct symbol *sym)
{
	struct symbol *base_type = examine_base_type(sym);
	unsigned long bit_size = -1, alignment;
	struct expression *array_size = sym->array_size;

	if (!base_type)
		return sym;

	if (array_size) {	
		bit_size = array_element_offset(base_type->bit_size,
						get_expression_value_silent(array_size));
		if (array_size->type != EXPR_VALUE) {
			if (Wvla)
				warning(array_size->pos, "Variable length array is used.");
			bit_size = -1;
		}
	}
	if (has_flexible_array(base_type) && Wflexible_array_array)
		warning(sym->pos, "array of flexible structures");
	alignment = base_type->ctype.alignment;
	if (!sym->ctype.alignment)
		sym->ctype.alignment = alignment;
	sym->bit_size = bit_size;
	return sym;
}

static struct symbol *examine_bitfield_type(struct symbol *sym)
{
	struct symbol *base_type = examine_base_type(sym);
	unsigned long alignment, modifiers;

	if (!base_type)
		return sym;
	if (sym->bit_size > base_type->bit_size) {
		sparse_error(sym->pos, "bitfield '%s' is wider (%d) than its type (%s)",
			show_ident(sym->ident), sym->bit_size, show_typename(base_type));
		sym->bit_size = -1;
	}

	alignment = base_type->ctype.alignment;
	if (!sym->ctype.alignment)
		sym->ctype.alignment = alignment;
	modifiers = base_type->ctype.modifiers;

	/* use -funsigned-bitfields to determine the sign if not explicit */
	if (!(modifiers & MOD_EXPLICITLY_SIGNED) && funsigned_bitfields)
		modifiers = (modifiers & ~MOD_SIGNED) | MOD_UNSIGNED;
	sym->ctype.modifiers |= modifiers & MOD_SIGNEDNESS;
	return sym;
}

/*
 * "typeof" will have to merge the types together
 */
void merge_type(struct symbol *sym, struct symbol *base_type)
{
	combine_address_space(sym->pos, &sym->ctype.as, base_type->ctype.as);
	sym->ctype.modifiers |= (base_type->ctype.modifiers & ~MOD_STORAGE);
	concat_ptr_list((struct ptr_list *)base_type->ctype.contexts,
	                (struct ptr_list **)&sym->ctype.contexts);
	sym->ctype.base_type = base_type->ctype.base_type;
	if (sym->ctype.base_type->type == SYM_NODE)
		merge_type(sym, sym->ctype.base_type);
}

static bool is_wstring_expr(struct expression *expr)
{
	while (expr) {
		switch (expr->type) {
		case EXPR_STRING:
			return 1;
		case EXPR_INITIALIZER:
			if (expression_list_size(expr->expr_list) != 1)
				return 0;
			expr = first_expression(expr->expr_list);
			break;
		case EXPR_PREOP:
			if (expr->op == '(') {
				expr = expr->unop;
				break;
			}
		default:
			return 0;
		}
	}
	return 0;
}

static int count_array_initializer(struct symbol *t, struct expression *expr)
{
	int nr = 0;
	int is_char = 0;

	/*
	 * Arrays of character types are special; they can be initialized by
	 * string literal _or_ by string literal in braces.  The latter means
	 * that with T x[] = {<string literal>} number of elements in x depends
	 * on T - if it's a character type, we get the length of string literal
	 * (including NUL), otherwise we have one element here.
	 */
	if (t->ctype.base_type == &int_type && t->rank == -2)
		is_char = 1;
	else if (t == wchar_ctype && is_wstring_expr(expr))
		is_char = 1;

	switch (expr->type) {
	case EXPR_INITIALIZER: {
		struct expression *entry;
		int count = 0;
		int str_len = 0;
		FOR_EACH_PTR(expr->expr_list, entry) {
			count++;
			switch (entry->type) {
			case EXPR_INDEX:
				if (entry->idx_to >= nr)
					nr = entry->idx_to+1;
				break;
			case EXPR_PREOP: {
				struct expression *e = entry;
				if (is_char) {
					while (e && e->type == EXPR_PREOP && e->op == '(')
						e = e->unop;
					if (e && e->type == EXPR_STRING) {
						entry = e;
			case EXPR_STRING:
						if (is_char)
							str_len = entry->string->length;
					}


				}
			}
			default:
				nr++;
			}
		} END_FOR_EACH_PTR(entry);
		if (count == 1 && str_len)
			nr = str_len;
		break;
	}
	case EXPR_PREOP:
		if (is_char) { 
			struct expression *e = expr;
			while (e && e->type == EXPR_PREOP && e->op == '(')
				e = e->unop;
			if (e && e->type == EXPR_STRING) {
				expr = e;
	case EXPR_STRING:
				if (is_char)
					nr = expr->string->length;
			}
		}
		break;
	default:
		break;
	}
	return nr;
}

static struct expression *get_symbol_initializer(struct symbol *sym)
{
	do {
		if (sym->initializer)
			return sym->initializer;
	} while ((sym = sym->same_symbol) != NULL);
	return NULL;
}

static unsigned int implicit_array_size(struct symbol *node, unsigned int count)
{
	struct symbol *arr_ori = node->ctype.base_type;
	struct symbol *arr_new = alloc_symbol(node->pos, SYM_ARRAY);
	struct symbol *elem_type = arr_ori->ctype.base_type;
	struct expression *size = alloc_const_expression(node->pos, count);
	unsigned int bit_size = array_element_offset(elem_type->bit_size, count);

	*arr_new = *arr_ori;
	arr_new->bit_size = bit_size;
	arr_new->array_size = size;
	node->array_size = size;
	node->ctype.base_type = arr_new;

	return bit_size;
}

static struct symbol * examine_node_type(struct symbol *sym)
{
	struct symbol *base_type = examine_base_type(sym);
	int bit_size;
	unsigned long alignment;

	/* SYM_NODE - figure out what the type of the node was.. */
	bit_size = 0;
	alignment = 0;
	if (!base_type)
		return sym;

	bit_size = base_type->bit_size;
	alignment = base_type->ctype.alignment;

	/* Pick up signedness information into the node */
	sym->ctype.modifiers |= (MOD_SIGNEDNESS & base_type->ctype.modifiers);

	if (!sym->ctype.alignment)
		sym->ctype.alignment = alignment;

	/* Unsized array? The size might come from the initializer.. */
	if (bit_size < 0 && base_type->type == SYM_ARRAY) {
		struct expression *initializer = get_symbol_initializer(sym);
		if (initializer) {
			struct symbol *node_type = base_type->ctype.base_type;
			int count = count_array_initializer(node_type, initializer);

			if (node_type && node_type->bit_size >= 0)
				bit_size = implicit_array_size(sym, count);
		}
	}
	
	sym->bit_size = bit_size;
	sym->rank = base_type->rank;
	return sym;
}

static struct symbol *examine_enum_type(struct symbol *sym)
{
	struct symbol *base_type = examine_base_type(sym);

	sym->ctype.modifiers |= (base_type->ctype.modifiers & MOD_SIGNEDNESS);
	sym->bit_size = bits_in_enum;
	if (base_type->bit_size > sym->bit_size)
		sym->bit_size = base_type->bit_size;
	sym->ctype.alignment = enum_alignment;
	if (base_type->ctype.alignment > sym->ctype.alignment)
		sym->ctype.alignment = base_type->ctype.alignment;
	return sym;
}

static struct symbol *examine_pointer_type(struct symbol *sym)
{
	/*
	 * Since pointers to incomplete types can be used,
	 * for example in a struct-declaration-list,
	 * the base type must *not* be examined here.
	 * It thus means that it needs to be done later,
	 * when the base type of the pointer is looked at.
	 */
	if (!sym->bit_size)
		sym->bit_size = bits_in_pointer;
	if (!sym->ctype.alignment)
		sym->ctype.alignment = pointer_alignment;
	return sym;
}

static struct symbol *examine_typeof(struct symbol *sym)
{
	struct symbol *base = evaluate_expression(sym->initializer);
	unsigned long mod = 0;

	if (!base)
		base = &bad_ctype;
	if (base->type == SYM_NODE) {
		mod |= base->ctype.modifiers & MOD_TYPEOF;
		base = base->ctype.base_type;
	}
	if (base->type == SYM_BITFIELD)
		warning(base->pos, "typeof applied to bitfield type");
	sym->type = SYM_NODE;
	sym->ctype.modifiers = mod;
	sym->ctype.base_type = base;
	return examine_node_type(sym);
}

/*
 * Fill in type size and alignment information for
 * regular SYM_TYPE things.
 */
struct symbol *examine_symbol_type(struct symbol * sym)
{
	if (!sym)
		return sym;

	/* Already done? */
	if (sym->examined)
		return sym;
	sym->examined = 1;

	switch (sym->type) {
	case SYM_FN:
	case SYM_NODE:
		return examine_node_type(sym);
	case SYM_ARRAY:
		return examine_array_type(sym);
	case SYM_STRUCT:
		return examine_struct_union_type(sym, 1);
	case SYM_UNION:
		return examine_struct_union_type(sym, 0);
	case SYM_PTR:
		return examine_pointer_type(sym);
	case SYM_ENUM:
		return examine_enum_type(sym);
	case SYM_BITFIELD:
		return examine_bitfield_type(sym);
	case SYM_BASETYPE:
		/* Size and alignment had better already be set up */
		return sym;
	case SYM_TYPEOF:
		return examine_typeof(sym);
	case SYM_PREPROCESSOR:
		sparse_error(sym->pos, "ctype on preprocessor command? (%s)", show_ident(sym->ident));
		return NULL;
	case SYM_UNINITIALIZED:
		sparse_error(sym->pos, "ctype on uninitialized symbol '%s'", show_typename(sym));
		return NULL;
	case SYM_RESTRICT:
		examine_base_type(sym);
		return sym;
	case SYM_FOULED:
		examine_base_type(sym);
		return sym;
	default:
		sparse_error(sym->pos, "Examining unknown symbol type %d", sym->type);
		break;
	}
	return sym;
}

const char* get_type_name(enum type type)
{
	const char *type_lookup[] = {
	[SYM_UNINITIALIZED] = "uninitialized",
	[SYM_PREPROCESSOR] = "preprocessor",
	[SYM_BASETYPE] = "basetype",
	[SYM_NODE] = "node",
	[SYM_PTR] = "pointer",
	[SYM_FN] = "function",
	[SYM_ARRAY] = "array",
	[SYM_STRUCT] = "struct",
	[SYM_UNION] = "union",
	[SYM_ENUM] = "enum",
	[SYM_TYPEOF] = "typeof",
	[SYM_BITFIELD] = "bitfield",
	[SYM_LABEL] = "label",
	[SYM_RESTRICT] = "restrict",
	[SYM_FOULED] = "fouled",
	[SYM_KEYWORD] = "keyword",
	[SYM_BAD] = "bad"};

	if (type <= SYM_BAD)
		return type_lookup[type];
	else
		return NULL;
}

struct symbol *examine_pointer_target(struct symbol *sym)
{
	return examine_base_type(sym);
}

static struct symbol_list *restr, *fouled;

void create_fouled(struct symbol *type)
{
	if (type->bit_size < bits_in_int) {
		struct symbol *new = alloc_symbol(type->pos, type->type);
		*new = *type;
		new->bit_size = bits_in_int;
		new->rank = 0;
		new->type = SYM_FOULED;
		new->ctype.base_type = type;
		add_symbol(&restr, type);
		add_symbol(&fouled, new);
	}
}

struct symbol *befoul(struct symbol *type)
{
	struct symbol *t1, *t2;
	while (type->type == SYM_NODE)
		type = type->ctype.base_type;
	PREPARE_PTR_LIST(restr, t1);
	PREPARE_PTR_LIST(fouled, t2);
	for (;;) {
		if (t1 == type)
			return t2;
		if (!t1)
			break;
		NEXT_PTR_LIST(t1);
		NEXT_PTR_LIST(t2);
	}
	FINISH_PTR_LIST(t2);
	FINISH_PTR_LIST(t1);
	return NULL;
}

static void inherit_declaration(struct symbol *sym, struct symbol *prev)
{
	unsigned long mods = prev->ctype.modifiers;

	// inherit function attributes
	sym->ctype.modifiers |= mods & MOD_FUN_ATTR;
}

void check_declaration(struct symbol *sym)
{
	int warned = 0;
	struct symbol *next = sym;

	while ((next = next->next_id) != NULL) {
		if (next->namespace != sym->namespace)
			continue;
		if (sym->scope == next->scope) {
			sym->same_symbol = next;
			inherit_declaration(sym, next);
			return;
		}
		/* Extern in block level matches a TOPLEVEL non-static symbol */
		if (sym->ctype.modifiers & MOD_EXTERN) {
			if ((next->ctype.modifiers & (MOD_TOPLEVEL|MOD_STATIC)) == MOD_TOPLEVEL) {
				sym->same_symbol = next;
				return;
			}
		}

		if (!Wshadow || warned)
			continue;
		if (get_sym_type(next) == SYM_FN)
			continue;
		warned = 1;
		warning(sym->pos, "symbol '%s' shadows an earlier one", show_ident(sym->ident));
		info(next->pos, "originally declared here");
	}
}

static void inherit_static(struct symbol *sym)
{
	struct symbol *prev;

	// only 'plain' symbols are concerned
	if (sym->ctype.modifiers & (MOD_STATIC|MOD_EXTERN))
		return;

	for (prev = sym->next_id; prev; prev = prev->next_id) {
		if (prev->namespace != NS_SYMBOL)
			continue;
		if (prev->scope != file_scope)
			continue;

		sym->ctype.modifiers |= prev->ctype.modifiers & MOD_STATIC;

		// previous declarations are already converted
		return;
	}
}

void bind_symbol_with_scope(struct symbol *sym, struct ident *ident, enum namespace ns, struct scope *scope)
{
	if (sym->bound) {
		sparse_error(sym->pos, "internal error: symbol type already bound");
		return;
	}
	if (ident->reserved && (ns & (NS_TYPEDEF | NS_STRUCT | NS_LABEL | NS_SYMBOL))) {
		sparse_error(sym->pos, "Trying to use reserved word '%s' as identifier", show_ident(ident));
		return;
	}
	sym->namespace = ns;
	sym->next_id = ident->symbols;
	ident->symbols = sym;
	if (sym->ident && sym->ident != ident)
		warning(sym->pos, "Symbol '%s' already bound", show_ident(sym->ident));
	sym->ident = ident;
	sym->bound = 1;

	if (ns == NS_SYMBOL && toplevel(scope)) {
		unsigned mod = MOD_ADDRESSABLE | MOD_TOPLEVEL;

		inherit_static(sym);

		scope = global_scope;
		if (sym->ctype.modifiers & MOD_STATIC ||
		    is_extern_inline(sym)) {
			scope = file_scope;
			mod = MOD_TOPLEVEL;
		}
		sym->ctype.modifiers |= mod;
	}
	bind_scope(sym, scope);
}

void bind_symbol(struct symbol *sym, struct ident *ident, enum namespace ns)
{
	struct scope *scope = block_scope;;

	if (ns == NS_MACRO)
		scope = file_scope;
	if (ns == NS_LABEL)
		scope = function_scope;
	bind_symbol_with_scope(sym, ident, ns, scope);
}

struct symbol *create_symbol(int stream, const char *name, int type, int namespace)
{
	struct ident *ident = built_in_ident(name);
	struct symbol *sym = lookup_symbol(ident, namespace);

	if (sym && sym->type != type)
		die("symbol %s created with different types: %d old %d", name,
				type, sym->type);

	if (!sym) {
		struct token *token = built_in_token(stream, ident);

		sym = alloc_symbol(token->pos, type);
		bind_symbol(sym, token->ident, namespace);
	}
	return sym;
}


/*
 * Abstract types
 */
struct symbol	int_type,
		fp_type;

/*
 * C types (i.e. actual instances that the abstract types
 * can map onto)
 */
struct symbol	bool_ctype, void_ctype, type_ctype,
		char_ctype, schar_ctype, uchar_ctype,
		short_ctype, sshort_ctype, ushort_ctype,
		int_ctype, sint_ctype, uint_ctype,
		long_ctype, slong_ctype, ulong_ctype,
		llong_ctype, sllong_ctype, ullong_ctype,
		int128_ctype, sint128_ctype, uint128_ctype,
		float_ctype, double_ctype, ldouble_ctype,
		string_ctype, ptr_ctype, lazy_ptr_ctype,
		incomplete_ctype, label_ctype, bad_ctype,
		null_ctype;
struct symbol	autotype_ctype;
struct symbol	schar_ptr_ctype, short_ptr_ctype;
struct symbol	int_ptr_ctype, uint_ptr_ctype;
struct symbol	long_ptr_ctype, ulong_ptr_ctype;
struct symbol	llong_ptr_ctype, ullong_ptr_ctype;
struct symbol	size_t_ptr_ctype, intmax_ptr_ctype, ptrdiff_ptr_ctype;
struct symbol	float32_ctype, float32x_ctype;
struct symbol	float64_ctype, float64x_ctype;
struct symbol	float128_ctype;
struct symbol	const_void_ctype, const_char_ctype;
struct symbol	const_ptr_ctype, const_string_ctype;
struct symbol	const_wchar_ctype, const_wstring_ctype;
struct symbol	volatile_void_ctype, volatile_ptr_ctype;
struct symbol	volatile_bool_ctype, volatile_bool_ptr_ctype;

struct symbol	zero_int;

#define __INIT_IDENT(str, res) { .len = sizeof(str)-1, .name = str, .reserved = res }
#define __IDENT(n,str,res) \
	struct ident n  = __INIT_IDENT(str,res)

#include "ident-list.h"

void init_symbols(void)
{
	int stream = init_stream(NULL, "builtin", -1, includepath);

#define __IDENT(n,str,res) \
	hash_ident(&n)
#include "ident-list.h"

	init_parser(stream);
}

// For fix-sized types
static int bits_in_type32 = 32;
static int bits_in_type64 = 64;
static int bits_in_type128 = 128;

#define T_BASETYPE      SYM_BASETYPE, 0, 0, NULL, NULL, NULL
#define T_INT(R, S, M)  SYM_BASETYPE, M, R, &bits_in_##S, &max_int_alignment, &int_type
#define T__INT(R, S)    T_INT(R, S, MOD_SIGNED)
#define T_SINT(R, S)    T_INT(R, S, MOD_ESIGNED)
#define T_UINT(R,S)     T_INT(R, S, MOD_UNSIGNED)
#define T_FLOAT_(R,S,A) SYM_BASETYPE, 0, R, &bits_in_##S, A, &fp_type
#define T_FLOAT(R, S)   T_FLOAT_(R, S, &max_fp_alignment)
#define T_PTR(B)        SYM_PTR, 0, 0, &bits_in_pointer, &pointer_alignment, B
#define T_NODE(M,B,S,A) SYM_NODE, M, 0, S, A, B
#define T_CONST(B,S,A)  T_NODE(MOD_CONST, B, S, A)

static const struct ctype_declare {
	struct symbol *ptr;
	enum type type;
	unsigned long modifiers;
	int rank;
	int *bit_size;
	int *maxalign;
	struct symbol *base_type;
} ctype_declaration[] = {
	{ &bool_ctype,         T_INT(-3, bool, MOD_UNSIGNED) },
	{ &void_ctype,         T_BASETYPE },
	{ &type_ctype,         T_BASETYPE },
	{ &incomplete_ctype,   T_BASETYPE },
	{ &autotype_ctype,     T_BASETYPE },
	{ &bad_ctype,          T_BASETYPE },

	{ &char_ctype,         T__INT(-2, char) },
	{ &schar_ctype,        T_SINT(-2, char) },
	{ &uchar_ctype,        T_UINT(-2, char) },
	{ &short_ctype,        T__INT(-1, short) },
	{ &sshort_ctype,       T_SINT(-1, short) },
	{ &ushort_ctype,       T_UINT(-1, short) },
	{ &int_ctype,          T__INT( 0, int) },
	{ &sint_ctype,         T_SINT( 0, int) },
	{ &uint_ctype,         T_UINT( 0, int) },
	{ &long_ctype,         T__INT( 1, long) },
	{ &slong_ctype,        T_SINT( 1, long) },
	{ &ulong_ctype,        T_UINT( 1, long) },
	{ &llong_ctype,        T__INT( 2, longlong) },
	{ &sllong_ctype,       T_SINT( 2, longlong) },
	{ &ullong_ctype,       T_UINT( 2, longlong) },
	{ &int128_ctype,       T__INT( 3, type128) },
	{ &sint128_ctype,      T_SINT( 3, type128) },
	{ &uint128_ctype,      T_UINT( 3, type128) },

	{ &float_ctype,        T_FLOAT(-1, float) },
	{ &double_ctype,       T_FLOAT( 0, double) },
	{ &ldouble_ctype,      T_FLOAT( 1, longdouble) },

	{ &float32_ctype,      T_FLOAT(-1, type32) },
	{ &float32x_ctype,     T_FLOAT(-1, double) },
	{ &float64_ctype,      T_FLOAT( 0, type64) },
	{ &float64x_ctype,     T_FLOAT( 1, longdouble) },
	{ &float128_ctype,     T_FLOAT_(2, type128, &max_alignment) },

	{ &string_ctype,       T_PTR(&char_ctype) },
	{ &ptr_ctype,          T_PTR(&void_ctype) },
	{ &null_ctype,         T_PTR(&void_ctype) },
	{ &label_ctype,        T_PTR(&void_ctype) },
	{ &lazy_ptr_ctype,     T_PTR(&void_ctype) },
	{ &schar_ptr_ctype,    T_PTR(&schar_ctype) },
	{ &short_ptr_ctype,    T_PTR(&short_ctype) },
	{ &int_ptr_ctype,      T_PTR(&int_ctype) },
	{ &uint_ptr_ctype,     T_PTR(&uint_ctype) },
	{ &long_ptr_ctype,     T_PTR(&long_ctype) },
	{ &ulong_ptr_ctype,    T_PTR(&ulong_ctype) },
	{ &llong_ptr_ctype,    T_PTR(&llong_ctype) },
	{ &ullong_ptr_ctype,   T_PTR(&ullong_ctype) },
	{ &size_t_ptr_ctype,   T_PTR(&void_ctype) },	// will be adjusted
	{ &intmax_ptr_ctype,   T_PTR(&void_ctype) },	// will be adjusted
	{ &ptrdiff_ptr_ctype,  T_PTR(&void_ctype) },	// will be adjusted
	{ &const_ptr_ctype,    T_PTR(&const_void_ctype) },
	{ &const_string_ctype, T_PTR(&const_char_ctype) },
	{ &const_wstring_ctype,T_PTR(&const_wchar_ctype) },

	{ &const_void_ctype,   T_CONST(&void_ctype, NULL, NULL) },
	{ &const_char_ctype,   T_CONST(&char_ctype, &bits_in_char, &max_int_alignment)},
	{ &const_wchar_ctype,  T_CONST(&int_ctype, NULL, NULL) },
	{ &volatile_void_ctype,T_NODE(MOD_VOLATILE, &void_ctype, NULL, NULL) },
	{ &volatile_ptr_ctype, T_PTR(&volatile_void_ctype) },
	{ &volatile_bool_ctype,T_NODE(MOD_VOLATILE, &bool_ctype, NULL, NULL) },
	{ &volatile_bool_ptr_ctype, T_PTR(&volatile_bool_ctype) },
	{ NULL, }
};

void init_ctype(void)
{
	const struct ctype_declare *ctype;

	for (ctype = ctype_declaration ; ctype->ptr; ctype++) {
		struct symbol *sym = ctype->ptr;
		unsigned long bit_size = ctype->bit_size ? *ctype->bit_size : -1;
		unsigned long maxalign = ctype->maxalign ? *ctype->maxalign : 0;
		unsigned long alignment = bits_to_bytes(bit_size);

		if (alignment > maxalign)
			alignment = maxalign;
		sym->type = ctype->type;
		sym->rank = ctype->rank;
		sym->bit_size = bit_size;
		sym->ctype.alignment = alignment;
		sym->ctype.base_type = ctype->base_type;
		sym->ctype.modifiers = ctype->modifiers;

		if (sym->type == SYM_NODE) {
			struct symbol *base = sym->ctype.base_type;
			sym->rank = base->rank;
			if (!ctype->bit_size)
				sym->bit_size = base->bit_size;
			if (!ctype->maxalign)
				sym->ctype.alignment = base->ctype.alignment;
		}
	}

	// and now some adjustments
	if (funsigned_char) {
		char_ctype.ctype.modifiers |= MOD_UNSIGNED;
		char_ctype.ctype.modifiers &= ~MOD_SIGNED;
	}

	if (!ptrdiff_ctype)
		ptrdiff_ctype = ssize_t_ctype;
	if (!intptr_ctype)
		intptr_ctype = ssize_t_ctype;
	if (!uintptr_ctype)
		uintptr_ctype = size_t_ctype;

	size_t_ptr_ctype.ctype.base_type = size_t_ctype;
	intmax_ptr_ctype.ctype.base_type = intmax_ctype;
	ptrdiff_ptr_ctype.ctype.base_type = ptrdiff_ctype;

	const_wchar_ctype.ctype.base_type = wchar_ctype;
	const_wchar_ctype.rank = wchar_ctype->rank;
	const_wchar_ctype.ctype.alignment = wchar_ctype->ctype.alignment;
	const_wchar_ctype.bit_size = wchar_ctype->bit_size;
}
