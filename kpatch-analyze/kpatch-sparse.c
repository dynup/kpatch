/*
 * kpatch-analyze
 *
 * check a kernel patch for its ability to kpatch it
 *
 * Copyright (C) 2021 Divya Cote
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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "expression.h"
#include "parse.h"
#include "scope.h"
#include "symbol.h"

#define _DEBUG 0

#ifdef _DEBUG
#define debug(level, args...) do {	\
	if ((level) <= _DEBUG)		\
		fprintf(stderr, args);	\
} while (0)
#else
#define debug(level, args...)
#endif

struct change_list *kpatch_changelist;
static struct streamid_list *file_streams;

enum scopes {
	SCOPE_NONE = 0,
	SCOPE_FILE = 1,
	SCOPE_GLOBAL = 2,
};

struct analysis_card {
	struct symbol *base;
	enum scopes scope;
	enum type type:8;
	enum namespace namespace:9;
	unsigned long modifiers;
} results;


static void push_new_streamid(int streamid)
{
	int *ptr;
	ptr = calloc(1, sizeof(int));
	if (!ptr)
		die("no memory to allocate new streamid");
	*ptr = streamid;
	add_ptr_list(&file_streams, ptr);
}

static void push_new_change(struct change_list **list, char *fname, int sline, int rline, int num)
{
	struct patch_change *change;

	change = calloc(1, sizeof(*change));
	if (!change)
		die("no memory to allocate new patch change info");

	change->pathname = fname;
	change->sourceline = sline;
	change->resultline = rline;
	change->numlines = num;

	debug(2, "change line: %s %d %d %d\n", change->pathname, change->sourceline,
	      change->resultline, change->numlines);

	add_ptr_list(list, change);
}

/*
 * Import patch line change list from data file
 *
 * Each line has the format:
 *
 * <pathname> <sourceline> <resultline> <numlines>
 *
 * example for a one liner change at line 78:
 * kernel/livepatch/patch.c 78 78 1
 *
 *
 */
static void import_changelist(struct change_list **list)
{
	char *changelist_path;
	FILE *fp;
	char *fname;
	int sline, rline, num;
	int ret = 0;

	changelist_path = getenv("KSPARSE_CHANGELIST");
	if(changelist_path == NULL)
		die("error: `KSPARSE_CHANGELIST` environment var needs to be set");

	fp = fopen(changelist_path, "r");
	if(fp == NULL)
		die("error while opening patch change list info file %s: %s\n", changelist_path, strerror(errno));

	for(errno = 0; ret != EOF; errno = 0){
		ret = fscanf(fp, "%ms %d %d %d\n", &fname, &sline, &rline, &num);
		if(ret == 4)
			push_new_change(list, fname, sline, rline, num);
	}
	if (errno != 0)
		die("error while reading patch change list info file: %s\n", strerror(errno));
	fclose(fp);
}

static void show_changed_symbol(struct position pos, const char *name)
{
	if (name == NULL)
		name = "<noname>";
	printf("%s:%d:%d change at '%s':\n", stream_name(pos.stream),
	        pos.line, pos.pos, name);
}

static int check_notrace(struct position pos, const char *name, struct analysis_card *results)
{
	if (results->namespace == NS_SYMBOL && results->type == SYM_FN &&
	    results->modifiers & MOD_NOTRACE) {
		show_changed_symbol(pos, name);
		printf("REPORT: patch changes code in a function with a 'notrace' modifier.\n"
		       "Livepatch cannot apply changes to those functions. A workaround is needed.\n\n");
		return 1;
	}
	return 0;
}

static int check_init(struct position pos, const char *name, struct analysis_card *results)
{
	if (results->namespace == NS_SYMBOL && results->type == SYM_FN &&
	    results->modifiers & MOD_INIT) {
		show_changed_symbol(pos, name);
		printf("REPORT: patch changes code in a function with a 'init' modifier.\n"
		       "Livepatch cannot apply changes to those functions. A workaround is needed.\n\n");
		return 1;
	}
	return 0;
}

static int check_global_changes(struct position pos, const char *name, struct analysis_card *results)
{
	if (results->namespace != NS_SYMBOL || (results->namespace == NS_SYMBOL &&
	    results->type != SYM_FN)) {
		show_changed_symbol(pos, name);
		printf("REPORT: patch changes data structures or definitions outside functions which\n"
		       "cannot be patched by Livepatch. A workaround like shadow variables is needed.\n\n");
		return 1;
	}
	return 0;
}

static void evaluate_change(struct position pos, const char *name)
{
	if (pos.changed) {
		debug(1, "EVAL: <%s> changed at line %d, running checks...\n",
		      name, pos.line);
		check_notrace(pos, name, &results);
		check_init(pos, name, &results);
		check_global_changes(pos, name, &results);
	}
}

static void add_base_symbol(struct symbol *sym)
{
	if (sym->visited)
		return;

	debug(3, "BASE symb[%-30s] %30s:%d:%d ns:%d type:%d changed:%d\n",
	        builtin_typename(sym) ?: show_ident(sym->ident),
	        stream_name(sym->pos.stream), sym->pos.line, sym->pos.pos,
	        sym->namespace, sym->type, sym->pos.changed);

	if (results.base == NULL) {
		results.base = sym;
		results.namespace = sym->namespace;
		if (sym->namespace == NS_SYMBOL) {
			if (sym->type == SYM_NODE)
				results.type = sym->ctype.base_type->type;
			else
				results.type = sym->type;
			results.modifiers = sym->ctype.modifiers;
		}
	}
}

static const char *statement_type_name(enum statement_type type)
{
	static const char *statement_type_name[] = {
		[STMT_NONE] = "STMT_NONE",
		[STMT_DECLARATION] = "STMT_DECLARATION",
		[STMT_EXPRESSION] = "STMT_EXPRESSION",
		[STMT_COMPOUND] = "STMT_COMPOUND",
		[STMT_IF] = "STMT_IF",
		[STMT_RETURN] = "STMT_RETURN",
		[STMT_CASE] = "STMT_CASE",
		[STMT_SWITCH] = "STMT_SWITCH",
		[STMT_ITERATOR] = "STMT_ITERATOR",
		[STMT_LABEL] = "STMT_LABEL",
		[STMT_GOTO] = "STMT_GOTO",
		[STMT_ASM] = "STMT_ASM",
		[STMT_CONTEXT] = "STMT_CONTEXT",
		[STMT_RANGE] = "STMT_RANGE",
	};
	return statement_type_name[type] ?: "UNKNOWN_STATEMENT_TYPE";
}

static const char *expression_type_name(enum expression_type type)
{
	static const char *expression_type_name[] = {
		[EXPR_VALUE] = "EXPR_VALUE",
		[EXPR_STRING] = "EXPR_STRING",
		[EXPR_SYMBOL] = "EXPR_SYMBOL",
		[EXPR_TYPE] = "EXPR_TYPE",
		[EXPR_BINOP] = "EXPR_BINOP",
		[EXPR_ASSIGNMENT] = "EXPR_ASSIGNMENT",
		[EXPR_LOGICAL] = "EXPR_LOGICAL",
		[EXPR_DEREF] = "EXPR_DEREF",
		[EXPR_PREOP] = "EXPR_PREOP",
		[EXPR_POSTOP] = "EXPR_POSTOP",
		[EXPR_CAST] = "EXPR_CAST",
		[EXPR_FORCE_CAST] = "EXPR_FORCE_CAST",
		[EXPR_IMPLIED_CAST] = "EXPR_IMPLIED_CAST",
		[EXPR_SIZEOF] = "EXPR_SIZEOF",
		[EXPR_ALIGNOF] = "EXPR_ALIGNOF",
		[EXPR_PTRSIZEOF] = "EXPR_PTRSIZEOF",
		[EXPR_CONDITIONAL] = "EXPR_CONDITIONAL",
		[EXPR_SELECT] = "EXPR_SELECT",
		[EXPR_STATEMENT] = "EXPR_STATEMENT",
		[EXPR_CALL] = "EXPR_CALL",
		[EXPR_COMMA] = "EXPR_COMMA",
		[EXPR_COMPARE] = "EXPR_COMPARE",
		[EXPR_LABEL] = "EXPR_LABEL",
		[EXPR_INITIALIZER] = "EXPR_INITIALIZER",
		[EXPR_IDENTIFIER] = "EXPR_IDENTIFIER",
		[EXPR_INDEX] = "EXPR_INDEX",
		[EXPR_POS] = "EXPR_POS",
		[EXPR_FVALUE] = "EXPR_FVALUE",
		[EXPR_SLICE] = "EXPR_SLICE",
		[EXPR_OFFSETOF] = "EXPR_OFFSETOF",
	};
	return expression_type_name[type] ?: "UNKNOWN_EXPRESSION_TYPE";
}

static void inspect_symbol(struct symbol *sym);
static void inspect_symbols(struct symbol_list *list);
static void inspect_statement(struct statement *stmt);

static void inspect_expression(struct expression *expr)
{
	if (!expr)
		return;

	debug(3, "expr[%-30s] %30s:%d:%d changed:%d\n",
	      expression_type_name(expr->type), stream_name(expr->pos.stream),
	      expr->pos.line, expr->pos.pos, expr->pos.changed);

	evaluate_change(expr->pos, expression_type_name(expr->type));

	switch (expr->type) {
	case EXPR_STATEMENT:
		inspect_statement(expr->statement);
		break;
	case EXPR_BINOP:
	case EXPR_COMMA:
	case EXPR_COMPARE:
	case EXPR_LOGICAL:
	case EXPR_ASSIGNMENT:
		inspect_expression(expr->left);
		inspect_expression(expr->right);
		break;
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
	case EXPR_IMPLIED_CAST:
		inspect_symbol(expr->cast_type);
		inspect_expression(expr->cast_expression);
		break;
	case EXPR_PREOP:
		inspect_expression(expr->unop);
		break;
	case EXPR_LABEL:
		inspect_symbol(expr->label_symbol);
		break;
	case EXPR_IDENTIFIER:
		inspect_symbol(expr->field);
		break;
	default:
		break;
	}
}

static void inspect_statements(struct statement_list *list)
{
	struct statement *stmt;
	FOR_EACH_PTR(list, stmt) {
		inspect_statement(stmt);
	} END_FOR_EACH_PTR(stmt);
}

static void inspect_statement(struct statement *stmt)
{
	if (!stmt)
		return;

	debug(3, "stmt[%-30s] %30s:%d:%d changed:%d\n",
	      statement_type_name(stmt->type), stream_name(stmt->pos.stream),
	      stmt->pos.line, stmt->pos.pos, stmt->pos.changed);

	evaluate_change(stmt->pos, statement_type_name(stmt->type));

	switch (stmt->type) {
	case STMT_COMPOUND:
		inspect_statements(stmt->stmts);
		inspect_symbol(stmt->ret);
		inspect_symbol(stmt->inline_fn);
		inspect_statement(stmt->args);
		break;
	case STMT_EXPRESSION:
		inspect_expression(stmt->expression);
		break;
	case STMT_IF:
		inspect_expression(stmt->if_conditional);
		inspect_statement(stmt->if_true);
		inspect_statement(stmt->if_false);
		break;
	case STMT_ITERATOR:
		inspect_symbol(stmt->iterator_break);
		inspect_symbol(stmt->iterator_continue);
		inspect_statement(stmt->iterator_pre_statement);
		inspect_statement(stmt->iterator_statement);
		inspect_statement(stmt->iterator_post_statement);
		break;
	case STMT_SWITCH:
		inspect_expression(stmt->switch_expression);
		inspect_statement(stmt->switch_statement);
		inspect_symbol(stmt->switch_break);
		inspect_symbol(stmt->switch_case);
		break;
	case STMT_CASE:
		inspect_expression(stmt->case_expression);
		inspect_expression(stmt->case_to);
		inspect_statement(stmt->case_statement);
		inspect_symbol(stmt->case_label);
		break;
	case STMT_RETURN:
		inspect_expression(stmt->ret_value);
		inspect_symbol(stmt->ret_target);
		break;
	case STMT_DECLARATION:
		inspect_symbols(stmt->declaration);
		break;
	default:
		break;
	}
}

static void inspect_symbols(struct symbol_list *list)
{
	struct symbol *sym;
	FOR_EACH_PTR(list, sym) {
		inspect_symbol(sym);
	} END_FOR_EACH_PTR(sym);
}

bool is_in_filestream(struct symbol *sym) {
	int *stream;
	if (!sym)
		return false;
	FOR_EACH_PTR(file_streams, stream) {
		if (*stream == sym->pos.stream)
			return true;
	} END_FOR_EACH_PTR(stream);
	return false;
}

static void inspect_symbol(struct symbol *sym)
{
	if (!sym || sym->visited)
	       return;

	switch (sym->namespace) {
	case NS_MACRO:
		return;
	default:
		break;
	}

	debug(2, "symb[%-30s] %30s:%d:%d ns:%d type:%d changed:%d\n",
	        builtin_typename(sym) ?: show_ident(sym->ident),
	        stream_name(sym->pos.stream), sym->pos.line, sym->pos.pos,
	        sym->namespace, sym->type, sym->pos.changed);

	evaluate_change(sym->pos, builtin_typename(sym) ?: show_ident(sym->ident));
	sym->visited = 1;

	if (sym->ctype.base_type)
		inspect_symbol(sym->ctype.base_type);

	inspect_symbols(sym->arguments);
	inspect_symbols(sym->symbol_list);
	inspect_statement(sym->stmt);
}

static inline void clear_intermediate_result(struct analysis_card *results)
{
	results->base = NULL;
	results->namespace = 0;
	results->type = 0;
}

static void inspect_symbols_init(struct symbol_list *list)
{
	struct symbol *sym;
	FOR_EACH_PTR(list, sym) {
		clear_intermediate_result(&results);
		add_base_symbol(sym);
		inspect_symbol(sym);
	} END_FOR_EACH_PTR(sym);
}

static void expand_symbols(struct symbol_list *list)
{
	struct symbol *sym;
	FOR_EACH_PTR(list, sym) {
		expand_symbol(sym);
	} END_FOR_EACH_PTR(sym);
}

static void register_stream(struct symbol_list *list, const char *file)
{
	struct symbol *sym;

	if (list) {
		sym = first_ptr_list((struct ptr_list *)list);
		debug(2, "new stream id: %d (%s)\n", sym->pos.stream, file);
		push_new_streamid(sym->pos.stream);
	}
}

int main(int argc, char **argv)
{
	struct string_list *filelist = NULL;
	struct symbol_list *allsyms = NULL;
	char *file;

	import_changelist(&kpatch_changelist);

	expand_symbols(sparse_initialize(argc, argv, &filelist));
	FOR_EACH_PTR(filelist, file) {
		struct symbol_list *syms = sparse(file);
		expand_symbols(syms);
		register_stream(syms, file);
		concat_symbol_list(syms, &allsyms);
	} END_FOR_EACH_PTR(file);
	expand_symbols(global_scope->symbols);
	concat_symbol_list(global_scope->symbols, &allsyms);
	inspect_symbols_init(allsyms);

	return 0;
}
