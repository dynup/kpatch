/*
 * 'sparse' library helper routines.
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>

#include "lib.h"
#include "allocate.h"
#include "token.h"
#include "parse.h"
#include "symbol.h"
#include "expression.h"
#include "evaluate.h"
#include "scope.h"
#include "linearize.h"
#include "target.h"
#include "machine.h"
#include "bits.h"

#ifdef DEBUG
#define debug(args...) fprintf(stderr, args)
#else
#define debug(args...)
#endif

static int prettify(const char **fnamep)
{
	const char *name = *fnamep;
	int len = strlen(name);

	if (len > 2 && !memcmp(name, "./", 2)) {
		name += 2;
		len -= 2;
	}

	*fnamep = name;
	return len;
}

static const char *show_include_chain(int stream, const char *base)
{
	static char buffer[200];
	int len = 0;

	while ((stream = stream_prev(stream)) >= 0) {
		const char *p = stream_name(stream);
		int pretty_len;

		if (p == base)
			break;

		pretty_len = prettify(&p);
		if (pretty_len <= 0)
			break;

		/*
		 * At worst, we'll need " (through %s, ...)" in addition to the
		 * new filename
		 */
		if (pretty_len + len + 20 > sizeof(buffer)) {
			if (!len)
				return "";
			memcpy(buffer+len, ", ...", 5);
			len += 5;
			break;
		}

		if (!len) {
			memcpy(buffer, " (through ", 10);
			len = 10;
		} else {
			buffer[len++] = ',';
			buffer[len++] = ' ';
		}

		memcpy(buffer+len, p, pretty_len);
		len += pretty_len;
	}
	if (!len)
		return "";

	buffer[len] = ')';
	buffer[len+1] = 0;
	return buffer;
}

static const char *show_stream_name(struct position pos)
{
	const char *name = stream_name(pos.stream);
	static const char *last;

	if (name == base_filename)
		return name;
	if (name == last)
		return name;
	last = name;

	fprintf(stderr, "%s: note: in included file%s:\n",
		base_filename,
		show_include_chain(pos.stream, base_filename));
	return name;
}

static void do_warn(const char *type, struct position pos, const char * fmt, va_list args)
{
	static char buffer[512];

	/* Shut up warnings if position is bad_token.pos */
	if (pos.type == TOKEN_BAD)
		return;

	vsprintf(buffer, fmt, args);	

	fflush(stdout);
	fprintf(stderr, "%s:%d:%d: %s%s%s\n",
		show_stream_name(pos), pos.line, pos.pos,
		diag_prefix, type, buffer);
}

static int show_info = 1;

void info(struct position pos, const char * fmt, ...)
{
	va_list args;

	if (!show_info)
		return;
	va_start(args, fmt);
	do_warn("", pos, fmt, args);
	va_end(args);
}

static void do_error(struct position pos, const char * fmt, va_list args)
{
	static int errors = 0;
        die_if_error = 1;
	show_info = 1;
	/* Shut up warnings if position is bad_token.pos */
	if (pos.type == TOKEN_BAD)
		return;
	/* Shut up warnings after an error */
	has_error |= ERROR_CURR_PHASE;
	if (errors > fmax_errors) {
		static int once = 0;
		show_info = 0;
		if (once)
			return;
		fmt = "too many errors";
		once = 1;
	}

	do_warn("error: ", pos, fmt, args);
	errors++;
}	

void warning(struct position pos, const char * fmt, ...)
{
	va_list args;

	if (Wsparse_error) {
		va_start(args, fmt);
		do_error(pos, fmt, args);
		va_end(args);
		return;
	}

	if (!fmax_warnings || has_error) {
		show_info = 0;
		return;
	}

	if (!--fmax_warnings) {
		show_info = 0;
		fmt = "too many warnings";
	}

	va_start(args, fmt);
	do_warn("warning: ", pos, fmt, args);
	va_end(args);
}

void sparse_error(struct position pos, const char * fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	do_error(pos, fmt, args);
	va_end(args);
}

void expression_error(struct expression *expr, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	do_error(expr->pos, fmt, args);
	va_end(args);
	expr->ctype = &bad_ctype;
}

NORETURN_ATTR
void error_die(struct position pos, const char * fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	do_warn("error: ", pos, fmt, args);
	va_end(args);
	exit(1);
}

NORETURN_ATTR
void die(const char *fmt, ...)
{
	va_list args;
	static char buffer[512];

	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);

	fprintf(stderr, "%s%s\n", diag_prefix, buffer);
	exit(1);
}

////////////////////////////////////////////////////////////////////////////////

static struct token *pre_buffer_begin = NULL;
static struct token **pre_buffer_next = &pre_buffer_begin;

void add_pre_buffer(const char *fmt, ...)
{
	va_list args;
	unsigned int size;
	struct token *begin, *end;
	char buffer[4096];

	va_start(args, fmt);
	size = vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);
	begin = tokenize_buffer(buffer, size, &end);
	*pre_buffer_next = begin;
	pre_buffer_next = &end->next;
}

static void create_builtin_stream(void)
{
	// Temporary hack
	add_pre_buffer("#define _Pragma(x)\n");

	/* add the multiarch include directories, if any */
	if (multiarch_dir && *multiarch_dir) {
		add_pre_buffer("#add_system \"/usr/include/%s\"\n", multiarch_dir);
		add_pre_buffer("#add_system \"/usr/local/include/%s\"\n", multiarch_dir);
	}

	/* We add compiler headers path here because we have to parse
	 * the arguments to get it, falling back to default. */
	add_pre_buffer("#add_system \"%s/include\"\n", gcc_base_dir);
	add_pre_buffer("#add_system \"%s/include-fixed\"\n", gcc_base_dir);

	add_pre_buffer("#define __builtin_stdarg_start(a,b) ((a) = (__builtin_va_list)(&(b)))\n");
	add_pre_buffer("#define __builtin_va_start(a,b) ((a) = (__builtin_va_list)(&(b)))\n");
	add_pre_buffer("#define __builtin_ms_va_start(a,b) ((a) = (__builtin_ms_va_list)(&(b)))\n");
	add_pre_buffer("#define __builtin_va_arg(arg,type)  ({ type __va_arg_ret = *(type *)(arg); arg += sizeof(type); __va_arg_ret; })\n");
	add_pre_buffer("#define __builtin_va_alist (*(void *)0)\n");
	add_pre_buffer("#define __builtin_va_arg_incr(x) ((x) + 1)\n");
	add_pre_buffer("#define __builtin_va_copy(dest, src) ({ dest = src; (void)0; })\n");
	add_pre_buffer("#define __builtin_ms_va_copy(dest, src) ({ dest = src; (void)0; })\n");
	add_pre_buffer("#define __builtin_va_end(arg)\n");
	add_pre_buffer("#define __builtin_ms_va_end(arg)\n");
	add_pre_buffer("#define __builtin_va_arg_pack()\n");
}

static struct symbol_list *sparse_tokenstream(struct token *token)
{
	int builtin = token && !token->pos.stream;

	// Preprocess the stream
	token = preprocess(token);

	if (dump_macro_defs || dump_macros_only) {
		if (!builtin)
			dump_macro_definitions();
		if (dump_macros_only)
			return NULL;
	}

	if (preprocess_only) {
		while (!eof_token(token)) {
			int prec = 1;
			struct token *next = token->next;
			const char *separator = "";
			if (next->pos.whitespace)
				separator = " ";
			if (next->pos.newline) {
				separator = "\n\t\t\t\t\t";
				prec = next->pos.pos;
				if (prec > 4)
					prec = 4;
			}
			printf("%s%.*s", show_token(token), prec, separator);
			token = next;
		}
		putchar('\n');

		return NULL;
	}

	// Parse the resulting C code
	while (!eof_token(token))
		token = external_declaration(token, &translation_unit_used_list, NULL);
	return translation_unit_used_list;
}

static int in_change_range(const struct token *token, const struct patch_change *chg)
{
	if (token->pos.line >= chg->resultline &&
	    token->pos.line < chg->resultline+chg->numlines) {
		debug("token: `%s`: pos line %d in range: %d-%d\n",
		      show_token(token), token->pos.line, chg->resultline, chg->resultline+chg->numlines);
		return 1;
	}
	return 0;
}

extern struct change_list *kpatch_changelist;

static void mark_ifchanged(const char *filename, struct token *token)
{
	struct patch_change *chg;

	// already marked as changed
	if (token->pos.changed)
		return;

	FOR_EACH_PTR(kpatch_changelist, chg) {
		if (strcmp(filename, chg->pathname)){
			debug("%s vs %s\n", filename, chg->pathname);
			continue;
		}
		if (in_change_range(token, chg))
			token->pos.changed = 1;
	} END_FOR_EACH_PTR(chg);
}

static struct symbol_list *sparse_file(const char *filename)
{
	int fd;
	struct token *token, *t;

	if (strcmp(filename, "-") == 0) {
		fd = 0;
	} else {
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			die("No such file: %s", filename);
	}
	base_filename = filename;

	// Tokenize the input stream
	t = token = tokenize(NULL, filename, fd, NULL, includepath);
	close(fd);

	while (!eof_token(t)) {
		struct token *next = t->next;
		mark_ifchanged(filename, t);
		t = next;
	}

	return sparse_tokenstream(token);
}

/*
 * This handles the "-include" directive etc: we're in global
 * scope, and all types/macros etc will affect all the following
 * files.
 *
 * NOTE NOTE NOTE! "#undef" of anything in this stage will
 * affect all subsequent files too, i.e. we can have non-local
 * behaviour between files!
 */
static struct symbol_list *sparse_initial(void)
{
	int i;

	// Prepend any "include" file to the stream.
	// We're in global scope, it will affect all files!
	for (i = 0; i < cmdline_include_nr; i++)
		add_pre_buffer("#argv_include \"%s\"\n", cmdline_include[i]);

	return sparse_tokenstream(pre_buffer_begin);
}

struct symbol_list *sparse_initialize(int argc, char **argv, struct string_list **filelist)
{
	char **args;
	struct symbol_list *list;

	base_filename = "command-line";

	// Initialize symbol stream first, so that we can add defines etc
	init_symbols();

	// initialize the default target to the native 'machine'
	target_config(MACH_NATIVE);

	args = argv;
	for (;;) {
		char *arg = *++args;
		if (!arg)
			break;

		if (arg[0] == '-' && arg[1]) {
			args = handle_switch(arg+1, args);
			continue;
		}
		add_ptr_list(filelist, arg);
	}
	handle_switch_finalize();

	// Redirect stdout if needed
	if (dump_macro_defs || preprocess_only)
		do_output = 1;
	if (do_output && outfile && strcmp(outfile, "-")) {
		if (!freopen(outfile, "w", stdout))
			die("error: cannot open %s: %s", outfile, strerror(errno));
	}

	if (fdump_ir == 0)
		fdump_ir = PASS_FINAL;

	list = NULL;
	if (filelist) {
		// Initialize type system
		target_init();
		init_ctype();

		predefined_macros();
		create_builtin_stream();
		init_builtins(0);

		list = sparse_initial();

		/*
		 * Protect the initial token allocations, since
		 * they need to survive all the others
		 */
		protect_token_alloc();
	}
	/*
	 * Evaluate the complete symbol list
	 * Note: This is not needed for normal cases.
	 *	 These symbols should only be predefined defines and
	 *	 declaratons which will be evaluated later, when needed.
	 *	 This is also the case when a file is directly included via
	 *	 '-include <file>' on the command line *AND* the file only
	 *	 contains defines, declarations and inline definitions.
	 *	 However, in the rare cases where the given file should
	 *	 contain some definitions, these will never be evaluated
	 *	 and thus won't be able to be linearized correctly.
	 *	 Hence the evaluate_symbol_list() here under.
	 */
	evaluate_symbol_list(list);
	return list;
}

struct symbol_list * sparse_keep_tokens(char *filename)
{
	struct symbol_list *res;

	/* Clear previous symbol list */
	translation_unit_used_list = NULL;

	new_file_scope();
	res = sparse_file(filename);

	/* And return it */
	return res;
}


struct symbol_list * __sparse(char *filename)
{
	struct symbol_list *res;

	res = sparse_keep_tokens(filename);

	/* Drop the tokens for this file after parsing */
	clear_token_alloc();

	/* And return it */
	return res;
}

struct symbol_list * sparse(char *filename)
{
	struct symbol_list *res = __sparse(filename);

	if (has_error & ERROR_CURR_PHASE)
		has_error = ERROR_PREV_PHASE;
	/* Evaluate the complete symbol list */
	evaluate_symbol_list(res);

	return res;
}
