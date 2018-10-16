/*
 * lookup.c
 *
 * This file contains functions that assist in the reading and searching
 * the symbol table of an ELF object.
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2014 Josh Poimboeuf <jpoimboe@redhat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA,
 * 02110-1301, USA.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <error.h>
#include <gelf.h>
#include <unistd.h>
#include <libgen.h>

#include "lookup.h"
#include "log.h"

struct object_symbol {
	unsigned long value;
	unsigned long size;
	char *name;
	int type, bind;
};

struct export_symbol {
	char *name;
	char *objname;
};

struct lookup_table {
	int obj_nr, exp_nr;
	struct object_symbol *obj_syms;
	struct export_symbol *exp_syms;
	struct object_symbol *local_syms;
};

#define for_each_obj_symbol(ndx, iter, table) \
	for (ndx = 0, iter = table->obj_syms; ndx < table->obj_nr; ndx++, iter++)

#define for_each_obj_symbol_continue(ndx, iter, table) \
	for (iter = table->obj_syms + ndx; ndx < table->obj_nr; ndx++, iter++)

#define for_each_exp_symbol(ndx, iter, table) \
	for (ndx = 0, iter = table->exp_syms; ndx < table->exp_nr; ndx++, iter++)

static int maybe_discarded_sym(const char *name)
{
	if (!name)
		return 0;

	/*
	 * Sometimes these symbols are discarded during linking, and sometimes
	 * they're not, depending on whether the parent object is vmlinux or a
	 * module, and also depending on the kernel version.  For simplicity,
	 * we just always skip them when comparing object symbol tables.
	 */
	if (!strncmp(name, "__exitcall_", 11) ||
	    !strncmp(name, "__brk_reservation_fn_", 21) ||
	    !strncmp(name, "__func_stack_frame_non_standard_", 32) ||
	    !strncmp(name, "__addressable_", 14))
		return 1;

	return 0;
}

static int locals_match(struct lookup_table *table, int idx,
			struct sym_compare_type *child_locals)
{
	struct sym_compare_type *child;
	struct object_symbol *sym;
	int i, found;

	i = idx + 1;
	for_each_obj_symbol_continue(i, sym, table) {
		if (sym->type == STT_FILE)
			break;
		if (sym->bind != STB_LOCAL)
			continue;
		if (sym->type != STT_FUNC && sym->type != STT_OBJECT)
			continue;

		found = 0;
		for (child = child_locals; child->name; child++) {
			if (child->type == sym->type &&
			    !strcmp(child->name, sym->name)) {
				found = 1;
				break;
			}
		}

		if (!found)
			return 0;
	}

	for (child = child_locals; child->name; child++) {
		/*
		 * Symbols which get discarded at link time are missing from
		 * the lookup table, so skip them.
		 */
		if (maybe_discarded_sym(child->name))
			continue;

		found = 0;
		i = idx + 1;
		for_each_obj_symbol_continue(i, sym, table) {
			if (sym->type == STT_FILE)
				break;
			if (sym->bind != STB_LOCAL)
				continue;
			if (sym->type != STT_FUNC && sym->type != STT_OBJECT)
				continue;
			if (maybe_discarded_sym(sym->name))
				continue;

			if (!strcmp(child->name, sym->name)) {
				found = 1;
				break;
			}
		}

		if (!found)
			return 0;
	}

	return 1;
}

static void find_local_syms(struct lookup_table *table, char *hint,
			    struct sym_compare_type *child_locals)
{
	struct object_symbol *sym;
	int i;

	if (!child_locals)
		return;

	for_each_obj_symbol(i, sym, table) {
		if (sym->type != STT_FILE)
			continue;
		if (strcmp(hint, sym->name))
			continue;
		if (!locals_match(table, i, child_locals))
			continue;
		if (table->local_syms)
			ERROR("find_local_syms for %s: found_dup", hint);

		table->local_syms = sym;
	}

	if (!table->local_syms)
		ERROR("find_local_syms for %s: couldn't find in vmlinux symbol table", hint);
}

/* Strip the path and replace '-' with '_' */
static char *make_modname(char *modname)
{
	char *cur;

	if (!modname)
		return NULL;

	cur = modname;
	while (*cur != '\0') {
		if (*cur == '-')
			*cur = '_';
		cur++;
	}

	return basename(modname);
}

static void symtab_read(struct lookup_table *table, char *path)
{
	FILE *file;
	long unsigned int value, size;
	unsigned int i = 0;
	int matched;
	char line[256], name[256], type[16], bind[16], ndx[16];

	if ((file = fopen(path, "r")) == NULL)
		ERROR("fopen");

	while (fgets(line, 256, file)) {
		matched = sscanf(line, "%*s %lx %lu %s %s %*s %s %s\n",
				 &value, &size, type, bind, ndx, name);

		if (matched == 5) {
			name[0] = '\0';
			matched++;
		}

		if (matched != 6 ||
		    !strcmp(ndx, "UNDEF") ||
		    !strcmp(type, "SECTION"))
			continue;

		table->obj_nr++;
	}

	table->obj_syms = malloc(table->obj_nr * sizeof(*table->obj_syms));
	if (!table->obj_syms)
		ERROR("malloc table.obj_syms");
	memset(table->obj_syms, 0, table->obj_nr * sizeof(*table->obj_syms));

	rewind(file);

	while (fgets(line, 256, file)) {
		matched = sscanf(line, "%*s %lx %lu %s %s %*s %s %s\n",
				 &value, &size, type, bind, ndx, name);

		if (matched == 5) {
			name[0] = '\0';
			matched++;
		}

		if (matched != 6 ||
		    !strcmp(ndx, "UNDEF") ||
		    !strcmp(type, "SECTION"))
			continue;

		table->obj_syms[i].value = value;
		table->obj_syms[i].size = size;
		table->obj_syms[i].name = strdup(name);

		if (!strcmp(bind, "LOCAL")) {
			table->obj_syms[i].bind = STB_LOCAL;
		} else if (!strcmp(bind, "GLOBAL")) {
			table->obj_syms[i].bind = STB_GLOBAL;
		} else if (!strcmp(bind, "WEAK")) {
			table->obj_syms[i].bind = STB_WEAK;
		} else {
			ERROR("unknown symbol bind %s", bind);
		}

		if (!strcmp(type, "NOTYPE")) {
			table->obj_syms[i].type = STT_NOTYPE;
		} else if (!strcmp(type, "OBJECT")) {
			table->obj_syms[i].type = STT_OBJECT;
		} else if (!strcmp(type, "FUNC")) {
			table->obj_syms[i].type = STT_FUNC;
		} else if (!strcmp(type, "FILE")) {
			table->obj_syms[i].type = STT_FILE;
		} else {
			ERROR("unknown symbol type %s", type);
		}

		table->obj_syms[i].name = strdup(name);
		if (!table->obj_syms[i].name)
			ERROR("strdup");
		i++;
	}

	fclose(file);
}

static void symvers_read(struct lookup_table *table, char *path)
{
	FILE *file;
	unsigned int crc, i = 0;
	char name[256], mod[256], export[256];
	char *objname, *symname;

	if ((file = fopen(path, "r")) == NULL)
		ERROR("fopen");

	while (fscanf(file, "%x %s %s %s\n",
		      &crc, name, mod, export) != EOF)
		table->exp_nr++;

	table->exp_syms = malloc(table->exp_nr * sizeof(*table->exp_syms));
	if (!table->exp_syms)
		ERROR("malloc table.exp_syms");
	memset(table->exp_syms, 0,
	       table->exp_nr * sizeof(*table->exp_syms));

	rewind(file);

	while (fscanf(file, "%x %s %s %s\n",
		      &crc, name, mod, export) != EOF) {
		symname = strdup(name);
		if (!symname)
			perror("strdup");

		objname = strdup(mod);
		if (!objname)
			perror("strdup");
		/* Modifies objname in-place */
		objname = make_modname(objname);

		table->exp_syms[i].name = symname;
		table->exp_syms[i].objname = objname;
		i++;
	}

	fclose(file);
}

struct lookup_table *lookup_open(char *symtab_path, char *symvers_path,
				 char *hint, struct sym_compare_type *locals)
{
	struct lookup_table *table;

	table = malloc(sizeof(*table));
	if (!table)
		ERROR("malloc table");
	memset(table, 0, sizeof(*table));

	symtab_read(table, symtab_path);
	symvers_read(table, symvers_path);
	find_local_syms(table, hint, locals);

	return table;
}

void lookup_close(struct lookup_table *table)
{
	free(table->obj_syms);
	free(table->exp_syms);
	free(table);
}

int lookup_local_symbol(struct lookup_table *table, char *name,
                        struct lookup_result *result)
{
	struct object_symbol *sym;
	unsigned long pos = 0;
	int i, match = 0, in_file = 0;

	if (!table->local_syms)
		return 1;

	memset(result, 0, sizeof(*result));
	for_each_obj_symbol(i, sym, table) {
		if (sym->bind == STB_LOCAL && !strcmp(sym->name, name))
			pos++;

		if (table->local_syms == sym) {
			in_file = 1;
			continue;
		}

		if (!in_file)
			continue;

		if (sym->type == STT_FILE)
			break;

		if (sym->bind == STB_LOCAL && !strcmp(sym->name, name)) {
			match = 1;
			break;
		}
	}

	if (!match)
		return 1;

	result->pos = pos;
	result->value = sym->value;
	result->size = sym->size;
	return 0;
}

int lookup_global_symbol(struct lookup_table *table, char *name,
                         struct lookup_result *result)
{
	struct object_symbol *sym;
	int i;

	memset(result, 0, sizeof(*result));
	for_each_obj_symbol(i, sym, table) {
		if ((sym->bind == STB_GLOBAL || sym->bind == STB_WEAK) &&
		    !strcmp(sym->name, name)) {
			result->value = sym->value;
			result->size = sym->size;
			result->pos = 0; /* always 0 for global symbols */
			return 0;
		}
	}

	return 1;
}

int lookup_is_exported_symbol(struct lookup_table *table, char *name)
{
	struct export_symbol *sym, *match = NULL;
	int i;

	for_each_exp_symbol(i, sym, table) {
		if (!strcmp(sym->name, name)) {
			if (match)
				ERROR("duplicate exported symbol found for %s", name);
			match = sym;
		}
	}

	return !!match;
}

/*
 * lookup_exported_symbol_objname - find the object/module an exported
 * symbol belongs to.
 */
char *lookup_exported_symbol_objname(struct lookup_table *table, char *name)
{
	struct export_symbol *sym, *match = NULL;
	int i;

	for_each_exp_symbol(i, sym, table) {
		if (!strcmp(sym->name, name)) {
			if (match)
				ERROR("duplicate exported symbol found for %s", name);
			match = sym;
		}
	}

	if (match)
		return match->objname;

	return NULL;
 }

#if 0 /* for local testing */
static void find_this(struct lookup_table *table, char *sym, char *hint)
{
	struct lookup_result result;

	if (hint)
		lookup_local_symbol(table, sym, hint, &result);
	else
		lookup_global_symbol(table, sym, &result);

	printf("%s %s w/ %s hint at 0x%016lx len %lu pos %lu\n",
	       hint ? "local" : "global", sym, hint ? hint : "no",
	       result.value, result.size, result.pos);
}

int main(int argc, char **argv)
{
	struct lookup_table *vmlinux;

	if (argc != 2)
		return 1;

	vmlinux = lookup_open(argv[1]);

	printf("printk is%s exported\n",
		lookup_is_exported_symbol(vmlinux, "__fentry__") ? "" : " not");
	printf("meminfo_proc_show is%s exported\n",
		lookup_is_exported_symbol(vmlinux, "meminfo_proc_show") ? "" : " not");

	find_this(vmlinux, "printk", NULL);
	find_this(vmlinux, "pages_to_scan_show", "ksm.c");
	find_this(vmlinux, "pages_to_scan_show", "huge_memory.c");
	find_this(vmlinux, "pages_to_scan_show", NULL); /* should fail */

	lookup_close(vmlinux);

	return 0;
}
#endif
