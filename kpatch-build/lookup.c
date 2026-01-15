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
#include <err.h>
#include <gelf.h>
#include <unistd.h>
#include <libgen.h>
#include <stdbool.h>

#include "lookup.h"
#include "log.h"

struct object_symbol {
	unsigned long addr;
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
	char *objname;
};

#define for_each_obj_symbol(ndx, iter, table) \
	for (ndx = 0, iter = table->obj_syms; ndx < table->obj_nr; ndx++, iter++)

#define for_each_obj_symbol_continue(ndx, iter, table) \
	for (iter = table->obj_syms + ndx; ndx < table->obj_nr; ndx++, iter++)

#define for_each_exp_symbol(ndx, iter, table) \
	for (ndx = 0, iter = table->exp_syms; ndx < table->exp_nr; ndx++, iter++)

static bool maybe_discarded_sym(const char *name)
{
	if (!name)
		return false;

	/*
	 * Sometimes these symbols are discarded during linking, and sometimes
	 * they're not, depending on whether the parent object is vmlinux or a
	 * module, and also depending on the kernel version.  For simplicity,
	 * we just always skip them when comparing object symbol tables.
	 */
	if (!strncmp(name, "__exitcall_", 11) ||
	    !strncmp(name, "__brk_reservation_fn_", 21) ||
	    !strncmp(name, "__func_stack_frame_non_standard_", 32) ||
	    strstr(name, "__addressable_") ||
	    strstr(name, "__UNIQUE_ID_") ||
	    !strncmp(name, ".L.str", 6) ||
	    !strncmp(name, ".L__const", 9) ||
	    is_ubsan_sec(name))
		return true;

	return false;
}

static bool locals_match(struct lookup_table *table, int idx,
			struct symbol *file_sym, struct list_head *sym_list)
{
	struct symbol *sym;
	struct object_symbol *table_sym;
	int i, found;

	i = idx + 1;
	for_each_obj_symbol_continue(i, table_sym, table) {
		if (table_sym->type == STT_FILE)
			break;
		if (table_sym->bind != STB_LOCAL)
			continue;
		if (table_sym->type != STT_FUNC && table_sym->type != STT_OBJECT)
			continue;

		found = 0;
		sym = file_sym;
		list_for_each_entry_continue(sym, sym_list, list) {
			if (sym->type == STT_FILE)
				break;
			if (sym->bind != STB_LOCAL)
				continue;

			if (sym->type == table_sym->type &&
			    !strcmp(sym->name, table_sym->name)) {
				found = 1;
				break;
			}
		}

		if (!found)
			return false;
	}

	sym = file_sym;
	list_for_each_entry_continue(sym, sym_list, list) {
		if (sym->type == STT_FILE)
			break;
		if (sym->bind != STB_LOCAL)
			continue;
		if (sym->type != STT_FUNC && sym->type != STT_OBJECT)
			continue;
		/*
		 * Symbols which get discarded at link time are missing from
		 * the lookup table, so skip them.
		 */
		if (maybe_discarded_sym(sym->name))
			continue;

		found = 0;
		i = idx + 1;
		for_each_obj_symbol_continue(i, table_sym, table) {
			if (table_sym->type == STT_FILE)
				break;
			if (table_sym->bind != STB_LOCAL)
				continue;
			if (maybe_discarded_sym(table_sym->name))
				continue;

			if (sym->type == table_sym->type &&
			    !strcmp(sym->name, table_sym->name)) {
				found = 1;
				break;
			}
		}

		if (!found)
			return false;
	}

	return true;
}

static bool file_has_locals(struct symbol *file_sym, struct list_head *sym_list)
{
	struct symbol *sym = file_sym;

	list_for_each_entry_continue(sym, sym_list, list) {
		if (sym->type == STT_FILE)
			break;
		if (sym->bind != STB_LOCAL)
			continue;
		if (maybe_discarded_sym(sym->name))
			continue;

		if (sym->type == STT_FUNC || sym->type == STT_OBJECT)
			return true;
	}

	return false;
}

static void find_local_syms(struct lookup_table *table, struct symbol *file_sym,
		struct list_head *sym_list)
{
	struct object_symbol *sym;
	struct object_symbol *lookup_table_file_sym = NULL;
	int i;

	for_each_obj_symbol(i, sym, table) {
		if (sym->type != STT_FILE)
			continue;
		if (strcmp(file_sym->name, sym->name))
			continue;
		if (!locals_match(table, i, file_sym, sym_list))
			continue;
		if (lookup_table_file_sym)
			ERROR("found duplicate matches for %s local symbols in %s symbol table",
			      file_sym->name, table->objname);

		lookup_table_file_sym = sym;

		if (!file_has_locals(file_sym, sym_list)) {
			/*
			 * If the file doesn't have local symbols, any empty
			 * match will do.  Skip the duplicate check.
			 */
			break;
		}
	}

	if (!lookup_table_file_sym)
		ERROR("couldn't find matching %s local symbols in %s symbol table",
		      file_sym->name, table->objname);

	list_for_each_entry_continue(file_sym, sym_list, list) {
		if (file_sym->type == STT_FILE)
			break;
		file_sym->lookup_table_file_sym = lookup_table_file_sym;
	}
}

/*
 * Because there can be duplicate symbols and duplicate filenames we need to
 * correlate each symbol from the elf file to it's corresponding symbol in
 * lookup table. Both the elf file and the lookup table can be split on
 * STT_FILE symbols into blocks of symbols originating from a single source
 * file. We then compare local symbol lists from both blocks and store the
 * pointer to STT_FILE symbol in lookup table for later use in
 * lookup_local_symbol().
 */
static void find_local_syms_multiple(struct lookup_table *table,
		struct kpatch_elf *kelf)
{
	struct symbol *sym;

	list_for_each_entry(sym, &kelf->symbols, list) {
		if (sym->type == STT_FILE)
			find_local_syms(table, sym, &kelf->symbols);
	}
}

/* Strip the path and replace '-' with '_' */
static char *make_modname(char *modname)
{
	char *cur, *name;

	if (!modname)
		return NULL;

	name = strdup(basename(modname));
	if (!name)
		ERROR("strdup");

	cur = name; /* use cur as tmp */
	while (*cur != '\0') {
		if (*cur == '-')
			*cur = '_';
		cur++;
	}

	return name;
}

static void symtab_read(struct lookup_table *table, char *path)
{
	FILE *file;
	long unsigned int addr;
	int alloc_nr = 0, i = 0;
	int matched;
	bool skip = false;
	char line[256], name[256], size[16], type[16], bind[16], ndx[16];

	if ((file = fopen(path, "r")) == NULL)
		ERROR("fopen");

	/*
	 * First, get an upper limit on the number of entries for allocation
	 * purposes:
	 */
	while (fgets(line, 256, file))
		alloc_nr++;

	table->obj_syms = malloc(alloc_nr * sizeof(*table->obj_syms));
	if (!table->obj_syms)
		ERROR("malloc table.obj_syms");
	memset(table->obj_syms, 0, alloc_nr * sizeof(*table->obj_syms));

	rewind(file);

	/* Now read the actual entries: */
	while (fgets(line, 256, file)) {

		/*
		 * On powerpc, "readelf -s" shows both .dynsym and .symtab
		 * tables.  .dynsym is just a subset of .symtab, so skip it to
		 * avoid duplicates.
		 */
		if (!strncmp(line, "Symbol table ", 13)) {
			if (strstr(line, ".dynsym")) {
				skip = true;
				continue;
			} else if (strstr(line, ".symtab")) {
				skip = false;
				continue;
			}
		}
		if (skip)
			continue;

		matched = sscanf(line, "%*s %lx %s %s %s %*s %s %s\n",
				 &addr, size, type, bind, ndx, name);

		if (matched == 5) {
			name[0] = '\0';
			matched++;
		}

		if (matched != 6 ||
		    !strcmp(ndx, "UND") ||
		    !strcmp(type, "SECTION"))
			continue;

		table->obj_syms[i].addr = addr;
		table->obj_syms[i].size = strtoul(size, NULL, 0);

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

	table->obj_nr = i;

	fclose(file);
}

/*
 * The Module.symvers file format is one of the following, depending on kernel
 * version:
 *
 * <CRC>	<Symbol>	<Module>	<Export Type>
 * <CRC>	<Symbol>	<Namespace>	<Module>	<Export Type>
 * <CRC>	<Symbol>	<Module>	<Export Type>	<Namespace>
 *
 * All we care about is Symbol and Module.  Since the format is unpredictable,
 * we have to dynamically determine which column is Module by looking for
 * "vmlinux".
 */
static void symvers_read(struct lookup_table *table, char *path)
{
	FILE *file;
	int i, column, mod_column = 0;
	char line[4096];
	char *tmp, *objname, *symname;

	if ((file = fopen(path, "r")) == NULL)
		ERROR("fopen");

	while (fgets(line, 4096, file)) {
		table->exp_nr++;

		if (mod_column)
			continue;

		/* Find the module column */
		for (column = 1, tmp = line; (tmp = strchr(tmp, '\t')); column++) {
			tmp++;
			if (*tmp && !strncmp(tmp, "vmlinux", 7))
				mod_column = column;
		}
	}

	if (table->exp_nr && !mod_column)
		ERROR("Module.symvers: invalid format");

	table->exp_syms = malloc(table->exp_nr * sizeof(*table->exp_syms));
	if (!table->exp_syms)
		ERROR("malloc table.exp_syms");
	memset(table->exp_syms, 0,
	       table->exp_nr * sizeof(*table->exp_syms));

	rewind(file);
	for (i = 0; fgets(line, 4096, file); i++) {
		char *name = NULL, *mod = NULL;

		for (column = 1, tmp = line; (tmp = strchr(tmp, '\t')); column++) {
			*tmp++ = '\0';
			if (*tmp && column == 1)
				name = tmp;
			else if (*tmp && column == mod_column)
				mod = tmp;
		}

		if (!name || !mod)
			continue;

		symname = strdup(name);
		if (!symname)
			perror("strdup");

		objname = make_modname(mod);

		table->exp_syms[i].name = symname;
		table->exp_syms[i].objname = objname;
	}

	fclose(file);
}

struct lookup_table *lookup_open(char *symtab_path, char *objname,
				 char *symvers_path, struct kpatch_elf *kelf)
{
	struct lookup_table *table;

	table = malloc(sizeof(*table));
	if (!table)
		ERROR("malloc table");
	memset(table, 0, sizeof(*table));

	table->objname = objname;
	symtab_read(table, symtab_path);
	symvers_read(table, symvers_path);

	find_local_syms_multiple(table, kelf);

	return table;
}

void lookup_close(struct lookup_table *table)
{
	int i;
	struct object_symbol *obj_sym;
	struct export_symbol *exp_sym;

	for_each_obj_symbol(i, obj_sym, table)
		free(obj_sym->name);
	free(table->obj_syms);

	for_each_exp_symbol(i, exp_sym, table) {
		free(exp_sym->name);
		free(exp_sym->objname);
	}
	free(table->exp_syms);
	free(table);
}

static bool lookup_local_symbol(struct lookup_table *table,
				struct symbol *lookup_sym,
				struct lookup_result *result)
{
	struct object_symbol *sym;
	unsigned long sympos = 0;
	int i, in_file = 0;
	bool found = false;

	memset(result, 0, sizeof(*result));
	for_each_obj_symbol(i, sym, table) {
		if (lookup_sym->lookup_table_file_sym == sym) {
			in_file = 1;
			continue;
		}

		if (!in_file)
			continue;

		if (sym->type == STT_FILE)
			break;

		if (sym->bind == STB_LOCAL && !strcmp(sym->name,
					lookup_sym->name)) {
			if (found)
				ERROR("duplicate local symbol found for %s",
						lookup_sym->name);

			result->objname		= table->objname;
			result->addr		= sym->addr;
			result->size		= sym->size;
			result->global		= false;
			result->exported	= false;
			found = true;
		}
	}
	if (!found)
		return false;

	/*
	 * The kernel calculates sympos based on the order of addresses.
	 * "readelf -s" does not guarantee the ordering of symbols.
	 * Therefore, it is safer to iterate the symbol table again to
	 * calcuate the actual sympos.
	 */
	for_each_obj_symbol(i, sym, table) {
		if (sym->bind == STB_LOCAL &&
		    !strcmp(sym->name, lookup_sym->name) &&
		    sym->addr <= result->addr)
			sympos++;
	}
	result->sympos = sympos;
	return true;
}

static bool lookup_exported_symbol(struct lookup_table *table, char *name,
				   struct lookup_result *result)
{
	struct export_symbol *sym;
	int i;

	if (result)
		memset(result, 0, sizeof(*result));

	for_each_exp_symbol(i, sym, table) {
		if (!strcmp(sym->name, name)) {

			if (!result)
				return true;

			if (result->objname)
				ERROR("duplicate exported symbol found for %s", name);

			result->objname		= sym->objname;
			result->addr		= 0; /* determined at runtime */
			result->size		= 0; /* not used for exported symbols */
			result->sympos		= 0; /* always 0 for exported symbols */
			result->global		= true;
			result->exported	= true;
		}
	}

	return result && result->objname;
}

bool is_exported(struct lookup_table *table, char *name)
{
	return lookup_exported_symbol(table, name, NULL);
}

static bool lookup_global_symbol(struct lookup_table *table, char *name,
				 struct lookup_result *result)
{
	struct object_symbol *sym;
	int i;

	memset(result, 0, sizeof(*result));
	for_each_obj_symbol(i, sym, table) {
		if ((sym->bind == STB_GLOBAL || sym->bind == STB_WEAK) &&
		    !strcmp(sym->name, name)) {

			if (result->objname)
				ERROR("duplicate global symbol found for %s", name);

			result->objname		= table->objname;
			result->addr		= sym->addr;
			result->size		= sym->size;
			result->sympos		= 0; /* always 0 for global symbols */
			result->global		= true;
			result->exported	= is_exported(table, name);
		}
	}

	return !!result->objname;
}

bool lookup_symbol(struct lookup_table *table, struct symbol *sym,
		   struct lookup_result *result)
{
	if (lookup_local_symbol(table, sym, result))
		return true;

	if (lookup_global_symbol(table, sym->name, result))
		return true;

	return lookup_exported_symbol(table, sym->name, result);
}
