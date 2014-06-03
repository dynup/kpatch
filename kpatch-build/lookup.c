/*
 * lookup.c
 *
 * This file contains functions that assist in the reading and searching
 * the symbol table of an ELF object.
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
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
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <error.h>
#include <gelf.h>
#include <unistd.h>

#include "lookup.h"

#define ERROR(format, ...) \
	error(1, 0, "%s: %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)

struct symbol {
	unsigned long value;
	unsigned long size;
	char *name;
	int type, bind, skip;
};

struct lookup_table {
	int fd, nr;
	Elf *elf;
	struct symbol *syms;
};

#define for_each_symbol(ndx, iter, table) \
	for (ndx = 0, iter = table->syms; ndx < table->nr; ndx++, iter++)

struct lookup_table *lookup_open(char *path)
{
	Elf *elf;
	int fd, i, len;
	Elf_Scn *scn;
	GElf_Shdr sh;
	GElf_Sym sym;
	Elf_Data *data;
	char *name;
	struct lookup_table *table;
	struct symbol *mysym;
	size_t shstrndx;

	if ((fd = open(path, O_RDONLY, 0)) < 0)
		ERROR("open");

	elf_version(EV_CURRENT);

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf) {
		printf("%s\n", elf_errmsg(-1));
		ERROR("elf_begin");
	}

	if (elf_getshdrstrndx(elf, &shstrndx))
		ERROR("elf_getshdrstrndx");

	scn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {
		if (!gelf_getshdr(scn, &sh))
			ERROR("gelf_getshdr");

		name = elf_strptr(elf, shstrndx, sh.sh_name);
		if (!name)
			ERROR("elf_strptr scn");

		if (!strcmp(name, ".symtab"))
			break;
	}

	if (!scn)
		ERROR(".symtab section not found");

	data = elf_getdata(scn, NULL);
	if (!data)
		ERROR("elf_getdata");

	len = sh.sh_size / sh.sh_entsize;

	table = malloc(sizeof(*table));
	if (!table)
		ERROR("malloc table");
	table->syms = malloc(len * sizeof(struct symbol));
	if (!table->syms)
		ERROR("malloc table.syms");
	memset(table->syms, 0, len * sizeof(struct symbol));
	table->nr = len;
	table->fd = fd;
	table->elf = elf;

	for_each_symbol(i, mysym, table) {
		if (!gelf_getsym(data, i, &sym))
			ERROR("gelf_getsym");

		if (sym.st_shndx == SHN_UNDEF) {
			mysym->skip = 1;
			continue;
		}

		name = elf_strptr(elf, sh.sh_link, sym.st_name);
		if(!name)
			ERROR("elf_strptr sym");

		mysym->value = sym.st_value;
		mysym->size = sym.st_size;
		mysym->type = GELF_ST_TYPE(sym.st_info);
		mysym->bind = GELF_ST_BIND(sym.st_info);
		mysym->name = name;
	}

	return table;
}

void lookup_close(struct lookup_table *table)
{
	elf_end(table->elf);
	close(table->fd);
	free(table);
}

int lookup_local_symbol(struct lookup_table *table, char *name, char *hint,
                        struct lookup_result *result)
{
	struct symbol *sym, *match = NULL;
	int i;
	char *curfile = NULL;

	memset(result, 0, sizeof(*result));
	for_each_symbol(i, sym, table) {
		if (sym->type == STT_FILE) {
			if (!strcmp(sym->name, hint)) {
				curfile = sym->name;
				continue; /* begin hint file symbols */
			} else if (curfile)
				curfile = NULL; /* end hint file symbols */
		}
		if (!curfile)
			continue;
		if (sym->bind == STB_LOCAL && !strcmp(sym->name, name)) {
			if (match)
				/* dup file+symbol, unresolvable ambiguity */
				return 1;
			match = sym;
		}
	}

	if (!match)
		return 1;

	result->value = match->value;
	result->size = match->size;
	return 0;
}

int lookup_global_symbol(struct lookup_table *table, char *name,
                         struct lookup_result *result)
{
	struct symbol *sym;
	int i;

	memset(result, 0, sizeof(*result));
	for_each_symbol(i, sym, table)
		if (!sym->skip && sym->bind == STB_GLOBAL &&
		    !strcmp(sym->name, name)) {
			result->value = sym->value;
			result->size = sym->size;
			return 0;
		}

	return 1;
}

int lookup_is_exported_symbol(struct lookup_table *table, char *name)
{
	struct symbol *sym;
	int i;
	char export[255] = "__ksymtab_";

	strncat(export, name, 254);

	for_each_symbol(i, sym, table)
		if (!sym->skip && !strcmp(sym->name, export))
			return 1;

	return 0;
}

#if 0 /* for local testing */
static void find_this(struct lookup_table *table, char *sym, char *hint)
{
	struct lookup_result result;

	if (hint)
		lookup_local_symbol(table, sym, hint, &result);
	else
		lookup_global_symbol(table, sym, &result);

	printf("%s %s w/ %s hint at 0x%016lx len %lu\n",
	       hint ? "local" : "global", sym, hint ? hint : "no",
	       result.value, result.size);
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
