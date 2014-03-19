/*
 * link-vmlinux-syms.c
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

/*
 * This tool takes the nearly complete hotfix kernel module and
 * the base vmlinux. It hardcodes the addresses of any global symbols
 * that are referenced by the output object but are not exported by
 * vmlinux into the symbol table of the kernel module.
 *
 * Global symbols that are exported by the base vmlinux can be
 * resolved by the kernel module linker at load time and are
 * left unmodified.
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

#define ERROR(format, ...) \
	error(1, 0, "%s: %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)

struct section {
	Elf_Scn *scn;
	GElf_Shdr sh;
};

enum symaction {
	NOOP, /* do nothing, default */
	PATCH, /* sym is a patched function */
	LINK, /* sym is a non-exported global sym */
};

struct sym {
	struct sym *next;
	GElf_Sym sym;
	char *name;
	int index;
	enum symaction action;
	unsigned long vm_addr;
	size_t vm_len;
};

struct symlist {
	struct sym *head;
	size_t len;
};

struct elf {
	Elf *elf;
	int fd;
	size_t shstrndx;
	struct section symtab, shstrtab;
};

#define for_each_sym(list, iter) \
	for((iter) = (list)->head; (iter); (iter) = (iter)->next)

enum elfmode {
	RDONLY,
	RDWR
};

static void open_elf(char *path, enum elfmode elfmode, struct elf *elf)
{
	mode_t mode;
	Elf_Cmd cmd;

	switch(elfmode) {
	case RDONLY:
		mode = O_RDONLY;
		cmd = ELF_C_READ_MMAP;
		break;
	case RDWR:
		mode = O_RDWR;
		cmd = ELF_C_RDWR;
		break;
	}

	if ((elf->fd = open(path, mode, 0)) < 0)
		ERROR("open");

	elf->elf = elf_begin(elf->fd, cmd, NULL);
	if (!elf->elf) {
		printf("%s\n", elf_errmsg(-1));
		ERROR("elf_begin");
	}

	if (elf_getshdrstrndx(elf->elf, &elf->shstrndx))
		ERROR("elf_getshdrstrndx");
}

static void insert_sym(struct symlist *list, GElf_Sym *sym, char *name,
                       int index)
{
	struct sym *newsym;

	newsym = malloc(sizeof(*newsym));
	if (!newsym)
		ERROR("malloc");
	memset(newsym, 0, sizeof(*newsym));
	newsym->sym = *sym;
	newsym->name = name;
	newsym->index = index;

	newsym->next = list->head;
	list->head = newsym;
}

static void find_section_by_name(struct elf *elf, char *name, struct section *sec)
{
	Elf_Scn *scn = NULL;
	GElf_Shdr sh;
	char *secname;

	while ((scn = elf_nextscn(elf->elf, scn))) {
		if (!gelf_getshdr(scn, &sh))
			ERROR("gelf_getshdr");

		secname = elf_strptr(elf->elf, elf->shstrndx, sh.sh_name);
		if (!secname)
			ERROR("elf_strptr scn");
			
		if (!strcmp(secname, name))
			break;
	}

	if (!scn)
		ERROR("no section %s found", name);

	sec->scn = scn;
	sec->sh = sh;
}

static void create_symlist(struct elf *elf, struct symlist *symlist)
{
	Elf_Scn *scn = elf->symtab.scn;
	GElf_Shdr *sh = &elf->symtab.sh;
	GElf_Sym sym;
	Elf_Data *data;
	char *name;
	int i;

	/* get symtab data buffer */
	data = elf_getdata(scn, NULL);
	if (!data)
		ERROR("elf_getdata");

	symlist->len = sh->sh_size / sh->sh_entsize;
	for (i = 0; i < symlist->len; i++) {
		if (!gelf_getsym(data, i, &sym))
			ERROR("gelf_getsym");

		name = elf_strptr(elf->elf, sh->sh_link, sym.st_name);
		if(!name)
			ERROR("elf_strptr sym");

		insert_sym(symlist, &sym, name, i);
	}
}

static struct sym *find_symbol_by_name(struct symlist *list, char *name)
{
	struct sym *cur, *ret = NULL;

	for_each_sym(list, cur) {
		if (!strcmp(cur->name, name)) {
			if (ret)
				ERROR("unresolvable symbol ambiguity for symbol '%s'", name);
			ret = cur;
		}
	}

	return ret;
}

/*
 * TODO: de-dup common code above these point with code
 * in add-patches-section.c
 */

int main(int argc, char **argv)
{
	struct symlist symlist, symlistv;
	struct sym *cur, *vsym;
	struct elf elf, elfv;
	char name[255];
	struct section symtab;
	Elf_Scn *scn;
	Elf_Data *data;

	/* set elf version (required by libelf) */
	if (elf_version(EV_CURRENT) == EV_NONE)
		ERROR("elf_version");

	memset(&elf, 0, sizeof(elf));
	memset(&elfv, 0, sizeof(elfv));
	open_elf(argv[1], RDWR, &elf);
	open_elf(argv[2], RDONLY, &elfv);

	find_section_by_name(&elf, ".symtab", &(elf.symtab));
	find_section_by_name(&elfv, ".symtab", &(elfv.symtab));

	find_section_by_name(&elf, ".shstrtab", &(elf.shstrtab));

	memset(&symlist, 0, sizeof(symlist));
	memset(&symlistv, 0, sizeof(symlistv));
	create_symlist(&elf, &symlist);
	create_symlist(&elfv, &symlistv);

	/* lookup non-exported globals and insert vmlinux address */
	for_each_sym(&symlist, cur) {
		if (GELF_ST_TYPE(cur->sym.st_info) != STT_NOTYPE ||
		    GELF_ST_BIND(cur->sym.st_info) != STB_GLOBAL ||
		    cur->sym.st_shndx != STN_UNDEF ||
		    !strcmp(cur->name, "kpatch_register") ||
		    !strcmp(cur->name, "kpatch_unregister"))
			continue;

		printf("found global symbol %s\n", cur->name);
		sprintf(name, "__kstrtab_%s", cur->name);
		vsym = find_symbol_by_name(&symlistv, name);
		if (vsym) {
			printf("symbol is exported by the kernel\n");
			continue;
		}

		vsym = find_symbol_by_name(&symlistv, cur->name);
		if (!vsym)
			ERROR("couldn't find global function %s in vmlinux",
			      cur->name);

		cur->vm_addr = vsym->sym.st_value;
		cur->vm_len = vsym->sym.st_size;
		cur->action = LINK;
		printf("original symbol at address %016lx (length %zu)\n",
		       cur->vm_addr, cur->vm_len);
	}

	elf_end(elfv.elf);
	close(elfv.fd);

	find_section_by_name(&elf, ".symtab", &symtab);
	scn = symtab.scn;

	data = elf_getdata(scn, NULL);
	if (!data)
		ERROR("elf_getdata");

	/* update LINK symbols */
	for_each_sym(&symlist, cur) {
		if (cur->action != LINK)
			continue;
		cur->sym.st_value = cur->vm_addr;
		cur->sym.st_info = GELF_ST_INFO(STB_LOCAL,STT_FUNC);
		cur->sym.st_shndx = SHN_ABS;
		gelf_update_sym(data, cur->index, &cur->sym);
	}

	if (elf_update(elf.elf, ELF_C_WRITE) < 0)
		ERROR("elf_update %s", elf_errmsg(-1));

	elf_end(elf.elf);
	close(elf.fd);

	return 0;
}
