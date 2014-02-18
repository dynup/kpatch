/*
 * tools/add-patches-section.c
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 *
 * This tool takes an elf object, the output of create-diff-object
 * and the base vmlinux as arguments and adds two new sections
 * to the elf object; .patches and .rela.patches.
 *
 * These two sections allow the kpatch core modules to know which
 * functions are overridden by the patch module.
 *
 * For each struct kpatch_patch entry in the .patches section, the core
 * module will register the new function as an ftrace handler for the
 * old function.  The new function will return to the caller of the old
 * function, not the old function itself, bypassing the old function.
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

#include "kpatch.h"

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

	while (scn = elf_nextscn(elf->elf, scn)) {
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

	/* find (local) function symbols
	 * NOTE: If the function symbol is in the kpatch-gen file, it needs
	 * to be patched.  If the function didn't need to be patched,
	 * it wouldn't have been incldued in the kpatch-gen file.
	 */
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
	struct sym *cur;

	for_each_sym(list, cur)
		if (!strcmp(cur->name, name))
			return cur;
	return NULL;
}

int main(int argc, char **argv)
{
	struct symlist symlist, symlistv;
	struct sym *cur, *vsym;
	struct elf elf, elfv;
	char name[255];
	void *buf;
	struct kpatch_patch *patches_data;
	GElf_Rela *relas_data;
	int patches_nr = 0, i, patches_size, relas_size, len;
	int patches_offset, relas_offset, patches_index, relas_index;
	struct section symtab;
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Shdr sh, *shp;
	GElf_Ehdr eh;
	GElf_Sym sym;

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

	/* lookup patched functions in vmlinux */
	for_each_sym(&symlist, cur) {
		if (GELF_ST_TYPE(cur->sym.st_info) != STT_FUNC)
			continue;

		printf("found patched function %s\n", cur->name);

		vsym = find_symbol_by_name(&symlistv, cur->name);
		if (!vsym)
			ERROR("couldn't find patched function in vmlinux");
		cur->vm_addr = vsym->sym.st_value;
		cur->vm_len = vsym->sym.st_size;
		cur->action = PATCH;
		printf("original function at address %016lx (length %d)\n",
		       cur->vm_addr, cur->vm_len);
		patches_nr++;
	}

#if 0
	/* lookup non-exported globals and insert vmlinux address */
	for_each_sym(&symlist, cur) {
		if (GELF_ST_TYPE(cur->sym.st_info) != STT_NOTYPE ||
		    GELF_ST_BIND(cur->sym.st_info) != STB_GLOBAL)
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
			ERROR("couldn't find global function in vmlinux");

		cur->vm_addr = vsym->sym.st_value;
		cur->vm_len = vsym->sym.st_size;
		cur->action = LINK;
		printf("original symbol at address %016lx (length %d)\n",
		       cur->vm_addr, cur->vm_len);
	}
#endif

	elf_end(elfv.elf);
	close(elfv.fd);

	printf("patches_nr = %d\n", patches_nr);

	/* allocate new section data buffers */
	patches_size = sizeof(*patches_data) * patches_nr;
	patches_data = malloc(patches_size);
	if (!patches_data)
		ERROR("malloc");
	memset(patches_data, 0, patches_size);

	relas_size = sizeof(*relas_data) * patches_nr;
	relas_data = malloc(relas_size);
	if (!relas_data)
		ERROR("malloc");
	memset(relas_data, 0, relas_size);

	printf("patches_size = %d\n",patches_size);
	printf("relas_size = %d\n",relas_size);

	/* populate new section data buffers */
	i = 0;
	for_each_sym(&symlist, cur) {
		if (cur->action != PATCH)
			continue;
		patches_data[i].orig = cur->vm_addr;
		patches_data[i].orig_end = cur->vm_addr + cur->vm_len;
		relas_data[i].r_offset = i * sizeof(struct kpatch_patch);
		relas_data[i].r_info = GELF_R_INFO(cur->index, R_X86_64_64);
		i++;
	}

	/* get next section index from elf header */
	if (!gelf_getehdr(elf.elf, &eh))
		ERROR("gelf_getehdr");
	patches_index = eh.e_shnum;
	relas_index = patches_index  + 1;

	/* add new section names to shstrtab */
	scn = elf.shstrtab.scn;
	shp = &elf.shstrtab.sh;

	data = elf_getdata(scn, NULL);
	if (!data)
		ERROR("elf_getdata");

	len = strlen(".patches") + strlen(".rela.patches") + 2;
	buf = malloc(data->d_size + len);
	memcpy(buf, data->d_buf, data->d_size);

	data->d_buf = buf;
	buf = data->d_buf + data->d_size;
	
	len = strlen(".patches") + 1;
	memcpy(buf, ".patches", len);
	patches_offset = buf - data->d_buf;
	printf("patches_offset = %d\n", patches_offset);
	buf += len;
	len = strlen(".rela.patches") + 1;
	memcpy(buf, ".rela.patches", len);
	relas_offset = buf - data->d_buf;
	printf("relas_offset = %d\n", relas_offset);
	buf += len;
	data->d_size = buf - data->d_buf;

	if (!elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY))
		ERROR("elf_flagdata");

	if (!gelf_update_shdr(scn, shp))
		ERROR("gelf_update_shdr");

	/* get symtab vars */
	find_section_by_name(&elf, ".symtab", &symtab);
	scn = symtab.scn;
	shp = &symtab.sh;

	data = elf_getdata(scn, NULL);
	if (!data)
		ERROR("elf_getdata");
#if 0
	/* update LINK symbols */
	for_each_sym(&symlist, cur) {
		if (cur->action != LINK)
			continue;
		cur->sym.st_value = cur->vm_addr;
		cur->sym.st_info = GELF_ST_INFO(STB_LOCAL,STT_FUNC);
		cur->sym.st_shndx = SHN_ABS;
		gelf_update_sym(data, cur->index, &cur->sym);
	}
#endif

	/* add new section symbols to symtab */
	len = sizeof(GElf_Sym) * 2;
	buf = malloc(data->d_size + len);
	memcpy(buf, data->d_buf, data->d_size);

	data->d_buf = buf;
	buf = data->d_buf + data->d_size;

	memset(&sym, 0, sizeof(GElf_Sym));
	sym.st_info = GELF_ST_INFO(STB_LOCAL, STT_SECTION);

	len = sizeof(GElf_Sym);
	sym.st_shndx = patches_index;
	memcpy(buf, &sym, len);
	buf += len;
	sym.st_shndx = relas_index;
	memcpy(buf, &sym, len);
	buf += len;
	data->d_size = buf - data->d_buf;

	if (!elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY))
		ERROR("elf_flagdata");

	if (!gelf_update_shdr(scn, shp))
		ERROR("gelf_update_shdr");

	/* create .patches section */
	scn = elf_newscn(elf.elf);
	if (!scn)
		ERROR("elf_newscn");

	data = elf_newdata(scn);
	if (!data)
		ERROR("elf_newdata");

	data->d_size = patches_size;
	data->d_buf = patches_data;
	data->d_type = ELF_T_BYTE;

	memset(&sh, 0, sizeof(sh));
	sh.sh_type = SHT_PROGBITS;
	sh.sh_name = patches_offset;
	sh.sh_entsize = sizeof(struct kpatch_patch);
	sh.sh_addralign = 8;
	sh.sh_flags = SHF_ALLOC;
	sh.sh_size = data->d_size;

	if (!gelf_update_shdr(scn, &sh))
		ERROR("gelf_update_shdr");

	/* create .rela.patches section */
	scn = elf_newscn(elf.elf);
	if (!scn)
		ERROR("elf_newscn");

	data = elf_newdata(scn);
	if (!data)
		ERROR("elf_newdata");

	data->d_size = relas_size;
	data->d_buf = relas_data;
	data->d_type = ELF_T_RELA;

	memset(&sh, 0, sizeof(sh));
	sh.sh_type = SHT_RELA;
	sh.sh_name = relas_offset;
	sh.sh_entsize = sizeof(GElf_Rela);
	sh.sh_addralign = 8;
	sh.sh_flags = SHF_ALLOC;
	sh.sh_link = elf_ndxscn(elf.symtab.scn);
	sh.sh_info = patches_index;
	sh.sh_size = data->d_size;

	if (!gelf_update_shdr(scn, &sh))
		ERROR("gelf_update_shdr");

	if (elf_update(elf.elf, ELF_C_WRITE) < 0)
		ERROR("elf_update %s", elf_errmsg(-1));

	elf_end(elf.elf);
	close(elf.fd);

	return 0;
}
