/*
 * create-klp-module.c
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

#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <argp.h>

#include "log.h"
#include "kpatch-elf.h"
#include "kpatch-intermediate.h"

/* For log.h */
char *childobj;
enum loglevel loglevel = NORMAL;

/*
 * Add a symbol from .kpatch.symbols to the symbol table
 *
 * If a symbol matching the .kpatch.symbols entry already
 * exists, return it.
 */
static struct symbol *find_or_add_ksym_to_symbols(struct kpatch_elf *kelf,
						  struct section *ksymsec,
						  char *strings, int offset)
{
	struct kpatch_symbol *ksyms, *ksym;
	struct symbol *sym;
	struct rela *rela;
	char *objname, *name;
	char pos[32], buf[256];
	int index;

	ksyms = ksymsec->data->d_buf;
	index = offset / sizeof(*ksyms);
	ksym = &ksyms[index];

	/* Get name of ksym */
	rela = find_rela_by_offset(ksymsec->rela,
				   offset + offsetof(struct kpatch_symbol, name));
	if (!rela)
		ERROR("name of ksym not found?");

	name = strdup(strings + rela->addend);
	if (!name)
		ERROR("strdup");

	/* Get objname of ksym */
	rela = find_rela_by_offset(ksymsec->rela,
				   offset + offsetof(struct kpatch_symbol, objname));
	if (!rela)
		ERROR("objname of ksym not found?");

	objname = strdup(strings + rela->addend);
	if (!objname)
		ERROR("strdup");

	snprintf(pos, 32, "%lu", ksym->pos);
	/* .klp.sym.objname.name,pos */
	snprintf(buf, 256, KLP_SYM_PREFIX "%s.%s,%s", objname, name, pos);

	/* Look for an already allocated symbol */
	list_for_each_entry(sym, &kelf->symbols, list) {
		if (!strcmp(buf, sym->name))
			return sym;
	}

	ALLOC_LINK(sym, &kelf->symbols);
	sym->name = strdup(buf);
	if (!sym->name)
		ERROR("strdup");
	sym->type = ksym->type;
	sym->bind = ksym->bind;
	/*
	 * Note that st_name will be set in kpatch_create_strtab(),
	 * and sym->index is set in kpatch_reindex_elements()
	 */
	sym->sym.st_shndx = SHN_LIVEPATCH;
	sym->sym.st_info = GELF_ST_INFO(sym->bind, sym->type);

	return sym;
}

/*
 * Create a klp rela section given the base section and objname
 *
 * If a klp rela section matching the base section and objname
 * already exists, return it.
 */
static struct section *find_or_add_klp_relasec(struct kpatch_elf *kelf,
					       struct section *base,
					       char *objname)
{
	struct section  *sec;
	char buf[256];

	/* .klp.rela.objname.secname */
	snprintf(buf, 256, KLP_RELASEC_PREFIX "%s.%s", objname, base->name);

	list_for_each_entry(sec, &kelf->sections, list) {
		if (!strcmp(sec->name, buf))
			return sec;
	}

	ALLOC_LINK(sec, &kelf->sections);
	sec->name = strdup(buf);
	if (!sec->name)
		ERROR("strdup");
	sec->base = base;

	INIT_LIST_HEAD(&sec->relas);

	sec->data = malloc(sizeof(*sec->data));
	if (!sec->data)
		ERROR("malloc");
	sec->data->d_type = ELF_T_RELA;

	/* sh_info and sh_link are set when rebuilding rela sections */
	sec->sh.sh_type = SHT_RELA;
	sec->sh.sh_entsize = sizeof(GElf_Rela);
	sec->sh.sh_addralign = 8;
	sec->sh.sh_flags = SHF_RELA_LIVEPATCH | SHF_INFO_LINK | SHF_ALLOC;

	return sec;
}

/*
 * Create klp relocation sections and klp symbols from .kpatch.relocations
 * and .kpatch.symbols sections
 *
 * For every entry in .kpatch.relocations:
 *   1) Allocate a symbol for the corresponding .kpatch.symbols entry if
 *      it doesn't already exist (find_or_add_ksym_to_symbols())
 *      This is the symbol that the relocation points to (rela->sym)
 *   2) Allocate a rela, and add it to the corresponding .klp.rela. section. If
 *      the matching .klp.rela. section (given the base section and objname)
 *      doesn't exist yet, create it (find_or_add_klp_relasec())
 */
static void create_klp_relasecs_and_syms(struct kpatch_elf *kelf, struct section *krelasec,
					 struct section *ksymsec, char *strings)
{
	struct section *klp_relasec;
	struct kpatch_relocation *krelas;
	struct symbol *sym, *dest;
	struct rela *rela;
	char *objname;
	int nr, index, offset, dest_off;

	krelas = krelasec->data->d_buf;
	nr = krelasec->data->d_size / sizeof(*krelas);

	for (index = 0; index < nr; index++) {
		offset = index * sizeof(*krelas);

		/* Get the rela dest sym + offset */
		rela = find_rela_by_offset(krelasec->rela,
					   offset + offsetof(struct kpatch_relocation, dest));
		if (!rela)
			ERROR("find_rela_by_offset");

		dest = rela->sym;
		dest_off = rela->addend;

		/* Get the name of the object the dest belongs to */
		rela = find_rela_by_offset(krelasec->rela,
					   offset + offsetof(struct kpatch_relocation, objname));
		if (!rela)
			ERROR("find_rela_by_offset");

		objname = strdup(strings + rela->addend);
		if (!objname)
			ERROR("strdup");

		/* Get the .kpatch.symbol entry for the rela src */
		rela = find_rela_by_offset(krelasec->rela,
					   offset + offsetof(struct kpatch_relocation, ksym));
		if (!rela)
			ERROR("find_rela_by_offset");

		/* Create (or find) a klp symbol from the rela src entry */
		sym = find_or_add_ksym_to_symbols(kelf, ksymsec, strings, rela->addend);
		if (!sym)
			ERROR("error finding or adding ksym to symtab");

		/* Create (or find) the .klp.rela. section for the dest sec and object */
		klp_relasec = find_or_add_klp_relasec(kelf, dest->sec, objname);
		if (!klp_relasec)
			ERROR("error finding or adding klp relasec");

		/* Add the klp rela to the .klp.rela. section */
		ALLOC_LINK(rela, &klp_relasec->relas);
		rela->offset = dest->sym.st_value + dest_off;
		rela->type = krelas[index].type;
		rela->sym = sym;
		rela->addend = krelas[index].addend;
	}
}

/*
 * Create .klp.arch. sections by iterating through the .kpatch.arch section
 *
 * A .kpatch.arch section is just an array of kpatch_arch structs:
 *
 * struct kpatch_arch {
 *   unsigned long sec;
 *   char *objname;
 * };
 *
 * There are two relas associated with each kpatch arch entry, one that points
 * to the section of interest (.parainstructions or .altinstructions), and one
 * rela points to the name of the object the section belongs to in
 * .kpatch.strings. This gives us the necessary information to create .klp.arch
 * sections, which use the '.klp.arch.objname.secname' name format.
 */
static void create_klp_arch_sections(struct kpatch_elf *kelf, char *strings)
{
	struct section *karch, *sec, *base = NULL;
	struct kpatch_arch *entries;
	struct rela *rela, *rela2;
	char *secname, *objname = NULL;
	char buf[256];
	int nr, index, offset, old_size, new_size;

	karch = find_section_by_name(&kelf->sections, ".kpatch.arch");
	if (!karch)
		return;

	entries = karch->data->d_buf;
	nr = karch->data->d_size / sizeof(*entries);

	for (index = 0; index < nr; index++) {
		offset = index * sizeof(*entries);

		/* Get the base section (.parainstructions or .altinstructions) */
		rela = find_rela_by_offset(karch->rela,
					   offset + offsetof(struct kpatch_arch, sec));
		if (!rela)
			ERROR("find_rela_by_offset");

		base = rela->sym->sec;
		if (!base)
			ERROR("base sec of kpatch_arch entry not found");

		/* Get the name of the object the base section belongs to */
		rela = find_rela_by_offset(karch->rela,
					   offset + offsetof(struct kpatch_arch, objname));
		if (!rela)
			ERROR("find_rela_by_offset");

		objname = strdup(strings + rela->addend);
		if (!objname)
			ERROR("strdup");

		/* Example: .klp.arch.vmlinux..parainstructions */
		snprintf(buf, 256, "%s%s.%s", KLP_ARCH_PREFIX, objname, base->name);

		/* Check if the .klp.arch. section already exists */
		sec = find_section_by_name(&kelf->sections, buf);
		if (!sec) {
			secname = strdup(buf);
			if (!secname)
				ERROR("strdup");

			/* Start with a new section with size 0 first */
			sec = create_section_pair(kelf, secname, 1, 0);
		}

		/*
		 * Merge .klp.arch. sections if necessary
		 *
		 * Example:
		 * If there are multiple .parainstructions sections for vmlinux
		 * (this can happen when, using the --unique option for ld,
		 * we've linked together multiple .o's with .parainstructions
		 * sections for the same object), they will be merged under a
		 * single .klp.arch.vmlinux..parainstructions section
		 */
		old_size = sec->data->d_size;
		new_size = old_size + base->data->d_size;
		sec->data->d_buf = realloc(sec->data->d_buf, new_size);
		sec->data->d_size = new_size;
		sec->sh.sh_size = sec->data->d_size;
		memcpy(sec->data->d_buf + old_size,
		       base->data->d_buf, base->data->d_size);

		list_for_each_entry(rela, &base->rela->relas, list) {
			ALLOC_LINK(rela2, &sec->rela->relas);
			rela2->sym = rela->sym;
			rela2->type = rela->type;
			rela2->addend = rela->addend;
			rela2->offset = old_size + rela->offset;
		}
	}
}

/*
 * We can't keep these sections since the module loader will apply them before
 * the patch module gets a chance to load (that's why we copied these sections
 * into .klp.arch. sections. Hence we remove them here.
 */
static void remove_arch_sections(struct kpatch_elf *kelf)
{
	int i;
	char *arch_sections[] = {
		".parainstructions",
		".rela.parainstructions",
		".altinstructions",
		".rela.altinstructions"
	};

	for (i = 0; i < sizeof(arch_sections)/sizeof(arch_sections[0]); i++)
		kpatch_remove_and_free_section(kelf, arch_sections[i]);

}

static void remove_intermediate_sections(struct kpatch_elf *kelf)
{
	int i;
	char *intermediate_sections[] = {
		".kpatch.symbols",
		".rela.kpatch.symbols",
		".kpatch.relocations",
		".rela.kpatch.relocations",
		".kpatch.arch",
		".rela.kpatch.arch"
	};

	for (i = 0; i < sizeof(intermediate_sections)/sizeof(intermediate_sections[0]); i++)
		kpatch_remove_and_free_section(kelf, intermediate_sections[i]);
}

struct arguments {
	char *args[2];
	int debug;
	int no_klp_arch;
};

static char args_doc[] = "input.ko output.ko";

static struct argp_option options[] = {
	{"debug", 'd', 0, 0, "Show debug output" },
	{"no-klp-arch-sections", 'n', 0, 0, "Do not output .klp.arch.* sections" },
	{ 0 }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	/* Get the input argument from argp_parse, which we
	   know is a pointer to our arguments structure. */
	struct arguments *arguments = state->input;

	switch (key)
	{
		case 'd':
			arguments->debug = 1;
			break;
		case 'n':
			arguments->no_klp_arch = 1;
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num >= 2)
				/* Too many arguments. */
				argp_usage (state);
			arguments->args[state->arg_num] = arg;
			break;
		case ARGP_KEY_END:
			if (state->arg_num < 2)
				/* Not enough arguments. */
				argp_usage (state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, 0 };

int main(int argc, char *argv[])
{
	struct kpatch_elf *kelf;
	struct section *symtab, *sec;
	struct section *ksymsec, *krelasec, *strsec;
	struct arguments arguments;
	char *strings;
	int ksyms_nr, krelas_nr;

	memset(&arguments, 0, sizeof(arguments));
	argp_parse (&argp, argc, argv, 0, 0, &arguments);
	if (arguments.debug)
		loglevel = DEBUG;

	elf_version(EV_CURRENT);

	childobj = basename(arguments.args[0]);

	kelf = kpatch_elf_open(arguments.args[0]);

	/*
	 * Sanity checks:
	 * - Make sure all the required sections exist
	 * - Make sure that the number of entries in
	 *   .kpatch.{symbols,relocations} match
	 */
	strsec = find_section_by_name(&kelf->sections, ".kpatch.strings");
	if (!strsec)
		ERROR("missing .kpatch.strings");
	strings = strsec->data->d_buf;

	ksymsec = find_section_by_name(&kelf->sections, ".kpatch.symbols");
	if (!ksymsec)
		ERROR("missing .kpatch.symbols section");
	ksyms_nr = ksymsec->data->d_size / sizeof(struct kpatch_symbol);

	krelasec = find_section_by_name(&kelf->sections, ".kpatch.relocations");
	if (!krelasec)
		ERROR("missing .kpatch.relocations section");
	krelas_nr = krelasec->data->d_size / sizeof(struct kpatch_relocation);

	if (krelas_nr != ksyms_nr)
		ERROR("number of krelas and ksyms do not match");

	/*
	 * Create klp rela sections and klp symbols from
	 * .kpatch.{relocations,symbols} sections
	 */
	create_klp_relasecs_and_syms(kelf, krelasec, ksymsec, strings);

	/*
	 * If --no-klp-arch-sections wasn't set, additionally
	 * create .klp.arch. sections
	 */
	if (!arguments.no_klp_arch) {
		create_klp_arch_sections(kelf, strings);
		remove_arch_sections(kelf);
	}

	remove_intermediate_sections(kelf);
	kpatch_reindex_elements(kelf);

	/* Rebuild rela sections, new klp rela sections will be rebuilt too. */
	symtab = find_section_by_name(&kelf->sections, ".symtab");
	list_for_each_entry(sec, &kelf->sections, list) {
		if (!is_rela_section(sec))
			continue;
		sec->sh.sh_link = symtab->index;
		sec->sh.sh_info = sec->base->index;
		kpatch_rebuild_rela_section_data(sec);
	}

	kpatch_create_shstrtab(kelf);
	kpatch_create_strtab(kelf);
	kpatch_create_symtab(kelf);

	kpatch_write_output_elf(kelf, kelf->elf, arguments.args[1]);
	kpatch_elf_teardown(kelf);
	kpatch_elf_free(kelf);

	return 0;
}
