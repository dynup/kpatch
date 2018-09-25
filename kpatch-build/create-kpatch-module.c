/*
 * create-kpatch-module.c
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
#include "kpatch-patch.h"

/* For log.h */
char *childobj;
enum loglevel loglevel = NORMAL;

/*
 * Create .kpatch.dynrelas from .kpatch.relocations and .kpatch.symbols sections
 *
 * Iterate through .kpatch.relocations and fill in the corresponding dynrela
 * entry using information from .kpatch.relocations and .kpatch.symbols
 */
static void create_dynamic_rela_sections(struct kpatch_elf *kelf, struct section *krelasec,
					 struct section *ksymsec, struct section *strsec)
{
	struct kpatch_patch_dynrela *dynrelas;
	struct kpatch_relocation *krelas;
	struct kpatch_symbol *ksym, *ksyms;
	struct section *dynsec;
	struct symbol *sym;
	struct rela *rela;
	int index, nr, offset, dest_offset, objname_offset, name_offset;

	ksyms = ksymsec->data->d_buf;
	krelas = krelasec->data->d_buf;
	nr = krelasec->data->d_size / sizeof(*krelas);

	dynsec = create_section_pair(kelf, ".kpatch.dynrelas", sizeof(*dynrelas), nr);
	dynrelas = dynsec->data->d_buf;

	for (index = 0; index < nr; index++) {
		offset = index * sizeof(*krelas);

		/*
		 * To fill in each dynrela entry, find dest location,
		 * objname offset, ksym, and symbol name offset
		 */

		/* Get dest location */
		rela = find_rela_by_offset(krelasec->rela,
					   offset + offsetof(struct kpatch_relocation, dest));
		if (!rela)
			ERROR("find_rela_by_offset");
		sym = rela->sym;
		dest_offset = rela->addend;

		/* Get objname offset */
		rela = find_rela_by_offset(krelasec->rela,
					   offset + offsetof(struct kpatch_relocation, objname));
		if (!rela)
			ERROR("find_rela_by_offset");
		objname_offset = rela->addend;

		/* Get ksym (.kpatch.symbols entry) and symbol name offset */
		rela = find_rela_by_offset(krelasec->rela,
					   offset + offsetof(struct kpatch_relocation, ksym));
		if (!rela)
			ERROR("find_rela_by_offset");
		ksym = ksyms + (rela->addend / sizeof(*ksyms));

		offset = index * sizeof(*ksyms);
		rela = find_rela_by_offset(ksymsec->rela,
					   offset + offsetof(struct kpatch_symbol, name));
		if (!rela)
			ERROR("find_rela_by_offset");
		name_offset = rela->addend;

		/* Fill in dynrela entry */
		dynrelas[index].src = ksym->src;
		dynrelas[index].addend = krelas[index].addend;
		dynrelas[index].type = krelas[index].type;
		dynrelas[index].external = krelas[index].external;
		dynrelas[index].sympos = ksym->pos;

		/* dest */
		ALLOC_LINK(rela, &dynsec->rela->relas);
		rela->sym = sym;
		rela->type = R_X86_64_64;
		rela->addend = dest_offset;
		rela->offset = index * sizeof(*dynrelas);

		/* name */
		ALLOC_LINK(rela, &dynsec->rela->relas);
		rela->sym = strsec->secsym;
		rela->type = R_X86_64_64;
		rela->addend = name_offset;
		rela->offset = index * sizeof(*dynrelas) + \
			       offsetof(struct kpatch_patch_dynrela, name);

		/* objname */
		ALLOC_LINK(rela, &dynsec->rela->relas);
		rela->sym = strsec->secsym;
		rela->type = R_X86_64_64;
		rela->addend = objname_offset;
		rela->offset = index * sizeof(*dynrelas) + \
			       offsetof(struct kpatch_patch_dynrela, objname);
	}
}

static void remove_intermediate_sections(struct kpatch_elf *kelf)
{
	size_t i;
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
};

static char args_doc[] = "input.o output.o";

static struct argp_option options[] = {
	{"debug", 'd', 0, 0, "Show debug output" },
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
	struct section *ksymsec, *krelasec, *strsec;
	struct arguments arguments;
	int ksyms_nr, krelas_nr;

	arguments.debug = 0;
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

	/* Create dynrelas from .kpatch.{relocations,symbols} sections */
	create_dynamic_rela_sections(kelf, krelasec, ksymsec, strsec);
	remove_intermediate_sections(kelf);

	kpatch_reindex_elements(kelf);

	kpatch_create_shstrtab(kelf);
	kpatch_create_strtab(kelf);
	kpatch_create_symtab(kelf);

	kpatch_write_output_elf(kelf, kelf->elf, arguments.args[1]);
	kpatch_elf_teardown(kelf);
	kpatch_elf_free(kelf);

	return 0;
}
