#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <argp.h>
#include <string.h>
#include <udis86.h>
#include <error.h>
#include <gelf.h>

struct section {
	struct section *next;
	Elf_Scn *sec;
	GElf_Shdr sh;
	Elf_Data *data;
	char *name;
	struct section *twin, *twino;
	size_t index;
	int diff;
};

struct symbol {
	struct symbol *next;
	GElf_Sym sym;
	char *name;
	struct symbol *twin, *twinv, *twino;
	struct section *sec;
	size_t index;
	int type;
	int bind;
	int diff;
};

struct kpatch_rela {
	unsigned long dest; /* TODO don't rely on this being the first */
	unsigned long src;
	unsigned long type;
};

struct rela {
	struct rela *next;
	GElf_Rela rela;
	struct rela *twin;
	struct section *rela_sec, *dest_sec;
	struct symbol *src_sym, *dest_sym;
	/* TODO: get right signed and # of bits for all these vars */
	long dest_off, src_off;
	const char *src_str;
	unsigned int type;
	struct kpatch_rela *kpatch_rela;
};

struct kpatch_patch {
	unsigned long new; /* TODO don't rely on this being the first */
	unsigned long orig; /* TODO eventually add name of symbol so we can verify it with kallsyms */
};


struct arguments {
	char *args[2];
	char *vmlinux;
	char *outfile;
};

#define SYM_ADDED		1
#define SYM_REMOVED		2
#define SYM_CHANGED		3
#define SEC_CHANGED		4 /* TODO: maybe not needed.  although a sanity
				     check somewhere re: section size = sum of
				     its symbol sizes might be good?  yes.*/

struct arguments args;
Elf *elf1, *elf2, *elfv, *elfo;
struct symbol *syms1, *syms2, *symsv, *symso;
struct section *secs1, *secs2, *secsv, *secso;
struct rela *relas1, *relas2;
int risky;



#define ERROR(format, ...) \
	error(1, 0, "%s: %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define elfname(elf) \
({									\
	const char *name = NULL;					\
	if (elf == elf1)						\
		name = args.args[0];					\
	else if (elf == elf2)						\
		name = args.args[1];					\
	else if (elf == elfv)						\
		name = args.vmlinux;					\
	else if (elf == elfo)						\
		name = args.outfile;					\
	name;								\
})


#define ELF_ERROR(elf, str) \
	error(1, 0, "%s:%d: " str " failed for '%s': %s", __FUNCTION__, __LINE__, elfname(elf), elf_errmsg(-1))

#define RISKY(format, ...) \
({									\
	printf("WARNING: " format "\n", ##__VA_ARGS__);			\
	risky = 1;							\
})

#define DIFF_FATAL(format, ...) \
({ \
	printf("%s:%d: " format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
	error(2, 0, "unreconcilable difference"); \
})

#define DIFF(d, s)							\
({									\
	/*printf("%s:%d: found diff for %s\n", __FUNCTION__, __LINE__, s->name);*/ \
	s->diff = d;							\
	if (s->twin)							\
		s->twin->diff = d;					\
})

#define list_add(head, new) \
({ \
	typeof(new) p = head; \
	if (!head) \
		head = new; \
	else { \
		while (p->next) \
			p = p->next; \
		p->next = new; \
	} \
})

#define list_size(head) \
({ \
	typeof(head) p; \
	int size = 0; \
	for (p = head; p; p = p->next) \
		size++; \
	size; \
})

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key) {
		case 'v':
			arguments->vmlinux = arg;
			break;
		case 'o':
			arguments->outfile = arg;
			break;
		case ARGP_KEY_ARG:
			if (state->arg_num > 1)
				argp_usage(state);
			arguments->args[state->arg_num] = arg;
			break;
		case ARGP_KEY_END:
			if (!arguments->args[0] || !arguments->args[1] ||
			    !arguments->vmlinux || !arguments->outfile)
				argp_usage(state);
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}

	return 0;
}
static const struct argp_option options[] = {
	{NULL, 'v', "file", 0, "original vmlinux"},
	{NULL, 'o', "file", 0, "output file"},
	{},
};
static struct argp argp = {
	.options	= options,
	.parser		= parse_opt,
	.args_doc	= "FILE1.o FILE2.o",
	.doc		= "Compare two kernel .o files and generate an object containing the changed and/or new functions.",
};

static Elf *elf_open(const char *name, int *fd)
{
	Elf *elf;

	*fd = open(name, O_RDONLY);
	if (*fd == -1)
		error(1, errno, "open of '%s' failed", name);

	elf = elf_begin(*fd, ELF_C_READ_MMAP, NULL);
	if (!elf)
		error(1, 0, "elf_begin failed for '%s': %s", name,
		      elf_errmsg(-1));

	return elf;
}

struct section *find_section_by_index(struct section *secs, unsigned int index)
{
	struct section *sec;

	for (sec = secs; sec && sec->index != index; sec = sec->next)
		;

	return sec;
}

struct section *find_section_by_name(struct section *secs, const char *name)
{
	struct section *sec;

	for (sec = secs; sec && strcmp(sec->name, name); sec = sec->next)
		;

	return sec;
}

struct symbol *find_symbol_by_offset(struct symbol *syms, struct section *sec,
				     int off, long *sym_off)
{
	struct symbol *sym;

	for (sym = syms; sym; sym = sym->next)
		if (sym->sec == sec && off >= sym->sym.st_value &&
		    off < sym->sym.st_value + sym->sym.st_size) {
			*sym_off = off - sym->sym.st_value;
			return sym;
		}

	return NULL;
}

struct symbol *find_symbol_by_index(struct symbol *syms, size_t index)
{
	struct symbol *sym;

	for (sym = syms; sym && sym->index != index; sym = sym->next)
		;

	return sym;
}

struct symbol *find_symbol_by_name(struct symbol *syms, const char *name)
{
	struct symbol *sym;

	for (sym = syms; sym && strcmp(sym->name, name); sym = sym->next)
		;

	return sym;
}

int addend_offset(struct rela *rela)
{
	ud_t ud;
	int rc;

	if (rela->type != R_X86_64_PC32)
		return 0;

	ud_init(&ud);
	ud_set_input_buffer(&ud, rela->dest_sec->data->d_buf + rela->dest_sym->sym.st_value, rela->dest_sym->sym.st_size);
	ud_set_mode(&ud, 64);

	while (1) {
		rc = ud_disassemble(&ud);
		if (!rc)
			ERROR("FIXME");

		/* TODO: check if we're past the end of the function and error */

		if (rela->dest_off >= ud_insn_off(&ud) &&
		    rela->dest_off < ud_insn_off(&ud) + ud_insn_len(&ud))
			break;
	}

	return ud_insn_off(&ud) + ud_insn_len(&ud) - rela->dest_off;
}

void init_section_list(Elf *elf, struct section **secs)
{
	Elf_Scn *scn;
	struct section *sec;
	size_t shstrndx;

	if (elf_getshdrstrndx(elf, &shstrndx))
		ELF_ERROR(elf, "elf_getshdrstrndx");

	scn = NULL;
	while ((scn = elf_nextscn(elf, scn))) {

		sec = malloc(sizeof(*sec));
		memset(sec, 0, sizeof(*sec));
		sec->sec = scn;

		if (!gelf_getshdr(scn, &sec->sh))
			ELF_ERROR(elf, "gelf_getshdr");

		sec->name = elf_strptr(elf, shstrndx, sec->sh.sh_name);
		if (!sec->name)
			ELF_ERROR(elf, "elf_strptr");

		sec->data = NULL;
		sec->data = elf_getdata(sec->sec, sec->data);
		if (!sec->data)
			ELF_ERROR(elf, "elf_getdata");
		/* TODO: check for any remaining data? */

		sec->index = elf_ndxscn(sec->sec);

		list_add(*secs, sec);
	}
}


void init_symbol_list(Elf *elf, struct section *secs,
		      struct symbol **syms)
{
	struct section *sec;
	struct symbol *sym = NULL, *last_sym = NULL;
	int count, i;

	sec = find_section_by_name(secs, ".symtab");
	if (!sec)
		ERROR("missing symbol table");

	count = sec->sh.sh_size / sec->sh.sh_entsize;

	for (i = 1; i < count; i++) { /* skip symbol 0 */

		last_sym = sym;
		sym = malloc(sizeof(*sym));
		memset(sym, 0, sizeof(*sym));

		sym->index = i;

		if (!gelf_getsym(sec->data, i, &sym->sym))
			ELF_ERROR(elf, "gelf_getsym");

		sym->name = elf_strptr(elf, sec->sh.sh_link,
				       sym->sym.st_name);
		if (!sym->name)
			ELF_ERROR(elf, "elf_strptr");

		sym->type = GELF_ST_TYPE(sym->sym.st_info);
		sym->bind = GELF_ST_BIND(sym->sym.st_info);
		switch (sym->type) {
			case STT_NOTYPE: /* TODO: compare ABS symbols */
			case STT_OBJECT:
			case STT_FUNC:
			case STT_SECTION:
			case STT_FILE: /* TODO: FILE getting compared properly? */
				break;
			default:
				ERROR("%s: unknown symbol type %d", sym->name,
				      sym->type);
		}

		if (sym->sym.st_shndx >= SHN_LORESERVE &&
		    sym->sym.st_shndx <= SHN_HIRESERVE &&
		    sym->sym.st_shndx != SHN_ABS)
			ERROR("%s: I don't know how to handle reserved section "
			      "index %d for symbol %s", elfname(elf),
			      sym->sym.st_shndx, sym->name);

		if (sym->sym.st_shndx != SHN_UNDEF)
			sym->sec = find_section_by_index(secs,
							 sym->sym.st_shndx);
		else
			sym->sec = NULL;

		if (sym->type == STT_SECTION)
			sym->name = sym->sec->name;

		/* optimized list_add */
		if (!*syms)
			*syms = sym;
		else
			last_sym->next = sym;

	}
}



void init_rela_list(Elf *elf, struct section *secs, struct symbol *syms,
		    struct rela **relas)
{
	struct section *rela_sec, *dest_sec;
	int count, i;
	unsigned int off, index;
	struct rela *rela;

	for (rela_sec = secs; rela_sec; rela_sec = rela_sec->next) {

		if (rela_sec->sh.sh_type != SHT_RELA ||
		    strstr(rela_sec->name, ".debug"))
			continue;

		dest_sec = find_section_by_name(secs, rela_sec->name + 5);
		if (!dest_sec)
			ERROR("can't find text section for rela %s",
			      rela_sec->name);

		count = rela_sec->sh.sh_size / rela_sec->sh.sh_entsize;

		for (i = 0; i < count; i++) {

			rela = malloc(sizeof(*rela));
			memset(rela, 0, sizeof(*rela));

			if (!gelf_getrela(rela_sec->data, i, &rela->rela))
				ELF_ERROR(elf, "gelf_getrela");

			rela->rela_sec = rela_sec;
			rela->dest_sec = dest_sec;

			off = rela->rela.r_offset;
			rela->dest_sym = find_symbol_by_offset(syms, dest_sec,
							       off,
							       &rela->dest_off);
			if (!rela->dest_sym) {
				/*
				 * This means there is no symbol associated
				 * with the address in the destination section.
				 *
				 * We ignore mcount relocations for now.
				 * They'll need to be automatically regenerated
				 * anyway...
				 */
				if (!strcmp(dest_sec->name, "__mcount_loc")) {
					free(rela);
					continue;
				} else
					ERROR("%s:%d: missing symbol at offset %d",
					      rela_sec->name, i, off);
			}

			rela->type = GELF_R_TYPE(rela->rela.r_info);
			index = GELF_R_SYM(rela->rela.r_info);

			rela->src_sym = find_symbol_by_index(syms, index);
			if (!rela->src_sym)
				ERROR("%s:%d: missing symbol at index %d",
				      rela_sec->name, i, index);

			rela->src_off = rela->rela.r_addend;

			/*
			 * If the source symbol is actually a section, we need
			 * to figure out the underlying function/object.
			 */
			if (rela->src_sym->type == STT_SECTION) {

				const char *name = rela->src_sym->name;

				if (!strcmp(name, ".text") ||
				    !strcmp(name, ".init.text") ||
				    !strncmp(name, ".data", 5) ||
				    !strcmp(name, ".bss") ||
				    !strcmp(name, ".rodata")) {

					/* Source is a function/object */

					/* TODO: too much indenting... */

					/* TODO: In the case of R_X86_64_PC32,
					 * for find_symbol_by_offset to be
					 * accurate for finding the source
					 * symbol, we will have to disassemble
					 * the target function, find which
					 * instruction includes the target
					 * address, and then modify addend
					 * appropriately.  e.g. .bss - 5.  and
					 * _then_ call find_symbol_by_offset
					 * with the correct offset.
					 *
					 * But for now, it should be ok because
					 * we don't allow any changes (or
					 * additions...) to global data anyway
					 * and this only seems to affect .bss?
					 *
					 * but....we may need this for the
					 * generation phase.  because when
					 * translating relocations we need to
					 * know what the source object is so we
					 * can look up its address in the
					 * vmlinux.
					 * 
					 * yeah.  so if the type is
					 * R_X86_64_PC32 we need to do this.
					 * examine the target location somehow,
					 * and convert the addend
					 * accordingly before calling
					 * find_symbol_by_offset.
					 *
					 */


					int addend_off = addend_offset(rela);


					rela->src_sym = find_symbol_by_offset(
							 syms,
							 rela->src_sym->sec,
							 rela->rela.r_addend + addend_off,
							 &rela->src_off);

					rela->src_off -= addend_off;
					

					if (!rela->src_sym)
						ERROR("unknown reloc src "
						      "symbol %s+%lx", name,
						      rela->rela.r_addend);

					/*
					printf("reloc: %s+%lx -> %s+%x\n",
					       name, rela->rela.r_addend,
					       rela->src_sym->name,
					       rela->src_off);
					*/

				} else if (!strncmp(name, ".rodata.str", 11) ||
					   !strcmp(name, "__ksymtab_strings")) {
					/* Source is a string */
					Elf_Data *str_data = rela->src_sym->sec->data;

					rela->src_str = str_data->d_buf +
							rela->rela.r_addend;

					rela->src_off = 0;

					/*
					printf("reloc: %s+%lx -> %s\n",
					       name, rela->rela.r_addend,
					       rela->src_str);
					*/

				} else
					ERROR("don't know how to handle "
					      "relocation source %s", name);
			}

			/*
			printf("rela: %s+0x%lx to %s+0x%x\n",
			       rela->src_sym->name, rela->rela.r_addend,
			       rela->dest_sym->name, rela->dest_off);
			*/

			list_add(*relas, rela);
		}
	}
}


void correlate_section_list(struct section *secs1, struct section *secs2)
{
	struct section *sec1, *sec2;

	for (sec1 = secs1; sec1; sec1 = sec1->next) {

		if (sec1->twin)
			continue;

		for (sec2 = secs2; sec2; sec2 = sec2->next) {

			if (!strcmp(sec1->name, sec2->name)) {
				if (sec2->twin)
					ERROR("duplicate section name %s for "
					      "sections %zu and %zu",
					      sec1->name, sec1->index,
					      sec2->index);
				sec1->twin = sec2;
				sec2->twin = sec1;
				break;
			}
		}
	}
}


void correlate_symbol_list(struct symbol *syms1, struct symbol *syms2)
{
	struct symbol *sym1, *sym2;

	for (sym1 = syms1; sym1; sym1 = sym1->next) {

		if (sym1->twin)
			continue;

		for (sym2 = syms2; sym2; sym2 = sym2->next) {

			if (!strcmp(sym1->name, sym2->name)) {
				if (sym2->twin)
					ERROR("duplicate symbol name %s for "
					      "symbols %zu and %zu", sym1->name,
					      sym1->index, sym2->index);
				sym1->twin = sym2;
				sym2->twin = sym1;
				break;
			}
		}
	}
}

void correlate_relocation_list(struct rela *relas1, struct rela *relas2)
{
	struct rela *rela1, *rela2;

	for (rela1 = relas1; rela1; rela1 = rela1->next) {

		if (rela1->twin)
			continue;

		for (rela2 = relas2; rela2; rela2 = rela2->next) {

			if (rela2->twin)
				continue;

			if (rela1->rela_sec->twin != rela2->rela_sec ||
			    rela1->dest_sec->twin != rela2->dest_sec ||
			    rela1->src_sym->twin != rela2->src_sym ||
			    rela1->src_off != rela2->src_off ||
			    rela1->dest_sym->twin != rela2->dest_sym ||
			    rela1->dest_off != rela2->dest_off ||
			    rela1->type != rela2->type ||
			    (rela1->src_str &&
			     rela2->src_str &&
			     strcmp(rela1->src_str, rela2->src_str)))
				continue;


			rela1->twin = rela2;
			rela2->twin = rela1;
		}
	}
}

void compare_sections(void)
{
	struct section *sec1, *sec2;

	for (sec1 = secs1; sec1; sec1 = sec1->next) {

		sec2 = sec1->twin;
		if (!sec2) {
			if (!strncmp(sec1->name, ".rodata.str", 11))
				continue;

			DIFF_FATAL("section %s was removed", sec1->name);
		}

		if (sec1->sh.sh_type != sec2->sh.sh_type ||
		    sec1->sh.sh_flags != sec2->sh.sh_flags ||
		    sec1->sh.sh_addr != sec2->sh.sh_addr ||
		    sec1->sh.sh_addralign != sec2->sh.sh_addralign ||
		    sec1->sh.sh_entsize != sec2->sh.sh_entsize)
			DIFF_FATAL("%s section header details differ",
				   sec1->name);

		if (sec1->sh.sh_link != SHN_UNDEF &&
		    sec2->sh.sh_link != SHN_UNDEF &&
		    find_section_by_index(secs1, sec1->sh.sh_link)->twin !=
		    find_section_by_index(secs2, sec2->sh.sh_link))
			DIFF_FATAL("%s section header details differ",
				   sec1->name);

		if (sec1->sh.sh_type == SHT_RELA &&
		    find_section_by_index(secs1, sec1->sh.sh_info)->twin !=
		    find_section_by_index(secs2, sec2->sh.sh_info))
			DIFF_FATAL("%s section header details differ",
				   sec1->name);

		if (strstr(sec1->name, ".debug") ||
		    strstr(sec1->name, "mcount") ||
		    !strcmp(sec1->name, ".symtab") ||
		    !strcmp(sec1->name, ".shstrtab") ||
		    !strcmp(sec1->name, ".strtab") ||
		    /*
		     * functions and data were already compared via
		     * compare_symbols
		     * */
		    !strcmp(sec1->name, ".text") ||
		    !strcmp(sec1->name, ".init.text") ||
		    !strncmp(sec1->name, ".data", 5) ||
		    !strcmp(sec1->name, ".bss") ||
		    !strcmp(sec1->name, ".rodata") ||
		    /*
		     * strings and relocations were already compared via
		     * compare_relocations
		     */
		    !strncmp(sec1->name, ".rodata.str", 11) ||
		    !strcmp(sec1->name, ".rela.text") ||
		    !strcmp(sec1->name, ".rela.init.text") ||
		    !strcmp(sec1->name, ".rela.rodata") ||
		    !strncmp(sec1->name, ".rela.data", 10) ||
		    !strncmp(sec1->name, ".rela___ksymtab_gpl", 19) ||
		    !strncmp(sec1->name, ".rela.initcall", 14))
			continue;

		/* TODO: handle changes to .initcall* and .rela.initcall*
		 * somewhere */

		/* TODO: compare ABS symbols */

		if (sec1->sh.sh_size != sec2->sh.sh_size)
			DIFF_FATAL("section %s changed", sec1->name);

		if (memcmp(sec1->data->d_buf, sec2->data->d_buf,
			   sec1->sh.sh_size))
			DIFF_FATAL("section %s changed", sec1->name);
	}

	for (sec2 = secs2; sec2; sec2 = sec2->next) {

		if (!sec2->twin && strncmp(sec2->name, ".rodata.str", 11))
			DIFF_FATAL("section %s added", sec2->name);
	}
}

void compare_function_data(struct symbol *sym1)
{
	struct symbol *sym2 = sym1->twin;
	struct symbol *target1_sym, *target2_sym;
	unsigned int target1, target2, lval1, lval2;
	ud_t ud1, ud2;
	struct ud_operand *op1, *op2;
	int rc1, rc2;
	long off;
	int i;

	ud_init(&ud1);
	ud_set_input_buffer(&ud1, sym1->sec->data->d_buf + sym1->sym.st_value,
			    sym1->sym.st_size);
	ud_set_mode(&ud1, 64);

	ud_init(&ud2);
	ud_set_input_buffer(&ud2, sym2->sec->data->d_buf + sym2->sym.st_value,
			    sym2->sym.st_size); /* TODO: put st_value and st_size in local struct vars more adequately named? */
	ud_set_mode(&ud2, 64);

	while (1) {

		rc1 = ud_disassemble(&ud1);
		rc2 = ud_disassemble(&ud2);

		/*
		 * Check if we made it to the end of one function but not the
		 * other.
		 */
		if (rc1 ^ rc2) {
			DIFF(SYM_CHANGED, sym1);
			break;
		}

		/* Check if we're at the end of the functions. */ /* TODO this is wrong.  it'll go past the end of the function to the next function.  instead we need to look at the address. */
		if (!rc1)
			break;

		/* Compare the instructions. */
		if (ud1.mnemonic != ud2.mnemonic)
			DIFF(SYM_CHANGED, sym1);

		for (i = 0; i < 3; i++) {
			op1 = &ud1.operand[i];
			op2 = &ud2.operand[i];
			if (op1->type != op2->type ||
			    op1->size != op2->size ||
			    op1->base != op2->base ||
			    op1->index != op2->index ||
			    op1->scale != op2->scale) {
				DIFF(SYM_CHANGED, sym1);
				goto exit;
			}

			if (ud1.mnemonic == UD_Icall && ud1.br_near &&
			    ud2.mnemonic == UD_Icall && ud2.br_near)
				goto compare_call_instructions;

			if (memcmp(&op1->lval, &op2->lval, op1->size / 8)) {
				DIFF(SYM_CHANGED, sym1);
				goto exit;
			}
		}

		/* We found no differences in the instructions.  Next... */
		continue;


compare_call_instructions:
		lval1 = ud1.operand[0].lval.sdword;
		lval2 = ud2.operand[0].lval.sdword;

		/*
		 * lvals are zero when they are relocation targets.  Consider
		 * them as identical here, as they will be compared elsewhere
		 * as part of the relocation analysis.
		 */
		if (!lval1 && !lval2)
			continue;

		/*
		 * If we got here, both instructions are call instructions.
		 * We'll need to translate their target addresses to symbols
		 * before comparing them, in case the functions are at
		 * different addresses between the two files.
		 */
		target1 = sym1->sym.st_value + ud1.insn_offset +
			  ud1.inp_ctr + lval1;
		target1_sym = find_symbol_by_offset(syms1, sym1->sec,
						    target1, &off);
		if (!target1_sym || off)
			ERROR("can't find symbol for call to %d", lval1);

		target2 = sym2->sym.st_value + ud2.insn_offset +
			  ud2.inp_ctr + lval2;
		target2_sym = find_symbol_by_offset(syms2, sym2->sec,
						    target2, &off);
		if (!target2_sym || off)
			ERROR("can't find symbol for call to %d", lval2);

		if (target1_sym->twin == target2_sym)
			continue;

		DIFF(SYM_CHANGED, sym1);
		break;
	}

exit:
		return;

}

void compare_symbols(void)
{
	struct symbol *sym1, *sym2;
	Elf_Data *data1, *data2;

	for (sym1 = syms1; sym1; sym1 = sym1->next) {

		if (!sym1->twin) {

			if (sym1->sym.st_shndx != SHN_UNDEF)
				DIFF(SYM_REMOVED, sym1);

			continue;
		}

		sym2 = sym1->twin;

		if (sym1->sym.st_info != sym2->sym.st_info ||
		    sym1->sym.st_other != sym2->sym.st_other || /* TODO st_other could point to a section # which can change and still be the same section? */
		    (sym1->sec && sym2->sec && sym1->sec->twin != sym2->sec) ||
		    (sym1->sec && !sym2->sec) ||
		    (sym2->sec && !sym1->sec))
			DIFF_FATAL("symbol info mismatch: %s", sym1->name);

		if (sym1->sym.st_shndx == SHN_UNDEF)
			continue;

		if (sym1->type == STT_OBJECT) {
			if (sym1->sym.st_size != sym2->sym.st_size)
				DIFF_FATAL("object size mismatch: %s",
					   sym1->name);

			data1 = sym1->sec->data;
			data2 = sym2->sec->data;

			if (data1->d_buf && data2->d_buf &&
			    memcmp(data1->d_buf + sym1->sym.st_value,
				   data2->d_buf + sym2->sym.st_value,
				   sym1->sym.st_size)) {
				DIFF(SYM_CHANGED, sym1);
				continue;
			}

		} else if (sym1->type == STT_FUNC) {

			if (sym1->sym.st_size != sym2->sym.st_size) {
				DIFF(SYM_CHANGED, sym1);
				continue;
			}

			compare_function_data(sym1);
		}
	}
	for (sym2 = syms2; sym2; sym2 = sym2->next) {

		if (!sym2->twin) {

			if (sym2->sym.st_shndx == SHN_UNDEF ||
			    sym2->type == STT_SECTION)
				continue;

			DIFF(SYM_ADDED, sym2);
		}
	}
	/* TODO:
	 *
	 * don't allow any rela changes which have an rodata section
	 * (and/or data? bss?) as its destination.  and double check that we
	 * have test coverage for rela of an extern global variable.
	 *
	 * also, in case of assembly you have a lot of NOTYPE symbols with
	 * actual section indexes and values (offsets).  for now,
	 * DIFF_stop if we even see anything like that.
	 *
	 * when this is all done, I need to test the shit out of it!  test all
	 * code and DIFF detection and error paths!
	 * */
}

void compare_relocation(struct rela *relas)
{
	struct rela *rela;

	for (rela = relas; rela; rela = rela->next) {

		if (rela->twin)
			continue;

		/*
		 * We ignore added/removed/changed relocations for
		 * added/removed functions.  All we care about are changed
		 * functions/objects here, because we have already looked for
		 * added/removed symbols previously.
		 */
		if (rela->dest_sym->twin) {

			switch (rela->dest_sym->type) {
			case STT_FUNC:
			case STT_OBJECT:
				DIFF(SYM_CHANGED, rela->dest_sym);
				//printf("%s:%s -> %s:%s\n", rela->rela_sec->name, rela->src_sym->name, rela->dest_sec->name, rela->dest_sym->name);
				break;
			default:
				ERROR("%s: unknown type for destination symbol "
				      "%s", rela->rela_sec->name,
				      rela->dest_sym->name);
			}
		}
	}
}

void compare_relocations(void)
{
	compare_relocation(relas1);
	compare_relocation(relas2);
}

void print_changes(void)
{
	/* TODO: go through any new/removed sections and warn about them? */

	/* TODO: fold this function into compare_symbols/compare_sections?  yes.*/
	struct symbol *sym;
	int changes = 0;

	/* TODO: only allow certain sections to change.  and we also might want
	 * to add some smarts about which sections are allowed to change based
	 * on which symbols have changed?  or maybe do that up above, when we
	 * call DIFF for a symbol.  diff_sym could then verify that the related
	 * sections had changed.  if not, then it's an ERROR.  or it could set
	 * sec->changed_symbols. so that we could here check to ensure that
	 * !(sec->diff ^ sec->changed_symbols), so that each section change is
	 * associated with one or more symbol changes and vice versa.
	 */
	for (sym = syms1; sym; sym = sym->next) {

		if (!sym->diff)
			continue;

		switch (sym->type) {

		case STT_OBJECT:
			switch (sym->diff) {
			case SYM_CHANGED:
				DIFF_FATAL("object %s changed", sym->name);
				break;
			case SYM_REMOVED:
				//RISKY("object %s was removed", sym->name);
				DIFF_FATAL("object %s removed", sym->name);
				break;
			default:
				ERROR("invalid diff %d for object %s",
				      sym->diff, sym->name);
			}
			break;

		case STT_FUNC:
			switch (sym->diff) {
			case SYM_CHANGED:
				changes++;
				printf("function %s changed\n", sym->name);
				/* TODO: add to generated object */
				break;
			case SYM_REMOVED:
				RISKY("function %s was removed", sym->name);
				break;
			default:
				ERROR("invalid diff %d for func %s",
				      sym->diff, sym->name);
			}
			break;

		default:
			ERROR("invalid diff %d for symbol %s", sym->diff,
			      sym->name);
		}
	}

	for (sym = syms2; sym; sym = sym->next) {

		if (!sym->diff)
			continue;

		switch (sym->type) {
		case STT_OBJECT:
			switch (sym->diff) {
			case SYM_ADDED:
				//printf("object %s added to %s\n", sym->name,
				       //sym->sec->name);
				/* TODO: add to generated object */
				DIFF_FATAL("object %s was added", sym->name);
				break;
			}
			break;

		case STT_FUNC:
			switch (sym->diff) {
			case SYM_ADDED:
				printf("func %s added to %s\n", sym->name,
				       sym->sec->name);
				changes++;
				/* TODO: add to generated object */
				break;
			}
			break;

		default:
			ERROR("invalid diff %d for symbol %s of type %d",
			      sym->diff, sym->name, sym->type);
		}
	}

	if (!changes) {
		printf("no changes\n");
		exit(0);
	}
}

void correlate_symbols_to_vmlinux(void)
{

	struct symbol *symv, *symv_inner, *sym, *symsv_global;
	int diff;

	/*
	 * First find the local symbols.  We have to do it this way so that we
	 * can avoid any ambiguity about which local symbols to resolve.
	 */
	if (syms1->type != STT_FILE)
		ERROR("can't find FILE symbol");

	for (symv = symsv; symv; symv = symv->next) { /* TODO: use find_symbol_by_name instead? */
		if (symv->type == STT_FILE &&
		    !strcmp(symv->name, syms1->name)) {
			diff = 0;
			symv_inner = symv->next;
			for (sym = syms1->next; sym; sym = sym->next) {
				if (sym->bind != STB_LOCAL ||
				    (sym->type != STT_FUNC &&
				     sym->type != STT_OBJECT))
					continue;
				if (symv_inner->type == STT_FILE ||
				    strcmp(symv_inner->name, sym->name)) {
					diff = 1;
					break;
				}
				sym->twinv = symv_inner;
				/* TODO: need better var names... */
				if (sym->twin)
					sym->twin->twinv = symv_inner;
				symv_inner = symv_inner->next;
			}
			/* TODO support for over 64K symbols/sections? here and elsewhere? */
			if (!diff &&
			    (symv_inner->type == STT_FILE ||
			     symv_inner->bind != STB_LOCAL)) {
				goto success;
			}
		}
	}
	ERROR("can't find symbols from %s in %s", args.args[0], args.vmlinux);

success:

	/*
	 * Now find the global symbols.
	 */
	for (symsv_global = symsv;
	     symsv_global && symsv_global->bind == STB_LOCAL;
	     symsv_global = symsv_global->next)
		;

	for (sym = syms2; sym; sym = sym->next) {

		if (sym->type == STT_FILE || sym->type == STT_SECTION)
			continue;

		if (sym->twinv)
			continue;

		/* new symbols won't have a corresponding vmlinux symbol */
		/* TODO what about new weak symbols? */
		if (sym->bind == STB_LOCAL && !sym->twin)
			continue;

		/* TODO: make sure this works for local global symbols */

		sym->twinv = find_symbol_by_name(symsv_global, sym->name);
		if (!sym->twinv)
			ERROR("can't find %s in %s", sym->name, args.vmlinux);

		/*
		printf("found %s (%lx) at %lx\n", sym->name, sym->sym.st_value,
		       sym->twinv->sym.st_value);
		       */
	}
}

void init_output_section_list()
{
	struct section *oldsec, *newsec;
	int index;

	index = 0;
	for (oldsec = secs2; oldsec; oldsec = oldsec->next) {

		if (strcmp(oldsec->name, ".text") &&
		    strcmp(oldsec->name, ".rela.text") &&
		    strncmp(oldsec->name, ".rodata.str", 11) &&
		    strcmp(oldsec->name, ".shstrtab") &&
		    strcmp(oldsec->name, ".symtab") &&
		    strcmp(oldsec->name, ".strtab") &&
		    //strcmp(oldsec->name, "__mcount_loc") && TODO
		    //strcmp(oldsec->name, ".rela__mcount_loc") && TODO
		    strcmp(oldsec->name, ".comment") &&
		    strcmp(oldsec->name, ".note.GNU-stack"))
			continue;

		newsec = malloc(sizeof(*newsec));
		memset(newsec, 0, sizeof(*newsec));

		newsec->sh = oldsec->sh;

		newsec->data = malloc(sizeof(*newsec->data));
		*newsec->data = *oldsec->data;

		newsec->name = oldsec->name;

		oldsec->twino = newsec;
		newsec->twino = oldsec;

		newsec->index = ++index;

		list_add(secso, newsec);
	}
}

void init_output_symbol_list(void)
{
	struct symbol *oldsym, *newsym;
	int index;

	index = 0;
	for (oldsym = syms2; oldsym; oldsym = oldsym->next) {
		if (!oldsym->diff &&
		    oldsym->type != STT_FILE &&
		    !(oldsym->type == STT_SECTION && oldsym->sec->twino))
			continue;

		newsym = malloc(sizeof(*newsym));
		memset(newsym, 0, sizeof(*newsym));

		newsym->sym = oldsym->sym;
		newsym->name = oldsym->name;
		if (oldsym->sym.st_shndx != SHN_ABS)
			newsym->sec = oldsym->sec->twino;
		newsym->index = ++index;
		newsym->type = oldsym->type;
		newsym->bind = oldsym->bind;
		newsym->diff = oldsym->diff;
		oldsym->twino = newsym;
		newsym->twino = oldsym;

		if (newsym->sec)
			newsym->sym.st_shndx = newsym->sec->index;
		newsym->sym.st_info = GELF_ST_INFO(STB_LOCAL, newsym->type);

		list_add(symso, newsym);
	}
}

size_t strtab_add(const char *strtab, const char *str)
{
	struct section *sec;
	size_t ndx;
	void *oldbuf;

	sec = find_section_by_name(secso, strtab);
	ndx = sec->data->d_size;
	sec->sh.sh_size = sec->data->d_size = ndx + strlen(str) + 1;
	oldbuf = sec->data->d_buf;
	sec->data->d_buf = malloc(sec->data->d_size);
	memcpy(sec->data->d_buf, oldbuf, sec->data->d_size);
	strcpy(sec->data->d_buf + ndx, str);

	return ndx;
}

int main(int argc, char *argv[])
{
	GElf_Ehdr eh1, eh2, eho;
	size_t phnum1, phnum2, shstrndx1, shstrndx2;
	int fd1, fd2, fdv, fdo; /*TODO: rename */
	int index, symtab_index;
	struct symbol *sym;
	struct section *sec;
	struct rela *rela;
	GElf_Rela *newrela;
	int rela_kpatch_relas_sec_strndx, kpatch_relas_sec_strndx; //FIXME int?
	int num_patches;
	int kpatch_patches_sec_strndx, rela_kpatch_patches_sec_strndx;
	int num_kpatch_relas; //FIXME int?
	size_t kpatch_rela_size;
	struct symbol *newsym;
	Elf_Data *newdata;
	struct kpatch_patch *patch;

	argp_parse(&argp, argc, argv, 0, NULL, &args);

	elf_version(EV_CURRENT);
	elf1 = elf_open(args.args[0], &fd1);
	elf2 = elf_open(args.args[1], &fd2);

	if (!gelf_getehdr(elf1, &eh1))
		ELF_ERROR(elf1, "gelf_getehdr");

	if (!gelf_getehdr(elf2, &eh2))
		ELF_ERROR(elf2, "gelf_getehdr");

	if (memcmp(eh1.e_ident, eh2.e_ident, EI_NIDENT) ||
	    eh1.e_type != eh2.e_type ||
	    eh1.e_machine != eh2.e_machine ||
	    eh1.e_version != eh2.e_version ||
	    eh1.e_entry != eh2.e_entry ||
	    eh1.e_phoff != eh2.e_phoff ||
	    eh1.e_flags != eh2.e_flags ||
	    eh1.e_ehsize != eh2.e_ehsize ||
	    eh1.e_phentsize != eh2.e_phentsize ||
	    eh1.e_shentsize != eh2.e_shentsize)
		DIFF_FATAL("ELF headers differ");


	if (elf_getphdrnum(elf1, &phnum1))
		ELF_ERROR(elf1, "elf_getphdrnum");

	if (elf_getphdrnum(elf2, &phnum2))
		ELF_ERROR(elf2, "elf_getphdrnum");

	if (phnum1 || phnum2)
		DIFF_FATAL("program header counts are nonzero");


#if 0
	if (elf_getshdrnum(elf1, &shnum1))
		ELF_ERROR(elf1, "elf_getshdrnum");

	if (elf_getshdrnum(elf2, &shnum2))
		ELF_ERROR(elf2, "elf_getshdrnum");

	if (shnum1 != shnum2)
		DIFF_FATAL("section counts differ");
#endif /* TODO remove this code */


	if (elf_getshdrstrndx(elf1, &shstrndx1))
		ELF_ERROR(elf1, "elf_getshdrstrndx");

	if (elf_getshdrstrndx(elf2, &shstrndx2))
		ELF_ERROR(elf2, "elf_getshdrstrndx");

	init_section_list(elf1, &secs1);
	init_symbol_list(elf1, secs1, &syms1);
	init_rela_list(elf1, secs1, syms1, &relas1);

	init_section_list(elf2, &secs2);
	init_symbol_list(elf2, secs2, &syms2);
	init_rela_list(elf2, secs2, syms2, &relas2);

	correlate_section_list(secs1, secs2);
	correlate_section_list(secs2, secs1);

	correlate_symbol_list(syms1, syms2);
	correlate_symbol_list(syms2, syms1);

	correlate_relocation_list(relas1, relas2);
	correlate_relocation_list(relas2, relas1);

	compare_sections();
	compare_symbols();
	compare_relocations();

	print_changes();

	elfv = elf_open(args.vmlinux, &fdv);
	init_section_list(elfv, &secsv);
	init_symbol_list(elfv, secsv, &symsv);
	correlate_symbols_to_vmlinux();

	/* TODO: do it twice to ensure there's only one match, but be careful b/c twinv is getting set in this function */

	/* TODO: at beginning, ensure only 1 FILE symbol */

	/* TODO: what if the needed global symbol is a new func in another patched .o?????  maybe we need to combine all patched.o's into a big .o before we do the address resolution...? */

	/* TODO: drop any changes made to .init.text, .rela.init.text, .initcall*, .rela.initcall*, .todata, .rela.rodata, *debug*, but make RISKY (in some cases)  all we really care about is .text, .rela.text, and .rodata.str*...? */

	/* TODO: make sure relocations with data as source, such as ".bss - 4", translate properly during the generation.
	 */

	/* TODO: too many strcmp's with section names.  we need to encapsulate that section knowledge in one function, which will be the only place that knows which sections are used for what.  diff'ing, generating, ignore, straight copy, etc. */

	/* TODO: why don't we just fail on any changes to initcalls, data, etc.  reduce the places where we put risky, since risky might not be noticed.  then the user can hopefully modify the patch to make it safe. */


	init_output_section_list();
	init_output_symbol_list();


	kpatch_relas_sec_strndx = strtab_add(".shstrtab", "__kpatch_relas");
	rela_kpatch_relas_sec_strndx = strtab_add(".shstrtab", ".rela__kpatch_relas");
	kpatch_patches_sec_strndx = strtab_add(".shstrtab", "__kpatch_patches");
	rela_kpatch_patches_sec_strndx = strtab_add(".shstrtab", ".rela__kpatch_patches");


	symtab_index = find_section_by_name(secso, ".symtab")->index;


	/* update .text relocations */
	sec = find_section_by_name(secso, ".rela.text");
	sec->sh.sh_link = symtab_index;
	sec->data->d_buf = malloc(sec->sh.sh_size);
	sec->sh.sh_size = sec->data->d_size = 0;
	sec->sh.sh_info = find_section_by_name(secso, ".text")->index;

	index = 0;
	num_kpatch_relas = 0;
	for (rela = relas2; rela; rela = rela->next) {
	/* 
	 * for each relas
	 * if rela target isn't in a changed symbol, drop it.
	 * if local symbol and symbol changed, keep rela.
	 * or if source is from .rodata.str, keep rela.
	 * else put in kpatch_rela.
	 */


		/* TODO
		 * or (!rela->src_sym->twino || !rela->dest_sym->twino)
		 */
		if (!rela->dest_sym->diff)
			continue;

		if (rela->src_sym->bind != STB_LOCAL ||
		    rela->src_sym->type == STT_OBJECT) {
			rela->kpatch_rela = malloc(sizeof(*rela->kpatch_rela));
			rela->kpatch_rela->type = rela->type;
			rela->kpatch_rela->dest = 0;
			rela->kpatch_rela->src = rela->src_sym->twinv->sym.st_value + rela->src_off;
			num_kpatch_relas++;
			continue;
		}

		sec->data->d_size = sec->sh.sh_size = (index + 1) * sec->sh.sh_entsize;
		newrela = sec->data->d_buf + (index * sizeof(*newrela));
		memcpy(newrela, &rela->rela, sizeof(*newrela));
		newrela->r_info = GELF_R_INFO(rela->src_sym->twino->index, rela->type);

		index++;
	}


	/* add __kpatch_relas section */
	sec = malloc(sizeof(*sec));
	memset(sec, 0, sizeof(*sec));

	kpatch_rela_size = sizeof(struct kpatch_rela);
	sec->name = "__kpatch_relas";
	sec->index = list_size(secso) + 1;
	sec->data = malloc(sizeof(Elf_Data));
	sec->data->d_size = sec->sh.sh_size = num_kpatch_relas * kpatch_rela_size;
	sec->data->d_buf = malloc(sec->data->d_size);
	sec->data->d_type = ELF_T_BYTE; /* TODO? */
	sec->sh.sh_type = SHT_PROGBITS;
	sec->sh.sh_name = kpatch_relas_sec_strndx;
	sec->sh.sh_addralign = 8;
	sec->sh.sh_entsize = kpatch_rela_size;
	sec->sh.sh_flags = SHF_ALLOC;
	index = 0;
	for (rela = relas2; rela; rela = rela->next) {
		if (!rela->kpatch_rela)
			continue;
		memcpy(sec->data->d_buf + (index * kpatch_rela_size),
		       rela->kpatch_rela, kpatch_rela_size);
		index++;
	}
	list_add(secso, sec);


	/* TODO verify somewhere that all inputs' data are only one d_buf */


	/* add __kpatch_relas symbol */ /* TODO necessary? */
	newsym = malloc(sizeof(*newsym));
	memset(newsym, 0, sizeof(*newsym));
	newsym->name = "__kpatch_relas";
	newsym->sec = find_section_by_name(secso, "__kpatch_relas");
	newsym->index = list_size(symso) + 1;
	newsym->sym.st_name = 0;
	newsym->sym.st_info = GELF_ST_INFO(STB_LOCAL, STT_SECTION);
	newsym->sym.st_other = 0;
	newsym->sym.st_shndx = newsym->sec->index;
	newsym->sym.st_value = 0;
	newsym->sym.st_size = 0;
	list_add(symso, newsym);




	/* add .rela__kpatch_relas section */
	sec = malloc(sizeof(*sec));
	memset(sec, 0, sizeof(*sec));

	sec->name = ".rela__kpatch_relas";
	sec->index = list_size(secso) + 1;
	sec->data = malloc(sizeof(Elf_Data));
	sec->data->d_buf = malloc(num_kpatch_relas * sizeof(GElf_Rela));
	sec->data->d_type = ELF_T_RELA;
	sec->data->d_size = sec->sh.sh_size = 0;
	sec->sh.sh_type = SHT_RELA;
	sec->sh.sh_name = rela_kpatch_relas_sec_strndx;
	sec->sh.sh_addralign = 8;
	sec->sh.sh_entsize = sizeof(GElf_Rela);
	sec->sh.sh_link = symtab_index;
	sec->sh.sh_info = find_section_by_name(secso, "__kpatch_relas")->index;
	index = 0;
	for (rela = relas2; rela; rela = rela->next) {
		if (!rela->kpatch_rela)
			continue;
		sec->data->d_size = sec->sh.sh_size = (index + 1) * sec->sh.sh_entsize; /* TODO - get rid of this incremental adding shit */
		newrela = sec->data->d_buf + (index * sizeof(*newrela));
		newrela->r_offset = index * kpatch_rela_size;
		newrela->r_info = GELF_R_INFO(find_symbol_by_name(symso, rela->dest_sym->sec->name)->index,
					     R_X86_64_64);
		newrela->r_addend = rela->dest_sym->sym.st_value + rela->dest_off;
		index++;
	}
	list_add(secso, sec);


	/* add __kpatch_patches section */
	num_patches = 0;
	for (sym = symso; sym; sym = sym->next)
		if (sym->diff)
			num_patches++;
		
	sec = malloc(sizeof(*sec));
	memset(sec, 0, sizeof(*sec));

	sec->name = "__kpatch_patches";
	sec->index = list_size(secso) + 1;
	sec->data = malloc(sizeof(Elf_Data));
	sec->data->d_size = sec->sh.sh_size = num_patches * sizeof(struct kpatch_patch);
	sec->data->d_buf = malloc(sec->data->d_size);
	sec->data->d_type = ELF_T_BYTE;
	sec->sh.sh_type = SHT_PROGBITS;
	sec->sh.sh_name = kpatch_patches_sec_strndx;
	sec->sh.sh_entsize = sizeof(struct kpatch_patch);
	sec->sh.sh_addralign = 8;
	sec->sh.sh_flags = SHF_ALLOC;
	index = 0;
	for (sym = symso; sym; sym = sym->next) {
		if (!sym->diff)
			continue;
		patch = sec->data->d_buf + (index * sec->sh.sh_entsize);
		patch->orig = sym->twino->twinv->sym.st_value;
		patch->new = 0;
		index++;
	}
	list_add(secso, sec);


	/* add .rela__kpatch_patches section */
	sec = malloc(sizeof(*sec));
	memset(sec, 0, sizeof(*sec));

	sec->name = ".rela__kpatch_patches";
	sec->index = list_size(secso) + 1;
	sec->data = malloc(sizeof(Elf_Data));
	sec->data->d_buf = malloc(num_patches * sizeof(GElf_Rela));
	sec->data->d_type = ELF_T_RELA;
	sec->data->d_size = sec->sh.sh_size = 0;
	sec->sh.sh_type = SHT_RELA;
	sec->sh.sh_name = rela_kpatch_patches_sec_strndx;
	sec->sh.sh_addralign = 8;
	sec->sh.sh_entsize = sizeof(GElf_Rela);
	sec->sh.sh_link = symtab_index;
	sec->sh.sh_info = find_section_by_name(secso, "__kpatch_patches")->index;
	index = 0;
	for (sym = symso; sym; sym = sym->next) {
		if (!sym->diff)
			continue;
		sec->data->d_size = sec->sh.sh_size = (index + 1) * sec->sh.sh_entsize;
		newrela = sec->data->d_buf + (index * sizeof(*newrela));
		newrela->r_offset = index * sizeof(struct kpatch_patch);
		newrela->r_info = GELF_R_INFO(sym->index, R_X86_64_64);
		newrela->r_addend = 0;
	}
	list_add(secso, sec);

	
#if 0 /* TODO enable mcount */
	/* fix .rela__mcount_loc link */
	sec = find_section_by_name(secso, ".rela__mcount_loc");
	sec->sh.sh_link = symtab_index;
	sec->sh.sh_info = find_section_by_name(secso, "__mcount_loc")->index;
#endif


	/* update symbol table section */
	sec = find_section_by_name(secso, ".symtab");
	sec->sh.sh_link = find_section_by_name(secso, ".strtab")->index;
	sec->data->d_buf = malloc((list_size(secso) + 1) * sec->sh.sh_entsize);
	sec->sh.sh_size = sec->data->d_size = 4; /* keep sym 0 */
	memcpy(sec->data->d_buf, sec->twino->data->d_buf, 4);
	sec->sh.sh_info = list_size(symso) + 1;
	for (sym = symso; sym; sym = sym->next) {
		sec->data->d_size = sec->sh.sh_size = (sym->index + 1) * sec->sh.sh_entsize;
		((Elf64_Sym *) sec->data->d_buf)[sym->index] = sym->sym;
	}


	/* create elf output file */
	fdo = creat(args.outfile, 0777);
	if (fdo == -1)
		error(1, errno, "create of %s failed", args.outfile);

	elfo = elf_begin(fdo, ELF_C_WRITE, NULL);
	if (!elfo)
		error(1, 0, "elf_begin failed for %s: %s", args.outfile,
		      elf_errmsg(-1));

	if (!gelf_newehdr(elfo, gelf_getclass(elf2)))
		ELF_ERROR(elfo, "gelf_newehdr");

	if (!gelf_getehdr(elfo, &eho))
		ELF_ERROR(elfo, "gelf_getehdr");

	eho.e_ident[EI_DATA] = eh2.e_ident[EI_DATA];
	eho.e_machine = eh2.e_machine;
	eho.e_type = eh2.e_type;
	eho.e_version = EV_CURRENT;
	eho.e_shstrndx = find_section_by_name(secso, ".shstrtab")->index;

	for (sec = secso; sec; sec = sec->next) {

		sec->sec = elf_newscn(elfo);
		if (!sec->sec)
			ELF_ERROR(elfo, "elf_newscn");

		newdata = elf_newdata(sec->sec);
		if (!newdata)
			ELF_ERROR(elfo, "elf_newdata");

		newdata->d_buf = sec->data->d_buf;
		newdata->d_type = sec->data->d_type;
		newdata->d_size = sec->data->d_size;

		sec->data = newdata;

		if (!elf_flagdata(sec->data, ELF_C_SET, ELF_F_DIRTY))
			ELF_ERROR(elfo, "elf_flagdata");

		if (!gelf_update_shdr(sec->sec, &sec->sh))
			ELF_ERROR(elfo, "gelf_update_shdr");
	}

	if (!gelf_update_ehdr(elfo, &eho))
		ELF_ERROR(elfo, "gelf_update_ehdr");

	if (elf_update(elfo, ELF_C_WRITE) < 0)
		ELF_ERROR(elfo, "elf_update");

	
	return 0;
}
