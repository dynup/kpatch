/*
 * tools/create-diff-object.c
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2013 Josh Poimboeuf <jpoimboe@redhat.com>
 *
 * This file contains the heart of the ELF object differencing engine.
 *
 * The tool takes two ELF objects from two versions of the same source
 * file; a "base" object and a "patched" object.  These object need to have
 * been compiled with the -ffunction-sections and -fdata-sections GCC options.
 *
 * The tool compares the objects at a section level to determine what
 * sections have changed.  Once a list of changed sections has been generated,
 * various rules are applied to determine any object local sections that
 * are dependencies of the changed section and also need to be included in
 * the output object.
 *
 * After all the sections for the output object have been selected, a
 * reachability test is performed to ensure that every included section
 * is reachable from a changed function symbol.  If there is a section that
 * is not reachable from a changed function, this means that the source-level
 * change can not be captured by employing ftrace and therefore can not be
 * dynamically patched by kpatch.  Changes to static data structures are an
 * example.
 *
 * If the reachability test succeeds
 * - Changed text sections are copied into the output object
 * - Changed rela sections have there symbol indexes fixed up
 * - shstrtab, strtab, and symtab are all rebuilt from scratch
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <error.h>
#include <gelf.h>

#include "kpatch.h"

#define ERROR(format, ...) \
	error(1, 0, "%s: %d: " format, __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define DIFF_FATAL(format, ...) \
({ \
	printf("%s:%d: " format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
	error(2, 0, "unreconcilable difference"); \
})


/*******************
 * Data structures
 * ****************/
struct section;
struct symbol;
struct rela;

enum status {
	NEW,
	CHANGED,
	SAME,
	DEPENDENCY
};

struct table {
	void *data;
	size_t nr;
};

struct section {
	struct section *twin, *twino;
	GElf_Shdr sh;
	Elf_Data *data;
	char *name;
	int index;
	enum status status;
	int reachable;
	union {
		struct { /* if (is_rela_section()) */
			struct section *base;
			struct table relas;
		};
		struct { /* else */
			struct section *rela;
			struct symbol *sym;
		};
	};
};

struct symbol {
	struct symbol *twin, *twino;
	struct section *sec;
	GElf_Sym sym;
	char *name;
	int index;
	unsigned char bind, type;
	enum status status;
	int reachable;
};

struct rela {
	struct rela *twin;
	GElf_Rela rela;
	struct symbol *sym;
	unsigned char type;
	int addend;
	int offset;
	char *string;
	enum status status;
};

#define for_each_entry(iter, entry, table, type) \
	for (iter = 0; (iter) < (table)->nr && ((entry) = &((type)(table)->data)[iter]); (iter)++)

#define for_each_section(iter, entry, table) \
	for_each_entry(iter, entry, table, struct section *)
#define for_each_symbol(iter, entry, table) \
	for_each_entry(iter, entry, table, struct symbol *)
#define for_each_rela(iter, entry, table) \
	for_each_entry(iter, entry, table, struct rela *)

struct kpatch_elf {
	Elf *elf;
	struct table sections;
	struct table sybmols;
};

/*******************
 * Helper functions
 ******************/

char *status_str(enum status status)
{
	switch(status) {
	case NEW:
		return "NEW";
	case CHANGED:
		return "CHANGED";
	case SAME:
		return "SAME";
	case DEPENDENCY:
		return "DEPENDENCY";
	default:
		ERROR("status_str");
	}
	/* never reached */
	return NULL;
}

int is_rela_section(struct section *sec)
{
	return (sec->sh.sh_type == SHT_RELA);
}

struct section *find_section_by_index(struct table *table, unsigned int index)
{
	struct section *sec;
	int i;

	for_each_section(i, sec, table)
		if (sec->index == index)
			return sec;

	return NULL;
}

struct section *find_section_by_name(struct table *table, const char *name)
{
	struct section *sec;
	int i;

	for_each_section(i, sec, table)
		if (!strcmp(sec->name, name))
			return sec;

	return NULL;
}

struct symbol *find_symbol_by_index(struct table *table, size_t index)
{
	struct symbol *sym;
	int i;

	for_each_symbol(i, sym, table)
		if (sym->index == index)
			return sym;

	return NULL;
}

struct symbol *find_symbol_by_name(struct table *table, const char *name)
{
	struct symbol *sym;
	int i;

	for_each_symbol(i, sym, table)
		if (sym->name && !strcmp(sym->name, name))
			return sym;

	return NULL;
}

void alloc_table(struct table *table, size_t entsize, size_t nr)
{
	size_t size = nr * entsize;

	table->data = malloc(size);
	if (!table->data)
		ERROR("malloc");
	memset(table->data, 0, size);
	table->nr = nr;
}

/*************
 * Functions
 * **********/
void kpatch_create_rela_table(struct kpatch_elf *kelf, struct section *sec)
{
	int rela_nr, i;
	struct rela *rela;
	unsigned int symndx;

	/* find matching base (text/data) section */
	sec->base = find_section_by_name(&kelf->sections, sec->name + 5);
	if (!sec->base)
		ERROR("can't find base section for rela section %s", sec->name);

	/* create reverse link from base section to this rela section */
	sec->base->rela = sec;
		
	/* allocate rela table for section */
	rela_nr = sec->sh.sh_size / sec->sh.sh_entsize;
	alloc_table(&sec->relas, sizeof(struct rela), rela_nr);

#if DEBUG
	printf("\n=== rela table for %s (%d entries) ===\n",
		sec->base->name, rela_nr);
#endif
	/* read and store the rela entries */
	for_each_rela(i, rela, &sec->relas) {
		if (!gelf_getrela(sec->data, i, &rela->rela))
			ERROR("gelf_getrela");

		rela->type = GELF_R_TYPE(rela->rela.r_info);
		rela->addend = rela->rela.r_addend;
		rela->offset = rela->rela.r_offset;
		symndx = GELF_R_SYM(rela->rela.r_info);
		rela->sym = find_symbol_by_index(&kelf->sybmols, symndx);
		if (!rela->sym)
			ERROR("could not find rela entry symbol\n");
		if (rela->sym->sec && (rela->sym->sec->sh.sh_flags & SHF_STRINGS)) {
			rela->string = rela->sym->sec->data->d_buf + rela->addend;
			if (!rela->string)
				ERROR("could not lookup rela string\n");
		}
#if DEBUG
		printf("offset %d, type %d, %s %s %d", rela->offset,
			rela->type, rela->sym->name,
			(rela->addend < 0)?"-":"+", abs(rela->addend));
		if (rela->string)
			printf(" (string = %s)", rela->string);
		printf("\n");
#endif
	}
}

void kpatch_create_section_table(struct kpatch_elf *kelf)
{
	Elf_Scn *scn = NULL;
	struct section *sec;
	size_t shstrndx, sections_nr;
	int i;

	if (elf_getshdrnum(kelf->elf, &sections_nr))
		ERROR("elf_getshdrnum");

	/*
	 * elf_getshdrnum() includes section index 0 but elf_nextscn
	 * doesn't return that section so subtract one.
	 */
	sections_nr--;

	alloc_table(&kelf->sections, sizeof(struct section), sections_nr);

	if (elf_getshdrstrndx(kelf->elf, &shstrndx))
		ERROR("elf_getshdrstrndx");

#if DEBUG
	printf("=== section list (%d) ===\n", sections_nr);
#endif

	for_each_section(i, sec, &kelf->sections) {
		scn = elf_nextscn(kelf->elf, scn);
		if (!scn)
			ERROR("scn NULL");

		if (!gelf_getshdr(scn, &sec->sh))
			ERROR("gelf_getshdr");

		sec->name = elf_strptr(kelf->elf, shstrndx, sec->sh.sh_name);
		if (!sec->name)
			ERROR("elf_strptr");

		sec->data = elf_getdata(scn, NULL);
		if (!sec->data)
			ERROR("elf_getdata");

		sec->index = elf_ndxscn(scn);

#if DEBUG
		printf("ndx %02d, data %08x, size, %08x, name %s\n",
			sec->index, sec->data->d_buf, sec->data->d_size,
			sec->name);
#endif
	}

	/* Sanity check, one more call to elf_nextscn() should return NULL */
	if (elf_nextscn(kelf->elf, scn))
		ERROR("expected NULL");
}

void kpatch_create_symbol_table(struct kpatch_elf *kelf)
{
	struct section *symtab;
	struct symbol *sym;
	int symbols_nr, i;

	symtab = find_section_by_name(&kelf->sections, ".symtab");
	if (!symtab)
		ERROR("missing symbol table");

	symbols_nr = symtab->sh.sh_size / symtab->sh.sh_entsize;

	alloc_table(&kelf->sybmols, sizeof(struct symbol), symbols_nr);

#if DEBUG
	printf("\n=== symbol table (%d entries) ===\n", symbols_nr);
#endif

	/* iterator i declared in for_each_entry() macro */
	for_each_symbol(i, sym, &kelf->sybmols) {
		if (i == 0) /* skip symbol 0 */
			continue;
		sym->index = i;

		if (!gelf_getsym(symtab->data, i, &sym->sym))
			ERROR("gelf_getsym");

		sym->name = elf_strptr(kelf->elf, symtab->sh.sh_link,
				       sym->sym.st_name);
		if (!sym->name)
			ERROR("elf_strptr");

		sym->type = GELF_ST_TYPE(sym->sym.st_info);
		sym->bind = GELF_ST_BIND(sym->sym.st_info);

		if (sym->sym.st_shndx != SHN_UNDEF &&
		    sym->sym.st_shndx != SHN_ABS) {
			sym->sec = find_section_by_index(&kelf->sections,
					sym->sym.st_shndx);
			if (!sym->sec)
				ERROR("couldn't find section for symbol %s\n",
					sym->name);

			/* create reverse link from sec to sym */
			sym->sec->sym = sym;

			if (sym->type == STT_SECTION)
				/* use the section name as the symbol name */
				sym->name = sym->sec->name;
		}
#if 0
		printf("sym %02d, type %d, bind %d, ndx %02d, name %s",
			sym->index, sym->type, sym->bind, sym->sym.st_shndx,
			sym->name);
		if (sym->sec && (sym->type == STT_FUNC || sym->type == STT_OBJECT))
			printf(" -> %s", sym->sec->name);
		printf("\n");
#endif
	}

}


struct kpatch_elf *kpatch_elf_open(const char *name)
{
	Elf *elf;
	int fd, i;
	struct kpatch_elf *kelf;
	struct section *sec;

	fd = open(name, O_RDONLY);
	if (fd == -1)
		ERROR("open");

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf)
		ERROR("elf_begin");

	kelf = malloc(sizeof(*kelf));
	if (!kelf)
		ERROR("malloc");
	memset(kelf, 0, sizeof(*kelf));

	/* read and store section, symbol entries from file */
	kelf->elf = elf;
	kpatch_create_section_table(kelf);
	kpatch_create_symbol_table(kelf);

	/* for each rela section, read and store the rela entries */
	for_each_section(i, sec, &kelf->sections) {
		if (!is_rela_section(sec))
			continue;
		kpatch_create_rela_table(kelf, sec);
	}

	return kelf;
}

void kpatch_compare_correlated_section(struct section *sec)
{
	struct section *sec1 = sec, *sec2 = sec->twin;
	enum status status;

	/* Compare section headers (must match or fatal) */
	if (sec1->sh.sh_type != sec2->sh.sh_type ||
	    sec1->sh.sh_flags != sec2->sh.sh_flags ||
	    sec1->sh.sh_addr != sec2->sh.sh_addr ||
	    sec1->sh.sh_addralign != sec2->sh.sh_addralign ||
	    sec1->sh.sh_entsize != sec2->sh.sh_entsize ||
	    sec1->sh.sh_link != sec1->sh.sh_link)
		DIFF_FATAL("%s section header details differ", sec1->name);

	if (sec1->sh.sh_size != sec2->sh.sh_size ||
	    sec1->data->d_size != sec2->data->d_size || 
	    memcmp(sec1->data->d_buf, sec2->data->d_buf, sec1->data->d_size))
		sec1->status = CHANGED;
	else
		sec1->status = SAME;

	if (!is_rela_section(sec1)) {
		/* Sync section symbol status */
		if (sec1->sym)
			sec1->sym->status = sec1->status;
		/* Sync rela section status */
		if (sec1->rela)
			sec1->rela->status = sec1->status;
	}

#if DEBUG
	printf("section %s is %s\n", sec1->name, status_str(sec1->status));
#endif
}

void kpatch_compare_correlated_sections(struct table *table)
{
	struct section *sec;
	int i;

	for_each_section(i, sec, table)
		if (sec->twin)
			kpatch_compare_correlated_section(sec);
		else
			sec->status = NEW;
}

void kpatch_compare_correlated_symbol(struct symbol *sym)
{
	struct symbol *sym1 = sym, *sym2 = sym->twin;

	if (sym1->sym.st_info != sym2->sym.st_info ||
	    sym1->sym.st_other != sym2->sym.st_other ||
	    (sym1->sec && sym2->sec && sym1->sec->twin != sym2->sec) ||
	    (sym1->sec && !sym2->sec) ||
	    (sym2->sec && !sym1->sec))
		DIFF_FATAL("symbol info mismatch: %s", sym1->name);

	if (sym1->type == STT_OBJECT &&
	    sym1->sym.st_size != sym2->sym.st_size)
		DIFF_FATAL("object size mismatch: %s", sym1->name);

	if (sym1->sym.st_shndx == SHN_UNDEF ||
	     sym1->sym.st_shndx == SHN_ABS)
		sym1->status = SAME;
	else if (sym1->sec)
		sym1->status = sym1->sec->status;
	else if (sym1->status != CHANGED)
		sym1->status = SAME;

	/* special case for type FILE */
	if (sym1->type == STT_FILE)
		sym1->status = DEPENDENCY;
#if DEBUG
	printf("symbol %s is %s\n", sym->name, status_str(sym->status));
#endif
}

void kpatch_compare_correlated_symbols(struct table *table)
{
	struct symbol *sym;
	int i;

	for_each_symbol(i, sym, table) {
		if (i == 0) /* ugh */
			continue;
		if (sym->twin)
			kpatch_compare_correlated_symbol(sym);
		else
			sym->status = NEW;
	}
}

void kpatch_compare_correlated_rela(struct rela *rela)
{
	struct rela *rela1 = rela, *rela2 = rela->twin;

	/*
	 * rela entry status is either SAME or NEW.  All correlated entries
	 * are SAME because the criteria used to correlate them is sufficient
	 * to consider them unchanged.
	 */
	rela->status = SAME;
}

void kpatch_compare_correlated_relas(struct table *table)
{
	struct rela *rela;
	int i;

	for_each_rela(i, rela, table)
		if (rela->twin)
			kpatch_compare_correlated_rela(rela);
		else
			rela->status = NEW;
}


void kpatch_correlate_sections(struct table *table1, struct table *table2)
{
	struct section *sec1, *sec2;
	int i, j;

	/* correlate all sections and compare nonrela sections */
	for_each_section(i, sec1, table1) {
		for_each_section(j, sec2, table2) {
			if (strcmp(sec1->name, sec2->name))
				continue;
			sec1->twin = sec2;
			sec2->twin = sec1;
			break;
		}
	}
}

void kpatch_correlate_symbols(struct table *table1, struct table *table2)
{
	struct symbol *sym1, *sym2;
	int i, j;

	for_each_symbol(i, sym1, table1) {
		if (i == 0) /* ugh */
			continue;
		for_each_symbol(j, sym2, table2) {
			if (j == 0) /* double ugh */
				continue;
			if (!strcmp(sym1->name, sym2->name)) {
				sym1->twin = sym2;
				sym2->twin = sym1;
				break;
			}
		}
	}
}

void kpatch_correlate_relas(struct section *sec)
{
	struct rela *rela1, *rela2;
	int i, j;

	for_each_rela(i, rela1, &sec->relas) {
		for_each_rela(j, rela2, &sec->twin->relas) {
			if (rela1->type == rela2->type &&
			    (rela1->addend == rela2->addend ||
			     (rela1->string && rela2->string &&
			      !strcmp(rela1->string, rela2->string))) &&
			    !strcmp(rela1->sym->name, rela2->sym->name) &&
			    rela1->offset == rela2->offset) {
				rela1->twin = rela2;
				rela2->twin = rela1;
				break;
			}
		}
	}
}

void kpatch_compare_elf_headers(Elf *elf1, Elf *elf2)
{
	GElf_Ehdr eh1, eh2;

	if (!gelf_getehdr(elf1, &eh1))
		ERROR("gelf_getehdr");

	if (!gelf_getehdr(elf2, &eh2))
		ERROR("gelf_getehdr");

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
#if DEBUG
	printf("kpatch_compare_elf_headers passed\n");
#endif
}

void kpatch_check_program_headers(Elf *elf)
{
	size_t ph_nr;

	if (elf_getphdrnum(elf, &ph_nr))
		ERROR("elf_getphdrnum");

	if (ph_nr != 0)
		DIFF_FATAL("ELF contains program header");
#if DEBUG
	printf("kpatch_check_program_headers passed\n");
#endif
}

void kpatch_verify_rela_section_status(struct section *sec)
{
	struct rela *rela;
	int i;

	for_each_rela(i, rela, &sec->relas)
		if (rela->status == NEW) {
			/*
			 * This rela section really is different. Make
			 * sure the base section comes along too.
			 */
			sec->base->status = CHANGED;
			return;
		}

	/*
	 * The difference in the section data was due to the renumeration
	 * of symbol indexes.  Consider this rela section unchanged.
	 */
	sec->status = SAME;
}

void kpatch_correlate_elfs(struct kpatch_elf *kelf1, struct kpatch_elf *kelf2)
{
	struct section *sec;
	int i;

	kpatch_correlate_sections(&kelf1->sections, &kelf2->sections);
	kpatch_correlate_symbols(&kelf1->sybmols, &kelf2->sybmols);

	/* at this point, sections are correlated, we can use sec->twin */
	for_each_section(i, sec, &kelf1->sections)
		if (is_rela_section(sec))
			kpatch_correlate_relas(sec);
}

void kpatch_compare_correlated_elements(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct rela *rela;
	int i, j;

	/* tables are already correlated at this point */
	kpatch_compare_correlated_sections(&kelf->sections);
	kpatch_compare_correlated_symbols(&kelf->sybmols);

	for_each_section(i, sec, &kelf->sections)
		if (is_rela_section(sec))
			kpatch_compare_correlated_relas(&sec->relas);

	/*
	 * Check for false positives on changed rela sections
	 * caused by symbol renumeration.
	 */
	for_each_section(i, sec, &kelf->sections)
		if (is_rela_section(sec) && sec->status == CHANGED)
			kpatch_verify_rela_section_status(sec);

	/*
	 * Find unchanged sections/symbols that are dependencies of
 	 * changed sections
 	 */
	for_each_section(i, sec, &kelf->sections) {
		if (!is_rela_section(sec) || sec->status != CHANGED)
			continue;
		for_each_rela(j, rela, &sec->relas) {
/*
 * Nuts, I know.  Determine if the section of the symbol referenced by
 * the rela entry is associated with a symbol of type STT_SECTION. This
 * is to avoid including unchanged local functions or objects that are
 * called by a changed function.
 */
			if (rela->sym->sym.st_shndx != SHN_UNDEF &&
			    rela->sym->sym.st_shndx != SHN_ABS &&
			    rela->sym->status != CHANGED &&
			    rela->sym->sec->sym->type == STT_SECTION) {
				rela->sym->status = DEPENDENCY;
				rela->sym->sec->status = DEPENDENCY;
			}
/*
 * All symbols referenced by entries in a changed rela section are
 * dependencies.
 */
			if (rela->sym->status == SAME)
				rela->sym->status = DEPENDENCY;
		}
	}
}

void kpatch_dump_kelf(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct symbol *sym;
	struct rela *rela;
	int i, j;

	printf("\n=== Sections ===\n");
	for_each_section(i, sec, &kelf->sections) {
		printf("%02d %s (%s)", sec->index, sec->name, status_str(sec->status));
		if (is_rela_section(sec)) {
			printf(", base-> %s\n", sec->base->name);
			printf("rela section expansion\n");
			for_each_rela(j, rela, &sec->relas) {
				printf("sym %d, offset %d, type %d, %s %s %d %s\n",
				       GELF_R_SYM(rela->rela.r_info),
				       rela->offset, rela->type,
				       rela->sym->name,
				       (rela->addend < 0)?"-":"+",
				       abs(rela->addend),
				       status_str(rela->status));
			}
		} else {
			if (sec->sym)
				printf(", sym-> %s", sec->sym->name);
			if (sec->rela)
				printf(", rela-> %s", sec->rela->name);
		}
		printf("\n");
	}

	printf("\n=== Symbols ===\n");
	for_each_symbol(i, sym, &kelf->sybmols) {
		if (i == 0) /* ugh */
			continue;
		printf("sym %02d, type %d=%d, bind %d=%d, ndx %02d, name %s (%s)",
			sym->index, sym->type, GELF_ST_TYPE(sym->sym.st_info), sym->bind, GELF_ST_BIND(sym->sym.st_info), sym->sym.st_shndx,
			sym->name, status_str(sym->status));
		if (sym->sec && (sym->type == STT_FUNC || sym->type == STT_OBJECT))
			printf(" -> %s", sym->sec->name);
		printf("\n");
	}
}

int kpatch_find_changed_functions(struct kpatch_elf *kelf)
{
	struct symbol *sym;
	int i, changed = 0;

	for_each_symbol(i, sym, &kelf->sybmols) {
		if (sym->type != STT_FUNC)
			continue;
		if (sym->status == CHANGED) {
			changed = 1;
			printf("function %s has changed\n",sym->name);
		}
	}

	if (!changed)
		printf("no changes found\n");
			
	return changed;
}

void kpatch_reachable_symbol(struct symbol *sym)
{
	struct rela *rela;
	struct section *sec;
	int i;

	sym->reachable = 1;
#if DEBUG
	printf("symbol %s is reachable\n", sym->name);
#endif
	if (!sym->sec)
		return;
	sec = sym->sec;
	sec->reachable = 1;
#if DEBUG
	printf("section %s is reachable\n", sec->name);
#endif
	if (sec->sym)
		sec->sym->reachable = 1;
#if DEBUG
	printf("symbol %s is reachable\n", sym->sec->name);
#endif
	if (!sec->rela)
		return;
	sec->rela->reachable = 1;
#if DEBUG
	printf("section %s is reachable\n", sec->rela->name);
#endif
	for_each_rela(i, rela, &sec->rela->relas) {
		if (rela->sym->status == SAME ||
		    rela->sym->reachable)
			continue;
		kpatch_reachable_symbol(rela->sym);
	}
}

void kpatch_validate_reachability(struct kpatch_elf *kelf)
{
	struct symbol *sym;
	struct section *sec;
	int i;

	for_each_symbol(i, sym, &kelf->sybmols)
		if (!sym->reachable && sym->status != SAME &&
		    sym->type == STT_FUNC)
			kpatch_reachable_symbol(sym);

	for_each_section(i, sec, &kelf->sections)
		if (sec->status != SAME && !sec->reachable &&
		    strcmp(sec->name, ".shstrtab") &&
		    strcmp(sec->name, ".symtab") &&
		    strcmp(sec->name, ".strtab"))
			DIFF_FATAL("unreachable changed section %s",
			           sec->name);

	printf("All changed sections are reachable\n");
}

void kpatch_generate_output(struct kpatch_elf *kelf, struct kpatch_elf **kelfout)
{
	int sections_nr = 0, symbols_nr = 0, i, index;
	struct section *sec, *secout;
	struct symbol *sym, *symout;
	struct kpatch_elf *out;

	/* count output sections */
	for_each_section(i, sec, &kelf->sections) {
		/* include these sections even if they haven't changed */
		if (sec->status == SAME &&
		    (!strcmp(sec->name, ".shstrtab") ||
		     !strcmp(sec->name, ".strtab") ||
		     !strcmp(sec->name, ".symtab")))
			sec->status = DEPENDENCY;

		if (sec->status != SAME)
			sections_nr++;
	}

#if DEBUG
	printf("outputting %d sections\n",sections_nr);
#endif

	/* count output symbols */
	for_each_symbol(i, sym, &kelf->sybmols) {
		if (i == 0 || sym->status != SAME)
			symbols_nr++;
	}
#if DEBUG
	printf("outputting %d symbols\n",symbols_nr);
#endif

	/* allocate output kelf */
	out = malloc(sizeof(*out));
	if (!out)
		ERROR("malloc");
	memset(out, 0, sizeof(*out));

	/* allocate tables */
	alloc_table(&out->sections, sizeof(struct section), sections_nr);
	alloc_table(&out->sybmols, sizeof(struct symbol), symbols_nr);

	/* copy to output kelf sections, link to kelf, and reindex */
	index = 0;
	for_each_section(i, sec, &kelf->sections) {
		if (sec->status == SAME)
			continue;

		secout = &((struct section *)(out->sections.data))[index];
		*secout = *sec;
		secout->index = ++index;
		secout->twino = sec;
		sec->twino = secout;
	}

	/* copy to output kelf symbols, link to kelf, and reindex */
	index = 0;
	for_each_symbol(i, sym, &kelf->sybmols) {
		if (i != 0 && sym->status == SAME)
			continue;

		symout = &((struct symbol *)(out->sybmols.data))[index];
		*symout = *sym;
		symout->index = index;
		symout->twino = sym;
		sym->twino = symout;
		index++;

		if (i == 0)
			continue;

		if (sym->sec && sym->sec->twino)
			symout->sym.st_shndx = sym->sec->twino->index;
	}

	for_each_symbol(i, sym, &out->sybmols) {
		if (i == 0)
			continue;
		/*
		 * Search symbol table for local functions whose sections are
		 * not included, and modify them to be non-local.
		 */
		if ((sym->type == STT_OBJECT ||
		     sym->type == STT_FUNC) &&
		    sym->status == DEPENDENCY) {
			sym->type = STT_NOTYPE;
			sym->bind = STB_GLOBAL;
			sym->sym.st_info = GELF_ST_INFO(STB_GLOBAL, STT_NOTYPE);
			sym->sym.st_shndx = SHN_UNDEF;
			sym->sym.st_size = 0;
		}
	}

	*kelfout = out;
}

void kpatch_create_rela_section(struct section *sec, int link)
{
	struct rela *rela;
	int i, symndx, type;
	char *buf;
	size_t size;

	/* create new rela data buffer */
	size = sec->sh.sh_size;
	buf = malloc(size);
	if (!buf)
		ERROR("malloc");
	memset(buf, 0, size);

	/* reindex and copy into buffer */
	for_each_rela(i, rela, &sec->relas) {
#if DEBUG
		if (!rela->sym || !rela->sym->twino)
			ERROR("expected rela symbol");
#endif
		symndx = rela->sym->twino->index;
		type = GELF_R_TYPE(rela->rela.r_info);
		rela->rela.r_info = GELF_R_INFO(symndx, type);

		memcpy(buf + (i * sec->sh.sh_entsize), &rela->rela,
		       sec->sh.sh_entsize);
	}

	sec->data->d_buf = buf;
	/* size is unchanged */

	sec->sh.sh_link = link;
	/* info is section index of text section that matches this rela */
	sec->sh.sh_info = sec->twino->base->twino->index;
}

void kpatch_create_rela_sections(struct kpatch_elf *kelf)
{
	struct section *sec;
	int i, link;

	link = find_section_by_name(&kelf->sections, ".symtab")->index;

	/* reindex rela symbols */
	for_each_section(i, sec, &kelf->sections)
		if (is_rela_section(sec))
			kpatch_create_rela_section(sec, link);
}

#if DEBUG
void print_strtab(char *buf, size_t size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (buf[i] == 0)
			printf("\\0");
		else
			printf("%c",buf[i]);
	}
}
#endif

void kpatch_create_shstrtab(struct kpatch_elf *kelf)
{
	struct section *shstrtab, *sec;
	size_t size, offset, len;
	int i;
	char *buf;

	shstrtab = find_section_by_name(&kelf->sections, ".shstrtab");
	if (!shstrtab)
		ERROR("find_section_by_name");

	/* determine size of string table */
	size = 1; /* for initial NULL terminator */
	for_each_section(i, sec, &kelf->sections)
		size += strlen(sec->name) + 1; /* include NULL terminator */

	/* allocate data buffer */
	buf = malloc(size);
	if (!buf)
		ERROR("malloc");
	memset(buf, 0, size);

	/* populate string table and link with section header */
	offset = 1;
	for_each_section(i, sec, &kelf->sections) {
		len = strlen(sec->name) + 1;
		sec->sh.sh_name = offset;
		memcpy(buf + offset, sec->name, len);
		offset += len;
	}

#if DEBUG
	if (offset != size)
		ERROR("shstrtab size mismatch");
#endif

	shstrtab->data->d_buf = buf;
	shstrtab->data->d_size = size;

#if DEBUG
	printf("shstrtab: ");
	print_strtab(buf, size);
	printf("\n");

	for_each_section(i, sec, &kelf->sections)
		printf("%s @ shstrtab offset %d\n",sec->name,sec->sh.sh_name);
#endif
}

void kpatch_create_strtab(struct kpatch_elf *kelf)
{
	struct section *strtab;
	struct symbol *sym;
	size_t size, offset, len;
	int i;
	char *buf;

	strtab = find_section_by_name(&kelf->sections, ".strtab");
	if (!strtab)
		ERROR("find_section_by_name");

	/* determine size of string table */
	size = 1; /* for initial NULL terminator */
	for_each_symbol(i, sym, &kelf->sybmols) {
		if (i == 0 || sym->type == STT_SECTION)
			continue;
		size += strlen(sym->name) + 1; /* include NULL terminator */
	}

	/* allocate data buffer */
	buf = malloc(size);
	if (!buf)
		ERROR("malloc");
	memset(buf, 0, size);

	/* populate string table and link with section header */
	offset = 1;
	for_each_symbol(i, sym, &kelf->sybmols) {
		if (i == 0)
			continue;
		if (sym->type == STT_SECTION) {
			sym->sym.st_name = 0;
			continue;
		}
		len = strlen(sym->name) + 1;
		sym->sym.st_name = offset;
		memcpy(buf + offset, sym->name, len);
		offset += len;
	}

#if DEBUG
	if (offset != size)
		ERROR("shstrtab size mismatch");
#endif

	strtab->data->d_buf = buf;
	strtab->data->d_size = size;

#if DEBUG
	printf("strtab: ");
	print_strtab(buf, size);
	printf("\n");

	for_each_symbol(i, sym, &kelf->sybmols)
		printf("%s @ strtab offset %d\n",sym->name,sym->sym.st_name);
#endif
}

void kpatch_create_symtab(struct kpatch_elf *kelf)
{
	struct section *symtab;
	struct symbol *sym;
	char *buf;
	size_t size;
	int i;

	symtab = find_section_by_name(&kelf->sections, ".symtab");
	if (!symtab)
		ERROR("find_section_by_name");

	/* create new symtab buffer */
	size = kelf->sybmols.nr * symtab->sh.sh_entsize;
	buf = malloc(size);
	if (!buf)
		ERROR("malloc");
	memset(buf, 0, size);

	for_each_symbol(i, sym, &kelf->sybmols) {
		memcpy(buf + (i * symtab->sh.sh_entsize), &sym->sym,
		       symtab->sh.sh_entsize);
	}

	symtab->data->d_buf = buf;
	symtab->data->d_size = size;

	symtab->sh.sh_link =
		find_section_by_name(&kelf->sections, ".strtab")->index;
	symtab->sh.sh_info =
		find_section_by_name(&kelf->sections, ".shstrtab")->index;
}

#if 0
void kpatch_link_symtab_vmlinux(struct kpatch_elf *kelf, struct kpatch_elf *vmkelf)
{
	struct symbol *sym, *vmsym;
#define BUFSIZE 255
	char kstrbuf[BUFSIZE];
	int i;

	for_each_symbol(i, sym, &kelf->sybmols) {
		if (GELF_ST_BIND(sym->sym.st_info) != STB_GLOBAL)
			continue;

		/* figure out if symbol is exported by the kernel */
		snprintf(kstrbuf, BUFSIZE, "%s%s", "__ksymtab_", sym->name);
		printf("looking for %s\n",kstrbuf);
		vmsym = find_symbol_by_name(&vmkelf->sybmols, kstrbuf);
		if (vmsym)
			continue;

		/* it is not, lookup address in vmlinux */
		vmsym = find_symbol_by_name(&vmkelf->sybmols, sym->name);
		if (!vmsym)
			ERROR("symbol not found in vmlinux");

		sym->sym.st_value = vmsym->sym.st_value;
		sym->sym.st_info = GELF_ST_INFO(STB_LOCAL,
			GELF_ST_TYPE(vmsym->sym.st_info));
		sym->sym.st_shndx = SHN_ABS;
#if DEBUG
		printf("symbol %s found with address %016lx\n",
			sym->name, sym->sym.st_value);
#endif
	}
}
#endif

void kpatch_write_output_elf(struct kpatch_elf *kelf, Elf *elf, char *outfile)
{
	int fd, i, index = 0;
	struct section *sec;
	Elf *elfout;
	GElf_Ehdr eh, ehout;
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Shdr sh;

	/* TODO make this argv */
	fd = creat(outfile, 0777);
	if (fd == -1)
		ERROR("creat");

	elfout = elf_begin(fd, ELF_C_WRITE, NULL);
	if (!elfout)
		ERROR("elf_begin");

	if (!gelf_newehdr(elfout, gelf_getclass(kelf->elf)))
		ERROR("gelf_newehdr");

	if (!gelf_getehdr(elfout, &ehout))
		ERROR("gelf_getehdr");

	if (!gelf_getehdr(elf, &eh))
		ERROR("gelf_getehdr");

	memset(&ehout, 0, sizeof(ehout));
	ehout.e_ident[EI_DATA] = eh.e_ident[EI_DATA];
	ehout.e_machine = eh.e_machine;
	ehout.e_type = eh.e_type;
	ehout.e_version = EV_CURRENT;
	ehout.e_shstrndx = find_section_by_name(&kelf->sections, ".shstrtab")->index;

	/* add changed sections */
	for_each_section(i, sec, &kelf->sections) {
		scn = elf_newscn(elfout);
		if (!scn)
			ERROR("elf_newscn");

		data = elf_newdata(scn);
		if (!data)
			ERROR("elf_newdata");

		*data = *sec->data;

		if(!gelf_getshdr(scn, &sh))
			ERROR("gelf_getshdr");

		sh = sec->sh;

		if (!elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY))
			ERROR("elf_flagdata");

		if (!gelf_update_shdr(scn, &sh))
			ERROR("gelf_update_shdr");	
	}

	if (!gelf_update_ehdr(elfout, &ehout))
		ERROR("gelf_update_ehdr");

	if (elf_update(elfout, ELF_C_WRITE) < 0) {
		printf("%s\n",elf_errmsg(-1));
		ERROR("elf_update");
	}
}

int main(int argc, char *argv[])
{
	struct kpatch_elf *kelf_base, *kelf_patched, *kelf_out;
	char *outfile;

	elf_version(EV_CURRENT);

	kelf_base = kpatch_elf_open(argv[1]);
	kelf_patched = kpatch_elf_open(argv[2]);
	outfile = argv[3];

	kpatch_compare_elf_headers(kelf_base->elf, kelf_patched->elf);
	kpatch_check_program_headers(kelf_base->elf);
	kpatch_check_program_headers(kelf_patched->elf);

	kpatch_correlate_elfs(kelf_base, kelf_patched);
	/*
	 * After this point, we don't care about kelf_base anymore.
	 * We access its sections via the twin pointers in the
	 * section, symbol, and rela lists of kelf_patched.
	 */
	kpatch_compare_correlated_elements(kelf_patched);
#if DEBUG
	kpatch_dump_kelf(kelf_patched);
#endif
	/*
	 * At this point, the kelf is fully linked and statuses on
	 * all sections and symbols have been set.
	 */

	/* Go through changes and make sure they are hot-patchable */
	kpatch_validate_reachability(kelf_patched);

	if (!kpatch_find_changed_functions(kelf_patched))
		return 0;

	/* Generate the output elf */
	kpatch_generate_output(kelf_patched, &kelf_out);
	kpatch_create_rela_sections(kelf_out);
	kpatch_create_shstrtab(kelf_out);
	kpatch_create_strtab(kelf_out);
	kpatch_create_symtab(kelf_out);
#if DEBUG
	kpatch_dump_kelf(kelf_out);
#endif

	kpatch_write_output_elf(kelf_out, kelf_patched->elf, outfile);

	return 0;
}
