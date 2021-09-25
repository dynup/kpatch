/*
 * kpatch-elf.h
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

#ifndef _KPATCH_ELF_H_
#define _KPATCH_ELF_H_

#include <stdbool.h>
#include <gelf.h>
#include "list.h"
#include "log.h"

#define KLP_SYM_PREFIX		".klp.sym."
#define KLP_RELASEC_PREFIX	".klp.rela."
#define KLP_ARCH_PREFIX 	".klp.arch."
#define SHF_RELA_LIVEPATCH	0x00100000
#define SHN_LIVEPATCH		0xff20

/*******************
 * Data structures
 * ****************/
struct section;
struct symbol;
struct rela;

enum status {
	NEW,
	CHANGED,
	SAME
};

struct section {
	struct list_head list;
	struct section *twin;
	GElf_Shdr sh;
	Elf_Data *data;
	char *name;
	unsigned int index;
	enum status status;
	int include;
	int ignore;
	int grouped;
	int groupindex;
	union {
		struct { /* if (is_rela_section()) */
			struct section *base;
			struct list_head relas;
		};
		struct { /* else */
			struct section *rela;
			struct symbol *secsym, *sym;
		};
	};
};

enum symbol_strip {
	SYMBOL_DEFAULT,
	SYMBOL_USED,
	SYMBOL_STRIP,
};

struct symbol {
	struct list_head list;
	struct symbol *twin;
	struct symbol *parent;
	struct list_head children;
	struct list_head subfunction_node;
	struct section *sec;
	GElf_Sym sym;
	char *name;
	struct object_symbol *lookup_table_file_sym;
	unsigned int index;
	unsigned char bind, type;
	enum status status;
	union {
		int include; /* used in the patched elf */
		enum symbol_strip strip; /* used in the output elf */
	};
	int has_func_profiling;
};

struct rela {
	struct list_head list;
	GElf_Rela rela;
	struct symbol *sym;
	unsigned int type;
	unsigned int offset;
	long addend;
	char *string;
	bool need_dynrela;
};

struct string {
	struct list_head list;
	char *name;
};

/*
 * Maintain list of group section
 */
struct group_section {
	struct list_head list;
	/* List of section link names of this group */
	char **secnames;
	char **symnames;
	int groupindex;
};

struct kpatch_elf {
	Elf *elf;
	struct list_head sections;
	struct list_head symbols;
	struct list_head strings;
	struct list_head groupsec;
	int fd;
};

/*******************
 * Helper functions
 ******************/
char *status_str(enum status status);
int is_rela_section(struct section *sec);
int is_text_section(struct section *sec);
int is_debug_section(struct section *sec);

struct section *find_section_by_index(struct list_head *list, unsigned int index);
struct section *find_section_by_name(struct list_head *list, const char *name);
struct symbol *find_symbol_by_index(struct list_head *list, size_t index);
struct symbol *find_symbol_by_name(struct list_head *list, const char *name);
struct rela *find_rela_by_offset(struct section *relasec, unsigned int offset);

#define ALLOC_LINK(_new, _list) \
{ \
	(_new) = malloc(sizeof(*(_new))); \
	if (!(_new)) \
		ERROR("malloc"); \
	memset((_new), 0, sizeof(*(_new))); \
	INIT_LIST_HEAD(&(_new)->list); \
	if (_list) \
		list_add_tail(&(_new)->list, (_list)); \
}

int offset_of_string(struct list_head *list, char *name);

#ifndef R_PPC64_ENTRY
#define R_PPC64_ENTRY   118
#endif

/*************
 * Functions
 * **********/
void kpatch_create_rela_list(struct kpatch_elf *kelf, struct section *sec);
void kpatch_create_section_list(struct kpatch_elf *kelf);
void kpatch_create_symbol_list(struct kpatch_elf *kelf);
struct kpatch_elf *kpatch_elf_open(const char *name);
void kpatch_dump_kelf(struct kpatch_elf *kelf);

int is_null_sym(struct symbol *sym);
int is_file_sym(struct symbol *sym);
int is_local_func_sym(struct symbol *sym);
int is_local_sym(struct symbol *sym);

void print_strtab(char *buf, size_t size);
void kpatch_create_shstrtab(struct kpatch_elf *kelf);
void kpatch_create_strtab(struct kpatch_elf *kelf);
void kpatch_create_symtab(struct kpatch_elf *kelf);
struct section *create_section_pair(struct kpatch_elf *kelf, char *name,
                                    int entsize, int nr);
void kpatch_remove_and_free_section(struct kpatch_elf *kelf, char *secname);
void kpatch_reindex_elements(struct kpatch_elf *kelf);
void kpatch_reindex_group_sections(struct kpatch_elf *kelf);
void kpatch_rebuild_rela_section_data(struct section *sec);
void kpatch_write_output_elf(struct kpatch_elf *kelf, Elf *elf, char *outfile,
			     mode_t mode);
void kpatch_free_groupsec(struct kpatch_elf *kelf);
void kpatch_elf_teardown(struct kpatch_elf *kelf);
void kpatch_elf_free(struct kpatch_elf *kelf);
void kpatch_mark_grouped_sections(struct kpatch_elf *kelf);
#endif /* _KPATCH_ELF_H_ */
