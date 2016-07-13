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

#include <gelf.h>
#include "list.h"
#include "log.h"

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
	int index;
	enum status status;
	int include;
	int ignore;
	int grouped;
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

struct symbol {
	struct list_head list;
	struct symbol *twin;
	struct section *sec;
	GElf_Sym sym;
	char *name;
	int index;
	unsigned char bind, type;
	enum status status;
	union {
		int include; /* used in the patched elf */
		int strip; /* used in the output elf */
	};
	int has_fentry_call;
};

struct rela {
	struct list_head list;
	GElf_Rela rela;
	struct symbol *sym;
	unsigned int type;
	int addend;
	int offset;
	char *string;
};

struct string {
	struct list_head list;
	char *name;
};

struct kpatch_elf {
	Elf *elf;
	struct list_head sections;
	struct list_head symbols;
	struct list_head strings;
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

#define ALLOC_LINK(_new, _list) \
{ \
	(_new) = malloc(sizeof(*(_new))); \
	if (!(_new)) \
		ERROR("malloc"); \
	memset((_new), 0, sizeof(*(_new))); \
	INIT_LIST_HEAD(&(_new)->list); \
	list_add_tail(&(_new)->list, (_list)); \
}

int offset_of_string(struct list_head *list, char *name);

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
void kpatch_write_output_elf(struct kpatch_elf *kelf, Elf *elf, char *outfile);
void kpatch_elf_teardown(struct kpatch_elf *kelf);
void kpatch_elf_free(struct kpatch_elf *kelf);
#endif /* _KPATCH_ELF_H_ */
