#ifndef _LOOKUP_H_
#define _LOOKUP_H_

#include <stdbool.h>
#include "kpatch-elf.h"

struct lookup_table;

struct lookup_result {
	char *objname;
	unsigned long addr;
	unsigned long size;
	unsigned long sympos;
	bool global, exported;
};

struct lookup_table *lookup_open(char *symtab_path, char *objname,
				 char *symvers_path, struct kpatch_elf *kelf);
void lookup_close(struct lookup_table *table);
bool lookup_symbol(struct lookup_table *table, struct symbol *sym,
		   struct lookup_result *result);

#endif /* _LOOKUP_H_ */
