#ifndef _LOOKUP_H_
#define _LOOKUP_H_

#include <stdbool.h>

struct lookup_table;

struct lookup_result {
	unsigned long addr;
	unsigned long size;
	unsigned long sympos;
};

struct sym_compare_type {
	char *name;
	int type;
};

struct lookup_table *lookup_open(char *symtab_path, char *symvers_path,
				 char *hint, struct sym_compare_type *locals);
void lookup_close(struct lookup_table *table);
bool lookup_local_symbol(struct lookup_table *table, char *name,
			 struct lookup_result *result);
bool lookup_global_symbol(struct lookup_table *table, char *name,
			  struct lookup_result *result);
bool lookup_is_exported_symbol(struct lookup_table *table, char *name);
char *lookup_exported_symbol_objname(struct lookup_table *table, char *name);

#endif /* _LOOKUP_H_ */
