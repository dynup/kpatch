#ifndef _LOOKUP_H_
#define _LOOKUP_H_

struct lookup_table;

struct lookup_result {
	unsigned long value;
	unsigned long size;
	unsigned long pos;
};

struct lookup_table *lookup_open(char *path);
void lookup_close(struct lookup_table *table);
int lookup_local_symbol(struct lookup_table *table, char *name, char *hint,
                        struct lookup_result *result);
int lookup_global_symbol(struct lookup_table *table, char *name,
                         struct lookup_result *result);
int lookup_is_exported_symbol(struct lookup_table *table, char *name);

#endif /* _LOOKUP_H_ */
