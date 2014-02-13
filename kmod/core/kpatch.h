/*
 * kpatch.h
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2013 Josh Poimboeuf <jpoimboe@redhat.com>
 *
 * Contains the API for the core kpatch module used by the hotfix modules
 */

#ifndef _KPATCH_H_
#define _KPATCH_H_

struct kpatch_func {
	unsigned long old_func_addr;
	unsigned long new_func_addr;
	char *old_func_name;
	unsigned long old_func_addr_end;
	struct module *mod;
};

struct kpatch_rela {
	unsigned long dest;
	unsigned long src;
	unsigned long type;
};

struct kpatch_patch {
	unsigned long new;
	unsigned long orig;
	unsigned long orig_end;
};

int kpatch_register(struct module *mod, void *kpatch_patches,
                    void *kpatch_patches_end);
int kpatch_unregister(struct module *mod);

#endif /* _KPATCH_H_ */
