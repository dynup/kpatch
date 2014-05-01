/*
 * kpatch.h
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 *
 * Contains the API for the core kpatch module used by the patch modules
 */

#ifndef _KPATCH_H_
#define _KPATCH_H_

#include <linux/types.h>
#include <linux/module.h>

enum kpatch_op {
	KPATCH_OP_NONE,
	KPATCH_OP_PATCH,
	KPATCH_OP_UNPATCH,
};

struct kpatch_func {
	/* public */
	unsigned long new_addr;
	unsigned long new_size;
	unsigned long old_addr;
	unsigned long old_size;

	/* private */
	struct hlist_node node;
	enum kpatch_op op;
};

struct kpatch_module {
	struct module *mod;
	struct kpatch_func *funcs;
	int num_funcs;

	bool enabled;
};

extern struct kobject *kpatch_patches_kobj;

extern int kpatch_register(struct kpatch_module *kpmod);
extern int kpatch_unregister(struct kpatch_module *kpmod);

#endif /* _KPATCH_H_ */
