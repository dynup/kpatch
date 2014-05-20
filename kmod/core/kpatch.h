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

struct kpatch_patch {
	unsigned long new_addr;
	unsigned long new_size;
	unsigned long old_addr;
	unsigned long old_size;
};

struct kpatch_dynrela {
	unsigned long dest;
	unsigned long src;
	unsigned long type;
};

#ifdef __KERNEL__

#include <linux/types.h>
#include <linux/module.h>

struct kpatch_internal;

struct kpatch_module {
	struct module *mod;
	struct kpatch_patch *patches;
	struct kpatch_dynrela *dynrelas;
	int patches_nr;
	int dynrelas_nr;
	bool enabled;
	struct kpatch_internal *internal; /* used internally by core module */
};

extern struct kobject *kpatch_patches_kobj;

extern int kpatch_register(struct kpatch_module *kpmod, bool replace);
extern int kpatch_unregister(struct kpatch_module *kpmod);

#endif /* __KERNEL__ */

#endif /* _KPATCH_H_ */
