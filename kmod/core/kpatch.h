/*
 * kpatch.h
 *
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
 * Copyright (C) 2013 Josh Poimboeuf <jpoimboe@redhat.com>
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
 *
 * Contains the API for the core kpatch module used by the patch modules
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
