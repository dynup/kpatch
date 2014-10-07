/*
 * kpatch-patch.h
 *
 * Copyright (C) 2014 Josh Poimboeuf <jpoimboe@redhat.com>
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
 * Contains the structs used for the patch module special sections
 */

#ifndef _KPATCH_PATCH_H_
#define _KPATCH_PATCH_H_

struct kpatch_patch_func {
	unsigned long new_addr;
	unsigned long new_size;
	unsigned long old_addr;
	unsigned long old_size;
	char *name;
	char *objname;
};

struct kpatch_patch_dynrela {
	unsigned long dest;
	unsigned long src;
	unsigned long type;
	char *name;
	char *objname;
	int external;
	int addend;
};

struct kpatch_patch_hook {
	void (*hook)(void);
	char *objname;
};

#endif /* _KPATCH_PATCH_H_ */
