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

#include <linux/version.h>

/* Support for livepatch callbacks? */
#ifdef RHEL_RELEASE_CODE
# if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 5)
#  define HAVE_CALLBACKS
# endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
# define HAVE_CALLBACKS
#endif

#ifdef HAVE_CALLBACKS
/* IMPORTANT: include ordering is critical! */
# ifdef _LINUX_LIVEPATCH_H_
typedef struct klp_object klp_obj;
# else
/*
 * Basically just a placeholder for when we can't include linux/livepatch.h.
 * The correct type, which is what gets packed in the section, is
 * struct klp_object.
 */
typedef void klp_obj;
# endif /* _LINUX_LIVEPATCH_H_ */
#else
#include "kpatch.h"
typedef struct kpatch_object klp_obj;
#endif /* HAVE_CALLBACKS */

struct kpatch_patch_func {
	unsigned long new_addr;
	unsigned long new_size;
	unsigned long old_addr;
	unsigned long old_size;
	unsigned long sympos;
	char *name;
	char *objname;
};

struct kpatch_patch_dynrela {
	unsigned long dest;
	unsigned long src;
	unsigned long type;
	unsigned long sympos;
	char *name;
	char *objname;
	int external;
	long addend;
};


struct kpatch_pre_patch_callback {
	int (*callback)(klp_obj *obj);
	char *objname;
};
struct kpatch_post_patch_callback {
	void (*callback)(klp_obj *obj);
	char *objname;
};
struct kpatch_pre_unpatch_callback {
	void (*callback)(klp_obj *obj);
	char *objname;
};
struct kpatch_post_unpatch_callback {
	void (*callback)(klp_obj *obj);
	char *objname;
};

#endif /* _KPATCH_PATCH_H_ */
