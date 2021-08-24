/*
 * Copyright (C) 2013-2014 Josh Poimboeuf <jpoimboe@redhat.com>
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com> 
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <generated/utsrelease.h>

#include <linux/livepatch.h>

#include "kpatch-patch.h"

#ifndef UTS_UBUNTU_RELEASE_ABI
#define UTS_UBUNTU_RELEASE_ABI 0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0) ||			\
    defined(RHEL_RELEASE_CODE)
#define HAVE_ELF_RELOCS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0) ||			\
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) &&			\
      UTS_UBUNTU_RELEASE_ABI >= 7) ||					\
    defined(RHEL_RELEASE_CODE)
#define HAVE_SYMPOS
#endif

#ifdef RHEL_RELEASE_CODE
# if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7, 5)
#  define HAVE_IMMEDIATE
# endif
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 12, 0) &&		\
       LINUX_VERSION_CODE <= KERNEL_VERSION(4, 15, 0))
# define HAVE_IMMEDIATE
#endif

#ifdef RHEL_RELEASE_CODE
# if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 5)
#  define HAVE_CALLBACKS
# endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
# define HAVE_CALLBACKS
#endif

#ifdef RHEL_RELEASE_CODE
# if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 8) && 		\
	 RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8, 0)) || 		\
      RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 2)
#  define HAVE_SIMPLE_ENABLE
# endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
# define HAVE_SIMPLE_ENABLE
#endif

#ifdef RHEL_RELEASE_CODE
# if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 2)
#  define HAVE_KLP_REPLACE
# endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
# define HAVE_KLP_REPLACE
#endif

#ifndef KLP_REPLACE_ENABLE
#define KLP_REPLACE_ENABLE true
#endif

/*
 * There are quite a few similar structures at play in this file:
 * - livepatch.h structs prefixed with klp_*
 * - kpatch-patch.h structs prefixed with kpatch_patch_*
 * - local scaffolding structs prefixed with patch_*
 *
 * The naming of the struct variables follows this convention:
 * - livepatch struct being with "l" (e.g. lfunc)
 * - kpatch_patch structs being with "k" (e.g. kfunc)
 * - local scaffolding structs have no prefix (e.g. func)
 *
 *  The program reads in kpatch_patch structures, arranges them into the
 *  scaffold structures, then creates a livepatch structure suitable for
 *  registration with the livepatch kernel API.  The scaffold structs only
 *  exist to allow the construction of the klp_patch struct.  Once that is
 *  done, the scaffold structs are no longer needed.
 */

static struct klp_patch *lpatch;

static LIST_HEAD(patch_objects);
static int patch_objects_nr;
struct patch_object {
	struct list_head list;
	struct list_head funcs;
	struct list_head relocs;
#ifdef HAVE_CALLBACKS
	struct klp_callbacks callbacks;
#endif
	const char *name;
	int funcs_nr, relocs_nr;
};

struct patch_func {
	struct list_head list;
	struct kpatch_patch_func *kfunc;
};

struct patch_reloc {
	struct list_head list;
	struct kpatch_patch_dynrela *kdynrela;
};

static struct patch_object *patch_alloc_new_object(const char *name)
{
	struct patch_object *object;

	object = kzalloc(sizeof(*object), GFP_KERNEL);
	if (!object)
		return NULL;
	INIT_LIST_HEAD(&object->funcs);
#ifndef HAVE_ELF_RELOCS
	INIT_LIST_HEAD(&object->relocs);
#endif
	if (strcmp(name, "vmlinux"))
		object->name = name;
	list_add(&object->list, &patch_objects);
	patch_objects_nr++;
	return object;
}

static struct patch_object *patch_find_object_by_name(const char *name)
{
	struct patch_object *object;

	list_for_each_entry(object, &patch_objects, list)
		if ((!strcmp(name, "vmlinux") && !object->name) ||
		    (object->name && !strcmp(object->name, name)))
			return object;
	return patch_alloc_new_object(name);
}

static int patch_add_func_to_object(struct kpatch_patch_func *kfunc)
{
	struct patch_func *func;
	struct patch_object *object;

	func = kzalloc(sizeof(*func), GFP_KERNEL);
	if (!func)
		return -ENOMEM;
	INIT_LIST_HEAD(&func->list);
	func->kfunc = kfunc;

	object = patch_find_object_by_name(kfunc->objname);
	if (!object) {
		kfree(func);
		return -ENOMEM;
	}
	list_add(&func->list, &object->funcs);
	object->funcs_nr++;
	return 0;
}

#ifndef HAVE_ELF_RELOCS
static int patch_add_reloc_to_object(struct kpatch_patch_dynrela *kdynrela)
{
	struct patch_reloc *reloc;
	struct patch_object *object;

	reloc = kzalloc(sizeof(*reloc), GFP_KERNEL);
	if (!reloc)
		return -ENOMEM;
	INIT_LIST_HEAD(&reloc->list);
	reloc->kdynrela = kdynrela;

	object = patch_find_object_by_name(kdynrela->objname);
	if (!object) {
		kfree(reloc);
		return -ENOMEM;
	}
	list_add(&reloc->list, &object->relocs);
	object->relocs_nr++;
	return 0;
}
#endif

static void patch_free_scaffold(void) {
	struct patch_func *func, *safefunc;
	struct patch_object *object, *safeobject;
#ifndef HAVE_ELF_RELOCS
	struct patch_reloc *reloc, *safereloc;
#endif

	list_for_each_entry_safe(object, safeobject, &patch_objects, list) {
		list_for_each_entry_safe(func, safefunc,
		                         &object->funcs, list) {
			list_del(&func->list);
			kfree(func);
		}
#ifndef HAVE_ELF_RELOCS
		list_for_each_entry_safe(reloc, safereloc,
		                         &object->relocs, list) {
			list_del(&reloc->list);
			kfree(reloc);
		}
#endif
		list_del(&object->list);
		kfree(object);
	}
}

static void patch_free_livepatch(struct klp_patch *patch)
{
	struct klp_object *object;

	if (patch) {
		for (object = patch->objs; object; object++) {
			if (object->funcs)
				kfree(object->funcs);
#ifndef HAVE_ELF_RELOCS
			if (object->relocs)
				kfree(object->relocs);
#endif
		}
		if (patch->objs)
			kfree(patch->objs);
		kfree(patch);
	}
}

extern struct kpatch_pre_patch_callback __kpatch_callbacks_pre_patch[], __kpatch_callbacks_pre_patch_end[];
extern struct kpatch_post_patch_callback __kpatch_callbacks_post_patch[], __kpatch_callbacks_post_patch_end[];
extern struct kpatch_pre_unpatch_callback __kpatch_callbacks_pre_unpatch[], __kpatch_callbacks_pre_unpatch_end[];
extern struct kpatch_post_unpatch_callback __kpatch_callbacks_post_unpatch[], __kpatch_callbacks_post_unpatch_end[];

#ifdef HAVE_CALLBACKS
static int add_callbacks_to_patch_objects(void)
{
	struct kpatch_pre_patch_callback *p_pre_patch_callback;
	struct kpatch_post_patch_callback *p_post_patch_callback;
	struct kpatch_pre_unpatch_callback *p_pre_unpatch_callback;
	struct kpatch_post_unpatch_callback *p_post_unpatch_callback;
	struct patch_object *object;

	for (p_pre_patch_callback = __kpatch_callbacks_pre_patch;
	     p_pre_patch_callback < __kpatch_callbacks_pre_patch_end;
	     p_pre_patch_callback++) {
		object = patch_find_object_by_name(p_pre_patch_callback->objname);
		if (!object)
			return -ENOMEM;
		if (object->callbacks.pre_patch) {
			pr_err("extra pre-patch callback for object: %s\n",
				object->name ? object->name : "vmlinux");
			return -EINVAL;
		}
		object->callbacks.pre_patch = (int (*)(struct klp_object *))
					       p_pre_patch_callback->callback;
	}

	for (p_post_patch_callback = __kpatch_callbacks_post_patch;
	     p_post_patch_callback < __kpatch_callbacks_post_patch_end;
	     p_post_patch_callback++) {
		object = patch_find_object_by_name(p_post_patch_callback->objname);
		if (!object)
			return -ENOMEM;
		if (object->callbacks.post_patch) {
			pr_err("extra post-patch callback for object: %s\n",
				object->name ? object->name : "vmlinux");
			return -EINVAL;
		}
		object->callbacks.post_patch = (void (*)(struct klp_object *))
						p_post_patch_callback->callback;
	}

	for (p_pre_unpatch_callback = __kpatch_callbacks_pre_unpatch;
	     p_pre_unpatch_callback < __kpatch_callbacks_pre_unpatch_end;
	     p_pre_unpatch_callback++) {
		object = patch_find_object_by_name(p_pre_unpatch_callback->objname);
		if (!object)
			return -ENOMEM;
		if (object->callbacks.pre_unpatch) {
			pr_err("extra pre-unpatch callback for object: %s\n",
				object->name ? object->name : "vmlinux");
			return -EINVAL;
		}
		object->callbacks.pre_unpatch = (void (*)(struct klp_object *))
						p_pre_unpatch_callback->callback;
	}

	for (p_post_unpatch_callback = __kpatch_callbacks_post_unpatch;
	     p_post_unpatch_callback < __kpatch_callbacks_post_unpatch_end;
	     p_post_unpatch_callback++) {
		object = patch_find_object_by_name(p_post_unpatch_callback->objname);
		if (!object)
			return -ENOMEM;
		if (object->callbacks.post_unpatch) {
			pr_err("extra post-unpatch callback for object: %s\n",
				object->name ? object->name : "vmlinux");
			return -EINVAL;
		}
		object->callbacks.post_unpatch = (void (*)(struct klp_object *))
						p_post_unpatch_callback->callback;
	}

	return 0;
}
#else /* HAVE_CALLBACKS */
static inline int add_callbacks_to_patch_objects(void)
{
	if (__kpatch_callbacks_pre_patch !=
	    __kpatch_callbacks_pre_patch_end ||
	    __kpatch_callbacks_post_patch !=
	    __kpatch_callbacks_post_patch_end ||
	    __kpatch_callbacks_pre_unpatch !=
	    __kpatch_callbacks_pre_unpatch_end ||
	    __kpatch_callbacks_post_unpatch !=
	    __kpatch_callbacks_post_unpatch_end) {
		pr_err("patch callbacks are not supported\n");
		return -EINVAL;
	}

	return 0;
}
#endif /* HAVE_CALLBACKS */

extern struct kpatch_patch_func __kpatch_funcs[], __kpatch_funcs_end[];
#ifndef HAVE_ELF_RELOCS
extern struct kpatch_patch_dynrela __kpatch_dynrelas[], __kpatch_dynrelas_end[];
#endif

static int __init patch_init(void)
{
	struct kpatch_patch_func *kfunc;
	struct klp_object *lobjects, *lobject;
	struct klp_func *lfuncs, *lfunc;
	struct patch_object *object;
	struct patch_func *func;
	int ret = 0, i, j;
#ifndef HAVE_ELF_RELOCS
	struct kpatch_patch_dynrela *kdynrela;
	struct patch_reloc *reloc;
	struct klp_reloc *lrelocs, *lreloc;
#endif

	/* organize functions and relocs by object in scaffold */
	for (kfunc = __kpatch_funcs;
	     kfunc != __kpatch_funcs_end;
	     kfunc++) {
		ret = patch_add_func_to_object(kfunc);
		if (ret)
			goto out;
	}

#ifndef HAVE_ELF_RELOCS
	for (kdynrela = __kpatch_dynrelas;
	     kdynrela != __kpatch_dynrelas_end;
	     kdynrela++) {
		ret = patch_add_reloc_to_object(kdynrela);
		if (ret)
			goto out;
	}
#endif

	ret = add_callbacks_to_patch_objects();
	if (ret)
		goto out;

	/* past this point, only possible return code is -ENOMEM */
	ret = -ENOMEM;

	/* allocate and fill livepatch structures */
	lpatch = kzalloc(sizeof(*lpatch), GFP_KERNEL);
	if (!lpatch)
		goto out;

	lobjects = kzalloc(sizeof(*lobjects) * (patch_objects_nr+1),
			   GFP_KERNEL);
	if (!lobjects)
		goto out;
	lpatch->mod = THIS_MODULE;
	lpatch->objs = lobjects;
#ifdef HAVE_KLP_REPLACE
	lpatch->replace = KLP_REPLACE_ENABLE;
#endif
#if defined(__powerpc64__) && defined(HAVE_IMMEDIATE)
	lpatch->immediate = true;
#endif

	i = 0;
	list_for_each_entry(object, &patch_objects, list) {
		lobject = &lobjects[i];
		lobject->name = object->name;
		lfuncs = kzalloc(sizeof(struct klp_func) *
		                 (object->funcs_nr+1), GFP_KERNEL);
		if (!lfuncs)
			goto out;
		lobject->funcs = lfuncs;
		j = 0;
		list_for_each_entry(func, &object->funcs, list) {
			lfunc = &lfuncs[j];
			lfunc->old_name = func->kfunc->name;
			lfunc->new_func = (void *)func->kfunc->new_addr;
#ifdef HAVE_SYMPOS
			lfunc->old_sympos = func->kfunc->sympos;
#else
			lfunc->old_addr = func->kfunc->old_addr;
#endif
			j++;
		}

#ifndef HAVE_ELF_RELOCS
		lrelocs = kzalloc(sizeof(struct klp_reloc) *
				  (object->relocs_nr+1), GFP_KERNEL);
		if (!lrelocs)
			goto out;
		lobject->relocs = lrelocs;
		j = 0;
		list_for_each_entry(reloc, &object->relocs, list) {
			lreloc = &lrelocs[j];
			lreloc->loc = reloc->kdynrela->dest;
#ifdef HAVE_SYMPOS
			lreloc->sympos = reloc->kdynrela->sympos;
#else
			lreloc->val = reloc->kdynrela->src;
#endif /* HAVE_SYMPOS */
			lreloc->type = reloc->kdynrela->type;
			lreloc->name = reloc->kdynrela->name;
			lreloc->addend = reloc->kdynrela->addend;
			lreloc->external = reloc->kdynrela->external;
			j++;
		}
#endif /* HAVE_ELF_RELOCS */

#ifdef HAVE_CALLBACKS
		lobject->callbacks = object->callbacks;
#endif

		i++;
	}

	/*
	 * Once the patch structure that the live patching API expects
	 * has been built, we can release the scaffold structure.
	 */
	patch_free_scaffold();

#ifndef HAVE_SIMPLE_ENABLE
	ret = klp_register_patch(lpatch);
	if (ret) {
		patch_free_livepatch(lpatch);
		return ret;
	}
#endif

	ret = klp_enable_patch(lpatch);
	if (ret) {
#ifndef HAVE_SIMPLE_ENABLE
		WARN_ON(klp_unregister_patch(lpatch));
#endif
		patch_free_livepatch(lpatch);
		return ret;
	}

	return 0;
out:
	patch_free_livepatch(lpatch);
	patch_free_scaffold();
	return ret;
}

static void __exit patch_exit(void)
{
#ifndef HAVE_SIMPLE_ENABLE
	WARN_ON(klp_unregister_patch(lpatch));
#endif
	patch_free_livepatch(lpatch);
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
