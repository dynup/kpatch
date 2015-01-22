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

#include <linux/livepatch.h>

#include "kpatch-patch.h"

struct klp_patch *patch;

static LIST_HEAD(patch_objects);
static int patch_objects_nr;
struct patch_object {
	struct list_head list;
	struct list_head funcs;
	struct list_head relocs;
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
	INIT_LIST_HEAD(&object->relocs);
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
		    !strcmp(object->name, name))
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

static int patch_add_reloc_to_object(struct kpatch_patch_dynrela *dynrela)
{
	struct patch_reloc *reloc;
	struct patch_object *object;

	reloc = kzalloc(sizeof(*reloc), GFP_KERNEL);
	if (!reloc)
		return -ENOMEM;
	INIT_LIST_HEAD(&reloc->list);
	reloc->kdynrela = dynrela;

	object = patch_find_object_by_name(dynrela->objname);
	if (!object) {
		kfree(reloc);
		return -ENOMEM;
	}
	list_add(&reloc->list, &object->relocs);
	object->relocs_nr++;
	return 0;
}

static void patch_free_scaffold(void) {
	struct patch_func *func, *safefunc;
	struct patch_reloc *reloc, *safereloc;
	struct patch_object *object, *safeobject;

	list_for_each_entry_safe(object, safeobject, &patch_objects, list) {
		list_for_each_entry_safe(func, safefunc,
		                         &object->funcs, list) {
			list_del(&func->list);
			kfree(func);
		}
		list_for_each_entry_safe(reloc, safereloc,
		                         &object->relocs, list) {
			list_del(&reloc->list);
			kfree(reloc);
		}
		list_del(&object->list);
		kfree(object);
	}
}

static void patch_free_livepatch(struct klp_patch *patch)
{
	struct klp_object *object;

	if (patch) {
		for (object = patch->objs; object && object->funcs; object++) {
			if (object->funcs)
				kfree(object->funcs);
			if (object->relocs)
				kfree(object->relocs);
		}
		if (patch->objs)
			kfree(patch->objs);
		kfree(patch);
	}
}

extern struct kpatch_patch_func __kpatch_funcs[], __kpatch_funcs_end[];
extern struct kpatch_patch_dynrela __kpatch_dynrelas[], __kpatch_dynrelas_end[];

static int __init patch_init(void)
{
	struct kpatch_patch_func *kfunc;
	struct kpatch_patch_dynrela *dynrela;
	struct klp_object *lobjects, *lobject;
	struct klp_func *lfuncs, *lfunc;
	struct klp_reloc *lrelocs, *lreloc;
	struct patch_object *object;
	struct patch_func *func;
	struct patch_reloc *reloc;
	int ret = 0, i, j;

	/* organize functions and relocs by object in scaffold */
	for (kfunc = __kpatch_funcs;
	     kfunc != __kpatch_funcs_end;
	     kfunc++) {
		ret = patch_add_func_to_object(kfunc);
		if (ret)
			goto out;
	}

	for (dynrela = __kpatch_dynrelas;
	     dynrela != __kpatch_dynrelas_end;
	     dynrela++) {
		ret = patch_add_reloc_to_object(dynrela);
		if (ret)
			goto out;
	}

	/* past this point, only possible return code is -ENOMEM */
	ret = -ENOMEM;

	/* allocate and fill livepatch structures */
	patch = kzalloc(sizeof(*patch), GFP_KERNEL);
	if (!patch)
		goto out;

	lobjects = kzalloc(sizeof(*lobjects) * (patch_objects_nr+1),
			   GFP_KERNEL);
	if (!lobjects)
		goto out;
	patch->mod = THIS_MODULE;
	patch->objs = lobjects;

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
			lfunc->old_addr = func->kfunc->old_addr;
			j++;
		}

		lrelocs = kzalloc(sizeof(struct klp_reloc) *
				  (object->relocs_nr+1), GFP_KERNEL);
		if (!lrelocs)
			goto out;
		lobject->relocs = lrelocs;
		j = 0;
		list_for_each_entry(reloc, &object->relocs, list) {
			lreloc = &lrelocs[j];
			lreloc->loc = reloc->kdynrela->dest;
			lreloc->val = reloc->kdynrela->src;
			lreloc->type = reloc->kdynrela->type;
			lreloc->name = reloc->kdynrela->name;
			lreloc->addend = reloc->kdynrela->addend;
			lreloc->external = reloc->kdynrela->external;
			j++;
		}

		i++;
	}

	/*
	 * Once the patch structure that the live patching API expects
	 * has been built, we can release the scaffold structure.
	 */
	patch_free_scaffold();

	ret = klp_register_patch(patch);
	if (ret) {
		patch_free_livepatch(patch);
		return ret;
	}

	ret = klp_enable_patch(patch);
	if (ret) {
		WARN_ON(klp_unregister_patch(patch));
		patch_free_livepatch(patch);
		return ret;
	}

	return 0;
out:
	patch_free_livepatch(patch);
	patch_free_scaffold();
	return ret;
}

static void __exit patch_exit(void)
{
	WARN_ON(klp_unregister_patch(patch));
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
