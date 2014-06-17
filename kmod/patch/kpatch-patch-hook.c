/*
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA,
 * 02110-1301, USA.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include "kpatch.h"
#include "kpatch-patch.h"

static bool replace;
module_param(replace, bool, S_IRUGO);
MODULE_PARM_DESC(replace, "replace all previously loaded patch modules");

extern struct kpatch_patch_func __kpatch_funcs[], __kpatch_funcs_end[];
extern struct kpatch_patch_dynrela __kpatch_dynrelas[], __kpatch_dynrelas_end[];

static struct kpatch_module kpmod;
static struct kobject *patch_kobj;
static struct kobject *functions_kobj;

struct kpatch_func_obj {
	struct kobject kobj;
	struct kpatch_patch_func *func;
	char name[KSYM_NAME_LEN];
};

static struct kpatch_func_obj **func_objs = NULL;

static ssize_t patch_enabled_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", kpmod.enabled);
}

static ssize_t patch_enabled_store(struct kobject *kobj,
				   struct kobj_attribute *attr, const char *buf,
				   size_t count)
{
	int ret;
	unsigned long val;

	/* only disabling is supported */
	if (!kpmod.enabled)
		return -EINVAL;

	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;

	val = !!val;

	/* only disabling is supported */
	if (val)
		return -EINVAL;

	ret = kpatch_unregister(&kpmod);
	if (ret)
		return ret;

	return count;
}

static struct kobj_attribute patch_enabled_attr =
	__ATTR(enabled, 0644, patch_enabled_show, patch_enabled_store);

static ssize_t func_old_addr_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct kpatch_func_obj *func =
		container_of(kobj, struct kpatch_func_obj, kobj);

	return sprintf(buf, "0x%lx\n", func->func->old_offset);
}

static ssize_t func_new_addr_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct kpatch_func_obj *func =
		container_of(kobj, struct kpatch_func_obj, kobj);

	return sprintf(buf, "0x%lx\n", func->func->new_addr);
}

static struct kobj_attribute old_addr_attr =
	__ATTR(old_addr, S_IRUGO, func_old_addr_show, NULL);

static struct kobj_attribute new_addr_attr =
	__ATTR(new_addr, S_IRUGO, func_new_addr_show, NULL);

static void func_kobj_free(struct kobject *kobj)
{
	struct kpatch_func_obj *func =
		container_of(kobj, struct kpatch_func_obj, kobj);
	kfree(func);
}

static struct attribute *func_kobj_attrs[] = {
	&old_addr_attr.attr,
	&new_addr_attr.attr,
	NULL,
};

static ssize_t func_kobj_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct kobj_attribute *func_attr =
		container_of(attr, struct kobj_attribute, attr);

	return func_attr->show(kobj, func_attr, buf);
}

static const struct sysfs_ops func_sysfs_ops = {
	.show	= func_kobj_show,
};

static struct kobj_type func_ktype = {
	.release	= func_kobj_free,
	.sysfs_ops	= &func_sysfs_ops,
	.default_attrs	= func_kobj_attrs,
};

static struct kpatch_func_obj *func_kobj_alloc(void)
{
	struct kpatch_func_obj *func;
	func = kzalloc(sizeof(*func), GFP_KERNEL);
	if (!func)
		return NULL;

	kobject_init(&func->kobj, &func_ktype);

	return func;
}

static struct kpatch_object *patch_find_or_add_object(struct list_head *head,
						      const char *name)
{
	struct kpatch_object *object;

	list_for_each_entry(object, head, list) {
		if (!strcmp(object->name, name))
			return object;
	}

	object = kzalloc(sizeof(*object), GFP_KERNEL);
	if (!object)
		return NULL;

	object->name = name;
	INIT_LIST_HEAD(&object->funcs);
	INIT_LIST_HEAD(&object->dynrelas);

	list_add_tail(&object->list, head);

	return object;
}

static void patch_free_objects(void)
{
	struct kpatch_object *object, *object_safe;
	struct kpatch_func *func, *func_safe;
	struct kpatch_dynrela *dynrela, *dynrela_safe;

	list_for_each_entry_safe(object, object_safe, &kpmod.objects, list) {
		list_for_each_entry_safe(func, func_safe, &object->funcs,
					 list) {
			list_del(&func->list);
			kfree(func);
		}
		list_for_each_entry_safe(dynrela, dynrela_safe,
					 &object->dynrelas, list) {
			list_del(&dynrela->list);
			kfree(dynrela);
		}
		list_del(&object->list);
		kfree(object);
	}
}

static int __init patch_init(void)
{
	int ret, funcs_nr, i;
	struct kpatch_func_obj *func_obj = NULL;
	struct kpatch_object *object;
	struct kpatch_patch_func *p_func;
	struct kpatch_func *func;
	struct kpatch_patch_dynrela *p_dynrela;
	struct kpatch_dynrela *dynrela;

	funcs_nr = __kpatch_funcs_end - __kpatch_funcs;
	func_objs = kzalloc(funcs_nr * sizeof(struct kpatch_func_obj*),
			    GFP_KERNEL);
	if (!func_objs)
		return -ENOMEM;

	patch_kobj = kobject_create_and_add(THIS_MODULE->name,
					    kpatch_patches_kobj);
	if (!patch_kobj) {
		ret = -ENOMEM;
		goto err_free;
	}

	ret = sysfs_create_file(patch_kobj, &patch_enabled_attr.attr);
	if (ret)
		goto err_put;

	functions_kobj = kobject_create_and_add("functions", patch_kobj);
	if (!functions_kobj) {
		ret = -ENOMEM;
		goto err_sysfs;
	}

	kpmod.mod = THIS_MODULE;
	INIT_LIST_HEAD(&kpmod.objects);

	i = 0;
	for (p_func = __kpatch_funcs; p_func < __kpatch_funcs_end; p_func++) {
		object = patch_find_or_add_object(&kpmod.objects,
						  p_func->objname);
		if (!object) {
			ret = -ENOMEM;
			goto err_objects;
		}

		func = kzalloc(sizeof(*func), GFP_KERNEL);
		if (!func) {
			ret = -ENOMEM;
			goto err_objects;
		}

		func->new_addr = p_func->new_addr;
		func->new_size = p_func->new_size;
		func->old_offset = p_func->old_offset;
		func->old_size = p_func->old_size;
		func->name = p_func->name;
		list_add_tail(&func->list, &object->funcs);

		func_obj = func_kobj_alloc();
		if (!func_obj) {
			ret = -ENOMEM;
			goto err_objects;
		}

		func_obj->func = p_func;
		func_objs[i++] = func_obj;
		sprint_symbol_no_offset(func_obj->name,
					p_func->old_offset);

		ret = kobject_add(&func_obj->kobj, functions_kobj,
				  "%s", func_obj->name);
		if (ret)
			goto err_objects;
	}

	for (p_dynrela = __kpatch_dynrelas; p_dynrela < __kpatch_dynrelas_end;
	     p_dynrela++) {
		object = patch_find_or_add_object(&kpmod.objects,
						  p_dynrela->objname);
		if (!object) {
			ret = -ENOMEM;
			goto err_objects;
		}

		dynrela = kzalloc(sizeof(*dynrela), GFP_KERNEL);
		if (!dynrela) {
			ret = -ENOMEM;
			goto err_objects;
		}

		dynrela->dest = p_dynrela->dest;
		dynrela->src = p_dynrela->src;
		dynrela->type = p_dynrela->type;
		dynrela->name = p_dynrela->name;
		dynrela->objname = p_dynrela->objname;
		dynrela->addend = p_dynrela->addend;
		list_add_tail(&dynrela->list, &object->dynrelas);
	}

	ret = kpatch_register(&kpmod, replace);
	if (ret)
		goto err_objects;

	return 0;

err_objects:
	for (i = 0; i < funcs_nr; i++)
		if (func_objs[i] != NULL)
			kobject_put(&func_objs[i]->kobj);
	patch_free_objects();
	kobject_put(functions_kobj);
err_sysfs:
	sysfs_remove_file(patch_kobj, &patch_enabled_attr.attr);
err_put:
	kobject_put(patch_kobj);
err_free:
	kfree(func_objs);
	return ret;
}

static void __exit patch_exit(void)
{
	int i;

	WARN_ON(kpmod.enabled);

	for (i = 0; i < __kpatch_funcs_end - __kpatch_funcs; i++)
		kobject_put(&func_objs[i]->kobj);
	patch_free_objects();
	kobject_put(functions_kobj);
	sysfs_remove_file(patch_kobj, &patch_enabled_attr.attr);
	kobject_put(patch_kobj);
	kfree(func_objs);
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
