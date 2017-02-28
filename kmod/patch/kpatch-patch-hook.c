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
extern struct kpatch_patch_hook __kpatch_hooks_load[], __kpatch_hooks_load_end[];
extern struct kpatch_patch_hook __kpatch_hooks_unload[], __kpatch_hooks_unload_end[];
extern unsigned long __kpatch_force_funcs[], __kpatch_force_funcs_end[];
extern char __kpatch_checksum[];

static struct kpatch_module kpmod;

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

	ret = kstrtoul(buf, 10, &val);
	if (ret)
		return ret;

	val = !!val;

	if (val)
		ret = kpatch_register(&kpmod, replace);
	else
		ret = kpatch_unregister(&kpmod);

	if (ret)
		return ret;

	return count;
}

static ssize_t patch_checksum_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", __kpatch_checksum);
}

static struct kobj_attribute patch_enabled_attr =
	__ATTR(enabled, 0644, patch_enabled_show, patch_enabled_store);
static struct kobj_attribute patch_checksum_attr =
	__ATTR(checksum, 0444, patch_checksum_show, NULL);

static struct attribute *patch_attrs[] = {
	&patch_enabled_attr.attr,
	&patch_checksum_attr.attr,
	NULL,
};

static void patch_kobj_free(struct kobject *kobj)
{
}

static struct kobj_type patch_ktype = {
        .release = patch_kobj_free,
        .sysfs_ops = &kobj_sysfs_ops,
        .default_attrs = patch_attrs,
};

static ssize_t patch_func_old_addr_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	struct kpatch_func *func =
		container_of(kobj, struct kpatch_func, kobj);

	return sprintf(buf, "0x%lx\n", func->old_addr);
}

static ssize_t patch_func_new_addr_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	struct kpatch_func *func =
		container_of(kobj, struct kpatch_func, kobj);

	return sprintf(buf, "0x%lx\n", func->new_addr);
}

static struct kobj_attribute patch_old_addr_attr =
	__ATTR(old_addr, S_IRUSR, patch_func_old_addr_show, NULL);

static struct kobj_attribute patch_new_addr_attr =
	__ATTR(new_addr, S_IRUSR, patch_func_new_addr_show, NULL);

static struct attribute *patch_func_kobj_attrs[] = {
	&patch_old_addr_attr.attr,
	&patch_new_addr_attr.attr,
	NULL,
};

static ssize_t patch_func_kobj_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct kobj_attribute *func_attr =
		container_of(attr, struct kobj_attribute, attr);

	return func_attr->show(kobj, func_attr, buf);
}

static const struct sysfs_ops patch_func_sysfs_ops = {
	.show	= patch_func_kobj_show,
};

static void patch_func_kobj_free(struct kobject *kobj)
{
	struct kpatch_func *func =
		container_of(kobj, struct kpatch_func, kobj);
	kfree(func);
}

static struct kobj_type patch_func_ktype = {
	.release	= patch_func_kobj_free,
	.sysfs_ops	= &patch_func_sysfs_ops,
	.default_attrs	= patch_func_kobj_attrs,
};

static void patch_object_kobj_free(struct kobject *kobj)
{
	struct kpatch_object *obj =
		container_of(kobj, struct kpatch_object, kobj);
	kfree(obj);
}

static struct kobj_type patch_object_ktype = {
	.release = patch_object_kobj_free,
	.sysfs_ops = &kobj_sysfs_ops,
};

static struct kpatch_object *patch_find_or_add_object(struct list_head *head,
						      const char *name)
{
	struct kpatch_object *object;
	int ret;

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
	INIT_LIST_HEAD(&object->hooks_load);
	INIT_LIST_HEAD(&object->hooks_unload);

	list_add_tail(&object->list, head);

	ret = kobject_init_and_add(&object->kobj, &patch_object_ktype,
				   &kpmod.kobj, "%s", object->name);
	if (ret) {
		list_del(&object->list);
		kfree(object);
		return NULL;
	}

	return object;
}

static void patch_free_objects(void)
{
	struct kpatch_object *object, *object_safe;
	struct kpatch_func *func, *func_safe;
	struct kpatch_dynrela *dynrela, *dynrela_safe;
	struct kpatch_hook *hook, *hook_safe;

	list_for_each_entry_safe(object, object_safe, &kpmod.objects, list) {
		list_for_each_entry_safe(func, func_safe, &object->funcs,
					 list) {
			list_del(&func->list);
			kobject_put(&func->kobj);
		}
		list_for_each_entry_safe(dynrela, dynrela_safe,
					 &object->dynrelas, list) {
			list_del(&dynrela->list);
			kfree(dynrela);
		}
		list_for_each_entry_safe(hook, hook_safe,
					 &object->hooks_load, list) {
			list_del(&hook->list);
			kfree(hook);
		}
		list_for_each_entry_safe(hook, hook_safe,
					 &object->hooks_unload, list) {
			list_del(&hook->list);
			kfree(hook);
		}
		list_del(&object->list);
		kobject_put(&object->kobj);
	}
}

static int patch_is_func_forced(unsigned long addr)
{
	unsigned long *a;
	for (a = __kpatch_force_funcs; a < __kpatch_force_funcs_end; a++)
		if (*a == addr)
			return 1;
	return 0;
}

static int patch_make_funcs_list(struct list_head *objects)
{
	struct kpatch_object *object;
	struct kpatch_patch_func *p_func;
	struct kpatch_func *func;
	int ret;

	for (p_func = __kpatch_funcs; p_func < __kpatch_funcs_end; p_func++) {
		object = patch_find_or_add_object(&kpmod.objects,
						  p_func->objname);
		if (!object)
			return -ENOMEM;

		func = kzalloc(sizeof(*func), GFP_KERNEL);
		if (!func)
			return -ENOMEM;

		func->new_addr = p_func->new_addr;
		func->new_size = p_func->new_size;
		func->old_size = p_func->old_size;
		func->sympos = p_func->sympos;
		func->name = p_func->name;
		func->force = patch_is_func_forced(func->new_addr);
		list_add_tail(&func->list, &object->funcs);

		ret = kobject_init_and_add(&func->kobj, &patch_func_ktype,
					   &object->kobj, "%s,%lu",
					   func->name, func->sympos ? func->sympos : 1);
		if (ret)
			return ret;
	}

	return 0;
}

static int patch_make_dynrelas_list(struct list_head *objects)
{
	struct kpatch_object *object;
	struct kpatch_patch_dynrela *p_dynrela;
	struct kpatch_dynrela *dynrela;

	for (p_dynrela = __kpatch_dynrelas; p_dynrela < __kpatch_dynrelas_end;
	     p_dynrela++) {
		object = patch_find_or_add_object(objects, p_dynrela->objname);
		if (!object)
			return -ENOMEM;

		dynrela = kzalloc(sizeof(*dynrela), GFP_KERNEL);
		if (!dynrela)
			return -ENOMEM;

		dynrela->dest = p_dynrela->dest;
		dynrela->type = p_dynrela->type;
		dynrela->sympos = p_dynrela->sympos;
		dynrela->name = p_dynrela->name;
		dynrela->external = p_dynrela->external;
		dynrela->addend = p_dynrela->addend;
		list_add_tail(&dynrela->list, &object->dynrelas);
	}

	return 0;
}

static int patch_make_hook_lists(struct list_head *objects)
{
	struct kpatch_object *object;
	struct kpatch_patch_hook *p_hook;
	struct kpatch_hook *hook;

	for (p_hook = __kpatch_hooks_load; p_hook < __kpatch_hooks_load_end;
	     p_hook++) {
		object = patch_find_or_add_object(objects, p_hook->objname);
		if (!object)
			return -ENOMEM;

		hook = kzalloc(sizeof(*hook), GFP_KERNEL);
		if (!hook)
			return -ENOMEM;

		hook->hook = p_hook->hook;
		list_add_tail(&hook->list, &object->hooks_load);
	}

	for (p_hook = __kpatch_hooks_unload; p_hook < __kpatch_hooks_unload_end;
	     p_hook++) {
		object = patch_find_or_add_object(objects, p_hook->objname);
		if (!object)
			return -ENOMEM;

		hook = kzalloc(sizeof(*hook), GFP_KERNEL);
		if (!hook)
			return -ENOMEM;

		hook->hook = p_hook->hook;
		list_add_tail(&hook->list, &object->hooks_unload);
	}
	return 0;
}

static int __init patch_init(void)
{
	int ret;

	ret = kobject_init_and_add(&kpmod.kobj, &patch_ktype,
				   kpatch_root_kobj, "%s",
				   THIS_MODULE->name);
	if (ret)
		return -ENOMEM;

	kpmod.mod = THIS_MODULE;
	INIT_LIST_HEAD(&kpmod.objects);

	ret = patch_make_funcs_list(&kpmod.objects);
	if (ret)
		goto err_objects;

	ret = patch_make_dynrelas_list(&kpmod.objects);
	if (ret)
		goto err_objects;

	ret = patch_make_hook_lists(&kpmod.objects);
	if (ret)
		goto err_objects;

	ret = kpatch_register(&kpmod, replace);
	if (ret)
		goto err_objects;

	return 0;

err_objects:
	patch_free_objects();
	kobject_put(&kpmod.kobj);
	return ret;
}

static void __exit patch_exit(void)
{
	WARN_ON(kpmod.enabled);

	patch_free_objects();
	kobject_put(&kpmod.kobj);
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
