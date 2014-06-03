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

static bool replace;
module_param(replace, bool, S_IRUGO);
MODULE_PARM_DESC(replace, "replace all previously loaded patch modules");

extern char __kpatch_patches, __kpatch_patches_end;
extern char __kpatch_dynrelas, __kpatch_dynrelas_end;

static struct kpatch_module kpmod;
static struct kobject *patch_kobj;
static struct kobject *functions_kobj;

struct kpatch_func_obj {
	struct kobject kobj;
	struct kpatch_patch *patch;
	char name[KSYM_NAME_LEN];
};

static struct kpatch_func_obj **funcs = NULL;

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

	return sprintf(buf, "0x%lx\n", func->patch->old_offset);
}

static ssize_t func_new_addr_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct kpatch_func_obj *func =
		container_of(kobj, struct kpatch_func_obj, kobj);

	return sprintf(buf, "0x%lx\n", func->patch->new_addr);
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

static int __init patch_init(void)
{
	int ret;
	int i = 0;
	struct kpatch_func_obj *func = NULL;

	kpmod.mod = THIS_MODULE;
	kpmod.patches = (struct kpatch_patch *)&__kpatch_patches;
	kpmod.patches_nr = (&__kpatch_patches_end - &__kpatch_patches) /
			  sizeof(*kpmod.patches);
	kpmod.dynrelas = (struct kpatch_dynrela *)&__kpatch_dynrelas;
	kpmod.dynrelas_nr = (&__kpatch_dynrelas_end - &__kpatch_dynrelas) /
			  sizeof(*kpmod.dynrelas);

	funcs = kzalloc(kpmod.patches_nr * sizeof(struct kpatch_func_obj*),
			GFP_KERNEL);
	if (!funcs) {
		ret = -ENOMEM;
		goto err_ret;
	}

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

	for (i = 0; i < kpmod.patches_nr; i++) {
		func = func_kobj_alloc();
		if (!func) {
			ret = -ENOMEM;
			goto err_sysfs2;
		}
		funcs[i] = func;

		sprint_symbol_no_offset(func->name, kpmod.patches[i].old_offset);

		ret = kobject_add(&func->kobj, functions_kobj,
				  "%s", func->name);
		if (ret)
			goto err_sysfs2;

		func->patch = &kpmod.patches[i];
	}

	ret = kpatch_register(&kpmod, replace);
	if (ret)
		goto err_sysfs2;

	return 0;

err_sysfs2:
	for (i = 0; i < kpmod.patches_nr; i++) {
		if (funcs[i] != NULL)
			kobject_put(&funcs[i]->kobj);
	}
	kobject_put(functions_kobj);
err_sysfs:
	sysfs_remove_file(patch_kobj, &patch_enabled_attr.attr);
err_put:
	kobject_put(patch_kobj);
err_free:
	kfree(funcs);
err_ret:
	return ret;
}

static void __exit patch_exit(void)
{
	int i;
	WARN_ON(kpmod.enabled);

	for (i = 0; i < kpmod.patches_nr; i++) {
		kobject_put(&funcs[i]->kobj);
	}
	kfree(funcs);
	kobject_put(functions_kobj);
	sysfs_remove_file(patch_kobj, &patch_enabled_attr.attr);
	kobject_put(patch_kobj);
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
