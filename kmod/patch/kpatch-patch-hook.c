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
#include "kpatch.h"
#include "kpatch-patch.h"

extern char __kpatch_patches, __kpatch_patches_end;

static struct kpatch_module kpmod;
static struct kobject *patch_kobj;

static ssize_t patch_enabled_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", kpmod.enabled);
}

static ssize_t patch_enabled_store(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf,
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

static int __init patch_init(void)
{
	struct kpatch_patch *patches;
	int i, ret;

	patches = (struct kpatch_patch *)&__kpatch_patches;

	kpmod.mod = THIS_MODULE;
	kpmod.num_funcs = (&__kpatch_patches_end - &__kpatch_patches) /
			  sizeof(*patches);
	kpmod.funcs = kmalloc(kpmod.num_funcs * sizeof(struct kpatch_func),
			      GFP_KERNEL);
	if (!kpmod.funcs)
		return -ENOMEM;

	for (i = 0; i < kpmod.num_funcs; i++) {
		kpmod.funcs[i].old_addr = patches[i].old_addr;
		kpmod.funcs[i].old_size = patches[i].old_size;
		kpmod.funcs[i].new_addr = patches[i].new_addr;
		kpmod.funcs[i].new_size = patches[i].new_size;
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

	ret = kpatch_register(&kpmod);
	if (ret)
		goto err_sysfs;

	return 0;

err_sysfs:
	sysfs_remove_file(patch_kobj, &patch_enabled_attr.attr);
err_put:
	kobject_put(patch_kobj);
err_free:
	kfree(kpmod.funcs);
	return ret;
}

static void __exit patch_exit(void)
{
	WARN_ON(kpmod.enabled);
	sysfs_remove_file(patch_kobj, &patch_enabled_attr.attr);
	kobject_put(patch_kobj);
	kfree(kpmod.funcs);
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
