/*
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
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include "kpatch.h"
#include "kpatch-patch.h"

extern char __kpatch_patches, __kpatch_patches_end;

static struct kpatch_func *funcs;
static int num_funcs;

static int __init patch_init(void)
{
	struct kpatch_patch *patches;
	int i, ret;

	patches = (struct kpatch_patch *)&__kpatch_patches;
	num_funcs = (&__kpatch_patches_end - &__kpatch_patches) /
		    sizeof(*patches);
	funcs = kmalloc(num_funcs * sizeof(*funcs), GFP_KERNEL);
	if (!funcs)
		return -ENOMEM;

	for (i = 0; i < num_funcs; i++) {
		funcs[i].old_addr = patches[i].old_addr;
		funcs[i].old_size = patches[i].old_size;
		funcs[i].new_addr = patches[i].new_addr;
	}

	ret = kpatch_register(THIS_MODULE, funcs, num_funcs);
	if (ret)
		goto err_free;

	return 0;

err_free:
	kfree(funcs);
	return ret;
}

static void __exit patch_exit(void)
{
	int ret;

	ret = kpatch_unregister(THIS_MODULE, funcs, num_funcs);
	if (ret) {
		/*
		 * TODO: If this happens, we're screwed.  We need a way to
		 * prevent the module from unloading if the activeness safety
		 * check fails.
		 *
		 * Or alternatively we could keep trying the activeness safety
		 * check in a loop, until it works or we timeout.  Then we
		 * could panic.
		 */
		panic("kpatch_unregister failed: %d", ret);
	}

	kfree(funcs);
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
