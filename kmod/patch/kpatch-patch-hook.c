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
#include "kpatch.h"

extern char __kpatch_patches, __kpatch_patches_end;

static int __init patch_init(void)
{
	printk("patch loading\n");
	return kpatch_register(THIS_MODULE, &__kpatch_patches,
	                      &__kpatch_patches_end);
}

static void __exit patch_exit(void)
{
	printk("patch unloading\n");
	kpatch_unregister(THIS_MODULE);
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
