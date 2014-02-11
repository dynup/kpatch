#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/printk.h>
#include "../kpatch-kmod/kpatch.h"

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
