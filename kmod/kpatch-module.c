#include <linux/module.h>
#include "kpatch.h"

#include <linux/seq_file.h>
#include <linux/kernel_stat.h>

extern char __kpatch_relas, __kpatch_relas_end,
	    __kpatch_patches, __kpatch_patches_end;



static int __init patch_init(void)
{
	int ret;
	
	ret = kpatch_register(THIS_MODULE, &__kpatch_relas, &__kpatch_relas_end,
			      &__kpatch_patches, &__kpatch_patches_end);

	return ret;
}

static void __exit patch_exit(void)
{

	int ret;

	ret = kpatch_unregister(THIS_MODULE);
}

module_init(patch_init);
module_exit(patch_exit);
MODULE_LICENSE("GPL");
