#define pr_fmt(fmt) "testmod: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>

static struct kobject *testmod_kobj;
int value = 2;

static ssize_t value_show(struct kobject *kobj,
                          struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", value);
}

static struct kobj_attribute testmod_value_attr = __ATTR_RO(value);

static int testmod_init(void)
{
	int ret;

	testmod_kobj = kobject_create_and_add("testmod", kernel_kobj);
	if (!testmod_kobj)
		return -ENOMEM;

	ret = sysfs_create_file(testmod_kobj, &testmod_value_attr.attr);
	if (ret) {
		kobject_put(testmod_kobj);
		return ret;
	}

	return 0;
}

static void testmod_exit(void)
{
	sysfs_remove_file(testmod_kobj, &testmod_value_attr.attr);
	kobject_put(testmod_kobj);
}

module_init(testmod_init);
module_exit(testmod_exit);
MODULE_LICENSE("GPL");
