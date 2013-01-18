#include <linux/module.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <asm/stacktrace.h>
#include <asm/cacheflush.h>
#include "kpatch.h"

struct kpatch_func kpatch_funcs[KPATCH_MAX_FUNCS+1];

static int kpatch_num_registered;

/*
 * Deal with some of the peculiarities caused by the trampoline being called
 * from __ftrace_ops_list_func instead of directly from ftrace_regs_caller.
 */
void kpatch_ftrace_hacks(void)
{
#define TRACE_INTERNAL_BIT		(1<<11)
#define trace_recursion_clear(bit)	do { (current)->trace_recursion &= ~(bit); } while (0)
	trace_recursion_clear(TRACE_INTERNAL_BIT);
	preempt_enable_notrace();
}

static int kpatch_num_funcs(struct kpatch_func *f)
{
	int i;

	for (i = 0; f[i].old_func_name; i++)
		;

	return i;
}

struct ktrace_backtrace_args {
	struct kpatch_func *funcs;
	int ret;
};

void kpatch_backtrace_address_verify(void *data, unsigned long address,
				     int reliable)
{
	struct kpatch_func *f;
	struct ktrace_backtrace_args *args = data;

	if (args->ret)
		return;

	for (f = args->funcs; f->old_func_name; f++)
		if (address >= f->old_func_addr &&
		    address < f->old_func_addr_end)
			goto unsafe;

	return;

unsafe:
	printk("kpatch: activeness safety check failed for '%s()'\n",
	       f->old_func_name);
	args->ret = -EBUSY;
}

static int kpatch_backtrace_stack(void *data, char *name)
{
	return 0;
}

struct stacktrace_ops kpatch_backtrace_ops = {
	.address	= kpatch_backtrace_address_verify,
	.stack		= kpatch_backtrace_stack,
	.walk_stack 	= print_context_stack_bp,
};


/*
 * Verify activeness safety, i.e. that none of the to-be-patched functions are
 * on the stack of any task.
 *
 * This function is called from stop_machine() context.
 */
static int kpatch_verify_activeness_safety(struct kpatch_func *funcs)
{
	struct task_struct *g, *t;
	int ret = 0;

	struct ktrace_backtrace_args args = {
		.funcs = funcs,
		.ret = 0
	};

	/* Check the stacks of all tasks. */
	do_each_thread(g, t) {
		dump_trace(t, NULL, NULL, 0, &kpatch_backtrace_ops, &args);
		if (args.ret) {
			ret = args.ret;
			goto out;
		}
	} while_each_thread(g, t);

	/* TODO: for preemptible support we would need to ensure that functions
	 * on top of the stack are actually seen on the stack.
	 */
out:
	return ret;
}

/* Called from stop_machine */
static int kpatch_apply_patch(void *data)
{
	int ret, num_global_funcs, num_new_funcs;
	struct kpatch_func *funcs = data;

	ret = kpatch_verify_activeness_safety(funcs);
	if (ret)
		goto out;

	num_global_funcs = kpatch_num_funcs(kpatch_funcs);
	num_new_funcs = kpatch_num_funcs(funcs);

	if (num_global_funcs + num_new_funcs > KPATCH_MAX_FUNCS) {
		printk("kpatch: exceeded maximum # of patched functions (%d)\n",
		       KPATCH_MAX_FUNCS);
		ret = -E2BIG;
		goto out;
	}

	memcpy(&kpatch_funcs[num_global_funcs], funcs,
	       num_new_funcs * sizeof(struct kpatch_func));

	/* TODO: sync_core? */

out:
	return ret;
}


static struct ftrace_ops kpatch_ftrace_ops __read_mostly = {
	.func = kpatch_trampoline,
	.flags = FTRACE_OPS_FL_NORETURN | FTRACE_OPS_FL_SAVE_REGS,
};


int kpatch_register(struct module *mod, void *kpatch_relas,
		    void *kpatch_relas_end, void *kpatch_patches,
		    void *kpatch_patches_end)
{
	int ret = 0;
	int ret2;
	int num_relas;
	struct kpatch_rela *relas;
	int i;
	u64 val;
	void *loc;
	int size;
	int num_patches;
	struct kpatch_patch *patches;
	struct kpatch_func *funcs;

	num_relas = (kpatch_relas_end - kpatch_relas) / sizeof(*relas);
	relas = kpatch_relas;

	num_patches = (kpatch_patches_end - kpatch_patches) / sizeof(*patches);
	patches = kpatch_patches;

	/* FIXME consider change dest/src to loc/val */
	/* TODO: ensure dest value is all zeros before touching it, and that it's within the module bounds */
	for (i = 0; i < num_relas; i++) {
		switch (relas[i].type) {
			case R_X86_64_PC32:
				loc = (void *)relas[i].dest;
				val = (u32)(relas[i].src - relas[i].dest);
				size = 4;
				break;
			case R_X86_64_32S:
				loc = (void *)relas[i].dest;
				val = (s32)relas[i].src;
				size = 4;
				break;
			default:
				ret = -EINVAL;
				goto out;
		}
		//printk("%p <- %lx\n", loc, val);
		//printk("%lx\n", (unsigned long)__va(__pa((unsigned long)loc)));
		//loc = __va(__pa((unsigned long)loc));
		set_memory_rw((unsigned long)loc & PAGE_MASK, 1);
		ret = probe_kernel_write(loc, &val, size);
		set_memory_ro((unsigned long)loc & PAGE_MASK, 1);
		if (ret)
			goto out;
		/* TODO: sync_core? */
		/* TODO: understand identity mapping vs text mapping */
	}

	/* TODO: mutex here? */

	/* TODO verify num_patches is within acceptable bounds */


	funcs = kmalloc((num_patches + 1) * sizeof(*funcs), GFP_KERNEL); /*TODO: error handling, free, etc */
	for (i = 0; i < num_patches; i++) {
		funcs[i].old_func_addr = patches[i].orig;
		funcs[i].new_func_addr = patches[i].new;
		funcs[i].old_func_name = "FIXME";

		ret = ftrace_set_filter_ip(&kpatch_ftrace_ops, patches[i].orig,
					   0, 0);
		if (ret) {
			printk("kpatch: can't set ftrace filter at "
				"%lx '%s' (%d)\n",
				funcs[i].old_func_addr, funcs[i].old_func_name, ret);
			goto out;
		}
	}
	memset(&funcs[num_patches], 0, sizeof(*funcs));

#if 0
	/* Find the functions to be replaced. */
	for (f = funcs; f->old_func_name; f++) {
		/* TODO: verify it's a function and look for duplicate symbol names */
		/* TODO: use pre-generated func address? if using exact kernel
		 * is a requirement?*/
		f->old_func_addr = kallsyms_lookup_name(f->old_func_name);
		if (!f->old_func_addr) {
			printk("kpatch: can't find function '%s'\n",
			       f->old_func_name);
			ret = -ENXIO;
			goto out;
		}

		/* Do any needed incremental patching. */
		for (g = kpatch_funcs; g->old_func_name; g++)
			if (f->old_func_addr == g->old_func_addr) {
				f->old_func_addr = g->new_func_addr;
				ref_module(f->owner, g->owner);
			}


		if (!kallsyms_lookup_size_offset(f->old_func_addr, &size,
						 &offset)) {
			printk("kpatch: no size for function '%s'\n",
			       f->old_func_name);

			ret = -ENXIO;
			goto out;
		}
		/* TODO: check ret, size, offset */

		f->old_func_addr_end = f->old_func_addr + size;

		ret = ftrace_set_filter_ip(&kpatch_ftrace_ops, f->old_func_addr,
					   0, 0);
		if (ret) {
			printk("kpatch: can't set ftrace filter at "
				"%lx '%s' (%d)\n",
				f->old_func_addr, f->old_func_name, ret);
			goto out;
		}
	}

	/* TODO: global variable/array locking */
#endif

	/* Register the ftrace trampoline if it hasn't been done already. */
	if (!kpatch_num_registered++) {
		ret = register_ftrace_function(&kpatch_ftrace_ops);
		if (ret) {
			printk("kpatch: can't register ftrace function \n");
			goto out;
		}
	}

	/*
	 * Idle the CPUs, verify activeness safety, and atomically make the new
	 * functions visible to the trampoline.
	 */
	ret = stop_machine(kpatch_apply_patch, funcs, NULL);
	if (ret) {
		if (!--kpatch_num_registered) {
			ret2 = unregister_ftrace_function(&kpatch_ftrace_ops);
			if (ret2)
				printk("kpatch: unregister failed (%d)\n",
				       ret2);
		}

		goto out;
	}

out:
	return ret;
}
EXPORT_SYMBOL(kpatch_register);

#if 0
/* Called from stop_machine */
static int kpatch_remove_patch(void *data)
{
	int num_remove_funcs, i, ret = 0;
	struct kpatch_func *funcs = data;

	ret = kpatch_verify_activeness_safety(funcs);
	if (ret)
		goto out;

	for (i = 0; i < KPATCH_MAX_FUNCS; i++)
		if (kpatch_funcs[i].old_func_addr == funcs->old_func_addr)
			break;

	if (i == KPATCH_MAX_FUNCS) {
		ret = -EINVAL;
		goto out;
	}

	num_remove_funcs = kpatch_num_funcs(funcs);

	memset(&kpatch_funcs[i], 0,
	       num_remove_funcs * sizeof(struct kpatch_func));

	for ( ;kpatch_funcs[i + num_remove_funcs].old_func_name; i++)
		memcpy(&kpatch_funcs[i], &kpatch_funcs[i + num_remove_funcs],
		       sizeof(struct kpatch_func));

out:
	return ret;
}
#endif

int kpatch_unregister(struct module *mod)
{
	int ret = 0;
#if 0
	struct kpatch_func *f;

	ret = stop_machine(kpatch_remove_patch, funcs, NULL);
	if (ret)
		goto out;

	if (!--kpatch_num_registered) {
		ret = unregister_ftrace_function(&kpatch_ftrace_ops);
		if (ret) {
			printk("kpatch: can't unregister ftrace function\n");
			goto out;
		}
	}

	for (f = funcs; f->old_func_name; f++) {
		ret = ftrace_set_filter_ip(&kpatch_ftrace_ops, f->old_func_addr,
					   1, 0);
		if (ret) {
			printk("kpatch: can't remove ftrace filter at "
			       "%lx '%s' (%d)\n",
			       f->old_func_addr, f->old_func_name, ret);
			goto out;
		}
	}

out:
#endif
	return ret;
}
EXPORT_SYMBOL(kpatch_unregister);

MODULE_LICENSE("GPL");
