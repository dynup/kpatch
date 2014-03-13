/*
 * Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
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

/* Contains the code for the core kpatch module.  Each patch module registers
 * with this module to redirect old functions to new functions.
 *
 * Each patch module can contain one or more new functions.  This information
 * is contained in the .patches section of the patch module.  For each function
 * patched by the module we must:
 * - Call stop_machine
 * - Ensure that no execution thread is currently in the old function (or has
 *   it in the call stack)
 * - Add the new function address to the kpatch_funcs table
 *
 * After that, each call to the old function calls into kpatch_ftrace_handler()
 * which finds the new function in the kpatch_funcs table and updates the
 * return instruction pointer so that ftrace will return to the new function.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/ftrace.h>
#include <asm/stacktrace.h>
#include <asm/cacheflush.h>
#include "kpatch.h"

/* TODO: this array is horrible */
#define KPATCH_MAX_FUNCS	256
struct kpatch_func kpatch_funcs[KPATCH_MAX_FUNCS+1];

static int kpatch_num_registered;

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

#define TRACE_INTERNAL_BIT		(1<<11)
#define trace_recursion_clear(bit)	do { (current)->trace_recursion &= ~(bit); } while (0)
void kpatch_ftrace_handler(unsigned long ip, unsigned long parent_ip,
		           struct ftrace_ops *op, struct pt_regs *regs)
{
	int i;
	struct kpatch_func *func = NULL;

	/*
	 * FIXME: HACKS
	 *
	 * Deal with some of the peculiarities caused by the handler being
	 * called from __ftrace_ops_list_func instead of directly from
	 * ftrace_regs_caller.
	 */
	trace_recursion_clear(TRACE_INTERNAL_BIT);
	preempt_enable_notrace();

	/*
	 * TODO: if preemption is possible then we'll need to think about how
	 * to ensure atomic access to the array and how to ensure activeness
	 * safety here.  if preemption is enabled then we need to make sure the
	 * IP isn't inside kpatch_trampoline for any task.
	 */

	for (i = 0; i < KPATCH_MAX_FUNCS &&
		    kpatch_funcs[i].old_func_addr; i++) {
		if (kpatch_funcs[i].old_func_addr == ip) {
			func = &kpatch_funcs[i];
			break;
		}
	}

	/*
	 * Check for the rare case where we don't have a new function to call.
	 * This can happen in the small window of time during patch module
	 * insmod after it has called register_ftrace_function() but before it
	 * has called stop_machine() to do the activeness safety check and the
	 * array update.  In this case we just return and let the old function
	 * run.
	 */
	if (!func)
		return;

	regs->ip = func->new_func_addr;
	return;
}


static struct ftrace_ops kpatch_ftrace_ops __read_mostly = {
	.func = kpatch_ftrace_handler,
	.flags = FTRACE_OPS_FL_SAVE_REGS,
};


int kpatch_register(struct module *mod, void *kpatch_patches,
		    void *kpatch_patches_end)
{
	int ret = 0;
	int ret2;
	int i;
	int num_patches;
	struct kpatch_patch *patches;
	struct kpatch_func *funcs, *f;

	pr_err("loading patch module \"%s\"", mod->name);

	num_patches = (kpatch_patches_end - kpatch_patches) / sizeof(*patches);
	patches = kpatch_patches;

	funcs = kmalloc((num_patches + 1) * sizeof(*funcs), GFP_KERNEL); /*TODO: error handling, free, etc */
	for (i = 0; i < num_patches; i++) {

		funcs[i].old_func_addr = patches[i].orig;
		funcs[i].old_func_addr_end = patches[i].orig_end;
		funcs[i].new_func_addr = patches[i].new;
		funcs[i].mod = mod;
		funcs[i].old_func_name = "TODO";

		/* Do any needed incremental patching. */
		for (f = kpatch_funcs; f->old_func_name; f++) {
			if (funcs[i].old_func_addr == f->old_func_addr) {
				funcs[i].old_func_addr = f->new_func_addr;
				ref_module(funcs[i].mod, f->mod);
			}
		}

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

/* Called from stop_machine */
static int kpatch_remove_patch(void *data)
{
	int num_remove_funcs, i, ret = 0;
	struct kpatch_func *funcs = data;

	ret = kpatch_verify_activeness_safety(funcs);
	if (ret)
		goto out;

	for (i = 0; i < KPATCH_MAX_FUNCS && kpatch_funcs[i].old_func_addr; i++)
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

int kpatch_unregister(struct module *mod)
{
	int ret = 0;
	struct kpatch_func *funcs, *f;
	int num_funcs, i;

	num_funcs = kpatch_num_funcs(kpatch_funcs);

	funcs = kmalloc((num_funcs + 1) * sizeof(*funcs), GFP_KERNEL);

	for (f = kpatch_funcs, i = 0; f->old_func_name; f++)
		if (f->mod == mod)
			memcpy(&funcs[i++], f, sizeof(*funcs));
	memset(&funcs[i], 0, sizeof(*funcs));

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
	kfree(funcs);
	return ret;
}
EXPORT_SYMBOL(kpatch_unregister);

MODULE_LICENSE("GPL");
