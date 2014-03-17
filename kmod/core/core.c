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
#include <linux/hashtable.h>
#include <asm/stacktrace.h>
#include <asm/cacheflush.h>
#include "kpatch.h"

#define KPATCH_HASH_BITS 8
DEFINE_HASHTABLE(kpatch_func_hash, KPATCH_HASH_BITS);

DEFINE_SEMAPHORE(kpatch_mutex);

static int kpatch_num_registered;

struct kpatch_backtrace_args {
	struct kpatch_func *funcs;
	int num_funcs, ret;
};

void kpatch_backtrace_address_verify(void *data, unsigned long address,
				     int reliable)
{
	struct kpatch_backtrace_args *args = data;
	struct kpatch_func *funcs = args->funcs;
	int i, num_funcs = args->num_funcs;

	if (args->ret)
		return;

	for (i = 0; i < num_funcs; i++) {
		struct kpatch_func *func = &funcs[i];

		if (address >= func->old_addr &&
		    address < func->old_addr + func->old_size) {
			printk("kpatch: activeness safety check failed for "
			       "function at address " "'%lx()'\n",
			       func->old_addr);
			args->ret = -EBUSY;
			return;
		}
	}
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
static int kpatch_verify_activeness_safety(struct kpatch_func *funcs,
					   int num_funcs)
{
	struct task_struct *g, *t;
	int ret = 0;

	struct kpatch_backtrace_args args = {
		.funcs = funcs,
		.num_funcs = num_funcs,
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

out:
	return ret;
}

struct kpatch_stop_machine_args {
	struct kpatch_func *funcs;
	int num_funcs;
};

/* Called from stop_machine */
static int kpatch_apply_patch(void *data)
{
	struct kpatch_stop_machine_args *args = data;
	struct kpatch_func *funcs = args->funcs;
	int num_funcs = args->num_funcs;
	int i, ret;

	ret = kpatch_verify_activeness_safety(funcs, num_funcs);
	if (ret)
		goto out;

	for (i = 0; i < num_funcs; i++) {
		struct kpatch_func *func = &funcs[i];

		/* update the global list and go live */
		hash_add(kpatch_func_hash, &func->node, func->old_addr);
	}

out:
	return ret;
}

/* Called from stop_machine */
static int kpatch_remove_patch(void *data)
{
	struct kpatch_stop_machine_args *args = data;
	struct kpatch_func *funcs = args->funcs;
	int num_funcs = args->num_funcs;
	int ret, i;

	ret = kpatch_verify_activeness_safety(funcs, num_funcs);
	if (ret)
		goto out;

	for (i = 0; i < num_funcs; i++)
		hlist_del(&funcs[i].node);

out:
	return ret;
}


void kpatch_ftrace_handler(unsigned long ip, unsigned long parent_ip,
		           struct ftrace_ops *op, struct pt_regs *regs)
{
	struct kpatch_func *f;

	/*
	 * This is where the magic happens.  Update regs->ip to tell ftrace to
	 * return to the new function.
	 *
	 * If there are multiple patch modules that have registered to patch
	 * the same function, the last one to register wins, as it'll be first
	 * in the hash bucket.
	 */
	preempt_disable_notrace();
	hash_for_each_possible(kpatch_func_hash, f, node, ip) {
		if (f->old_addr == ip) {
			regs->ip = f->new_addr;
			break;
		}
	}
	preempt_enable_notrace();
}

static struct ftrace_ops kpatch_ftrace_ops __read_mostly = {
	.func = kpatch_ftrace_handler,
	.flags = FTRACE_OPS_FL_SAVE_REGS,
};

int kpatch_register(struct module *mod, struct kpatch_func *funcs,
		    int num_funcs)
{
	int ret, ret2, i;
	struct kpatch_stop_machine_args args = {
		.funcs = funcs,
		.num_funcs = num_funcs,
	};

	down(&kpatch_mutex);

	for (i = 0; i < num_funcs; i++) {
		struct kpatch_func *f, *func = &funcs[i];
		bool found = false;

		func->mod = mod;

		/*
		 * If any other modules have also patched this function, it
		 * already has an ftrace handler.
		 */
		hash_for_each_possible(kpatch_func_hash, f, node,
				       func->old_addr) {
			if (f->old_addr == func->old_addr) {
				found = true;
				break;
			}
		}
		if (found)
			continue;

		/* Add an ftrace handler for this function. */
		ret = ftrace_set_filter_ip(&kpatch_ftrace_ops, func->old_addr,
					   0, 0);
		if (ret) {
			printk("kpatch: can't set ftrace filter at address "
				"0x%lx (%d)\n",
				func->old_addr, ret);
			goto out;
		}
	}

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
	ret = stop_machine(kpatch_apply_patch, &args, NULL);
	if (ret) {
		if (!--kpatch_num_registered) {
			ret2 = unregister_ftrace_function(&kpatch_ftrace_ops);
			if (ret2)
				printk("kpatch: unregister failed (%d)\n",
				       ret2);
		}

		goto out;
	}

	pr_notice("loaded patch module \"%s\"\n", mod->name);

out:
	up(&kpatch_mutex);
	return ret;
}
EXPORT_SYMBOL(kpatch_register);

int kpatch_unregister(struct module *mod, struct kpatch_func *funcs,
		      int num_funcs)
{
	int i, ret;
	struct kpatch_stop_machine_args args = {
		.funcs = funcs,
		.num_funcs = num_funcs,
	};

	down(&kpatch_mutex);

	ret = stop_machine(kpatch_remove_patch, &args, NULL);
	if (ret)
		goto out;

	if (!--kpatch_num_registered) {
		ret = unregister_ftrace_function(&kpatch_ftrace_ops);
		if (ret) {
			printk("kpatch: can't unregister ftrace function\n");
			goto out;
		}
	}

	for (i = 0; i < num_funcs; i++) {
		struct kpatch_func *f, *func = &funcs[i];
		bool found = false;

		/*
		 * If any other modules have also patched this function, don't
		 * remove its ftrace handler.
		 */
		hash_for_each_possible(kpatch_func_hash, f, node,
				       func->old_addr) {
			if (f->old_addr == func->old_addr) {
				found = true;
				break;
			}
		}
		if (found)
			continue;

		/* Remove the ftrace handler for this function. */
		ret = ftrace_set_filter_ip(&kpatch_ftrace_ops, func->old_addr,
					   1, 0);
		if (ret) {
			printk("kpatch: can't remove ftrace filter at address "
			       "0x%lx (%d)\n",
			       func->old_addr, ret);
			goto out;
		}
	}

	pr_notice("unloaded patch module \"%s\"\n", mod->name);

out:
	up(&kpatch_mutex);
	return ret;
}
EXPORT_SYMBOL(kpatch_unregister);

MODULE_LICENSE("GPL");
