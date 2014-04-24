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
	struct kpatch_module *kpmod;
	int ret;
};

enum {
	KPATCH_STATUS_START,
	KPATCH_STATUS_SUCCESS,
	KPATCH_STATUS_FAILURE,
};
static atomic_t kpatch_status;

static inline void kpatch_start_status(void)
{
	atomic_set(&kpatch_status, KPATCH_STATUS_START);
}

/* Try to set a finish status, and return the result status */
static inline int kpatch_finish_status(int status)
{
	int result;
	result = atomic_cmpxchg(&kpatch_status, KPATCH_STATUS_START, status);
	return result == KPATCH_STATUS_START ? status : result;
}

enum {
	KPATCH_OP_NONE,
	KPATCH_OP_PATCH,
	KPATCH_OP_UNPATCH,
};
static atomic_t kpatch_operation;

static struct kpatch_func *kpatch_get_func(unsigned long ip)
{
	struct kpatch_func *f;

	/* Here, we have to use rcu safe hlist because of NMI concurrency */
	hash_for_each_possible_rcu(kpatch_func_hash, f, node, ip)
		if (f->old_addr == ip)
			return f;
	return NULL;
}

static struct kpatch_func *kpatch_get_committed_func(struct kpatch_func *f,
						     unsigned long ip)
{
	/* Continuing on the same hlist to find commited (!updating) func */
	if (f) {
		hlist_for_each_entry_continue_rcu(f, node)
			if (f->old_addr == ip && !f->updating)
				return f;
	}
	return NULL;
}

void kpatch_backtrace_address_verify(void *data, unsigned long address,
				     int reliable)
{
	struct kpatch_backtrace_args *args = data;
	struct kpatch_module *kpmod = args->kpmod;
	int i;

	if (args->ret)
		return;

	for (i = 0; i < kpmod->num_funcs; i++) {
		unsigned long func_addr, func_size;
		struct kpatch_func *func, *active_func;

		func = &kpmod->funcs[i];
		active_func = kpatch_get_func(func->old_addr);
		if (!active_func) {
			/* patching an unpatched func */
			func_addr = func->old_addr;
			func_size = func->old_size;
		} else {
			/* repatching or unpatching */
			func_addr = active_func->new_addr;
			func_size = active_func->new_size;
		}

		if (address >= func_addr && address < func_addr + func_size) {
			pr_err("activeness safety check failed for function "
			       "at address 0x%lx\n", func_addr);
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
static int kpatch_verify_activeness_safety(struct kpatch_module *kpmod)
{
	struct task_struct *g, *t;
	int ret = 0;

	struct kpatch_backtrace_args args = {
		.kpmod = kpmod,
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

/* Called from stop_machine */
static int kpatch_apply_patch(void *data)
{
	struct kpatch_module *kpmod = data;
	struct kpatch_func *funcs = kpmod->funcs;
	int num_funcs = kpmod->num_funcs;
	int i, ret;

	ret = kpatch_verify_activeness_safety(kpmod);
	if (ret)
		return ret;

	for (i = 0; i < num_funcs; i++) {
		struct kpatch_func *func = &funcs[i];

		/* update the global list and go live */
		hash_add_rcu(kpatch_func_hash, &func->node, func->old_addr);
	}

	/* Check if any inconsistent NMI has happened while updating */
	ret = kpatch_finish_status(KPATCH_STATUS_SUCCESS);
	if (ret == KPATCH_STATUS_FAILURE) {
		/* Failed, we have to rollback patching process */
		for (i = 0; i < num_funcs; i++)
			hash_del_rcu(&funcs[i].node);
		return -EBUSY;
	}

	/* Succeeded, clear updating flags */
	for (i = 0; i < num_funcs; i++)
		funcs[i].updating = false;

	return 0;
}

/* Called from stop_machine */
static int kpatch_remove_patch(void *data)
{
	struct kpatch_module *kpmod = data;
	struct kpatch_func *funcs = kpmod->funcs;
	int num_funcs = kpmod->num_funcs;
	int ret, i;

	ret = kpatch_verify_activeness_safety(kpmod);
	if (ret)
		return ret;

	/* Check if any inconsistent NMI has happened while updating */
	ret = kpatch_finish_status(KPATCH_STATUS_SUCCESS);
	if (ret == KPATCH_STATUS_FAILURE) {
		/* Failed, we must keep funcs on hash table */
		for (i = 0; i < num_funcs; i++)
			funcs[i].updating = false;
		return -EBUSY;
	}

	/* Succeeded, remove all updating funcs from hash table */
	for (i = 0; i < num_funcs; i++)
		hash_del_rcu(&funcs[i].node);

	return 0;
}

/*
 * This is where the magic happens.  Update regs->ip to tell ftrace to return
 * to the new function.
 *
 * If there are multiple patch modules that have registered to patch the same
 * function, the last one to register wins, as it'll be first in the hash
 * bucket.
 */
void notrace kpatch_ftrace_handler(unsigned long ip, unsigned long parent_ip,
				   struct ftrace_ops *fops,
				   struct pt_regs *regs)
{
	struct kpatch_func *func;
	int ret, op;

	preempt_disable_notrace();
retry:
	func = kpatch_get_func(ip);
	if (unlikely(in_nmi())) {
		op = atomic_read(&kpatch_operation);
		if (likely(op == KPATCH_OP_NONE))
			goto done;
		/*
		 * Make sure no memory reordering between
		 * kpatch_operation and kpatch_status
		 */
		smp_rmb();
		/*
		 * Checking for NMI inconsistency.
		 * If this can set the KPATCH_STATUS_FAILURE here, it means an
		 * NMI occures in updating process. In that case, we should
		 * rollback the process.
		 */
		ret = kpatch_finish_status(KPATCH_STATUS_FAILURE);
		if (ret == KPATCH_STATUS_FAILURE) {
			/*
			 * Inconsistency happens here, Newly added funcs have
			 * to be ignored.
			 */
			if (op == KPATCH_OP_PATCH)
				func = kpatch_get_committed_func(func, ip);
		} else {
			/*
			 * Here, the updating process has been finished
			 * successfully. Unpatched funcs have to be ignored.
			 */
			if (op == KPATCH_OP_UNPATCH)
				func = kpatch_get_committed_func(func, ip);
			/*
			 * This is a very rare case but possible if the func
			 * is added in the hash table right after calling
			 * kpatch_get_func(ip) and before calling
			 * kpatch_finish_status(KPATCH_STATUS_FAILURE).
			 */
			else if (!func)
				goto retry;
		}
	}
done:
	if (func)
		regs->ip = func->new_addr;

	preempt_enable_notrace();
}

static struct ftrace_ops kpatch_ftrace_ops __read_mostly = {
	.func = kpatch_ftrace_handler,
	.flags = FTRACE_OPS_FL_SAVE_REGS,
};

/* Remove kpatch_funcs from ftrace filter */
static int kpatch_remove_funcs_from_filter(struct kpatch_func *funcs,
					   int num_funcs)
{
	int i, ret = 0;

	for (i = 0; i < num_funcs; i++) {
		struct kpatch_func *func = &funcs[i];

		/*
		 * If any other modules have also patched this function, don't
		 * remove its ftrace handler.
		 */
		if (kpatch_get_func(func->old_addr))
			continue;

		/* Remove the ftrace handler for this function. */
		ret = ftrace_set_filter_ip(&kpatch_ftrace_ops, func->old_addr,
					   1, 0);
		if (ret) {
			pr_err("can't remove ftrace filter at address 0x%lx\n",
			       func->old_addr);
			break;
		}
	}

	return ret;
}

int kpatch_register(struct kpatch_module *kpmod)
{
	int ret, i;
	struct kpatch_func *funcs = kpmod->funcs;
	int num_funcs = kpmod->num_funcs;

	if (!kpmod->mod || !funcs || !num_funcs)
		return -EINVAL;

	down(&kpatch_mutex);

	for (i = 0; i < num_funcs; i++) {
		struct kpatch_func *func = &funcs[i];

		func->updating = true;

		/*
		 * If any other modules have also patched this function, it
		 * already has an ftrace handler.
		 */
		if (kpatch_get_func(func->old_addr))
			continue;

		/* Add an ftrace handler for this function. */
		ret = ftrace_set_filter_ip(&kpatch_ftrace_ops, func->old_addr,
					   0, 0);
		if (ret) {
			pr_err("can't set ftrace filter at address 0x%lx\n",
			       func->old_addr);
			num_funcs = i;
			goto err_rollback;
		}
	}

	/* Register the ftrace trampoline if it hasn't been done already. */
	if (!kpatch_num_registered) {
		ret = register_ftrace_function(&kpatch_ftrace_ops);
		if (ret) {
			pr_err("can't register ftrace handler\n");
			goto err_rollback;
		}
	}
	kpatch_num_registered++;

	kpatch_start_status();
	/*
	 * Make sure no memory reordering between kpatch_operation and
	 * kpatch_status. kpatch_ftrace_handler() has corresponding smp_rmb().
	 */
	smp_wmb();
	atomic_set(&kpatch_operation, KPATCH_OP_PATCH);
	/*
	 * Idle the CPUs, verify activeness safety, and atomically make the new
	 * functions visible to the trampoline.
	 */
	ret = stop_machine(kpatch_apply_patch, kpmod, NULL);
	if (ret) {
		/*
		 * This synchronize_rcu is to ensure any other kpatch_get_func
		 * user exits the rcu locked(preemt_disabled) critical section
		 * and hash_del_rcu() is correctly finished.
		 */
		synchronize_rcu();
		goto err_unregister;
	}

	/* TODO: need TAINT_KPATCH */
	pr_notice_once("tainting kernel with TAINT_USER\n");
	add_taint(TAINT_USER, LOCKDEP_STILL_OK);

	pr_notice("loaded patch module \"%s\"\n", kpmod->mod->name);

	atomic_set(&kpatch_operation, KPATCH_OP_NONE);
	up(&kpatch_mutex);
	return 0;

err_unregister:
	atomic_set(&kpatch_operation, KPATCH_OP_NONE);
	if (kpatch_num_registered == 1) {
		int ret2 = unregister_ftrace_function(&kpatch_ftrace_ops);
		if (ret2) {
			pr_err("ftrace unregister failed (%d)\n", ret2);
			goto err_rollback;
		}
	}
	kpatch_num_registered--;
err_rollback:
	kpatch_remove_funcs_from_filter(funcs, num_funcs);
	up(&kpatch_mutex);
	return ret;
}
EXPORT_SYMBOL(kpatch_register);

int kpatch_unregister(struct kpatch_module *kpmod)
{
	struct kpatch_func *funcs = kpmod->funcs;
	int num_funcs = kpmod->num_funcs;
	int i, ret;

	down(&kpatch_mutex);

	/* Start unpatching operation */
	kpatch_start_status();
	/*
	 * Make sure no memory reordering between kpatch_operation and
	 * kpatch_status. kpatch_ftrace_handler() has corresponding smp_rmb().
	 */
	smp_wmb();
	atomic_set(&kpatch_operation, KPATCH_OP_UNPATCH);
	for (i = 0; i < num_funcs; i++)
		funcs[i].updating = true;

	ret = stop_machine(kpatch_remove_patch, kpmod, NULL);
	if (ret)
		goto out;

	if (kpatch_num_registered == 1) {
		ret = unregister_ftrace_function(&kpatch_ftrace_ops);
		if (ret) {
			pr_err("can't unregister ftrace handler\n");
			goto out;
		}
	}
	kpatch_num_registered--;

	/*
	 * This synchronize_rcu is to ensure any other kpatch_get_func
	 * user exits the rcu locked(preemt_disabled) critical section
	 * and hash_del_rcu() is correctly finished.
	 */
	synchronize_rcu();

	ret = kpatch_remove_funcs_from_filter(funcs, num_funcs);
	if (ret)
		goto out;

	pr_notice("unloaded patch module \"%s\"\n", kpmod->mod->name);

out:
	atomic_set(&kpatch_operation, KPATCH_OP_NONE);
	up(&kpatch_mutex);
	return ret;
}
EXPORT_SYMBOL(kpatch_unregister);

MODULE_LICENSE("GPL");
