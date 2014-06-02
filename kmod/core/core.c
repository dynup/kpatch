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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * kpatch core module
 *
 * Patch modules register with this module to redirect old functions to new
 * functions.
 *
 * For each function patched by the module we must:
 * - Call stop_machine
 * - Ensure that no task has the old function in its call stack
 * - Add the new function address to kpatch_func_hash
 *
 * After that, each call to the old function calls into kpatch_ftrace_handler()
 * which finds the new function in kpatch_func_hash table and updates the
 * return instruction pointer so that ftrace will return to the new function.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/ftrace.h>
#include <linux/hashtable.h>
#include <linux/hardirq.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <asm/stacktrace.h>
#include <asm/cacheflush.h>
#include "kpatch.h"

#if !defined(CONFIG_FUNCTION_TRACER) || \
	!defined(CONFIG_HAVE_FENTRY) || \
	!defined(CONFIG_MODULES) || \
	!defined(CONFIG_SYSFS)
#error "CONFIG_FUNCTION_TRACER, CONFIG_HAVE_FENTRY, CONFIG_MODULES, and CONFIG_SYSFS kernel config options are required"
#endif

#define KPATCH_HASH_BITS 8
static DEFINE_HASHTABLE(kpatch_func_hash, KPATCH_HASH_BITS);

static DEFINE_SEMAPHORE(kpatch_mutex);

static int kpatch_num_registered;

static struct kobject *kpatch_root_kobj;
struct kobject *kpatch_patches_kobj;
EXPORT_SYMBOL_GPL(kpatch_patches_kobj);

struct kpatch_backtrace_args {
	struct kpatch_module *kpmod;
	int ret;
};

struct kpatch_kallsyms_args {
	char *name;
	unsigned long addr;
};

/*
 * The kpatch core module has a state machine which allows for proper
 * synchronization with kpatch_ftrace_handler() when it runs in NMI context.
 *
 *         +-----------------------------------------------------+
 *         |                                                     |
 *         |                                                     +
 *         v                                     +---> KPATCH_STATE_SUCCESS
 * KPATCH_STATE_IDLE +---> KPATCH_STATE_UPDATING |
 *         ^                                     +---> KPATCH_STATE_FAILURE
 *         |                                                     +
 *         |                                                     |
 *         +-----------------------------------------------------+
 *
 * KPATCH_STATE_IDLE: No updates are pending.  The func hash is valid, and the
 * reader doesn't need to check func->op.
 *
 * KPATCH_STATE_UPDATING: An update is in progress.  The reader must call
 * kpatch_state_finish(KPATCH_STATE_FAILURE) before accessing the func hash.
 *
 * KPATCH_STATE_FAILURE: An update failed, and the func hash might be
 * inconsistent (pending patched funcs might not have been removed yet).  If
 * func->op is KPATCH_OP_PATCH, then rollback to the previous version of the
 * func.
 *
 * KPATCH_STATE_SUCCESS: An update succeeded, but the func hash might be
 * inconsistent (pending unpatched funcs might not have been removed yet).  If
 * func->op is KPATCH_OP_UNPATCH, then rollback to the previous version of the
 * func.
 */
enum {
	KPATCH_STATE_IDLE,
	KPATCH_STATE_UPDATING,
	KPATCH_STATE_SUCCESS,
	KPATCH_STATE_FAILURE,
};
static atomic_t kpatch_state;

enum kpatch_op {
	KPATCH_OP_NONE,
	KPATCH_OP_PATCH,
	KPATCH_OP_UNPATCH,
};

struct kpatch_func {
	struct kpatch_patch *patch;
	unsigned long old_addr;
	struct hlist_node node;
	struct kpatch_module *kpmod;
	enum kpatch_op op;
};

/*
 * This structure is allocated on a per registered module basis
 * and is stored in the struct kpatch_module "internal" field.
 * Any data associated with each registered module used internally
 * by this core module can be added here.
 */
struct kpatch_internal {
	struct kpatch_func *funcs;
};

static inline void kpatch_state_idle(void)
{
	int state = atomic_read(&kpatch_state);
	WARN_ON(state != KPATCH_STATE_SUCCESS && state != KPATCH_STATE_FAILURE);
	atomic_set(&kpatch_state, KPATCH_STATE_IDLE);
}

static inline void kpatch_state_updating(void)
{
	WARN_ON(atomic_read(&kpatch_state) != KPATCH_STATE_IDLE);
	atomic_set(&kpatch_state, KPATCH_STATE_UPDATING);
}

/* If state is updating, change it to success or failure and return new state */
static inline int kpatch_state_finish(int state)
{
	int result;
	WARN_ON(state != KPATCH_STATE_SUCCESS && state != KPATCH_STATE_FAILURE);
	result = atomic_cmpxchg(&kpatch_state, KPATCH_STATE_UPDATING, state);
	return result == KPATCH_STATE_UPDATING ? state : result;
}

static struct kpatch_func *kpatch_get_func(unsigned long ip)
{
	struct kpatch_func *f;

	/* Here, we have to use rcu safe hlist because of NMI concurrency */
	hash_for_each_possible_rcu(kpatch_func_hash, f, node, ip)
		if (f->old_addr == ip)
			return f;
	return NULL;
}

static struct kpatch_func *kpatch_get_prev_func(struct kpatch_func *f,
						unsigned long ip)
{
	hlist_for_each_entry_continue_rcu(f, node)
		if (f->old_addr == ip)
			return f;
	return NULL;
}

static inline int kpatch_compare_addresses(unsigned long stack_addr,
					   unsigned long func_addr,
					   unsigned long func_size)
{
	if (stack_addr >= func_addr && stack_addr < func_addr + func_size) {
		/* TODO: use kallsyms to print symbol name */
		pr_err("activeness safety check failed for function at address 0x%lx\n",
		       stack_addr);
		return -EBUSY;
	}
	return 0;
}

static void kpatch_backtrace_address_verify(void *data, unsigned long address,
					    int reliable)
{
	struct kpatch_backtrace_args *args = data;
	struct kpatch_module *kpmod = args->kpmod;
	struct kpatch_func *func;
	int i;

	if (args->ret)
		return;

	/* check kpmod funcs */
	for (i = 0; i < kpmod->patches_nr; i++) {
		unsigned long func_addr, func_size;
		struct kpatch_func *active_func;

		func = &kpmod->internal->funcs[i];
		active_func = kpatch_get_func(func->old_addr);
		if (!active_func) {
			/* patching an unpatched func */
			func_addr = func->old_addr;
			func_size = func->patch->old_size;
		} else {
			/* repatching or unpatching */
			func_addr = active_func->patch->new_addr;
			func_size = active_func->patch->new_size;
		}

		args->ret = kpatch_compare_addresses(address, func_addr,
						     func_size);
		if (args->ret)
			return;
	}

	/* in the replace case, need to check the func hash as well */
	hash_for_each_rcu(kpatch_func_hash, i, func, node) {
		if (func->op == KPATCH_OP_UNPATCH) {
			args->ret = kpatch_compare_addresses(address,
			                        func->patch->new_addr,
			                        func->patch->new_size);
			if (args->ret)
				return;
		}
	}
}

static int kpatch_backtrace_stack(void *data, char *name)
{
	return 0;
}

static const struct stacktrace_ops kpatch_backtrace_ops = {
	.address	= kpatch_backtrace_address_verify,
	.stack		= kpatch_backtrace_stack,
	.walk_stack	= print_context_stack_bp,
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
	struct kpatch_func *funcs = kpmod->internal->funcs;
	int num_funcs = kpmod->patches_nr;
	int i, ret;

	ret = kpatch_verify_activeness_safety(kpmod);
	if (ret) {
		kpatch_state_finish(KPATCH_STATE_FAILURE);
		return ret;
	}

	/* tentatively add the new funcs to the global func hash */
	for (i = 0; i < num_funcs; i++)
		hash_add_rcu(kpatch_func_hash, &funcs[i].node,
			     funcs[i].old_addr);

	/* memory barrier between func hash add and state change */
	smp_wmb();

	/*
	 * Check if any inconsistent NMI has happened while updating.  If not,
	 * move to success state.
	 */
	ret = kpatch_state_finish(KPATCH_STATE_SUCCESS);
	if (ret == KPATCH_STATE_FAILURE) {
		pr_err("NMI activeness safety check failed\n");

		/* Failed, we have to rollback patching process */
		for (i = 0; i < num_funcs; i++)
			hash_del_rcu(&funcs[i].node);

		return -EBUSY;
	}

	return 0;
}

/* Called from stop_machine */
static int kpatch_remove_patch(void *data)
{
	struct kpatch_module *kpmod = data;
	struct kpatch_func *funcs = kpmod->internal->funcs;
	int num_funcs = kpmod->patches_nr;
	int ret, i;

	ret = kpatch_verify_activeness_safety(kpmod);
	if (ret) {
		kpatch_state_finish(KPATCH_STATE_FAILURE);
		return ret;
	}

	/* Check if any inconsistent NMI has happened while updating */
	ret = kpatch_state_finish(KPATCH_STATE_SUCCESS);
	if (ret == KPATCH_STATE_FAILURE)
		return -EBUSY;

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
static void notrace
kpatch_ftrace_handler(unsigned long ip, unsigned long parent_ip,
		      struct ftrace_ops *fops, struct pt_regs *regs)
{
	struct kpatch_func *func;
	int state;

	preempt_disable_notrace();

	if (likely(!in_nmi()))
		func = kpatch_get_func(ip);
	else {
		/* Checking for NMI inconsistency */
		state = kpatch_state_finish(KPATCH_STATE_FAILURE);

		/* no memory reordering between state and func hash read */
		smp_rmb();

		func = kpatch_get_func(ip);

		if (likely(state == KPATCH_STATE_IDLE))
			goto done;

		if (state == KPATCH_STATE_SUCCESS) {
			/*
			 * Patching succeeded.  If the function was being
			 * unpatched, roll back to the previous version.
			 */
			if (func && func->op == KPATCH_OP_UNPATCH)
				func = kpatch_get_prev_func(func, ip);
		} else {
			/*
			 * Patching failed.  If the function was being patched,
			 * roll back to the previous version.
			 */
			if (func && func->op == KPATCH_OP_PATCH)
				func = kpatch_get_prev_func(func, ip);
		}
	}
done:
	if (func)
		regs->ip = func->patch->new_addr;

	preempt_enable_notrace();
}

static struct ftrace_ops kpatch_ftrace_ops __read_mostly = {
	.func = kpatch_ftrace_handler,
	.flags = FTRACE_OPS_FL_SAVE_REGS,
};

/* Remove kpatch_funcs from ftrace filter */
static void kpatch_remove_funcs_from_filter(struct kpatch_func *funcs,
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
		ret = ftrace_set_filter_ip(&kpatch_ftrace_ops,
		                  func->old_addr, 1, 0);

		WARN(ret, "can't remove ftrace filter at address 0x%lx (rc=%d)",
		     func->old_addr, ret);
	}
}

static int kpatch_kallsyms_callback(void *data, const char *name,
					 struct module *mod,
					 unsigned long addr)
{
	struct kpatch_kallsyms_args *args = data;

	if (args->addr == addr && !strcmp(args->name, name))
		return 1;

	return 0;
}

static int kpatch_verify_symbol_match(char *name, unsigned long addr)
{
	int ret;

	struct kpatch_kallsyms_args args = {
		.name = name,
		.addr = addr,
	};

	ret = kallsyms_on_each_symbol(kpatch_kallsyms_callback, &args);
	if (!ret) {
		pr_err("base kernel mismatch for symbol '%s'\n", name);
		pr_err("expected address was 0x%016lx\n", addr);
		return -EINVAL;
	}

	return 0;
}

static int kpatch_write_relocations(struct kpatch_module *kpmod)
{
	int ret, i, size, readonly = 0;
	struct kpatch_dynrela *dynrela;
	u64 loc, val;
	unsigned long core = (unsigned long)kpmod->mod->module_core;
	unsigned long core_ro_size = kpmod->mod->core_ro_size;
	unsigned long core_size = kpmod->mod->core_size;

	for (i = 0; i < kpmod->dynrelas_nr; i++) {
		dynrela = &kpmod->dynrelas[i];

		ret = kpatch_verify_symbol_match(dynrela->name, dynrela->src);
		if (ret)
			return ret;

		switch (dynrela->type) {
			case R_X86_64_PC32:
				loc = dynrela->dest;
				val = (u32)(dynrela->src + dynrela->addend -
				            dynrela->dest);
				size = 4;
				break;
			case R_X86_64_32S:
				loc = dynrela->dest;
				val = (s32)dynrela->src + dynrela->addend;
				size = 4;
				break;
			default:
				printk("unsupported rela type %ld for "
				       "0x%lx <- 0x%lx at index %d\n",
				       dynrela->type, dynrela->dest,
				       dynrela->src, i);
				return -EINVAL;
		}

		if (loc >= core && loc < core + core_ro_size)
			readonly = 1;
		else if (loc >= core + core_ro_size && loc < core + core_size)
			readonly = 0;
		else {
			pr_err("bad dynrela location 0x%llx for symbol %s\n",
			       loc, dynrela->name);
			return -EINVAL;
		}

		if (readonly)
			set_memory_rw(loc & PAGE_MASK, 1);

		ret = probe_kernel_write((void *)loc, &val, size);

		if (readonly)
			set_memory_ro(loc & PAGE_MASK, 1);

		if (ret) {
			pr_err("write to 0x%llx failed for symbol %s\n",
			       loc, dynrela->name);
			return ret;
		}
	}

	return 0;
}

int kpatch_register(struct kpatch_module *kpmod, bool replace)
{
	int ret, i;
	struct kpatch_func *funcs, *func;
	int num_funcs = kpmod->patches_nr;

	if (!kpmod->mod || !kpmod->patches || !num_funcs)
		return -EINVAL;

	kpmod->enabled = false;

	kpmod->internal = kmalloc(sizeof(*kpmod->internal), GFP_KERNEL);
	if (!kpmod->internal)
		return -ENOMEM;

	funcs = kmalloc(sizeof(*funcs) * num_funcs, GFP_KERNEL);
	if (!funcs) {
		kfree(kpmod->internal);
		return -ENOMEM;
	}
	kpmod->internal->funcs = funcs;

	down(&kpatch_mutex);

	if (!try_module_get(kpmod->mod)) {
		ret = -ENODEV;
		goto err_up;
	}

	ret = kpatch_write_relocations(kpmod);
	if (ret)
		goto err_put;

	for (i = 0; i < num_funcs; i++) {
		func = &funcs[i];

		func->op = KPATCH_OP_PATCH;
		func->kpmod = kpmod;
		func->patch = &kpmod->patches[i];
		func->old_addr = func->patch->old_offset;

		ret = kpatch_verify_symbol_match(func->patch->name,
		                               func->old_addr);
		if (ret)
			goto err_rollback;

		/*
		 * If any other modules have also patched this function, it
		 * already has an ftrace handler.
		 */
		if (kpatch_get_func(func->old_addr))
			continue;

		/* Add an ftrace handler for this function. */
		ret = ftrace_set_filter_ip(&kpatch_ftrace_ops,
		                  func->old_addr, 0, 0);
		if (ret) {
			pr_err("can't set ftrace filter at address 0x%lx\n",
			       func->old_addr);
			num_funcs = i;
			goto err_rollback;
		}
	}

	/* Register the ftrace handler if it hasn't been done already. */
	if (!kpatch_num_registered) {
		ret = register_ftrace_function(&kpatch_ftrace_ops);
		if (ret) {
			pr_err("can't register ftrace handler\n");
			goto err_rollback;
		}
	}
	kpatch_num_registered++;

	if (replace)
		hash_for_each_rcu(kpatch_func_hash, i, func, node)
			func->op = KPATCH_OP_UNPATCH;

	/* memory barrier between func hash and state write */
	smp_wmb();

	kpatch_state_updating();

	/*
	 * Idle the CPUs, verify activeness safety, and atomically make the new
	 * functions visible to the ftrace handler.
	 */
	ret = stop_machine(kpatch_apply_patch, kpmod, NULL);

	/*
	 * For the replace case, remove any obsolete funcs from the hash and
	 * the ftrace filter, and disable the owning patch module so that it
	 * can be removed.
	 */
	if (!ret && replace)
		hash_for_each_rcu(kpatch_func_hash, i, func, node) {
			if (func->op != KPATCH_OP_UNPATCH)
				continue;
			hash_del_rcu(&func->node);
			kpatch_remove_funcs_from_filter(func, 1);
			if (func->kpmod->enabled) {
				kpatch_num_registered--;
				func->kpmod->enabled = false;
				pr_notice("unloaded patch module \"%s\"\n",
					  func->kpmod->mod->name);
				module_put(func->kpmod->mod);
			}
		}

	/* memory barrier between func hash and state write */
	smp_wmb();

	/* NMI handlers can return to normal now */
	kpatch_state_idle();

	/*
	 * Wait for all existing NMI handlers to complete so that they don't
	 * see any changes to funcs or funcs->op that might occur after this
	 * point.
	 *
	 * Any NMI handlers starting after this point will see the IDLE state.
	 */
	synchronize_rcu();

	if (ret)
		goto err_unregister;

	for (i = 0; i < num_funcs; i++)
		funcs[i].op = KPATCH_OP_NONE;

	/* TODO: need TAINT_KPATCH */
	pr_notice_once("tainting kernel with TAINT_USER\n");
	add_taint(TAINT_USER, LOCKDEP_STILL_OK);

	pr_notice("loaded patch module \"%s\"\n", kpmod->mod->name);

	kpmod->enabled = true;

	up(&kpatch_mutex);
	return 0;

err_unregister:
	if (replace)
		hash_for_each_rcu(kpatch_func_hash, i, func, node)
			func->op = KPATCH_OP_NONE;
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
err_put:
	module_put(kpmod->mod);
err_up:
	up(&kpatch_mutex);
	kfree(kpmod->internal->funcs);
	kfree(kpmod->internal);
	return ret;
}
EXPORT_SYMBOL(kpatch_register);

int kpatch_unregister(struct kpatch_module *kpmod)
{
	struct kpatch_func *funcs = kpmod->internal->funcs;
	int num_funcs = kpmod->patches_nr;
	int i, ret;

	if (!kpmod->enabled)
		return -EINVAL;

	down(&kpatch_mutex);

	for (i = 0; i < num_funcs; i++)
		funcs[i].op = KPATCH_OP_UNPATCH;

	/* memory barrier between func hash and state write */
	smp_wmb();

	kpatch_state_updating();

	ret = stop_machine(kpatch_remove_patch, kpmod, NULL);

	/* NMI handlers can return to normal now */
	kpatch_state_idle();

	/*
	 * Wait for all existing NMI handlers to complete so that they don't
	 * see any changes to funcs or funcs->op that might occur after this
	 * point.
	 *
	 * Any NMI handlers starting after this point will see the IDLE state.
	 */
	synchronize_rcu();

	if (ret) {
		for (i = 0; i < num_funcs; i++)
			funcs[i].op = KPATCH_OP_NONE;
		goto out;
	}

	kpatch_num_registered--;
	if (!kpatch_num_registered) {
		ret = unregister_ftrace_function(&kpatch_ftrace_ops);
		if (ret) {
			WARN(1, "can't unregister ftrace handler");
			kpatch_num_registered++;
		}
	}

	kpatch_remove_funcs_from_filter(funcs, num_funcs);

	kfree(kpmod->internal->funcs);
	kfree(kpmod->internal);

	pr_notice("unloaded patch module \"%s\"\n", kpmod->mod->name);

	kpmod->enabled = false;
	module_put(kpmod->mod);

out:
	up(&kpatch_mutex);
	return ret;
}
EXPORT_SYMBOL(kpatch_unregister);

static int kpatch_init(void)
{
	kpatch_root_kobj = kobject_create_and_add("kpatch", kernel_kobj);
	if (!kpatch_root_kobj)
		return -ENOMEM;

	kpatch_patches_kobj = kobject_create_and_add("patches",
						     kpatch_root_kobj);
	if (!kpatch_patches_kobj)
		return -ENOMEM;

	return 0;
}

static void kpatch_exit(void)
{
	WARN_ON(kpatch_num_registered != 0);
	kobject_put(kpatch_patches_kobj);
	kobject_put(kpatch_root_kobj);
}

module_init(kpatch_init);
module_exit(kpatch_exit);
MODULE_LICENSE("GPL");
