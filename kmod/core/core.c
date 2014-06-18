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

LIST_HEAD(kpmod_list);

static int kpatch_num_patched;

static struct kobject *kpatch_root_kobj;
struct kobject *kpatch_patches_kobj;
EXPORT_SYMBOL_GPL(kpatch_patches_kobj);

struct kpatch_backtrace_args {
	struct kpatch_module *kpmod;
	int ret;
};

struct kpatch_kallsyms_args {
	const char *name;
	unsigned long addr;
};

/* this is a double loop, use goto instead of break */
#define do_for_each_linked_func(kpmod, func) {				\
	struct kpatch_object *_object;					\
	list_for_each_entry(_object, &kpmod->objects, list) {		\
		if (!kpatch_object_linked(_object))			\
			continue;					\
		list_for_each_entry(func, &_object->funcs, list) {

#define while_for_each_linked_func()					\
		}							\
	}								\
}


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

static inline bool kpatch_object_linked(struct kpatch_object *object)
{
	return object->mod || !strcmp(object->name, "vmlinux");
}

static inline int kpatch_compare_addresses(unsigned long stack_addr,
					   unsigned long func_addr,
					   unsigned long func_size,
					   const char *func_name)
{
	if (stack_addr >= func_addr && stack_addr < func_addr + func_size) {
		pr_err("activeness safety check failed for %s\n", func_name);
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
	do_for_each_linked_func(kpmod, func) {
		unsigned long func_addr, func_size;
		const char *func_name;
		struct kpatch_func *active_func;

		active_func = kpatch_get_func(func->old_addr);
		if (!active_func) {
			/* patching an unpatched func */
			func_addr = func->old_addr;
			func_size = func->old_size;
			func_name = func->name;
		} else {
			/* repatching or unpatching */
			func_addr = active_func->new_addr;
			func_size = active_func->new_size;
			func_name = active_func->name;
		}

		args->ret = kpatch_compare_addresses(address, func_addr,
						     func_size, func_name);
		if (args->ret)
			return;
	} while_for_each_linked_func();

	/* in the replace case, need to check the func hash as well */
	hash_for_each_rcu(kpatch_func_hash, i, func, node) {
		if (func->op == KPATCH_OP_UNPATCH) {
			args->ret = kpatch_compare_addresses(address,
			                        func->new_addr,
			                        func->new_size,
						func->name);
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
	struct kpatch_func *func;
	int ret;

	ret = kpatch_verify_activeness_safety(kpmod);
	if (ret) {
		kpatch_state_finish(KPATCH_STATE_FAILURE);
		return ret;
	}

	/* tentatively add the new funcs to the global func hash */
	do_for_each_linked_func(kpmod, func) {
		hash_add_rcu(kpatch_func_hash, &func->node, func->old_addr);
	} while_for_each_linked_func();

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
		do_for_each_linked_func(kpmod, func) {
			hash_del_rcu(&func->node);
		} while_for_each_linked_func();

		return -EBUSY;
	}

	return 0;
}

/* Called from stop_machine */
static int kpatch_remove_patch(void *data)
{
	struct kpatch_module *kpmod = data;
	struct kpatch_func *func;
	int ret;

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
	do_for_each_linked_func(kpmod, func) {
		hash_del_rcu(&func->node);
	} while_for_each_linked_func();

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
		regs->ip = func->new_addr;

	preempt_enable_notrace();
}

static struct ftrace_ops kpatch_ftrace_ops __read_mostly = {
	.func = kpatch_ftrace_handler,
	.flags = FTRACE_OPS_FL_SAVE_REGS,
};

static int kpatch_ftrace_add_func(unsigned long ip)
{
	int ret;

	/* check if any other patch modules have also patched this func */
	if (kpatch_get_func(ip))
		return 0;

	ret = ftrace_set_filter_ip(&kpatch_ftrace_ops, ip, 0, 0);
	if (ret) {
		pr_err("can't set ftrace filter at address 0x%lx\n", ip);
		return ret;
	}

	if (!kpatch_num_patched) {
		ret = register_ftrace_function(&kpatch_ftrace_ops);
		if (ret) {
			pr_err("can't register ftrace handler\n");
			ftrace_set_filter_ip(&kpatch_ftrace_ops, ip, 1, 0);
			return ret;
		}
	}
	kpatch_num_patched++;

	return 0;
}

static int kpatch_ftrace_remove_func(unsigned long ip)
{
	int ret;

	/* check if any other patch modules have also patched this func */
	if (kpatch_get_func(ip))
		return 0;

	ret = ftrace_set_filter_ip(&kpatch_ftrace_ops, ip, 1, 0);
	if (ret) {
		pr_err("can't remove ftrace filter at address 0x%lx\n", ip);
		return ret;
	}

	if (kpatch_num_patched == 1) {
		ret = unregister_ftrace_function(&kpatch_ftrace_ops);
		if (ret) {
			pr_err("can't unregister ftrace handler\n");
			ftrace_set_filter_ip(&kpatch_ftrace_ops, ip, 0, 0);
			return ret;
		}
	}
	kpatch_num_patched--;

	return 0;
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

static int kpatch_verify_symbol_match(const char *name, unsigned long addr)
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

static unsigned long kpatch_find_module_symbol(struct module *mod,
					       const char *name)
{
	char buf[KSYM_SYMBOL_LEN];

	/* check total string length for overrun */
	if (strlen(mod->name) + strlen(name) + 1 >= KSYM_SYMBOL_LEN) {
		pr_err("buffer overrun finding symbol '%s' in module '%s'\n",
		       name, mod->name);
		return 0;
	}

	/* encode symbol name as "mod->name:name" */
	strcpy(buf, mod->name);
	strcat(buf, ":");
	strcat(buf, name);

	return kallsyms_lookup_name(buf);
}

static int kpatch_write_relocations(struct kpatch_module *kpmod,
				    struct kpatch_object *object)
{
	int ret, size, readonly = 0;
	struct kpatch_dynrela *dynrela;
	u64 loc, val;
	unsigned long core = (unsigned long)kpmod->mod->module_core;
	unsigned long core_ro_size = kpmod->mod->core_ro_size;
	unsigned long core_size = kpmod->mod->core_size;
	unsigned long src;

	list_for_each_entry(dynrela, &object->dynrelas, list) {
		if (!strcmp(object->name, "vmlinux")) {
			ret = kpatch_verify_symbol_match(dynrela->name,
							 dynrela->src);
			if (ret)
				return ret;
		} else {
			/* module, dynrela->src needs to be discovered */

			if (dynrela->exported)
				src = (unsigned long)__symbol_get(dynrela->name);
			else
				src = kpatch_find_module_symbol(object->mod,
								dynrela->name);

			if (!src) {
				pr_err("unable to find symbol '%s'\n",
				       dynrela->name);
				return -EINVAL;
			}

			dynrela->src = src;
		}

		switch (dynrela->type) {
			case R_X86_64_NONE:
				continue;
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
			case R_X86_64_64:
				loc = dynrela->dest;
				val = dynrela->src;
				size = 8;
				break;
			default:
				printk("unsupported rela type %ld for source %s (0x%lx <- 0x%lx)\n",
				       dynrela->type, dynrela->name,
				       dynrela->dest, dynrela->src);
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

static int kpatch_unlink_object(struct kpatch_object *object)
{
	struct kpatch_func *func;
	struct kpatch_dynrela *dynrela;
	int ret;

	list_for_each_entry(func, &object->funcs, list) {
		if (!func->old_addr)
			continue;
		ret = kpatch_ftrace_remove_func(func->old_addr);
		if (ret) {
			WARN(1, "can't unregister ftrace for address 0x%lx\n",
			     func->old_addr);
			return ret;
		}
	}

	list_for_each_entry(dynrela, &object->dynrelas, list)
		if (dynrela->src && dynrela->exported)
			__symbol_put(dynrela->name);

	if (object->mod)
		module_put(object->mod);

	return 0;
}

/*
 * Link to a to-be-patched object in preparation for patching it.
 *
 * - Find the object module
 * - Write patch module relocations which reference the object
 * - Calculate the patched functions' addresses
 * - Register them with ftrace
 */
static int kpatch_link_object(struct kpatch_module *kpmod,
			      struct kpatch_object *object)
{
	struct module *mod = NULL;
	struct kpatch_func *func;
	int ret;
	bool vmlinux = !strcmp(object->name, "vmlinux");

	if (!vmlinux) {
		mutex_lock(&module_mutex);
		mod = find_module(object->name);
		if (!mod) {
			/*
			 * The module hasn't been loaded yet.  We can patch it
			 * later in kpatch_module_notify().
			 */
			mutex_unlock(&module_mutex);
			return 0;
		}

		/* should never fail because we have the mutex */
		WARN_ON(!try_module_get(mod));
		mutex_unlock(&module_mutex);
		object->mod = mod;
	}

	ret = kpatch_write_relocations(kpmod, object);
	if (ret)
		goto err_unlink;

	list_for_each_entry(func, &object->funcs, list) {
		unsigned long old_addr;

		/* calculate actual old location */
		if (vmlinux) {
			old_addr = func->old_offset;
			ret = kpatch_verify_symbol_match(func->name,
							 old_addr);
			if (ret)
				goto err_unlink;
		} else
			old_addr = (unsigned long)mod->module_core +
				   func->old_offset;

		/* add to ftrace filter and register handler if needed */
		ret = kpatch_ftrace_add_func(old_addr);
		if (ret)
			goto err_unlink;

		func->old_addr = old_addr;
	}

	return 0;

err_unlink:
	kpatch_unlink_object(object);
	return ret;
}

static int kpatch_module_notify(struct notifier_block *nb, unsigned long action,
				void *data)
{
	struct module *mod = data;
	struct kpatch_module *kpmod;
	struct kpatch_object *object;
	struct kpatch_func *func;
	int ret = 0;
	bool found = false;

	if (action != MODULE_STATE_COMING)
		return 0;

	down(&kpatch_mutex);

	list_for_each_entry(kpmod, &kpmod_list, list) {
		list_for_each_entry(object, &kpmod->objects, list) {
			if (kpatch_object_linked(object))
				continue;
			if (!strcmp(object->name, mod->name)) {
				found = true;
				goto done;
			}
		}
	}
done:
	if (!found)
		goto out;

	ret = kpatch_link_object(kpmod, object);
	if (ret)
		goto out;

	BUG_ON(!object->mod);

	pr_notice("patching newly loaded module '%s'\n", object->name);

	/* add to the global func hash */
	list_for_each_entry(func, &object->funcs, list)
		hash_add_rcu(kpatch_func_hash, &func->node, func->old_addr);

out:
	up(&kpatch_mutex);

	/* no way to stop the module load on error */
	WARN(ret, "error (%d) patching newly loaded module '%s'\n", ret,
	     object->name);
	return 0;
}

int kpatch_register(struct kpatch_module *kpmod, bool replace)
{
	int ret, i;
	struct kpatch_object *object;
	struct kpatch_func *func;

	if (!kpmod->mod || list_empty(&kpmod->objects))
		return -EINVAL;

	down(&kpatch_mutex);

	kpmod->enabled = false;
	list_add_tail(&kpmod->list, &kpmod_list);

	if (!try_module_get(kpmod->mod)) {
		ret = -ENODEV;
		goto err_up;
	}

	list_for_each_entry(object, &kpmod->objects, list) {

		ret = kpatch_link_object(kpmod, object);
		if (ret)
			goto err_unlink;

		if (!object->mod) {
			pr_notice("delaying patch of unloaded module '%s'\n",
				  object->name);
			continue;
		}

		pr_notice("patching module '%s\n", object->name);

		list_for_each_entry(func, &object->funcs, list)
			func->op = KPATCH_OP_PATCH;
	}

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
	if (!ret && replace) {
		struct kpatch_module *kpmod2, *safe;

		hash_for_each_rcu(kpatch_func_hash, i, func, node) {
			if (func->op != KPATCH_OP_UNPATCH)
				continue;
			hash_del_rcu(&func->node);
			WARN_ON(kpatch_ftrace_remove_func(func->old_addr));
		}

		list_for_each_entry_safe(kpmod2, safe, &kpmod_list, list) {
			if (kpmod == kpmod2)
				continue;

			kpmod2->enabled = false;
			pr_notice("unloaded patch module '%s'\n",
				  kpmod2->mod->name);
			module_put(kpmod2->mod);
			list_del(&kpmod2->list);
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
		goto err_ops;

	do_for_each_linked_func(kpmod, func) {
		func->op = KPATCH_OP_NONE;
	} while_for_each_linked_func();

	/* TODO: need TAINT_KPATCH */
	pr_notice_once("tainting kernel with TAINT_USER\n");
	add_taint(TAINT_USER, LOCKDEP_STILL_OK);

	pr_notice("loaded patch module '%s'\n", kpmod->mod->name);

	kpmod->enabled = true;

	up(&kpatch_mutex);
	return 0;

err_ops:
	if (replace)
		hash_for_each_rcu(kpatch_func_hash, i, func, node)
			func->op = KPATCH_OP_NONE;
err_unlink:
	list_for_each_entry(object, &kpmod->objects, list)
		if (kpatch_object_linked(object))
			kpatch_unlink_object(object);
	module_put(kpmod->mod);
err_up:
	list_del(&kpmod->list);
	up(&kpatch_mutex);
	return ret;
}
EXPORT_SYMBOL(kpatch_register);

int kpatch_unregister(struct kpatch_module *kpmod)
{
	struct kpatch_object *object;
	struct kpatch_func *func;
	int ret;

	if (!kpmod->enabled)
		return -EINVAL;

	down(&kpatch_mutex);

	do_for_each_linked_func(kpmod, func) {
		func->op = KPATCH_OP_UNPATCH;
	} while_for_each_linked_func();

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
		do_for_each_linked_func(kpmod, func) {
			func->op = KPATCH_OP_NONE;
		} while_for_each_linked_func();
		goto out;
	}

	list_for_each_entry(object, &kpmod->objects, list) {
		if (!kpatch_object_linked(object))
			continue;
		ret = kpatch_unlink_object(object);
		if (ret)
			goto out;
	}

	pr_notice("unloaded patch module '%s'\n", kpmod->mod->name);

	kpmod->enabled = false;
	module_put(kpmod->mod);
	list_del(&kpmod->list);

out:
	up(&kpatch_mutex);
	return ret;
}
EXPORT_SYMBOL(kpatch_unregister);


static struct notifier_block kpatch_module_nb = {
	.notifier_call = kpatch_module_notify,
	.priority = INT_MIN, /* called last */
};

static int kpatch_init(void)
{
	int ret;

	kpatch_root_kobj = kobject_create_and_add("kpatch", kernel_kobj);
	if (!kpatch_root_kobj)
		return -ENOMEM;

	kpatch_patches_kobj = kobject_create_and_add("patches",
						     kpatch_root_kobj);
	if (!kpatch_patches_kobj) {
		ret = -ENOMEM;
		goto err_root_kobj;
	}

	ret = register_module_notifier(&kpatch_module_nb);
	if (ret)
		goto err_patches_kobj;

	return 0;

err_patches_kobj:
	kobject_put(kpatch_patches_kobj);
err_root_kobj:
	kobject_put(kpatch_root_kobj);
	return ret;
}

static void kpatch_exit(void)
{
	WARN_ON(kpatch_num_patched != 0);
	WARN_ON(unregister_module_notifier(&kpatch_module_nb));
	kobject_put(kpatch_patches_kobj);
	kobject_put(kpatch_root_kobj);
}

module_init(kpatch_init);
module_exit(kpatch_exit);
MODULE_LICENSE("GPL");
