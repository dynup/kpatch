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
#include <linux/version.h>
#include <linux/string.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>
#include <asm/cacheflush.h>
#include <generated/utsrelease.h>
#include "kpatch.h"

#ifndef UTS_UBUNTU_RELEASE_ABI
#define UTS_UBUNTU_RELEASE_ABI 0
#endif

#if !defined(CONFIG_FUNCTION_TRACER) || \
	!defined(CONFIG_MODULES) || \
	!defined(CONFIG_SYSFS) || \
	!defined(CONFIG_STACKTRACE) || \
	!defined(CONFIG_KALLSYMS_ALL)
#error "CONFIG_FUNCTION_TRACER, CONFIG_MODULES, CONFIG_SYSFS, CONFIG_KALLSYMS_ALL kernel config options are required"
#endif

#define KPATCH_HASH_BITS 8
static DEFINE_HASHTABLE(kpatch_func_hash, KPATCH_HASH_BITS);

static DEFINE_SEMAPHORE(kpatch_mutex);

static LIST_HEAD(kpmod_list);

static int kpatch_num_patched;

struct kobject *kpatch_root_kobj;
EXPORT_SYMBOL_GPL(kpatch_root_kobj);

struct kpatch_kallsyms_args {
	const char *objname;
	const char *name;
	unsigned long addr;
	unsigned long count;
	unsigned long pos;
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

static int (*kpatch_set_memory_rw)(unsigned long addr, int numpages);
static int (*kpatch_set_memory_ro)(unsigned long addr, int numpages);

extern int static_relocate(struct module *mod, unsigned long type,
			   void * loc, unsigned long value);

#define MAX_STACK_TRACE_DEPTH   64
static unsigned long stack_entries[MAX_STACK_TRACE_DEPTH];
static struct stack_trace trace = {
	.max_entries	= ARRAY_SIZE(stack_entries),
	.entries	= &stack_entries[0],
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

static int kpatch_backtrace_address_verify(struct kpatch_module *kpmod,
					   unsigned long address)
{
	struct kpatch_func *func;
	int i;
	int ret;

	/* check kpmod funcs */
	do_for_each_linked_func(kpmod, func) {
		unsigned long func_addr, func_size;
		const char *func_name;
		struct kpatch_func *active_func;

		if (func->force)
			continue;

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

		ret = kpatch_compare_addresses(address, func_addr,
					       func_size, func_name);
		if (ret)
			return ret;
	} while_for_each_linked_func();

	/* in the replace case, need to check the func hash as well */
	hash_for_each_rcu(kpatch_func_hash, i, func, node) {
		if (func->op == KPATCH_OP_UNPATCH && !func->force) {
			ret = kpatch_compare_addresses(address,
						       func->new_addr,
						       func->new_size,
						       func->name);
			if (ret)
				return ret;
		}
	}

	return ret;
}

/*
 * Verify activeness safety, i.e. that none of the to-be-patched functions are
 * on the stack of any task.
 *
 * This function is called from stop_machine() context.
 */
static int kpatch_verify_activeness_safety(struct kpatch_module *kpmod)
{
	struct task_struct *g, *t;
	int i;
	int ret = 0;

	/* Check the stacks of all tasks. */
	do_each_thread(g, t) {

		trace.nr_entries = 0;
		save_stack_trace_tsk(t, &trace);
		if (trace.nr_entries >= trace.max_entries) {
			ret = -EBUSY;
			pr_err("more than %u trace entries!\n",
			       trace.max_entries);
			goto out;
		}

		for (i = 0; i < trace.nr_entries; i++) {
			if (trace.entries[i] == ULONG_MAX)
				break;
			ret = kpatch_backtrace_address_verify(kpmod,
							      trace.entries[i]);
			if (ret)
				goto out;
		}

	} while_each_thread(g, t);

out:
	if (ret) {
		pr_err("PID: %d Comm: %.20s\n", t->pid, t->comm);
		for (i = 0; i < trace.nr_entries; i++) {
			if (trace.entries[i] == ULONG_MAX)
				break;
			pr_err("  [<%pK>] %pB\n",
			       (void *)trace.entries[i],
			       (void *)trace.entries[i]);
		}
	}

	return ret;
}

static inline int pre_patch_callback(struct kpatch_object *object)
{
	int ret;

	if (kpatch_object_linked(object) &&
	    object->pre_patch_callback) {
		ret = (*object->pre_patch_callback)(object);
		if (ret) {
			object->callbacks_enabled = false;
			return ret;
		}
	}
	object->callbacks_enabled = true;

	return 0;
}

static inline void post_patch_callback(struct kpatch_object *object)
{
	if (kpatch_object_linked(object) &&
	    object->post_patch_callback &&
	    object->callbacks_enabled)
		(*object->post_patch_callback)(object);
}

static inline void pre_unpatch_callback(struct kpatch_object *object)
{
	if (kpatch_object_linked(object) &&
	    object->pre_unpatch_callback &&
	    object->callbacks_enabled)
		(*object->pre_unpatch_callback)(object);
}

static inline void post_unpatch_callback(struct kpatch_object *object)
{
	if (kpatch_object_linked(object) &&
	    object->post_unpatch_callback &&
	    object->callbacks_enabled)
		(*object->post_unpatch_callback)(object);
}

/* Called from stop_machine */
static int kpatch_apply_patch(void *data)
{
	struct kpatch_module *kpmod = data;
	struct kpatch_func *func;
	struct kpatch_object *object;
	int ret;

	ret = kpatch_verify_activeness_safety(kpmod);
	if (ret) {
		kpatch_state_finish(KPATCH_STATE_FAILURE);
		return ret;
	}

	/* run any user-defined pre-patch callbacks */
	list_for_each_entry(object, &kpmod->objects, list) {
		ret = pre_patch_callback(object);
		if (ret) {
			pr_err("pre-patch callback failed!\n");
			kpatch_state_finish(KPATCH_STATE_FAILURE);
			goto err;
		}
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

		ret = -EBUSY;
		goto err;
	}

	/* run any user-defined post-patch callbacks */
	list_for_each_entry(object, &kpmod->objects, list)
		post_patch_callback(object);

	return 0;
err:
	/* undo pre-patch callbacks by calling post-unpatch counterparts */
	list_for_each_entry(object, &kpmod->objects, list)
		post_unpatch_callback(object);

	return ret;
}

/* Called from stop_machine */
static int kpatch_remove_patch(void *data)
{
	struct kpatch_module *kpmod = data;
	struct kpatch_func *func;
	struct kpatch_object *object;
	int ret;

	ret = kpatch_verify_activeness_safety(kpmod);
	if (ret) {
		kpatch_state_finish(KPATCH_STATE_FAILURE);
		return ret;
	}

	/* run any user-defined pre-unpatch callbacks */
	list_for_each_entry(object, &kpmod->objects, list)
		pre_unpatch_callback(object);

	/* Check if any inconsistent NMI has happened while updating */
	ret = kpatch_state_finish(KPATCH_STATE_SUCCESS);
	if (ret == KPATCH_STATE_FAILURE) {
		ret = -EBUSY;
		goto err;
	}

	/* Succeeded, remove all updating funcs from hash table */
	do_for_each_linked_func(kpmod, func) {
		hash_del_rcu(&func->node);
	} while_for_each_linked_func();

	/* run any user-defined post-unpatch callbacks */
	list_for_each_entry(object, &kpmod->objects, list)
		post_unpatch_callback(object);

	return 0;

err:
	/* undo pre-unpatch callbacks by calling post-patch counterparts */
	list_for_each_entry(object, &kpmod->objects, list)
		post_patch_callback(object);

	return ret;
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

#ifdef CONFIG_ARM64
	ip -= AARCH64_INSN_SIZE;
#endif

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
#ifdef CONFIG_X86
		regs->ip = func->new_addr + MCOUNT_INSN_SIZE;
#elif defined(CONFIG_ARM64)
		regs->pc = func->new_addr;
#else
		pr_err("Not support this arch\n");
#endif

	preempt_enable_notrace();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
#define FTRACE_OPS_FL_IPMODIFY 0
#endif

static struct ftrace_ops kpatch_ftrace_ops __read_mostly = {
	.func = kpatch_ftrace_handler,
	.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,
};

static int kpatch_ftrace_add_func(unsigned long ip)
{
	int ret;

	/* check if any other patch modules have also patched this func */
	if (kpatch_get_func(ip))
		return 0;

#ifdef CONFIG_ARM64
	ip += AARCH64_INSN_SIZE;
#endif
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

	if (kpatch_num_patched == 1) {
		ret = unregister_ftrace_function(&kpatch_ftrace_ops);
		if (ret) {
			pr_err("can't unregister ftrace handler\n");
			return ret;
		}
	}
	kpatch_num_patched--;

#ifdef CONFIG_ARM64
	ip += AARCH64_INSN_SIZE;
#endif
	ret = ftrace_set_filter_ip(&kpatch_ftrace_ops, ip, 1, 0);
	if (ret) {
		pr_err("can't remove ftrace filter at address 0x%lx\n", ip);
		return ret;
	}

	return 0;
}

static int kpatch_kallsyms_callback(void *data, const char *name,
					 struct module *mod,
					 unsigned long addr)
{
	struct kpatch_kallsyms_args *args = data;
	bool vmlinux = !strcmp(args->objname, "vmlinux");

	if ((mod && vmlinux) || (!mod && !vmlinux))
		return 0;

	if (strcmp(args->name, name))
		return 0;

	if (!vmlinux && strcmp(args->objname, mod->name))
		return 0;

	args->addr = addr;
	args->count++;

	/*
	 * Finish the search when the symbol is found for the desired position
	 * or the position is not defined for a non-unique symbol.
	 */
	if ((args->pos && (args->count == args->pos)) ||
	    (!args->pos && (args->count > 1))) {
		return 1;
	}

	return 0;
}

static int kpatch_find_object_symbol(const char *objname, const char *name,
				     unsigned long sympos, unsigned long *addr)
{
	struct kpatch_kallsyms_args args = {
		.objname = objname,
		.name = name,
		.addr = 0,
		.count = 0,
		.pos = sympos,
	};

	mutex_lock(&module_mutex);
	kallsyms_on_each_symbol(kpatch_kallsyms_callback, &args);
	mutex_unlock(&module_mutex);

	/*
	 * Ensure an address was found. If sympos is 0, ensure symbol is unique;
	 * otherwise ensure the symbol position count matches sympos.
	 */
	if (args.addr == 0)
		pr_err("symbol '%s' not found in symbol table\n", name);
	else if (args.count > 1 && sympos == 0) {
		pr_err("unresolvable ambiguity for symbol '%s' in object '%s'\n",
		       name, objname);
	} else if (sympos != args.count && sympos > 0) {
		pr_err("symbol position %lu for symbol '%s' in object '%s' not found\n",
		       sympos, name, objname);
	} else {
		*addr = args.addr;
		return 0;
	}

	*addr = 0;
	return -EINVAL;
}

/*
 * External symbols are located outside the parent object (where the parent
 * object is either vmlinux or the kmod being patched).
 */
static int kpatch_find_external_symbol(const char *objname, const char *name,
				       unsigned long sympos, unsigned long *addr)

{
	const struct kernel_symbol *sym;

	/* first, check if it's an exported symbol */
	preempt_disable();
	sym = find_symbol(name, NULL, NULL, true, true);
	preempt_enable();
	if (sym) {
#ifdef CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
		*addr = (unsigned long)offset_to_ptr(&sym->value_offset);
#else
		*addr = sym->value;
#endif
		return 0;
	}

	/* otherwise check if it's in another .o within the patch module */
	return kpatch_find_object_symbol(objname, name, sympos, addr);
}

static int kpatch_write_relocations(struct kpatch_module *kpmod,
				    struct kpatch_object *object)
{
	int ret, size, readonly = 0, numpages;
	struct kpatch_dynrela *dynrela;
	u64 loc, val;
#if (( LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0) ) || \
     ( LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
      UTS_UBUNTU_RELEASE_ABI >= 7 ) \
    )
	unsigned long core = (unsigned long)kpmod->mod->core_layout.base;
	unsigned long core_size = kpmod->mod->core_layout.size;
#else
	unsigned long core = (unsigned long)kpmod->mod->module_core;
	unsigned long core_size = kpmod->mod->core_size;
#endif

	list_for_each_entry(dynrela, &object->dynrelas, list) {
		if (dynrela->external)
			ret = kpatch_find_external_symbol(kpmod->mod->name,
							  dynrela->name,
							  dynrela->sympos,
							  &dynrela->src);
		else
			ret = kpatch_find_object_symbol(object->name,
							dynrela->name,
							dynrela->sympos,
							&dynrela->src);
		if (ret) {
			pr_err("unable to find symbol '%s'\n", dynrela->name);
			return ret;
		}

		switch (dynrela->type) {
#ifdef CONFIG_X86
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
#endif
		default:
			pr_err("unsupported rela type %ld for source %s (0x%lx <- 0x%lx)\n",
			       dynrela->type, dynrela->name, dynrela->dest,
			       dynrela->src);
			return -EINVAL;
		}

		if (loc < core || loc >= core + core_size) {
			pr_err("bad dynrela location 0x%llx for symbol %s\n",
			       loc, dynrela->name);
			return -EINVAL;
		}

		/*
		 * Skip it if the instruction to be relocated has been
		 * changed already (paravirt or alternatives may do this).
		 */
		if (memchr_inv((void *)loc, 0, size)) {
			pr_notice("Skipped dynrela for %s (0x%lx <- 0x%lx): the instruction has been changed already.\n",
				  dynrela->name, dynrela->dest, dynrela->src);
			pr_notice_once(
"This is not necessarily a bug but it may indicate in some cases "
"that the binary patch does not handle paravirt operations, alternatives or the like properly.\n");
			continue;
		}

#if defined(CONFIG_DEBUG_SET_MODULE_RONX) || defined(CONFIG_ARCH_HAS_SET_MEMORY)
#if (( LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0) ) || \
     ( LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0) && \
      UTS_UBUNTU_RELEASE_ABI >= 7 ) \
    )
		readonly = (loc < core + kpmod->mod->core_layout.ro_size);
#else
		readonly = (loc < core + kpmod->mod->core_ro_size);
#endif
#endif

		numpages = (PAGE_SIZE - (loc & ~PAGE_MASK) >= size) ? 1 : 2;

		if (readonly)
			kpatch_set_memory_rw(loc & PAGE_MASK, numpages);

		ret = probe_kernel_write((void *)loc, &val, size);

		if (readonly)
			kpatch_set_memory_ro(loc & PAGE_MASK, numpages);

		if (ret) {
			pr_err("write to 0x%llx failed for symbol %s\n",
			       loc, dynrela->name);
			return ret;
		}
	}

	return 0;
}

static int kpatch_write_relocations_arm64(struct kpatch_module *kpmod,
					struct kpatch_object *object)
{
	struct module *mod = kpmod->mod;
	struct kpatch_dynrela *dynrela;
	u64 loc, val;
	int type, ret;

	module_disable_ro(mod);
	list_for_each_entry(dynrela, &object->dynrelas, list) {
		if (dynrela->external)
			ret = kpatch_find_external_symbol(kpmod->mod->name,
							  dynrela->name,
							  dynrela->sympos,
							  &dynrela->src);
		else
			ret = kpatch_find_object_symbol(object->name,
							dynrela->name,
							dynrela->sympos,
							&dynrela->src);
		if (ret) {
			pr_err("unable to find symbol '%s'\n", dynrela->name);
			module_enable_ro(mod, true);
			return ret;
		}

		loc = dynrela->dest;
		val = dynrela->src + dynrela->addend;
		type = dynrela->type;
		ret = static_relocate(mod, type, (void *)loc, val);
		if (ret) {
			pr_err("write to 0x%llx failed for symbol %s\n",
				loc, dynrela->name);
			module_enable_ro(mod, true);
			return ret;
		}
	}
	module_enable_ro(mod, true);
	return 0;
}

static int kpatch_unlink_object(struct kpatch_object *object)
{
	struct kpatch_func *func;
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

	if (object->mod) {
		module_put(object->mod);
		object->mod = NULL;
	}

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
	struct kpatch_func *func, *func_err = NULL;
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

#ifdef	CONFIG_X86
	ret = kpatch_write_relocations(kpmod, object);
#elif defined(CONFIG_ARM64)
	ret = kpatch_write_relocations_arm64(kpmod, object);
#else
	pr_err("Not support this arch relocations\n");
	ret = -EINVAL;
#endif
	if (ret)
		goto err_put;

	list_for_each_entry(func, &object->funcs, list) {

		/* lookup the old location */
		ret = kpatch_find_object_symbol(object->name,
						func->name,
						func->sympos,
						&func->old_addr);
		if (ret) {
			func_err = func;
			goto err_ftrace;
		}

		/* add to ftrace filter and register handler if needed */
		ret = kpatch_ftrace_add_func(func->old_addr);
		if (ret) {
			func_err = func;
			goto err_ftrace;
		}
	}

	return 0;

err_ftrace:
	list_for_each_entry(func, &object->funcs, list) {
		if (func == func_err)
			break;
		WARN_ON(kpatch_ftrace_remove_func(func->old_addr));
	}
err_put:
	if (!vmlinux)
		module_put(mod);
	return ret;
}

static int kpatch_module_notify_coming(struct notifier_block *nb,
				       unsigned long action, void *data)
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

	/* run user-defined pre-patch callback */
	ret = pre_patch_callback(object);
	if (ret) {
		pr_err("pre-patch callback failed!\n");
		goto out;	/* and WARN */
	}

	/* add to the global func hash */
	list_for_each_entry(func, &object->funcs, list)
		hash_add_rcu(kpatch_func_hash, &func->node, func->old_addr);

	/* run user-defined post-patch callback */
	post_patch_callback(object);
out:
	up(&kpatch_mutex);

	/* no way to stop the module load on error */
	WARN(ret, "error (%d) patching newly loaded module '%s'\n", ret,
	     object->name);

	return 0;
}

static int kpatch_module_notify_going(struct notifier_block *nb,
				      unsigned long action, void *data)
{
	struct module *mod = data;
	struct kpatch_module *kpmod;
	struct kpatch_object *object;
	struct kpatch_func *func;
	bool found = false;

	if (action != MODULE_STATE_GOING)
		return 0;

	down(&kpatch_mutex);

	list_for_each_entry(kpmod, &kpmod_list, list) {
		list_for_each_entry(object, &kpmod->objects, list) {
			if (!kpatch_object_linked(object))
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

	/* run user-defined pre-unpatch callback */
	pre_unpatch_callback(object);

	/* remove from the global func hash */
	list_for_each_entry(func, &object->funcs, list)
		hash_del_rcu(&func->node);

	/* run user-defined pre-unpatch callback */
	post_unpatch_callback(object);

	kpatch_unlink_object(object);

out:
	up(&kpatch_mutex);

	return 0;
}

int kpatch_register(struct kpatch_module *kpmod, bool replace)
{
	int ret, i, force = 0;
	struct kpatch_object *object, *object_err = NULL;
	struct kpatch_func *func;

	if (!kpmod->mod || list_empty(&kpmod->objects))
		return -EINVAL;

	down(&kpatch_mutex);

	if (kpmod->enabled) {
		ret = -EINVAL;
		goto err_up;
	}

	list_add_tail(&kpmod->list, &kpmod_list);

	if (!try_module_get(kpmod->mod)) {
		ret = -ENODEV;
		goto err_list;
	}

	list_for_each_entry(object, &kpmod->objects, list) {

		ret = kpatch_link_object(kpmod, object);
		if (ret) {
			object_err = object;
			goto err_unlink;
		}

		if (!kpatch_object_linked(object)) {
			pr_notice("delaying patch of unloaded module '%s'\n",
				  object->name);
			continue;
		}

		if (strcmp(object->name, "vmlinux"))
			pr_notice("patching module '%s'\n", object->name);

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
			if (func->force)
				force = 1;
			hash_del_rcu(&func->node);
			WARN_ON(kpatch_ftrace_remove_func(func->old_addr));
		}

		list_for_each_entry_safe(kpmod2, safe, &kpmod_list, list) {
			if (kpmod == kpmod2)
				continue;

			kpmod2->enabled = false;
			pr_notice("unloaded patch module '%s'\n",
				  kpmod2->mod->name);

			/*
			 * Don't allow modules with forced functions to be
			 * removed because they might still be in use.
			 */
			if (!force)
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

/* HAS_MODULE_TAINT - upstream 2992ef29ae01 "livepatch/module: make TAINT_LIVEPATCH module-specific" */
/* HAS_MODULE_TAINT_LONG - upstream 7fd8329ba502 "taint/module: Clean up global and module taint flags handling" */
#ifdef RHEL_RELEASE_CODE
# if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 4)
#  define HAS_MODULE_TAINT
# endif
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
# define HAS_MODULE_TAINT_LONG
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
# define HAS_MODULE_TAINT
#endif

#ifdef TAINT_LIVEPATCH
	pr_notice_once("tainting kernel with TAINT_LIVEPATCH\n");
	add_taint(TAINT_LIVEPATCH, LOCKDEP_STILL_OK);
# ifdef HAS_MODULE_TAINT_LONG
	set_bit(TAINT_LIVEPATCH, &kpmod->mod->taints);
# elif defined(HAS_MODULE_TAINT)
	kpmod->mod->taints |= (1 << TAINT_LIVEPATCH);
# endif
#else
	pr_notice_once("tainting kernel with TAINT_USER\n");
	add_taint(TAINT_USER, LOCKDEP_STILL_OK);
#endif

	pr_notice("loaded patch module '%s'\n", kpmod->mod->name);

	kpmod->enabled = true;

	up(&kpatch_mutex);
	return 0;

err_ops:
	if (replace)
		hash_for_each_rcu(kpatch_func_hash, i, func, node)
			func->op = KPATCH_OP_NONE;
err_unlink:
	list_for_each_entry(object, &kpmod->objects, list) {
		if (object == object_err)
			break;
		if (!kpatch_object_linked(object))
			continue;
		WARN_ON(kpatch_unlink_object(object));
	}
	module_put(kpmod->mod);
err_list:
	list_del(&kpmod->list);
err_up:
	up(&kpatch_mutex);
	return ret;
}
EXPORT_SYMBOL(kpatch_register);

int kpatch_unregister(struct kpatch_module *kpmod)
{
	struct kpatch_object *object;
	struct kpatch_func *func;
	int ret, force = 0;

	down(&kpatch_mutex);

	if (!kpmod->enabled) {
	    ret = -EINVAL;
	    goto out;
	}

	do_for_each_linked_func(kpmod, func) {
		func->op = KPATCH_OP_UNPATCH;
		if (func->force)
			force = 1;
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

	/*
	 * Don't allow modules with forced functions to be removed because they
	 * might still be in use.
	 */
	if (!force)
		module_put(kpmod->mod);

	list_del(&kpmod->list);

out:
	up(&kpatch_mutex);
	return ret;
}
EXPORT_SYMBOL(kpatch_unregister);


static struct notifier_block kpatch_module_nb_coming = {
	.notifier_call = kpatch_module_notify_coming,
	.priority = INT_MIN, /* called last */
};
static struct notifier_block kpatch_module_nb_going = {
	.notifier_call = kpatch_module_notify_going,
	.priority = INT_MAX, /* called first */
};

static int kpatch_init(void)
{
	int ret;

	kpatch_set_memory_rw = (void *)kallsyms_lookup_name("set_memory_rw");
	if (!kpatch_set_memory_rw) {
		pr_err("can't find set_memory_rw symbol\n");
		return -ENXIO;
	}

	kpatch_set_memory_ro = (void *)kallsyms_lookup_name("set_memory_ro");
	if (!kpatch_set_memory_ro) {
		pr_err("can't find set_memory_ro symbol\n");
		return -ENXIO;
	}

	kpatch_root_kobj = kobject_create_and_add("kpatch", kernel_kobj);
	if (!kpatch_root_kobj)
		return -ENOMEM;

	ret = register_module_notifier(&kpatch_module_nb_coming);
	if (ret)
		goto err_root_kobj;
	ret = register_module_notifier(&kpatch_module_nb_going);
	if (ret)
		goto err_unregister_coming;

	return 0;

err_unregister_coming:
	WARN_ON(unregister_module_notifier(&kpatch_module_nb_coming));
err_root_kobj:
	kobject_put(kpatch_root_kobj);
	return ret;
}

static void kpatch_exit(void)
{
	rcu_barrier();

	WARN_ON(kpatch_num_patched != 0);
	WARN_ON(unregister_module_notifier(&kpatch_module_nb_coming));
	WARN_ON(unregister_module_notifier(&kpatch_module_nb_going));
	kobject_put(kpatch_root_kobj);
}

module_init(kpatch_init);
module_exit(kpatch_exit);
MODULE_LICENSE("GPL");
