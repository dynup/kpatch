#ifndef __KPATCH_MACROS_H_
#define __KPATCH_MACROS_H_

#include <linux/compiler.h>

typedef void (*kpatch_loadcall_t)(void);
typedef void (*kpatch_unloadcall_t)(void);

struct kpatch_load {
	kpatch_loadcall_t fn;
	char *objname; /* filled in by create-diff-object */
};

struct kpatch_unload {
	kpatch_unloadcall_t fn;
	char *objname; /* filled in by create-diff-object */
};

/*
 * KPATCH_LOAD_HOOK macro
 *
 * The first line only ensures that the hook being registered has the required
 * function signature.  If not, there is compile error on this line.
 *
 * The section line declares a struct kpatch_load to be allocated in a new
 * .kpatch.hook.load section.  This kpatch_load_data symbol is later stripped
 * by create-diff-object so that it can be declared in multiple objects that
 * are later linked together, avoiding global symbol collision.  Since multiple
 * hooks can be registered, the .kpatch.hook.load section is a table of struct
 * kpatch_load elements that will be executed in series by the kpatch core
 * module at load time, assuming the kernel object (module) is currently
 * loaded; otherwise, the hook is called when module to be patched is loaded
 * via the module load notifier.
 */
#define KPATCH_LOAD_HOOK(_fn) \
	static inline kpatch_loadcall_t __loadtest(void) { return _fn; } \
	struct kpatch_load kpatch_load_data __section(.kpatch.hooks.load) = { \
		.fn = _fn, \
		.objname = NULL \
	};

/*
 * KPATCH_UNLOAD_HOOK
 *
 * Same as LOAD hook with s/load/unload/
 */
#define KPATCH_UNLOAD_HOOK(_fn) \
	static inline kpatch_unloadcall_t __unloadtest(void) { return _fn; } \
	struct kpatch_unload kpatch_unload_data __section(.kpatch.hooks.unload) = { \
		.fn = _fn, \
		.objname = NULL \
	};

#endif /* __KPATCH_HOOKS_H_ */
