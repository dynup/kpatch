#ifndef __KPATCH_HOOKS_H_
#define __KPATCH_HOOKS_H_

#include <linux/compiler.h>

typedef int (*kpatch_loadcall_t)(void);
typedef int (*kpatch_unloadcall_t)(void);

struct kpatch_load {
	kpatch_loadcall_t fn;
	char *objname; /* filled in by create-diff-object */
};

struct kpatch_unload {
	kpatch_unloadcall_t fn;
	char *objname; /* filled in by create-diff-object */
};

#define kpatch_load_hook(_fn) \
	static inline kpatch_loadcall_t __loadtest(void) { return _fn; } \
	struct kpatch_load kpatch_load_data __section(.kpatch.hooks.load) = { \
		.fn = _fn, \
		.objname = NULL \
	};

#define kpatch_unload_hook(_fn) \
	static inline kpatch_unloadcall_t __unloadtest(void) { return _fn; } \
	struct kpatch_unload kpatch_unload_data __section(.kpatch.hooks.unload) = { \
		.fn = _fn, \
		.objname = NULL \
	};

#endif /* __KPATCH_HOOKS_H_ */
