#ifndef __KPATCH_MACROS_H_
#define __KPATCH_MACROS_H_

#include <linux/compiler.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include "kpatch-syscall.h"

/* upstream 33def8498fdd "treewide: Convert macro and uses of __section(foo) to __section("foo")" */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
# define __kpatch_section(section) __section(section)
#else
# define __kpatch_section(section) __section(#section)
#endif

/*
 * KPATCH_IGNORE_SECTION macro
 *
 * This macro is for ignoring sections that may change as a side effect of
 * another change or might be a non-bundlable section; that is one that does
 * not honor -ffunction-section and create a one-to-one relation from function
 * symbol to section.
 */
#define KPATCH_IGNORE_SECTION(_sec) \
	char *__UNIQUE_ID(kpatch_ignore_section_) __kpatch_section(.kpatch.ignore.sections) = _sec;

/*
 * KPATCH_IGNORE_FUNCTION macro
 *
 * This macro is for ignoring functions that may change as a side effect of a
 * change in another function.  The WARN class of macros, for example, embed
 * the line number in an instruction, which will cause the function to be
 * detected as changed when, in fact, there has been no functional change.
 */
#define KPATCH_IGNORE_FUNCTION(_fn) \
	void *__kpatch_ignore_func_##_fn __kpatch_section(.kpatch.ignore.functions) = _fn;


/* Support for livepatch callbacks */
#if IS_ENABLED(CONFIG_LIVEPATCH)
# ifdef RHEL_RELEASE_CODE
#  if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 5)
#   define HAS_LIVEPATCH_CALLBACKS
#  endif
# elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
#  define HAS_LIVEPATCH_CALLBACKS
# endif
#endif

#ifdef HAS_LIVEPATCH_CALLBACKS
# include <linux/livepatch.h>
typedef struct klp_object patch_object;
#else
# include "kpatch.h"
typedef struct kpatch_object patch_object;
#endif /* HAS_LIVEPATCH_CALLBACKS */

typedef int (*kpatch_pre_patch_call_t)(patch_object *obj);
typedef void (*kpatch_post_patch_call_t)(patch_object *obj);
typedef void (*kpatch_pre_unpatch_call_t)(patch_object *obj);
typedef void (*kpatch_post_unpatch_call_t)(patch_object *obj);

struct kpatch_pre_patch_callback {
	kpatch_pre_patch_call_t fn;
	char *objname; /* filled in by create-diff-object */
};

struct kpatch_post_patch_callback {
	kpatch_post_patch_call_t fn;
	char *objname; /* filled in by create-diff-object */
};

struct kpatch_pre_unpatch_callback {
	kpatch_pre_unpatch_call_t fn;
	char *objname; /* filled in by create-diff-object */
};

struct kpatch_post_unpatch_callback {
	kpatch_post_unpatch_call_t fn;
	char *objname; /* filled in by create-diff-object */
};


#define KPATCH_PRE_PATCH_CALLBACK(_fn) \
	static inline kpatch_pre_patch_call_t __pre_patchtest(void) { return _fn; } \
	static struct kpatch_pre_patch_callback kpatch_pre_patch_data __kpatch_section(.kpatch.callbacks.pre_patch) __used = { \
		.fn = _fn, \
		.objname = NULL \
	};
#define KPATCH_POST_PATCH_CALLBACK(_fn) \
	static inline kpatch_post_patch_call_t __post_patchtest(void) { return _fn; } \
	static struct kpatch_post_patch_callback kpatch_post_patch_data __kpatch_section(.kpatch.callbacks.post_patch) __used = { \
		.fn = _fn, \
		.objname = NULL \
	};
#define KPATCH_PRE_UNPATCH_CALLBACK(_fn) \
	static inline kpatch_pre_unpatch_call_t __pre_unpatchtest(void) { return _fn; } \
	static struct kpatch_pre_unpatch_callback kpatch_pre_unpatch_data __kpatch_section(.kpatch.callbacks.pre_unpatch) __used = { \
		.fn = _fn, \
		.objname = NULL \
	};
#define KPATCH_POST_UNPATCH_CALLBACK(_fn) \
	static inline kpatch_post_unpatch_call_t __post_unpatchtest(void) { return _fn; } \
	static struct kpatch_post_unpatch_callback kpatch_post_unpatch_data __kpatch_section(.kpatch.callbacks.post_unpatch) __used = { \
		.fn = _fn, \
		.objname = NULL \
	};

/*
 * KPATCH_FORCE_UNSAFE macro
 *
 * USE WITH EXTREME CAUTION!
 *
 * Allows patch authors to bypass the activeness safety check at patch load
 * time. Do this ONLY IF 1) the patch application will always/likely fail due
 * to the function being on the stack of at least one thread at all times and
 * 2) it is safe for both the original and patched versions of the function to
 * run concurrently.
 */
#define KPATCH_FORCE_UNSAFE(_fn) \
	void *__kpatch_force_func_##_fn __kpatch_section(.kpatch.force) = _fn;

/*
 * KPATCH_PRINTK macro
 *
 * Use this instead of calling printk to avoid unwanted compiler optimizations
 * which cause kpatch-build errors.
 *
 * The printk function is annotated with the __cold attribute, which tells gcc
 * that the function is unlikely to be called.  A side effect of this is that
 * code paths containing calls to printk might also be marked cold, leading to
 * other functions called in those code paths getting moved into .text.unlikely
 * or being uninlined.
 *
 * This macro places printk in its own code path so as not to make the
 * surrounding code path cold.
 */
#define KPATCH_PRINTK(_fmt, ...) \
({ \
	if (jiffies) \
		printk(_fmt, ## __VA_ARGS__); \
})


/*
 * KPATCH_PRINTK_DEFERRED macro
 *
 * Use this instead of calling printk_deferred to avoid unwanted compiler optimizations
 * which cause kpatch-build errors.
 *
 * The printk function is annotated with the __cold attribute, which tells gcc
 * that the function is unlikely to be called.  A side effect of this is that
 * code paths containing calls to printk might also be marked cold, leading to
 * other functions called in those code paths getting moved into .text.unlikely
 * or being uninlined.
 *
 * And yet, printk may cause dead lock in the context in kernel because when printing
 * warning in console, it will call schedule_work which will take the rq_lock.
 * If queue_work put this task into current queue, it will cause dead lock when
 * try_to_weak_up try to take the rq_lock either. However, printk_deferred will
 * call irq_work_queue which can avoid this situation.
 *
 * This macro places printk_deferred in its own code path so as not to make the
 * surrounding code path cold.
 */
#define KPATCH_PRINTK_DEFERRED(_fmt, ...) \
({ \
	if (jiffies) \
		printk_deferred(_fmt, ## __VA_ARGS__); \
})

/*
 * KPATCH_STATIC_CALL macro
 *
 * Replace usages of static_call() with this macro, when create-diff-object
 * recommends it due to the original static call key living in a module.
 *
 * This converts the static call to a regular indirect call.
 */
#define KPATCH_STATIC_CALL(name) \
	((typeof(STATIC_CALL_TRAMP(name))*)(STATIC_CALL_KEY(name).func))

#endif /* __KPATCH_MACROS_H_ */
