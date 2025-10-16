kpatch Patch Author Guide
=========================

Because kpatch-build is relatively easy to use, it can be easy to assume that a
successful patch module build means that the patch is safe to apply.  But in
fact that's a very dangerous assumption.

There are many pitfalls that can be encountered when creating a live patch.
This document attempts to guide the patch creation process.  It's a work in
progress.  If you find it useful, please contribute!

Table of contents
=================

- [Patch analysis](#patch-analysis)
- [kpatch vs livepatch vs kGraft](#kpatch-vs-livepatch-vs-kgraft)
- [Patch upgrades](#patch-upgrades)
- [Data structure changes](#data-structure-changes)
- [Data semantic changes](#data-semantic-changes)
- [Init code changes](#init-code-changes)
- [Header file changes](#header-file-changes)
- [Dealing with unexpected changed functions](#dealing-with-unexpected-changed-functions)
- [Removing references to static local variables](#removing-references-to-static-local-variables)
- [Code removal](#code-removal)
- [Once macros](#once-macros)
- [inline implies notrace](#inline-implies-notrace)
- [Jump labels and static calls](#jump-labels-and-static-calls)
- [Sibling calls](#sibling-calls)
- [Exported symbol versioning](#exported-symbol-versioning)
- [System calls](#system-calls)
- [Symbol Namespaces](#symbol-namespaces)
- [Cross Compile](#cross-compile)


Patch analysis
--------------

kpatch provides _some_ guarantees, but it does not guarantee that all patches
are safe to apply.  Every patch must also be analyzed in-depth by a human.

The most important point here cannot be stressed enough.  Here comes the bold:

**Do not blindly apply patches.  There is no substitute for human analysis and
reasoning on a per-patch basis.  All patches must be thoroughly analyzed by a
human kernel expert who completely understands the patch and the affected code
and how they relate to the live patching environment.**

kpatch vs livepatch vs kGraft
-----------------------------

This document assumes that the kpatch-build tool is being used to create
livepatch kernel modules.  Other live patching systems may have different
consistency models, their own guarantees, and other subtle differences.
The guidance in this document applies **only** to kpatch-build generated
livepatches.

Patch upgrades
--------------

Due to potential unexpected interactions between patches, it's highly
recommended that when patching a system which has already been patched, the
second patch should be a cumulative upgrade which is a superset of the first
patch.

Since upstream kernel 5.1, livepatch supports a "replace" flag to help the
management of cumulative patches. With the flag set, the kernel will load
the cumulative patch and unload all existing patches in one transition.
kpatch-build enables the replace flag by default. If replace behavior is
not desired, the user can disable it with -R|--non-replace.


Data structure changes
----------------------

kpatch patches functions, not data.  If the original patch involves a change to
a data structure, the patch will require some rework, as changes to data
structures are not allowed by default.

Usually you have to get creative.  There are several possible ways to handle
this:

### Change the code which uses the data structure

Sometimes, instead of changing the data structure itself, you can change the
code which uses it.

For example, consider this
[patch](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=54a20552e1eae07aa240fa370a0293e006b5faed).
which has the following hunk:

```diff
@@ -3270,6 +3277,7 @@ static int (*const svm_exit_handlers[])(struct vcpu_svm *svm) = {
 	[SVM_EXIT_EXCP_BASE + PF_VECTOR]	= pf_interception,
 	[SVM_EXIT_EXCP_BASE + NM_VECTOR]	= nm_interception,
 	[SVM_EXIT_EXCP_BASE + MC_VECTOR]	= mc_interception,
+	[SVM_EXIT_EXCP_BASE + AC_VECTOR]	= ac_interception,
 	[SVM_EXIT_INTR]				= intr_interception,
 	[SVM_EXIT_NMI]				= nmi_interception,
 	[SVM_EXIT_SMI]				= nop_on_interception,
```

`svm_exit_handlers[]` is an array of function pointers.  The patch adds a
`ac_interception` function pointer to the array at index `[SVM_EXIT_EXCP_BASE +
AC_VECTOR]`.  That change is incompatible with kpatch.

Looking at the source file, we can see that this function pointer is only
accessed by a single function, `handle_exit()`:

```c
        if (exit_code >= ARRAY_SIZE(svm_exit_handlers)
            || !svm_exit_handlers[exit_code]) {
                WARN_ONCE(1, "svm: unexpected exit reason 0x%x\n", exit_code);
                kvm_queue_exception(vcpu, UD_VECTOR);
                return 1;
        }

        return svm_exit_handlers[exit_code](svm);
```

So an easy solution here is to just change the code to manually check for the
new case before looking in the data structure:

```diff
@@ -3580,6 +3580,9 @@ static int handle_exit(struct kvm_vcpu *vcpu)
                return 1;
        }

+       if (exit_code == SVM_EXIT_EXCP_BASE + AC_VECTOR)
+               return ac_interception(svm);
+
        return svm_exit_handlers[exit_code](svm);
 }
```

Not only is this an easy solution, it's also safer than touching data since
`svm_exit_handlers[]` may be in use by tasks that haven't been patched
yet.

### Use a kpatch callback macro

Kpatch supports the kernel's livepatch [(Un)patching
callbacks](https://github.com/torvalds/linux/blob/master/Documentation/livepatch/callbacks.rst).
The kernel API requires callback registration through `struct klp_callbacks`,
but to do so through kpatch-build, `kpatch-macros.h` defines the following:

* `KPATCH_PRE_PATCH_CALLBACK` - executed before patching
* `KPATCH_POST_PATCH_CALLBACK` - executed after patching
* `KPATCH_PRE_UNPATCH_CALLBACK` - executed before unpatching, complements the
                                  post-patch callback.
* `KPATCH_POST_UNPATCH_CALLBACK` - executed after unpatching, complements the
                                   pre-patch callback.

A pre-patch callback routine has the following signature:

```c
static int callback(patch_object *obj) { }
KPATCH_PRE_PATCH_CALLBACK(callback);
```

and any non-zero return status indicates failure to the kernel.  For more
information on pre-patch callback failure, see the **Pre-patch return status**
section below.

Post-patch, pre-unpatch, and post-unpatch callback routines all share the
following signature:

```c
static void callback(patch_object *obj) { }
KPATCH_POST_PATCH_CALLBACK(callback);            /* or */
KPATCH_PRE_UNPATCH_CALLBACK(callback);           /* or */
KPATCH_POST_UNPATCH_CALLBACK(callback);
```

Generally pre-patch callbacks are paired with post-unpatch callbacks, meaning
that anything the former allocates or sets up should be torn down by the former
callback.  Likewise for post-patch and pre-unpatch callbacks.

#### Pre-patch return status

If kpatch is currently patching already loaded objects (vmlinux always by
definition as well as any currently loaded kernel modules), a non-zero pre-patch
callback status stops the current patch in progress.  The kpatch-module
is rejected, completely reverted, and unloaded.

If an already loaded kpatch is patching an incoming kernel module, then
a failing pre-patch callback will result in the kernel module loader
rejecting the new module.

In both cases, if a pre-patch callback fails, none of its other
associated callbacks will be executed.

#### Callback context

* For patches to vmlinux or already loaded kernel modules, callback functions
will be run around the livepatch transitions in the `klp_enable_patch()`
callchain.  This is executed automatically on kpatch module init.

* For patches to kernel modules which haven't been loaded yet, a
module-notifier will execute callbacks when the module is loaded into
the `MODULE_STATE_COMING` state.  The pre and post-patch callbacks are
called before any module_init code.

Example: a kpatch fix for CVE-2016-5696 could utilize the
`KPATCH_PRE_PATCH_CALLBACK` and `KPATCH_POST_UNPATCH_CALLBACK` macros to modify
variable `sysctl_tcp_challenge_ack_limit` in-place:

```diff
+#include "kpatch-macros.h"
+
+static bool kpatch_write = false;
+static int kpatch_pre_patch_tcp_send_challenge_ack(patch_object *obj)
+{
+	if (sysctl_tcp_challenge_ack_limit == 100) {
+		sysctl_tcp_challenge_ack_limit = 1000;
+		kpatch_write = true;
+	}
+	return 0;
+}
static void kpatch_post_unpatch_tcp_send_challenge_ack(patch_object *obj)
+{
+	if (kpatch_write && sysctl_tcp_challenge_ack_limit == 1000)
+		sysctl_tcp_challenge_ack_limit = 100;
+}
+KPATCH_PRE_PATCH_CALLBACK(kpatch_pre_patch_tcp_send_challenge_ack);
+KPATCH_POST_UNPATCH_CALLBACK(kpatch_post_unpatch_tcp_send_challenge_ack);
```

Don't forget to protect access to data as needed. Spinlocks and mutexes /
sleeping locks **may be used** (this is a change of behavior from when kpatch
relied on the kpatch.ko support module and `stop_machine()` context.)

Be careful when upgrading.  If patch A has a pre/post-patch callback which
writes to X, and then you load patch B which is a superset of A, in some cases
you may want to prevent patch B from writing to X, if A is already loaded.


### Use a shadow variable

If you need to add a field to an existing data structure, or even many existing
data structures, you can use the kernel's
[Shadow Variable](https://www.kernel.org/doc/html/latest/livepatch/shadow-vars.html) API.

Example: The `shadow-newpid.patch` integration test employs shadow variables
to add a rolling counter to the new `struct task_struct` instances.  A
simplified version is presented here.

A shadow PID variable is allocated in `do_fork()`: it is associated with the
current `struct task_struct *p` value, given an ID of `KPATCH_SHADOW_NEWPID`,
sized accordingly, and allocated as per `GFP_KERNEL` flag rules.  Note that
the shadow variable <obj, id> association is global -- hence it is best to
provide unique ID enumerations per kpatch as needed.

`klp_shadow_alloc()` returns a pointer to the shadow variable, so we can
dereference and make assignments as usual.  In this patch chunk, the shadow
`newpid` is allocated then assigned to a rolling `ctr` counter value:
```patch
diff --git a/kernel/fork.c b/kernel/fork.c
index 9bff3b28c357..18374fd35bd9 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -1751,6 +1751,8 @@ struct task_struct *fork_idle(int cpu)
 	return task;
 }
 
+#include <linux/livepatch.h>
+#define KPATCH_SHADOW_NEWPID 0
 /*
  *  Ok, this is the main fork-routine.
  *
@@ -1794,6 +1796,14 @@ long do_fork(unsigned long clone_flags,
 	if (!IS_ERR(p)) {
 		struct completion vfork;
 		struct pid *pid;
+		int *newpid;
+		static int ctr = 0;
+
+		newpid = klp_shadow_get_or_alloc(p, KPATCH_SHADOW_NEWPID,
+						 sizeof(*newpid), GFP_KERNEL,
+						 NULL, NULL);
+		if (newpid)
+			*newpid = ctr++;
 
 		trace_sched_process_fork(current, p);
```

A shadow variable may be accessed via `klp_shadow_get()`.  Here the patch
modifies `task_context_switch_counts()` to fetch the shadow variable
associated with the current `struct task_struct *p` object and a
`KPATCH_SHADOW_NEWPID ID`.  As in the previous patch chunk, the shadow
variable pointer may be accessed as an ordinary pointer type:
```patch
diff --git a/fs/proc/array.c b/fs/proc/array.c
index 39684c79e8e2..fe0259d057a3 100644
--- a/fs/proc/array.c
+++ b/fs/proc/array.c
@@ -394,13 +394,19 @@ static inline void task_seccomp(struct seq_file *m, struct task_struct *p)
 	seq_putc(m, '\n');
 }
 
+#include <linux/livepatch.h>
+#define KPATCH_SHADOW_NEWPID 0
 static inline void task_context_switch_counts(struct seq_file *m,
 						struct task_struct *p)
 {
+	int *newpid;
 	seq_printf(m,	"voluntary_ctxt_switches:\t%lu\n"
 			"nonvoluntary_ctxt_switches:\t%lu\n",
 			p->nvcsw,
 			p->nivcsw);
+	newpid = klp_shadow_get(p, KPATCH_SHADOW_NEWPID);
+	if (newpid)
+		seq_printf(m, "newpid:\t%d\n", *newpid);
 }
 
 static void task_cpus_allowed(struct seq_file *m, struct task_struct *task)
```

A shadow variable is freed by calling `klp_shadow_free()` and providing
the object / enum ID combination.  Once freed, the shadow variable is no
longer safe to access:
```patch
diff --git a/kernel/exit.c b/kernel/exit.c
index 148a7842928d..44b6fe61e912 100644
--- a/kernel/exit.c
+++ b/kernel/exit.c
@@ -791,6 +791,8 @@ static void check_stack_usage(void)
 static inline void check_stack_usage(void) {}
 #endif
 
+#include <linux/livepatch.h>
+#define KPATCH_SHADOW_NEWPID 0
 void do_exit(long code)
 {
 	struct task_struct *tsk = current;
@@ -888,6 +890,8 @@ void do_exit(long code)
 	check_stack_usage();
 	exit_thread();
 
+	klp_shadow_free(tsk, KPATCH_SHADOW_NEWPID, NULL);
+
 	/*
 	 * Flush inherited counters to the parent - before the parent
 	 * gets woken up by child-exit notifications.
```
Notes:
* `klp_shadow_alloc()` and `klp_shadow_get_or_alloc()` initialize only shadow
  variable metadata. They allocate variable storage via `kmalloc` with the
  `gfp_t` flags given, but otherwise leave the area untouched. Initialization
  of a shadow variable is the responsibility of the caller.
* As soon as `klp_shadow_alloc()` or `klp_shadow_get_or_alloc()` create a shadow
  variable, its presence will be reported by `klp_shadow_get()`. Care should be
  taken to avoid any potential race conditions between a kernel thread that
  allocates a shadow variable and concurrent threads that may attempt to use
  it.
* Patches may need to call `klp_shadow_free_all()` from a post-unpatch handler
  to safely cleanup any shadow variables of a particular ID.  From post-unpatch
  context, unloading kpatch module code (aside from .exit) should be
  completely inactive.  As long as these shadow variables were only accessed by
  the unloaded kpatch, they are be safe to release.

Data semantic changes
---------------------

Part of the stable-tree [backport](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/commit/fs/aio.c?h=linux-3.10.y&id=6745cb91b5ec93a1b34221279863926fba43d0d7)
to fix CVE-2014-0206 changed the reference count semantic of `struct
kioctx.reqs_active`. Associating a shadow variable to new instances of this
structure can be used by patched code to handle both new (post-patch) and
existing (pre-patch) instances.

(Note: this example is trimmed to highlight this use-case. Boilerplate code is
also required to allocate/free a shadow variable with enum ID
`KPATCH_SHADOW_REQS_ACTIVE_V2` whenever a new `struct kioctx` is
created/released. No values are ever assigned to the shadow variable.)

```patch
diff --git a/fs/aio.c b/fs/aio.c
index ebd06fd0de89..6a33b73c9107 100644
--- a/fs/aio.c
+++ b/fs/aio.c
@@ -280,6 +280,8 @@ static void free_ioctx_rcu(struct rcu_head *head)
  * and ctx->users has dropped to 0, so we know no more kiocbs can be submitted -
  * now it's safe to cancel any that need to be.
  */
+#include <linux/livepatch.h>
+#define KPATCH_SHADOW_REQS_ACTIVE_V2 1
 static void free_ioctx(struct kioctx *ctx)
 {
        struct aio_ring *ring;
```

Shadow variable existence can be verified before applying the *new* data
semantic of the associated object:
```diff
@@ -678,6 +681,8 @@ void aio_complete(struct kiocb *iocb, long res, long res2)
 put_rq:
        /* everything turned out well, dispose of the aiocb. */
        aio_put_req(iocb);
+       if (klp_shadow_get(ctx, KPATCH_SHADOW_REQS_ACTIVE_V2))
+               atomic_dec(&ctx->reqs_active);
 
        /*
         * We have to order our ring_info tail store above and test
```

Likewise, shadow variable non-existence can be tested to continue applying the
*old* data semantic:
```diff
@@ -310,7 +312,8 @@ static void free_ioctx(struct kioctx *ctx)
 
                avail = (head <= ctx->tail ? ctx->tail : ctx->nr_events) - head;
 
-               atomic_sub(avail, &ctx->reqs_active);
+               if (!klp_shadow_get(ctx, KPATCH_SHADOW_REQS_ACTIVE_V2))
+                       atomic_sub(avail, &ctx->reqs_active);
                head += avail;
                head %= ctx->nr_events;
        }
@@ -757,6 +762,8 @@ static long aio_read_events_ring(struct kioctx *ctx,
        pr_debug("%li  h%u t%u\n", ret, head, ctx->tail);
 
        atomic_sub(ret, &ctx->reqs_active);
+       if (!klp_shadow_get(ctx, KPATCH_SHADOW_REQS_ACTIVE_V2))
+               atomic_sub(ret, &ctx->reqs_active);
 out:
        mutex_unlock(&ctx->ring_lock);
```
 
The previous example can be extended to use shadow variable storage to handle
locking semantic changes.  Consider the [upstream fix](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1d147bfa64293b2723c4fec50922168658e613ba)
for CVE-2014-2706, which added a `ps_lock` to `struct sta_info` to protect
critical sections throughout `net/mac80211/sta_info.c`.

When allocating a new `struct sta_info`, allocate a corresponding shadow
variable large enough to hold a `spinlock_t` instance, then initialize the
spinlock:
```patch
diff --git a/net/mac80211/sta_info.c b/net/mac80211/sta_info.c
index decd30c1e290..758533dda4d8 100644
--- a/net/mac80211/sta_info.c
+++ b/net/mac80211/sta_info.c
@@ -287,6 +287,8 @@ static int sta_prepare_rate_control(struct ieee80211_local *local,
 	return 0;
 }
 
+#include <linux/livepatch.h>
+#define KPATCH_SHADOW_PS_LOCK 2
 struct sta_info *sta_info_alloc(struct ieee80211_sub_if_data *sdata,
 				const u8 *addr, gfp_t gfp)
 {
@@ -295,6 +297,7 @@ struct sta_info *sta_info_alloc(struct ieee80211_sub_if_data *sdata,
 	struct timespec uptime;
 	struct ieee80211_tx_latency_bin_ranges *tx_latency;
 	int i;
+	spinlock_t *ps_lock;
 
 	sta = kzalloc(sizeof(*sta) + local->hw.sta_data_size, gfp);
 	if (!sta)
@@ -330,6 +333,10 @@ struct sta_info *sta_info_alloc(struct ieee80211_sub_if_data *sdata,
 	rcu_read_unlock();
 
 	spin_lock_init(&sta->lock);
+	ps_lock = klp_shadow_alloc(sta, KPATCH_SHADOW_PS_LOCK,
+				   sizeof(*ps_lock), gfp, NULL, NULL);
+	if (ps_lock)
+		spin_lock_init(ps_lock);
 	INIT_WORK(&sta->drv_unblock_wk, sta_unblock);
 	INIT_WORK(&sta->ampdu_mlme.work, ieee80211_ba_session_work);
 	mutex_init(&sta->ampdu_mlme.mtx);
```

Patched code can reference the shadow variable associated with a given `struct
sta_info` to determine and apply the correct locking semantic for that
instance:
```patch
diff --git a/net/mac80211/tx.c b/net/mac80211/tx.c
index 97a02d3f7d87..0edb0ed8dc60 100644
--- a/net/mac80211/tx.c
+++ b/net/mac80211/tx.c
@@ -459,12 +459,15 @@ static int ieee80211_use_mfp(__le16 fc, struct sta_info *sta,
 	return 1;
 }
 
+#include <linux/livepatch.h>
+#define KPATCH_SHADOW_PS_LOCK 2
 static ieee80211_tx_result
 ieee80211_tx_h_unicast_ps_buf(struct ieee80211_tx_data *tx)
 {
 	struct sta_info *sta = tx->sta;
 	struct ieee80211_tx_info *info = IEEE80211_SKB_CB(tx->skb);
 	struct ieee80211_local *local = tx->local;
+	spinlock_t *ps_lock;
 
 	if (unlikely(!sta))
 		return TX_CONTINUE;
@@ -478,6 +481,23 @@ ieee80211_tx_h_unicast_ps_buf(struct ieee80211_tx_data *tx)
 		       sta->sta.addr, sta->sta.aid, ac);
 		if (tx->local->total_ps_buffered >= TOTAL_MAX_TX_BUFFER)
 			purge_old_ps_buffers(tx->local);
+
+		/* sync with ieee80211_sta_ps_deliver_wakeup */
+		ps_lock = klp_shadow_get(sta, KPATCH_SHADOW_PS_LOCK);
+		if (ps_lock) {
+			spin_lock(ps_lock);
+			/*
+			 * STA woke up the meantime and all the frames on ps_tx_buf have
+			 * been queued to pending queue. No reordering can happen, go
+			 * ahead and Tx the packet.
+			 */
+			if (!test_sta_flag(sta, WLAN_STA_PS_STA) &&
+			    !test_sta_flag(sta, WLAN_STA_PS_DRIVER)) {
+				spin_unlock(ps_lock);
+				return TX_CONTINUE;
+			}
+		}
+
 		if (skb_queue_len(&sta->ps_tx_buf[ac]) >= STA_MAX_TX_BUFFER) {
 			struct sk_buff *old = skb_dequeue(&sta->ps_tx_buf[ac]);
 			ps_dbg(tx->sdata,
```

Init code changes
-----------------

Any code which runs in an `__init` function or during module or device
initialization is problematic, as it may have already run before the patch was
applied.  The patch may require a pre-patch callback which detects whether such
init code has run, and which rewrites or changes the original initialization to
force it into the desired state.  Some changes involving hardware init are
inherently incompatible with live patching.

Header file changes
-------------------

When changing header files, be extra careful.  If data is being changed, you
probably need to modify the patch.  See "Data struct changes" above.

If a function prototype is being changed, make sure it's not an exported
function.  Otherwise it could break out-of-tree modules.  One way to
workaround this is to define an entirely new copy of the function (with
updated code) and patch in-tree callers to invoke it rather than the
deprecated version.

Many header file changes result in a complete rebuild of the kernel tree, which
makes kpatch-build have to compare every .o file in the kernel.  It slows the
build down a lot, and can even fail to build if kpatch-build has any bugs
lurking.  If it's a trivial header file change, like adding a macro, it's
advisable to just move that macro into the .c file where it's needed to avoid
changing the header file at all.

Dealing with unexpected changed functions
-----------------------------------------

In general, it's best to patch as minimally as possible.  If kpatch-build is
reporting some unexpected function changes, it's always a good idea to try to
figure out why it thinks they changed.  In many cases you can change the source
patch so that they no longer change.

Some examples:

* If a changed function was inlined, then the callers which inlined the
  function will also change.  In this case there's nothing you can do to
  prevent the extra changes.

* If a changed function was originally inlined, but turned into a callable
  function after patching, consider adding `__always_inline` to the function
  definition.  Likewise, if a function is only inlined after patching,
  consider using `noinline` to prevent the compiler from doing so.

* If your patch adds a call to a function where the original version of the
  function's ELF symbol has a .constprop or .isra suffix, and the corresponding
  patched function doesn't, that means the patch caused gcc to no longer
  perform an interprocedural optimization, which affects the function and all
  its callers.  If you want to prevent this from happening, copy/paste the
  function with a new name and call the new function from your patch.

* Moving around source code lines can introduce unique instructions if any
  `__LINE__` preprocessor macros are in use. This can be mitigated by adding
  any new functions to the bottom of source files, using newline whitespace to
  maintain original line counts, etc. A more exact fix can be employed by
  modifying the source code that invokes `__LINE__` and hard-coding the
  original line number in place.  This occurred in issue #1124 for example.

Removing references to static local variables
---------------------------------------------

Removing references to static locals will fail to patch unless extra steps are taken.
Static locals are basically global variables because they outlive the function's
scope. They need to be correlated so that the new function will use the old static
local. That way patching the function doesn't inadvertently reset the variable
to zero; instead the variable keeps its old value.

To work around this limitation one needs to retain the reference to the static local.
This might be as simple as adding the variable back in the patched function in a 
non-functional way and ensuring the compiler doesn't optimize it away.

Code removal
------------

Some fixes may replace or completely remove functions and references
to them. Remember that kpatch modules can only add new functions and
redirect existing functions, so "removed" functions will continue to exist in
kernel address space as effectively dead code.

That means this patch (source code removal of `cmdline_proc_show`):
```patch
diff -Nupr src.orig/fs/proc/cmdline.c src/fs/proc/cmdline.c
--- src.orig/fs/proc/cmdline.c	2016-11-30 19:39:49.317737234 +0000
+++ src/fs/proc/cmdline.c	2016-11-30 19:39:52.696737234 +0000
@@ -3,15 +3,15 @@
 #include <linux/proc_fs.h>
 #include <linux/seq_file.h>
 
-static int cmdline_proc_show(struct seq_file *m, void *v)
-{
-	seq_printf(m, "%s\n", saved_command_line);
-	return 0;
-}
+static int cmdline_proc_show_v2(struct seq_file *m, void *v)
+{
+	seq_printf(m, "%s kpatch\n", saved_command_line);
+	return 0;
+}
 
 static int cmdline_proc_open(struct inode *inode, struct file *file)
 {
-	return single_open(file, cmdline_proc_show, NULL);
+	return single_open(file, cmdline_proc_show_v2, NULL);
 }
 
 static const struct file_operations cmdline_proc_fops = {
```
will generate an equivalent kpatch module to this patch (dead
`cmdline_proc_show` left in source):
```patch
diff -Nupr src.orig/fs/proc/cmdline.c src/fs/proc/cmdline.c
--- src.orig/fs/proc/cmdline.c	2016-11-30 19:39:49.317737234 +0000
+++ src/fs/proc/cmdline.c	2016-11-30 19:39:52.696737234 +0000
@@ -9,9 +9,15 @@ static int cmdline_proc_show(struct seq_
 	return 0;
 }
 
+static int cmdline_proc_show_v2(struct seq_file *m, void *v)
+{
+	seq_printf(m, "%s kpatch\n", saved_command_line);
+	return 0;
+}
+
 static int cmdline_proc_open(struct inode *inode, struct file *file)
 {
-	return single_open(file, cmdline_proc_show, NULL);
+	return single_open(file, cmdline_proc_show_v2, NULL);
 }
 
 static const struct file_operations cmdline_proc_fops = {
```
In both versions, `kpatch-build` will determine that only
`cmdline_proc_open` has changed and that `cmdline_proc_show_v2` is a
new function.

In some patching cases it might be necessary to completely remove the original
function to avoid the compiler complaining about a defined, but unused
function.  This will depend on symbol scope and kernel build options.

"Once" macros
-------------

When adding a call to `printk_once()`, `pr_warn_once()`, or any other "once"
variation of `printk()`, you'll get the following eror:

```
ERROR: vmx.o: 1 unsupported section change(s)
vmx.o: WARNING: unable to correlate static local variable __print_once.60588 used by vmx_update_pi_irte, assuming variable is new
vmx.o: changed function: vmx_update_pi_irte
vmx.o: data section .data..read_mostly selected for inclusion
/usr/lib/kpatch/create-diff-object: unreconcilable difference
```
This error occurs because the `printk_once()` adds a static local variable to
the `.data..read_mostly` section.  kpatch-build strict disallows any changes to
that section, because in some cases a change to this section indicates a bug.

To work around this issue, you'll need to manually implement your own "once"
logic which doesn't store the static variable in the `.data..read_mostly`
section.

For example, a `pr_warn_once()` can be replaced with:
```c
	static bool print_once;
	...
	if (!print_once) {
		print_once = true;
		pr_warn("...");
	}
```

inline implies notrace
----------------------

The linux kernel defines its own version of "inline" in
include/linux/compiler_types.h which includes "notrace" as well:

```c
#if !defined(CONFIG_OPTIMIZE_INLINING)
#define inline inline __attribute__((__always_inline__)) __gnu_inline \
        __inline_maybe_unused notrace
#else
#define inline inline                                    __gnu_inline \
        __inline_maybe_unused notrace
#endif
```

With the implicit "notrace", use of "inline" in patch sources may lead
to kpatch-build errors like the following:

1. `__tcp_mtu_to_mss()` is marked as inline:

```c
net/ipv4/tcp_output.c:

/* Calculate MSS not accounting any TCP options.  */
static inline int __tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
```

2. the compiler decides not to inline it and keeps it in its own
   function-section.  Then kpatch-build notices that it doesn't have an
   fentry/mcount call:

```console
% kpatch-build ...

tcp_output.o: function __tcp_mtu_to_mss has no fentry/mcount call, unable to patch
```

3. a peek at the generated code:

```c
Disassembly of section .text.__tcp_mtu_to_mss:

0000000000000000 <__tcp_mtu_to_mss>:
   0:   48 8b 87 60 05 00 00    mov    0x560(%rdi),%rax
   7:   0f b7 50 30             movzwl 0x30(%rax),%edx
   b:   0f b7 40 32             movzwl 0x32(%rax),%eax
   f:   29 d6                   sub    %edx,%esi
  11:   83 ee 14                sub    $0x14,%esi
  ...
```

This could be a little confusing since one might have expected to see
changes to all of `__tcp_mtu_to_mss()` callers (ie, it was inlined as
requested).  In this case, a simple workaround is to specify
`__tcp_mtu_to_mss()` as `__always_inline` to force the compiler to do so.

Jump labels and static calls
----------------------------

### Late module patching vs special section relocations

Jump labels and static calls can be problematic due to "late module patching",
which is a feature (design flaw?) in upstream livepatch.  When a livepatch
module patches another module, unfortunately the livepatch module doesn't have
an official module dependency on the patched module.  That means the patched
module doesn't even have to be loaded when the livepatch module gets loaded.
In that case the patched module gets patched on demand whenever it might get
loaded in the future.  It also gets unpatched on demand whenever it gets
unloaded.

Loading (and patching) the module at some point after loading the livepatch
module is called "late module patching".  In order to support this
(mis?)feature, all relocations in the livepatch module which reference module
symbols must be converted to "klp relocations", which get resolved at patching
time.

In all modules (livepatch and otherwise), jump labels and static calls rely on
special sections which trigger jump-label/static-call code patching when a
module gets loaded.  But unfortunately those special sections have relocations
which need to get resolved, so there's an ordering issue.

When a (livepatch) module gets loaded, first its relocations are resolved, then
its special section handling (and code patching) is done.  The problem is, for
klp relocations, if they reference another module's symbols, and that module
isn't loaded, they're not yet defined.  So if a `.static_call_sites` entry
tries to reference its corresponding `struct static_call_key`, but that key
lives in another module which is not yet loaded, the key reference won't be
resolved, and so `mod->static_call_sites` will be corrupted when
`static_call_module_notify()` runs when the livepatch module first loads.

### Jump labels

With pre-5.8 kernels, kpatch-build will error out if it encounters any jump
labels:
```
oom_kill.o: Found a jump label at out_of_memory()+0x10a, using key cpusets_enabled_key.  Jump labels aren't supported with this kernel.  Use static_key_enabled() instead.
```

With Linux 5.8+, klp relocation handling is integrated with the module relocation
code, so jump labels in patched functions are supported when the static key was
originally defined in the kernel proper (vmlinux).

However, if the static key lives in a module, jump labels are _not_ supported
in patched code, due to the ordering issue described above.  If the jump label
is a tracepoint, kpatch-build will silently remove the tracepoint.  Otherwise,
there will be an error:
```
vmx.o: Found a jump label at vmx_hardware_enable.cold()+0x23, using key enable_evmcs, which is defined in a module.  Use static_key_enabled() instead.
```

When you get one of the above errors, the fix is to remove the jump label usage
in the patched function, replacing it with a regular C conditional.

This can be done by replacing any usages of `static_branch_likely()`,
`static_branch_unlikely()`, `static_key_true()`, and `static_key_false()` with
`static_key_enabled()` in the patch file.

### Static calls

Similarly, static calls are not supported when the corresponding static call
key was originally defined in a module.  If such a static call is part of a
tracepoint, kpatch-build will silently remove it.  Otherwise, there will be an
error:
```
cpuid.o: Found a static call at kvm_set_cpuid.cold()+0x32c, using key __SCK__kvm_x86_vcpu_after_set_cpuid, which is defined in a module.  Use KPATCH_STATIC_CALL() instead.
```

To fix this error, simply replace such static calls with regular indirect
branches (or retpolines, if applicable) by adding `#include "kpatch-macros.h"`
to the patch source and replacing usages of `static_call()` with
`KPATCH_STATIC_CALL()`.

Sibling calls
-------------

GCC may generate sibling calls that are incompatible with kpatch, resulting in
an error like: `ERROR("Found an unsupported sibling call at foo()+0x123.  Add __attribute__((optimize("-fno-optimize-sibling-calls"))) to foo() definition."`

For example, if function A() calls function B() at the end of A() and both
return similar data-types, GCC may deem them "sibling calls" and apply a tail
call optimization in which A() restores the stack to is callee state before
setting up B()'s arguments and jumping to B().

This may be an issue for kpatches on PowerPC which modify only A() or B() and
the function call crosses a kernel module boundary: the sibling call
optimization has changed expected calling conventions and (un)patched code may
not be similarly modified.

Commit [8b952bd77130](https://github.com/dynup/kpatch/commit/8b952bd77130)
("create-diff-object/ppc64le: Don't allow sibling calls") contains an
excellent example and description of this problem with annotated disassembly.

Adding `__attribute__((optimize("-fno-optimize-sibling-calls")))` instructs
GCC to turn off the optimization for the given function.

Exported symbol versioning
--------------------------

### Background

`CONFIG_MODVERSIONS` enables an ABI check between exported kernel symbols and
modules referencing those symbols, enforced on module load.  When building the
kernel, preprocessor output from `gcc -E` for each source file is passed to
scripts/genksyms.  The genksyms script recursively expands each exported symbol
to its basic types.  A hash is generated for each symbol as it traverses back up
the symbol tree.  The end result is a CRC for each exported function in
the Module.symvers file and embedded in the vmlinux kernel object itself.

A similar checksumming is performed when building modules: referenced exported
symbol CRCs are stored in the module’s `__versions` section (you can also find
these in plain-text intermediate \*.mod.c files.)

When the kernel loads a module, the symbol CRCs found in its `__versions` are
compared to those of the kernel, if the two do not match, the kernel will refuse
to load it:
```
<module>: disagrees about version of symbol <symbol>
<module>: Unknown symbol <symbol> (err -22)
```

### Kpatch detection

After building the original and patched sources, kpatch-build compares the
newly calculated Module.symvers against the original.  Discrepancies are
reported:

```
ERROR: Version disagreement for symbol <symbol>
```

These reports should be addressed to ensure that the resulting kpatch module
can be loaded.

#### False positives

It is rare, but possible for a kpatch to introduce inadvertent symbol CRC
changes that are not true ABI changes.  The following conditions must occur:

1. The kpatch must modify the definition of an exported symbol.  For example,
   introducing a new header file may further define an opaque data type:
   Before the kpatch, compilation unit U from the original kernel build only
   knew about a `struct S` declaration (not its complete type).  At the same
   time, U contains function F, which has an interface that references S.  If
   the kpatch adds a header file to U that now fully defines `struct S { int
   a, b, c; }`, its symbol type graph changes, CRCs generated for F are updated,
   but its ABI remains consistent.

2. The kpatch must introduce either a change or reference to F such that it is
   included in the resulting kpatch module.  This will force a `__version`
   entry based on the new CRC.

   Note: if a kpatch doesn't change or reference F such that it is **not**
   included in the resulting kpatch module, the new CRC value won't be added
   to the module's `__version` table.  However, if a future accumulative patch
   does add a new change or reference to F, the new CRC will become a problem.

#### Avoidance

Kpatches should introduce new `#include` directives sparingly.  Whenever
possible, extract the required definitions from header filers into kpatched
compilation units directly.

If additional header files or symbol definitions cannot be avoided, consider
surrounding the offending include/definitions in an `#ifndef __GENKSYMS__`
macro.  The genksyms script will skip over those blocks when performing its CRC
calculations.

### But what about a real ABI change?

If a kpatch introduces a true ABI change, each of calling functions would
consequently need to be updated in the kpatch module.  For unexported functions,
this may be handled safely if the kpatch does indeed update all callers.
However, since motivation behind `CONFIG_MODVERSIONS` is to provide basic ABI
verification between the kernel and modules for  **exported** functions, kpatch
cannot safely change this ABI without worrying about breaking other out-of-tree
drivers.  Those drivers have been built against the reference kernel's original
set of CRCs and expect the original ABI.

To track down specifically what caused a symbol CRC change, tools like
[kabi-dw](https://github.com/skozina/kabi-dw) can be employed to produce a
detailed symbol definition report.  For a kpatch-build, kabi-dw can be modified
to operate on .o object files (not just .ko and vmlinux files) and the
`$CACHEDIR/tmp/{orig, patched}` directories compared.

System calls
------------

Attempting to patch a syscall typically results in an error, due to a missing
fentry hook in the inner `__do_sys##name()` function.  The fentry hook is
missing because of the 'inline' annotation, which invokes 'notrace'.

This problem can be worked around by adding `#include "kpatch-syscall.h"` and
replacing the use of the `SYSCALL_DEFINE1` (or similar) macro with the
`KPATCH_` prefixed version.

Symbol Namespaces
-----------------

While kpatch modules automatically inherit namespace imports from
already-patched object files, a manual import may be required when
patching kernel code that is normally built-in.

The original built-in code doesn't need to explicitly import namespaces.
However, when converted into a kpatch module, it must declare any namespace
dependencies. Without this explicit import, the kpatch-build command will fail
with modpost errors for using symbols from a namespace without importing
it, i.e.
```
ERROR: modpost: module livepatch-test uses symbol dma_buf_export from namespace DMA_BUF, but does not import it.
```
To manually import the required namespace, add the MODULE_IMPORT_NS() macro to
the patch source. For example: `MODULE_IMPORT_NS("DMA_BUF")`

Cross Compile
-------------

It is recommended to build the livepatch in the same environment (compiler/library/etc.) as
the target kernel. When the target kernel was cross compiled for a different architecture,
it is recommended to cross compile the livepatch.

There are two options to cross compile a livepatch.

To specify a separate set of cross compilers,
we can set the `CROSS_COMPILE` environment variable. For example, to use `aarch64-gcc` and `aarch64-ld`,
we can run kpatch-build as
```
CROSS_COMPILE=aarch64- kpatch-build ...
```

llvm/clang supports cross compile with the same binaries. To specify a cross compile target, we can
use the TARGET_ARCH environment variable, for example:
```
TARGET_ARCH=aarch64 kpatch-build ...
```
