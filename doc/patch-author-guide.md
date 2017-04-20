kpatch Patch Author Guide
=========================

Because kpatch-build is relatively easy to use, it can be easy to assume that a
successful patch module build means that the patch is safe to apply.  But in
fact that's a very dangerous assumption.

There are many pitfalls that can be encountered when creating a live patch.
This document attempts to guide the patch creation process.  It's a work in
progress.  If you find it useful, please contribute!

Patch Analysis
--------------

kpatch provides _some_ guarantees, but it does not guarantee that all patches
are safe to apply.  Every patch must also be analyzed in-depth by a human.

The most important point here cannot be stressed enough.  Here comes the bold:

**Do not blindly apply patches.  There is no subsitute for human analysis and
reasoning on a per-patch basis.  All patches must be thoroughly analyzed by a
human kernel expert who completely understands the patch and the affected code
and how they relate to the live patching environment.**

kpatch vs livepatch vs kGraft
-----------------------------

This document assumes that the kpatch core module is being used.  Other live
patching systems (e.g., livepatch and kGraft) have different consistency
models.  Each comes with its own guarantees, and there are some subtle
differences.  The guidance in this document applies **only** to kpatch.

Patch upgrades
--------------

Due to potential unexpected interactions between patches, it's highly
recommended that when patching a system which has already been patched, the
second patch should be a cumulative upgrade which is a superset of the first
patch.

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

```
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

```
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

```
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
kpatch creates a barrier between the calling of old functions and new
functions.

### Use a kpatch load hook

If you need to change the contents of an existing variable in-place, you can
use the `KPATCH_LOAD_HOOK` macro to specify a function to be called when the
patch module is loaded.

`kpatch-macros.h` provides `KPATCH_LOAD_HOOK` and `KPATCH_UNLOAD_HOOK` macros
to define such functions.  The signature of both hook functions is `void
foo(void)`.  Their execution context is as follows:

* For patches to vmlinux or already loaded kernel modules, hook functions
will be run by `stop_machine` as part of applying or removing a patch.
(Therefore the hooks must not block or sleep.)

* For patches to kernel modules which haven't been loaded yet, a
module-notifier will execute load hooks when the associated module is loaded
into the `MODULE_STATE_COMING` state.  The load hook is called before any
module_init code.

Example: a kpatch fix for CVE-2016-5389 utilized the `KPATCH_LOAD_HOOK` and
`KPATCH_UNLOAD_HOOK` macros to modify variable `sysctl_tcp_challenge_ack_limit`
in-place:

```
+static bool kpatch_write = false;
+void kpatch_load_tcp_send_challenge_ack(void)
+{
+	if (sysctl_tcp_challenge_ack_limit == 100) {
+		sysctl_tcp_challenge_ack_limit = 1000;
+		kpatch_write = true;
+	}
+}
+void kpatch_unload_tcp_send_challenge_ack(void)
+{
+	if (kpatch_write && sysctl_tcp_challenge_ack_limit == 1000)
+		sysctl_tcp_challenge_ack_limit = 100;
+}
+#include "kpatch-macros.h"
+KPATCH_LOAD_HOOK(kpatch_load_tcp_send_challenge_ack);
+KPATCH_UNLOAD_HOOK(kpatch_unload_tcp_send_challenge_ack);
```

Don't forget to protect access to the data as needed.

Also be careful when upgrading.  If patch A has a load hook which writes to X,
and then you load patch B which is a superset of A, in some cases you may want
to prevent patch B from writing to X, if A is already loaded.


### Use a shadow variable

If you need to add a field to an existing data structure, or even many existing
data structures, you can use the `kpatch_shadow_*()` functions:

* `kpatch_shadow_alloc` - allocates a new shadow variable associated with a
  given object
* `kpatch_shadow_get` - find and return a pointer to a shadow variable
* `kpatch_shadow_free` - find and free a shadow variable

Example: The `shadow-newpid.patch` integration test demonstrates the usage of
these functions.

A shadow PID variable is allocated in `do_fork()` : it is associated with the
current `struct task_struct *p` value, given a string lookup key of "newpid",
sized accordingly, and allocated as per `GFP_KERNEL` flag rules.

`kpatch_shadow_alloc` returns a pointer to the shadow variable, so we can
dereference and make assignments as usual.  In this patch chunk, the shadow
`newpid` is allocated then assigned to a rolling `ctr` counter value:
```
+		int *newpid;
+		static int ctr = 0;
+
+		newpid = kpatch_shadow_alloc(p, "newpid", sizeof(*newpid),
+					     GFP_KERNEL);
+		if (newpid)
+			*newpid = ctr++;
```

A shadow variable may also be accessed via `kpatch_shadow_get`.  Here the
patch modifies `task_context_switch_counts()` to fetch the shadow variable
associated with the current `struct task_struct *p` object and a "newpid" tag.
As in the previous patch chunk, the shadow variable pointer may be accessed
as an ordinary pointer type:
```
+	int *newpid;
+
 	seq_put_decimal_ull(m, "voluntary_ctxt_switches:\t", p->nvcsw);
 	seq_put_decimal_ull(m, "\nnonvoluntary_ctxt_switches:\t", p->nivcsw);
 	seq_putc(m, '\n');
+
+	newpid = kpatch_shadow_get(p, "newpid");
+	if (newpid)
+		seq_printf(m, "newpid:\t%d\n", *newpid);
```

A shadow variable is freed by calling `kpatch_shadow_free` and providing
the object / string key combination.  Once freed, the shadow variable is not
safe to access:
```
 	exit_task_work(tsk);
 	exit_thread(tsk);
 
+	kpatch_shadow_free(tsk, "newpid");
+
 	/*
 	 * Flush inherited counters to the parent - before the parent
 	 * gets woken up by child-exit notifications.
```
Notes:
* `kpatch_shadow_alloc` initializes only shadow variable metadata. It
  allocates variable storage via `kmalloc` with the `gfp_t` flags it is
  given, but otherwise leaves the area untouched. Initialization of a shadow
  variable is the responsibility of the caller.
* As soon as `kpatch_shadow_alloc` creates a shadow variable, its presence
  will be reported by `kpatch_shadow_get`. Care should be taken to avoid any
  potential race conditions between a kernel thread that allocates a shadow
  variable and concurrent threads that may attempt to use it.

Data semantic changes
---------------------

Part of the stable-tree [backport](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/commit/fs/aio.c?h=linux-3.10.y&id=6745cb91b5ec93a1b34221279863926fba43d0d7)
to fix CVE-2014-0206 changed the reference count semantic of `struct
kioctx.reqs_active`. Associating a shadow variable to new instances of this
structure can be used by patched code to handle both new (post-patch) and
existing (pre-patch) instances.

(This example is trimmed to highlight this use-case. Boilerplate code is also
required to allocate/free a shadow variable called "reqs_active_v2" whenever a
new `struct kioctx` is created/released. No values are ever assigned to the
shadow variable.)

Shadow variable existence can be verified before applying the new data
semantic of the associated object:
```
@@ -678,6 +688,9 @@ void aio_complete(struct kiocb *iocb, lo
 put_rq:
 	/* everything turned out well, dispose of the aiocb. */
 	aio_put_req(iocb);
+	reqs_active_v2 = kpatch_shadow_get(ctx, "reqs_active_v2");
+	if (reqs_active_v2)
+		atomic_dec(&ctx->reqs_active);
 
 	/*
 	 * We have to order our ring_info tail store above and test
```

Likewise, shadow variable non-existence can be tested to continue applying the
old data semantic:
```
@@ -705,6 +718,7 @@ static long aio_read_events_ring(struct
 	unsigned head, pos;
 	long ret = 0;
 	int copy_ret;
+	int *reqs_active_v2;
 
 	mutex_lock(&ctx->ring_lock);
 
@@ -756,7 +770,9 @@ static long aio_read_events_ring(struct
 
 	pr_debug("%li  h%u t%u\n", ret, head, ctx->tail);
 
-	atomic_sub(ret, &ctx->reqs_active);
+	reqs_active_v2 = kpatch_shadow_get(ctx, "reqs_active_v2");
+	if (!reqs_active_v2)
+		atomic_sub(ret, &ctx->reqs_active);
 out:
 	mutex_unlock(&ctx->ring_lock);
```
 
The previous example can be extended to use shadow variable storage to handle
locking semantic changes.  Consider the [upstream fix](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1d147bfa64293b2723c4fec50922168658e613ba)
for CVE-2014-2706, which added a `ps_lock` to `struct sta_info` to protect
critical sections throughout `net/mac80211/sta_info.c`.

When allocating a new `struct sta_info`, allocate a corresponding "ps_lock"
shadow variable large enough to hold a `spinlock_t` instance, then initialize
the spinlock:
```
@@ -333,12 +336,16 @@ struct sta_info *sta_info_alloc(struct ieee80211_sub_if_data *sdata,
 	struct sta_info *sta;
 	struct timespec uptime;
 	int i;
+	spinlock_t *ps_lock;
 
 	sta = kzalloc(sizeof(*sta) + local->hw.sta_data_size, gfp);
 	if (!sta)
 		return NULL;
 
 	spin_lock_init(&sta->lock);
+	ps_lock = kpatch_shadow_alloc(sta, "ps_lock", sizeof(*ps_lock), gfp);
+	if (ps_lock)
+		spin_lock_init(ps_lock);
 	INIT_WORK(&sta->drv_unblock_wk, sta_unblock);
 	INIT_WORK(&sta->ampdu_mlme.work, ieee80211_ba_session_work);
 	mutex_init(&sta->ampdu_mlme.mtx);
```

Patched code can reference the "ps_lock" shadow variable associated with a
given `struct sta_info` to determine and apply the correct locking semantic
for that instance:
```
@@ -471,6 +475,23 @@ ieee80211_tx_h_unicast_ps_buf(struct ieee80211_tx_data *tx)
 		       sta->sta.addr, sta->sta.aid, ac);
 		if (tx->local->total_ps_buffered >= TOTAL_MAX_TX_BUFFER)
 			purge_old_ps_buffers(tx->local);
+
+		/* sync with ieee80211_sta_ps_deliver_wakeup */
+		ps_lock = kpatch_shadow_get(sta, "ps_lock");
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
applied.  The patch may require a load hook function which detects whether such
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
  original line number in place.

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
```
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
```
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
