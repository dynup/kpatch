kpatch: dynamic kernel patching
===============================

kpatch is a Linux dynamic kernel patching infrastructure which allows you to
patch a running kernel without rebooting or restarting any processes.  It
enables sysadmins to apply critical security patches to the kernel immediately,
without having to wait for long-running tasks to complete, for users to log
off, or for scheduled reboot windows.  It gives more control over uptime
without sacrificing security or stability.

**WARNING: Use with caution!  Kernel crashes, spontaneous reboots, and data loss
may occur!**

Here's a video of kpatch in action:

[![kpatch video](https://img.youtube.com/vi/juyQ5TsJRTA/0.jpg)](https://www.youtube.com/watch?v=juyQ5TsJRTA)

And a few more:

- https://www.youtube.com/watch?v=rN0sFjrJQfU
- https://www.youtube.com/watch?v=Mftc80KyjA4

Table of contents
=================

- [Supported Architectures](#supported-architectures)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Patch Author Guide](#patch-author-guide)
- [How it works](#how-it-works)
	- [kpatch-build](#kpatch-build)
- [Limitations](#limitations)
- [Frequently Asked Questions](#frequently-asked-questions)
- [Get involved](#get-involved)
- [License](#license)


Supported Architectures
-----------------------

- [x] x86-64
- [x] ppc64le
- [x] arm64 [upstream prerequisites](doc/arm64-upstream-prerequisites.md)
- [x] s390 [upstream prerequisites](doc/s390-upstream-prerequisites.md)

Installation
------------

See [INSTALL.md](doc/INSTALL.md).


Quick start
-----------

> NOTE: While kpatch is designed to work with any recent Linux
kernel on any distribution, `kpatch-build` has specifically been tested and
confirmed to work on Fedora and RHEL.  It has also been known to work on Oracle
Linux, Ubuntu, Debian, and Gentoo.

First, make a source code patch against the kernel tree using diff, git, or
quilt.

As a contrived example, let's patch /proc/meminfo to show VmallocChunk in ALL
CAPS so we can see it better:

    $ cat meminfo-string.patch
    Index: src/fs/proc/meminfo.c
    ===================================================================
    --- src.orig/fs/proc/meminfo.c
    +++ src/fs/proc/meminfo.c
    @@ -95,7 +95,7 @@ static int meminfo_proc_show(struct seq_
     		"Committed_AS:   %8lu kB\n"
     		"VmallocTotal:   %8lu kB\n"
     		"VmallocUsed:    %8lu kB\n"
    -		"VmallocChunk:   %8lu kB\n"
    +		"VMALLOCCHUNK:   %8lu kB\n"
     #ifdef CONFIG_MEMORY_FAILURE
     		"HardwareCorrupted: %5lu kB\n"
     #endif

Build the patch module:

    $ kpatch-build meminfo-string.patch
    Using cache at /home/jpoimboe/.kpatch/3.13.10-200.fc20.x86_64/src
    Testing patch file
    checking file fs/proc/meminfo.c
    Building original kernel
    Building patched kernel
    Detecting changed objects
    Rebuilding changed objects
    Extracting new and modified ELF sections
    meminfo.o: changed function: meminfo_proc_show
    Building patch module: livepatch-meminfo-string.ko
    SUCCESS

That outputs a patch module named `kpatch-meminfo-string.ko` in the current
directory.  Now apply it to the running kernel:

    $ sudo kpatch load kpatch-meminfo-string.ko
    loading patch module: livepatch-meminfo-string.ko

Done!  The kernel is now patched.

    $ grep -i chunk /proc/meminfo
    VMALLOCCHUNK:   34359337092 kB


Patch author guide
------------------

Unfortunately, live patching isn't always as easy as the previous example, and
can have some major pitfalls if you're not careful.  To learn more about how to
properly create live patches, see the [Patch Author
Guide](doc/patch-author-guide.md).


How it works
------------

kpatch works at a function granularity: old functions are replaced with new
ones.  It has three main components:

- **kpatch-build**: a collection of tools which convert a source diff patch to
  a patch module.  They work by compiling the kernel both with and without
  the source patch, comparing the binaries, and generating a patch module
  which includes new binary versions of the functions to be replaced.

- **patch module**: a kernel livepatch module (.ko file) which includes the
  replacement functions and metadata about the original functions.  Upon
  loading, it registers itself with the kernel livepatch infrastructure
  (CONFIG\_LIVEPATCH) which does the patching.

- **kpatch utility:** a command-line tool which allows a user to manage a
  collection of patch modules.  One or more patch modules may be
  configured to load at boot time, so that a system can remain patched
  even after a reboot into the same version of the kernel.


### kpatch-build

The "kpatch-build" command converts a source-level diff patch file to a kernel
patch module.  Most of its work is performed by the kpatch-build script
which uses a utility named `create-diff-object` to compare changed objects.

The primary steps in kpatch-build are:
- Build the unstripped vmlinux for the kernel
- Patch the source tree
- Rebuild vmlinux and monitor which objects are being rebuilt.
  These are the "changed objects".
- Recompile each changed object with `-ffunction-sections -fdata-sections`,
  resulting in the changed patched objects
- Unpatch the source tree
- Recompile each changed object with `-ffunction-sections -fdata-sections`,
  resulting in the changed original objects
- For every changed object, use `create-diff-object` to do the following:
	* Analyze each original/patched object pair for patchability
	* Add `.kpatch.funcs` and `.rela.kpatch.funcs` sections to the output object.
	The kpatch core module uses this to determine the list of functions
	that need to be redirected using ftrace.
	* Add `.kpatch.dynrelas` and `.rela.kpatch.dynrelas` sections to the output object.
	This will be used to resolve references to non-included local
	and non-exported global symbols. These relocations will be resolved by the kpatch core module.
	* Generate the resulting output object containing the new and modified sections
- Link all the output objects into a cumulative object
- Generate the patch module


Limitations
-----------

- NOTE: Many of these limitations can be worked around with creative solutions.
  For more details, see the [Patch Author Guide](doc/patch-author-guide.md).

- Patches which modify init functions (annotated with `__init`) are not
  supported.  kpatch-build will return an error if the patch attempts
  to do so.

- Patches which modify statically allocated data are not directly supported.
  kpatch-build will detect that and return an error.  This limitation can be
  overcome by using callbacks or shadow variables, as described in the
  [Patch Author Guide](doc/patch-author-guide.md).

- Patches which change the way a function interacts with dynamically
  allocated data might be safe, or might not.  It isn't possible for
  kpatch-build to verify the safety of this kind of patch.  It's up to
  the user to understand what the patch does, whether the new functions
  interact with dynamically allocated data in a different way than the
  old functions did, and whether it would be safe to atomically apply
  such a patch to a running kernel.

- Patches which modify functions in vdso are not supported.  These run in
  user-space and ftrace can't hook them.

- Patches which modify functions that are missing a `fentry` call are not
  supported.  This includes any `lib-y` targets that are archived into a
  `lib.a` library for later linking (for example, `lib/string.o`).

- Some incompatibilities currently exist between kpatch and usage of ftrace and
  kprobes.  See the Frequently Asked Questions section for more details.


Frequently Asked Questions
--------------------------

**Q. Isn't this just a virus/rootkit injection framework?**

kpatch uses kernel modules to replace code.  It requires the `CAP_SYS_MODULE`
capability.  If you already have that capability, then you already have the
ability to arbitrarily modify the kernel, with or without kpatch.

**Q. How can I detect if somebody has patched the kernel?**

If a patch is currently applied, you can see it in `/sys/kernel/livepatch`.

Also, if a patch has been previously applied, the `TAINT_LIVEPATCH` flag is
set.  To test for these flags, `cat /proc/sys/kernel/tainted` and check to see
if the value of `TAINT_LIVEPATCH` (32768) has been OR'ed in.

Note that the `TAINT_OOT_MODULE` flag (4096) will also be set, since the patch
module is built outside the Linux kernel source tree.

If your patch module is unsigned, the `TAINT_UNSIGNED_MODULE` flag (8192) will
also be set.

**Q. Will it destabilize my system?**

No, as long as the patch is created carefully.  See the Limitations section
above and the [Patch Author Guide](doc/patch-author-guide.md).

**Q. Why not use something like kexec instead?**

If you want to avoid a hardware reboot, but are ok with restarting processes or
using CRIU, kexec is a good alternative.

**Q. If an application can't handle a reboot, it's designed wrong.**

That's a good poi... [system reboots]

**Q. What kernels are supported?**

kpatch needs gcc >= 4.8 and Linux >= 4.0.

**Q. Is it possible to remove a patch?**

Yes.  Just run `kpatch unload` which will disable and unload the patch module
and restore the function to its original state.

**Q. Can you apply multiple patches?**

Yes, but to prevent any unexpected interactions between multiple patch modules,
it's recommended that patch upgrades are cumulative, so that each patch is a
superset of the previous patch.  This can be achieved by combining the new
patch with the previous patch using `combinediff` before running
`kpatch-build`.  It's also recommended to use livepatch atomic "replace" mode,
which is the default.

**Q. Why did kpatch-build detect a changed function that wasn't touched by the
source patch?**

There could be a variety of reasons for this, such as:

- The patch changed an inline function.
- The compiler decided to inline a changed function, resulting in the outer
  function getting recompiled.  This is common in the case where the inner
  function is static and is only called once.
- A bug in kpatch-build's detection of `__LINE__` macro usage.

**Q. Are patching of kernel modules supported?**

- Yes.

**Q. Can you patch out-of-tree modules?**

Yes! There's a few requirements, and the feature is still in its infancy.

1. You need to use the `--oot-module` flag to specify the version of the
module that's currently running on the machine.
2. `--oot-module-src` has to be passed with a directory containing the same
version of code as the running module, all set up and ready to build with a
`make` command. For example, some modules need `autogen.sh` and
`./configure` to have been run with the appropriate flags to match the
currently-running module.
3. If the `Module.symvers` file for the out-of-tree module doesn't appear
in the root of the provided source directory, a symlink needs to be created
in that directory that points to its actual location.
4. Usually you'll need to pass the `--target` flag as well, to specify the
proper `make` target names.
5. This has only been tested for a single out-of-tree module per patch, and
not for out-of-tree modules with dependencies on other out-of-tree modules
built separately.

***Sample invocation***

`kpatch-build --oot-module-src ~/test/ --target default --oot-module /lib/modules/$(uname -r)/extra/test.ko test.patch`


**Q. What is needed to support a new architecture?**

Porting an architecture can be done in three phases:

1. In the kernel, add `CONFIG_HAVE_LIVEPATCH` support. For some arches
this might be as simple as enabling `CONFIG_DYNAMIC_FTRACE_WITH REGS`.
With this support you can do basic live patches like those in
samples/livepatch. Livepatch functionality is limited and extra care
must be taken to avoid certain pitfalls.
2. Add kpatch-build (create-diff-object) support. This makes it easier
to build patches, and avoids some of the pitfalls.  For example,
https://github.com/dynup/kpatch/pull/1203 added s390x support.
3. Add `CONFIG_HAVE_RELIABLE_STACKTRACE` and (if needed) objtool
support in the kernel. This avoids more pitfalls and enables full
livepatch functionality.


Get involved
------------

If you have questions or feedback, join the #kpatch IRC channel on
[Libera](https://libera.chat) and say hi.

Contributions are very welcome.  Feel free to open issues or PRs on github.
For big PRs, it's a good idea to discuss them first in github
issues/discussions or on IRC before you write a lot of code.


License
-------

kpatch is under the GPLv2 license.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
