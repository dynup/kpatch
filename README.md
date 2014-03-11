kpatch: dynamic kernel patching
===============================

kpatch is a Linux dynamic kernel patching tool which allows you to patch a
running kernel without rebooting or restarting any processes.  It enables
sysadmins to apply critical security patches to the kernel immediately, without
having to wait for long-running tasks to complete, users to log off, or
for scheduled reboot windows.  It gives more control over uptime without
sacrificing security or stability.

kpatch is currently in active development.  For now, it should _not_ be used
in production environments.

**WARNING: Use with caution!  Kernel crashes, spontaneous reboots, and data loss
may occur!**


Installation
------------

*NOTE: These installation instructions are currently Fedora-specific.  Support
for other distributions is planned soon.*

Install the dependencies for compiling kpatch:

    sudo yum install gcc kernel-devel elfutils elfutils-devel

*NOTE: Ensure you have elfutils-0.158 or newer.*

Install the dependencies for the "kpatch-build" command:

    sudo yum install rpmdevtools pesign
    sudo yum-builddep kernel

    # optional, but highly recommended
    sudo yum install ccache

Compile kpatch:

    make

Install kpatch to /usr/local:

    sudo make install


Quick start
-----------

*NOTE: While kpatch is designed to work with any recent Linux
kernel on any distribution, the "kpatch-build" command currently
only works on Fedora.*

Load the kpatch core module:

    sudo insmod /usr/local/lib/modules/$(uname -r)/kpatch/kpatch.ko

Make a source patch against the kernel tree:

    # from a kernel git tree:
    git diff > /path/to/foo.patch

Build the hot patch kernel module:

    kpatch-build /path/to/foo.patch

This outputs a hot patch module named `kpatch-foo.ko` in the current
directory.  Now apply it to the running kernel:

    sudo insmod kpatch-foo.ko

Done!  The kernel is now patched.


How it works
------------

kpatch works at a function granularity: old functions are replaced with new
ones.  It has four main components:

- **kpatch-build**: a collection of tools which convert a source diff patch to
  a hot patch module.  They work by compiling the kernel both with and without
  the source patch, comparing the binaries, and generating a hot patch module
  which includes new binary versions of the functions to be replaced.

- **hot patch module**: a kernel module (.ko file) which includes the
  replacement functions and metadata about the original functions.

- **kpatch core module**: a kernel module (.ko file) which provides an
  interface for the hot patch modules to register new functions for
  replacement.  It uses the kernel ftrace subsystem to hook into the original
  function's mcount call instruction, so that a call to the original function
  is redirected to the replacement function.

- **kpatch utility:** a command-line tool which allows a user to manage a
  collection of hot patch modules.  One or more hot patch modules may be
  configured to load at boot time, so that a system can remain patched
  even after a reboot into the same version of the kernel.


### kpatch-build

The "kpatch-build" command converts a source-level diff patch file to a hot
patch kernel module.  Most of its work is performed by the kpatch-build script
which uses a collection of utilities: `create-diff-object`,
`add-patch-section`, and `link-vmlinux-syms`.

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
- Use `create-diff-object` to analyze each original/patched object pair
  for patchability and generate an output object containing modified
  sections
- Link all the output objects into a cumulative object
- Use `add-patches-section` to add the .patches section that the
  core kpatch module uses to determine the list of functions that need
  to be redirected using ftrace
- Generate the patch kernel module
- Use `link-vmlinux-syms` to hardcode non-exported kernel symbols
  into the symbol table of the patch kernel module

### Patching

The hot patch kernel modules register with the core module (`kpatch.ko`).
They provide information about original functions that need to be replaced, and
corresponding function pointers to the replacement functions.

The kpatch core module registers a trampoline function with ftrace.  The
trampoline function is called by ftrace immediately before the original
function begins executing.  This occurs with the help of the reserved mcount
call at the beginning of every function, created by the gcc `-mfentry` flag.
The trampoline function then modifies the return instruction pointer (IP)
address on the stack and returns to ftrace, which then restores the original
function's arguments and stack, and "returns" to the new function.


Limitations
-----------

- kpatch can't detect when a patch changes the contents of a dynamically
  allocated data structure, and isn't able to determine whether such patches
  are safe to apply.  It's the user's responsibility to analyze any such
  patches for safety before applying them.
- Patches which change the contents of static data structures are not currently
  supported.  kpatch-build will detect such changes and report an error.
- Patches to functions which are always in the call stack of a task, such as
  schedule(), will fail to apply at runtime.
- Patches which change functions that are only called in the kernel init path
  will have no effect (obviously).
- Currently, kernel module functions can't be patched -- only functions in the
  base kernel image.


Frequently Asked Questions
--------------------------

**Q. Isn't this just a virus/rootkit injection framework?**

kpatch uses kernel modules to replace code.  It requires the `CAP_SYS_MODULE`
capability.  If you already have that capability, then you already have the
ability to arbitrarily modify the kernel, with or without kpatch.

**Q. How can I detect if somebody has patched the kernel?**

We hope to create a new kernel TAINT flag which will get set whenever a kpatch
module is loaded.

Also, many distros ship with cryptographically signed kernel modules, and will
taint the kernel anyway if you load an unsigned module.

**Q. Will it destabilize my system?**

No, as long as the patch is chosen carefully.  See the Limitations section
above.

**Q. Why does kpatch use ftrace to jump to the replacement function instead of
adding the jump directly?**

ftrace owns the first "call mcount" instruction of every kernel function.  In
order to keep compatibility with ftrace, we go through ftrace rather than
updating the instruction directly.

**Q Is kpatch compatible with \<insert kernel debugging subsystem here\>?**

We aim to be good kernel citizens and maintain compatibility.  A hot patch
replacement function is no different than a function loaded by any other kernel
module.  Each replacement function has its own symbol name and kallsyms entry,
so it looks like a normal function to the kernel.

- **oops stack traces**: Yes.  If the replacement function is involved in an
  oops, the stack trace will show the function and kernel module name of the
  replacement function, just like any other kernel module function.  The oops
  message will also show the taint flag. [TODO: taint flag]
- **kdump/crash**: Yes.  Replacement functions are normal functions, so crash
  will have no issues. [TODO: create patch module debuginfo symbols and crash
  warning message]
- **ftrace**: Yes, see previous question.
- **systemtap/kprobes**: TODO: try it out
- **perf**: TODO: try it out

**Q. Why not use something like kexec instead?**

If you want to avoid a hardware reboot, but are ok with restarting processes,
kexec is a good alternative.

**Q. If an application can't handle a reboot, it's designed wrong.**

That's a good poi... [system reboots]

**Q. What changes are needed in other upstream projects?**

We hope to make the following changes to other projects:

- kernel:
	- ftrace improvements to close any windows that would allow a patch to
	  be inadvertently disabled
	- hot patch taint flag
	- possibly the kpatch core module itself

- crash:
	- make it glaringly obvious that you're debugging a patched kernel
	- point it to where the patch modules and corresponding debug symbols
	  live on the file system

**Q: Is it possible to register a function that gets called atomically with
`stop_machine` when the patch module loads and unloads?**

We do have plans to implement something like that.

**Q. What kernels are supported?**

kpatch needs gcc >= 4.6 and Linux >= 3.7 for use of the -mfentry flag.

**Q. Is it possible to remove a patch?**

Yes.  Just unload the patch module and the original function will be restored.

**Q. Can you apply multiple patches?**

Yes.  Also, a single function can even be patched multiple times if needed.


Demonstration
-------------

A low-level demonstration of kpatch is available on Youtube:

http://www.youtube.com/watch?v=WeSmG-XirC4

This demonstration completes each step in the previous section in a manual
fashion.  However, from a end-user perspective, most of these steps are hidden
by the "kpatch-build" command.


Get involved
------------

If you have questions, feedback, or you'd like to contribute, feel free to join
the mailing list at https://www.redhat.com/mailman/listinfo/kpatch and say hi.


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
