kpatch: dynamic kernel patching
===============================

kpatch is a tool for the generation and application of kernel
modules that patch a running Linux kernel while in operation,
without requiring a reboot.  This is very valuable in cases
where critical workloads, which do not have high availability via
scale-out, run on a single machine and are very downtime
sensitive or require a heavyweight approval process and
notification of workload users in the event of downtime.

kpatch is currently is early development.  For now, it should _not_ be used
in production environments until significantly more testing on various
patches and environments is conducted.


Installation
------------

*NOTE: These installation instructions are currently Fedora-specific.  Support
for other distributions is planned soon.*

Install the dependencies for compiling kpatch:

    sudo yum install gcc kernel-devel elfutils elfutils-devel

*NOTE: Ensure you have elfutils-0.158 or newer.*

Install the dependencies for the "kpatch build" command:

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
kernel on any distribution, the "kpatch build" command currently
only works on Fedora.*

Load the kpatch core module:

    sudo insmod /usr/local/lib/modules/$(uname -r)/kpatch/kpatch.ko

Make a source patch against the kernel tree:

    # from a kernel git tree:
    git diff > /path/to/foo.patch

Build the hot patch kernel module:

    kpatch build /path/to/foo.patch

This outputs a hot patch module named `kpatch-foo.ko` in the current
directory.  Now apply it to the running kernel:

    sudo insmod kpatch-foo.ko

Done!  The kernel is now patched.


How it works
------------

### kpatch build

The "kpatch build" command converts a source-level diff patch file to a hot
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


Demonstration
-------------

A low-level demonstration of kpatch is available on Youtube:

http://www.youtube.com/watch?v=WeSmG-XirC4

This demonstration completes each step in the previous section in a manual
fashion.  However, from a end-user perspective, most of these steps are hidden
by the "kpatch build" command.


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
