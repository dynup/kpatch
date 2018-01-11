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

Installation
------------

### Prerequisites

#### Fedora

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Install the dependencies for compiling kpatch:

```bash
UNAME=$(uname -r)
sudo dnf install gcc kernel-devel-${UNAME%.*} elfutils elfutils-devel
```

Install the dependencies for the "kpatch-build" command:

```bash
sudo dnf install rpmdevtools pesign yum-utils openssl wget numactl-devel
sudo dnf builddep kernel-${UNAME%.*}
sudo dnf debuginfo-install kernel-${UNAME%.*}

# optional, but highly recommended
sudo dnf install ccache
ccache --max-size=5G

# optional, for kpatch-test
sudo dnf install patchutils
```

#### RHEL 7

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Install the dependencies for compiling kpatch:

```bash
UNAME=$(uname -r)
sudo yum install gcc kernel-devel-${UNAME%.*} elfutils elfutils-devel
```

Install the dependencies for the "kpatch-build" command:

```bash
sudo yum-config-manager --enable rhel-7-server-optional-rpms
sudo yum install rpmdevtools pesign yum-utils zlib-devel \
  binutils-devel newt-devel python-devel perl-ExtUtils-Embed \
  audit-libs-devel numactl-devel pciutils-devel bison ncurses-devel

sudo yum-builddep kernel-${UNAME%.*}
sudo debuginfo-install kernel-${UNAME%.*}

# optional, but highly recommended
sudo yum install https://dl.fedoraproject.org/pub/epel/7/x86_64/c/ccache-3.2.7-3.el7.x86_64.rpm
ccache --max-size=5G

# optional, for kpatch-test
sudo yum install patchutils
```

#### CentOS 7

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Install the dependencies for compiling kpatch:

```bash
UNAME=$(uname -r)
sudo yum install gcc kernel-devel-${UNAME%.*} elfutils elfutils-devel
```

Install the dependencies for the "kpatch-build" command:

```bash
sudo yum install rpmdevtools pesign yum-utils zlib-devel \
  binutils-devel newt-devel python-devel perl-ExtUtils-Embed \
  audit-libs audit-libs-devel numactl-devel pciutils-devel bison

# enable CentOS 7 debug repo
sudo yum-config-manager --enable debug

sudo yum-builddep kernel-${UNAME%.*}
sudo debuginfo-install kernel-${UNAME%.*}

# optional, but highly recommended - enable EPEL 7
sudo yum install ccache
ccache --max-size=5G

# optional, for kpatch-test
sudo yum install patchutils
```

#### Oracle Linux 7

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Install the dependencies for compiling kpatch:

```bash
UNAME=$(uname -r)
sudo yum install gcc kernel-devel-${UNAME%.*} elfutils elfutils-devel
```

Install the dependencies for the "kpatch-build" command:

```bash
sudo yum install rpmdevtools pesign yum-utils zlib-devel \
  binutils-devel newt-devel python-devel perl-ExtUtils-Embed \
  audit-libs numactl-devel pciutils-devel bison

# enable ol7_optional_latest repo
sudo yum-config-manager --enable ol7_optional_latest

sudo yum-builddep kernel-${UNAME%.*}

# manually install kernel debuginfo packages
rpm -ivh https://oss.oracle.com/ol7/debuginfo/kernel-debuginfo-$(uname -r).rpm
rpm -ivh https://oss.oracle.com/ol7/debuginfo/kernel-debuginfo-common-x86_64-$(uname -r).rpm

# optional, but highly recommended - enable EPEL 7
sudo yum install ccache
ccache --max-size=5G

# optional, for kpatch-test
sudo yum install patchutils
```

#### Ubuntu 14.04

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Install the dependencies for compiling kpatch:

```bash
apt-get install make gcc libelf-dev
```

Install the dependencies for the "kpatch-build" command:

```bash
apt-get install dpkg-dev devscripts
apt-get build-dep linux

# optional, but highly recommended
apt-get install ccache
ccache --max-size=5G
```

Install kernel debug symbols:

```bash
# Add ddebs repository
codename=$(lsb_release -sc)
sudo tee /etc/apt/sources.list.d/ddebs.list << EOF
deb http://ddebs.ubuntu.com/ ${codename} main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-security main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
EOF

# add APT key
wget -Nq http://ddebs.ubuntu.com/dbgsym-release-key.asc -O- | sudo apt-key add -
apt-get update && apt-get install linux-image-$(uname -r)-dbgsym
```
If there are no packages published yet to the codename-security pocket, the
apt update may report a "404 Not Found" error, as well as a complaint about
disabling the repository by default.  This message may be ignored (see issue
#710).

#### Debian 9 (Stretch)

Since Stretch the stock kernel can be used without changes, however the
version of kpatch in Stretch is too old so you still need to build it
manually. Follow the instructions for Debian Jessie (next section) but skip
building a custom kernel/rebooting.

#### Debian 8 (Jessie)

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Install the dependencies for compiling kpatch:

    apt-get install make gcc libelf-dev build-essential

Install and prepare the kernel sources:

```bash
apt-get install linux-source-$(uname -r)
cd /usr/src && tar xvf linux-source-$(uname -r).tar.xz && ln -s linux-source-$(uname -r) linux && cd linux
cp /boot/config-$(uname -r) .config
for OPTION in CONFIG_KALLSYMS_ALL CONFIG_FUNCTION_TRACER ; do sed -i "s/# $OPTION is not set/$OPTION=y/g" .config ; done
sed -i "s/^SUBLEVEL.*/SUBLEVEL =/" Makefile
make -j`getconf _NPROCESSORS_CONF` deb-pkg KDEB_PKGVERSION=$(uname -r).9-1
```

Install the kernel packages and reboot

    dpkg -i /usr/src/*.deb
    reboot

Install the dependencies for the "kpatch-build" command:

    apt-get install dpkg-dev
    apt-get build-dep linux

    # optional, but highly recommended
    apt-get install ccache
    ccache --max-size=5G

#### Debian 7 (Lenny)

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Add backports repositories:

```bash
echo "deb http://http.debian.net/debian wheezy-backports main" > /etc/apt/sources.list.d/wheezy-backports.list
echo "deb http://packages.incloudus.com backports-incloudus main" > /etc/apt/sources.list.d/incloudus.list
wget http://packages.incloudus.com/incloudus/incloudus.pub -O- | apt-key add -
aptitude update
```

Install the linux kernel, symbols and gcc 4.9:

    aptitude install -t wheezy-backports -y initramfs-tools
    aptitude install -y gcc gcc-4.9 g++-4.9 linux-image-3.14 linux-image-3.14-dbg

Configure gcc 4.9 as the default gcc compiler:

    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.7 20
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.9 50
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.7 20
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.9 50

Install kpatch and these dependencies:

    aptitude install kpatch

Configure ccache (installed by kpatch package):

    ccache --max-size=5G

#### Gentoo

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Install Kpatch and Kpatch dependencies:

```bash
emerge --ask sys-kernel/kpatch
```

Install ccache (optional):

```bash
emerge --ask dev-util/ccache
```

Configure ccache:

```bash
ccache --max-size=5G
```

### Build

Compile kpatch:

    make


### Install

OPTIONAL: Install kpatch to `/usr/local`:

    sudo make install

Alternatively, the kpatch and kpatch-build scripts can be run directly from the
git tree.


Quick start
-----------

> NOTE: While kpatch is designed to work with any recent Linux
kernel on any distribution, the `kpatch-build` command has **ONLY** been tested
and confirmed to work on Fedora 20 and later, RHEL 7, Oracle Linux 7, CentOS 7 and Ubuntu 14.04.

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

    $ kpatch-build -t vmlinux meminfo-string.patch
    Using cache at /home/jpoimboe/.kpatch/3.13.10-200.fc20.x86_64/src
    Testing patch file
    checking file fs/proc/meminfo.c
    Building original kernel
    Building patched kernel
    Detecting changed objects
    Rebuilding changed objects
    Extracting new and modified ELF sections
    meminfo.o: changed function: meminfo_proc_show
    Building patch module: kpatch-meminfo-string.ko
    SUCCESS

> NOTE: The `-t vmlinux` option is used to tell `kpatch-build` to only look for
> changes in the `vmlinux` base kernel image, which is much faster than also
> compiling all the kernel modules.  If your patch affects a kernel module, you
> can either omit this option to build everything, and have `kpatch-build`
> detect which modules changed, or you can specify the affected kernel build
> targets with multiple `-t` options.

That outputs a patch module named `kpatch-meminfo-string.ko` in the current
directory.  Now apply it to the running kernel:

    $ sudo kpatch load kpatch-meminfo-string.ko
    loading core module: /usr/local/lib/modules/3.13.10-200.fc20.x86_64/kpatch/kpatch.ko
    loading patch module: kpatch-meminfo-string.ko

Done!  The kernel is now patched.

    $ grep -i chunk /proc/meminfo
    VMALLOCCHUNK:   34359337092 kB


Patch Author Guide
------------------

Unfortunately, live patching isn't always as easy as the previous example, and
can have some major pitfalls if you're not careful.  To learn more about how to
properly create live patches, see the [Patch Author
Guide](doc/patch-author-guide.md).


How it works
------------

kpatch works at a function granularity: old functions are replaced with new
ones.  It has four main components:

- **kpatch-build**: a collection of tools which convert a source diff patch to
  a patch module.  They work by compiling the kernel both with and without
  the source patch, comparing the binaries, and generating a patch module
  which includes new binary versions of the functions to be replaced.

- **patch module**: a kernel module (.ko file) which includes the
  replacement functions and metadata about the original functions.

- **kpatch core module**: a kernel module (.ko file) which provides an
  interface for the patch modules to register new functions for
  replacement.  It uses the kernel ftrace subsystem to hook into the original
  function's mcount call instruction, so that a call to the original function
  is redirected to the replacement function.

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


### Patching

The patch modules register with the core module (`kpatch.ko`).
They provide information about original functions that need to be replaced, and
corresponding function pointers to the replacement functions.

The core module registers a handler function with ftrace.  The
handler function is called by ftrace immediately before the original
function begins executing.  This occurs with the help of the reserved mcount
call at the beginning of every function, created by the gcc `-mfentry` flag.
The ftrace handler then modifies the return instruction pointer (IP)
address on the stack and returns to ftrace, which then restores the original
function's arguments and stack, and "returns" to the new function.


Limitations
-----------

- Patches which modify init functions (annotated with `__init`) are not
  supported.  kpatch-build will return an error if the patch attempts
  to do so.

- Patches which modify statically allocated data are not supported.
  kpatch-build will detect that and return an error.  (In the future
  we will add a facility to support it.  It will probably require the
  user to write code which runs at patch module loading time which manually
  updates the data.)

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

**Q. What's the relationship between kpatch and the upstream Linux live kernel
patching component (livepatch)?**

Starting with Linux 4.0, the Linux kernel has livepatch, which is a new
converged live kernel patching framework.  Livepatch is similar in
functionality to the kpatch core module, though it doesn't yet have all the
features that kpatch does.

kpatch-build already works with both livepatch and kpatch.  If your kernel has
CONFIG\_LIVEPATCH enabled, it detects that and builds a patch module in the
livepatch format.  Otherwise it builds a kpatch patch module.

The kpatch script also supports both patch module formats.

**Q. Isn't this just a virus/rootkit injection framework?**

kpatch uses kernel modules to replace code.  It requires the `CAP_SYS_MODULE`
capability.  If you already have that capability, then you already have the
ability to arbitrarily modify the kernel, with or without kpatch.

**Q. How can I detect if somebody has patched the kernel?**

When a patch module is loaded, the `TAINT_USER` or `TAINT_LIVEPATCH` flag is
set.  (The latter flag was introduced in Linux version 4.0.)  To test for
these flags, `cat /proc/sys/kernel/tainted` and check to see if the value of
`TAINT_USER` (64) or `TAINT_LIVEPATCH` (32768) has been OR'ed in.

Note that the `TAINT_OOT_MODULE` flag (4096) will also be set, since the patch
module is built outside the Linux kernel source tree.

If your patch module is unsigned, the `TAINT_FORCED_MODULE` flag (2) will also
be set.  Starting with Linux 3.15, this will be changed to the more specific
`TAINT_UNSIGNED_MODULE` (8192).

Linux versions starting with 4.9 also support a per-module `TAINT_LIVEPATCH`
taint flag. This can be checked by verifying the output of
`cat /sys/module/<kpatch module>/taint` -- a 'K' character indicates the
presence of `TAINT_LIVEPATCH`.

**Q. Will it destabilize my system?**

No, as long as the patch is chosen carefully.  See the Limitations section
above.

**Q. Why does kpatch use ftrace to jump to the replacement function instead of
adding the jump directly?**

ftrace owns the first "call mcount" instruction of every kernel function.  In
order to keep compatibility with ftrace, we go through ftrace rather than
updating the instruction directly.  This approach also ensures that the code
modification path is reliable, since ftrace has been doing it successfully for
years.

**Q. Is kpatch compatible with \<insert kernel debugging subsystem here\>?**

We aim to be good kernel citizens and maintain compatibility.  A kpatch
replacement function is no different than a function loaded by any other kernel
module.  Each replacement function has its own symbol name and kallsyms entry,
so it looks like a normal function to the kernel.

- **oops stack traces**: Yes.  If the replacement function is involved in an
  oops, the stack trace will show the function and kernel module name of the
  replacement function, just like any other kernel module function.  The oops
  message will also show the taint flag (see the FAQ "How can I detect if
  somebody has patched the kernel" for specifics).
- **kdump/crash**: Yes.  Replacement functions are normal functions, so crash
  will have no issues.
- **ftrace**: Yes, but certain uses of ftrace which involve opening the
  `/sys/kernel/debug/tracing/trace` file or using `trace-cmd record` can result
  in a tiny window of time where a patch gets temporarily disabled.  Therefore
  it's a good idea to avoid using ftrace on a patched system until this issue
  is resolved.
- **systemtap/kprobes**: Some incompatibilities exist.
  - If you setup a kprobe module at the beginning of a function before loading
    a kpatch module, and they both affect the same function, kprobes "wins"
    until the kprobe has been unregistered.  This is tracked in issue
    [#47](https://github.com/dynup/kpatch/issues/47).
  - Setting a kretprobe before loading a kpatch module could be unsafe.  See
    issue [#67](https://github.com/dynup/kpatch/issues/67).
- **perf**: Yes.
- **tracepoints**: Patches to a function which uses tracepoints will result in
  the tracepoints being effectively disabled as long as the patch is applied.

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

**Q. Is it possible to register a function that gets called atomically with
`stop_machine` when the patch module loads and unloads?**

We do have plans to implement something like that.

**Q. What kernels are supported?**

kpatch needs gcc >= 4.8 and Linux >= 3.9.

**Q. Is it possible to remove a patch?**

Yes.  Just run `kpatch unload` which will disable and unload the patch module
and restore the function to its original state.

**Q. Can you apply multiple patches?**

Yes, but to prevent any unexpected interactions between multiple patch modules,
it's recommended that patch upgrades are cumulative, so that each patch is a
superset of the previous patch.  This can be achieved by combining the new
patch with the previous patch using `combinediff` before running
`kpatch-build`.

**Q. Why did kpatch-build detect a changed function that wasn't touched by the
source patch?**

There could be a variety of reasons for this, such as:

- The patch changed an inline function.
- The compiler decided to inline a changed function, resulting in the outer
  function getting recompiled.  This is common in the case where the inner
  function is static and is only called once.

**Q. How do I patch a function which is always on the stack of at least one
task, such as schedule(), sys_poll(), sys_select(), sys_read(),
sys_nanosleep(), etc?**

- If you're sure it would be safe for the old function and the new function to
  run simultaneously, use the `KPATCH_FORCE_UNSAFE` macro to skip the
  activeness safety check for the function.  See `kmod/patch/kpatch-macros.h`
  for more details.

**Q. Are patching of kernel modules supported?**

- Yes.

**Q. Can you patch out-of-tree modules?**

- Yes, though it's currently a bit of a manual process.  See this
  [message](https://www.redhat.com/archives/kpatch/2015-June/msg00004.html) on
  the kpatch mailing list for more information.


Get involved
------------

If you have questions or feedback, join the #kpatch IRC channel on freenode and
say hi.  We also have a [mailing list](https://www.redhat.com/mailman/listinfo/kpatch).

Contributions are very welcome.  Feel free to open issues or PRs on github.
For big PRs, it's a good idea to discuss them first in github issues or on the
[mailing list](https://www.redhat.com/mailman/listinfo/kpatch) before you write
a lot of code.


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
