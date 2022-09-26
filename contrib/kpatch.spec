# needed for the kernel specific module
%define KVER %(uname -r)

# Don't build kpatch kernel module by default
%bcond_with kpatch_mod

Name: kpatch
Summary: Dynamic kernel patching
Version: 0.9.7
License: GPLv2
Group: System Environment/Kernel
URL: http://github.com/dynup/kpatch
Release: 1%{?dist}
Source0: %{name}-%{version}.tar.gz

Requires: kmod bash
BuildRequires: gcc kernel-devel elfutils elfutils-devel
%if %{with kpatch_mod}
BuildRequires: kernel-devel-uname-r = %{KVER}
BuildRequires: kernel-uname-r = %{KVER}
%endif
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

%description
kpatch is a Linux dynamic kernel patching tool which allows you to patch a
running kernel without rebooting or restarting any processes.  It enables
sysadmins to apply critical security patches to the kernel immediately, without
having to wait for long-running tasks to complete, users to log off, or
for scheduled reboot windows.  It gives more control over up-time without
sacrificing security or stability.


%package runtime
Summary: Dynamic kernel patching
Buildarch: noarch
Provides: %{name} = %{version}
%description runtime
kpatch is a Linux dynamic kernel patching tool which allows you to patch a
running kernel without rebooting or restarting any processes.  It enables
sysadmins to apply critical security patches to the kernel immediately, without
having to wait for long-running tasks to complete, users to log off, or
for scheduled reboot windows.  It gives more control over up-time without
sacrificing security or stability.


%package build
Requires: %{name}
Summary: Dynamic kernel patching
%description build
kpatch is a Linux dynamic kernel patching tool which allows you to patch a
running kernel without rebooting or restarting any processes.  It enables
sysadmins to apply critical security patches to the kernel immediately, without
having to wait for long-running tasks to complete, users to log off, or
for scheduled reboot windows.  It gives more control over up-time without
sacrificing security or stability.

%if %{with kpatch_mod}
%package %{KVER}
Requires: %{name}
Summary: Dynamic kernel patching
%description %{KVER}
kpatch is a Linux dynamic kernel patching tool which allows you to patch a
running kernel without rebooting or restarting any processes.  It enables
sysadmins to apply critical security patches to the kernel immediately, without
having to wait for long-running tasks to complete, users to log off, or
for scheduled reboot windows.  It gives more control over up-time without
sacrificing security or stability.

%endif

%prep
%setup -q

%build
make %{_smp_mflags} %{?with_kpatch_mod: BUILDMOD=yes KPATCH_BUILD=/lib/modules/%{KVER}/build}

%install
rm -rf %{buildroot}

make install PREFIX=/%{_usr} DESTDIR=%{buildroot} %{?with_kpatch_mod: BUILDMOD=yes KPATCH_BUILD=/lib/modules/%{KVER}/build}

%clean
rm -rf %{buildroot}

%files runtime
%defattr(-,root,root,-)
%doc COPYING README.md
%{_sbindir}/kpatch
%{_mandir}/man1/kpatch.1*
%{_usr}/lib/systemd/system/*
%{_sysconfdir}/init/kpatch.conf

%if %{with kpatch_mod}
%files %{KVER}
%defattr(-,root,root,-)
%{_usr}/lib/kpatch/%{KVER}
%endif

%files build
%defattr(-,root,root,-)
%{_bindir}/*
%{_libexecdir}/*
%{_datadir}/%{name}
%{_mandir}/man1/kpatch-build.1*

%changelog
* Wed Sep 14 Yannick Cote <ycote@redhat.com> - 0.9.7
* S390x kpatch support
* Add support for openEuler + documentation (kpatch-build)
* Use err.h instead of error.h for musl support (kpatch-build)
* Add support for .return_sites section (kpatch-build x86)
* Create missing section symbol (kpatch-build)
* Fix symtab parsing lookup (kpatch-build)
* Many fixes and improvements in create-diff-object (kpatch-build)
* Unload already disabled modules (kpatch util)
* Add integration tests for: rhel-{8.6,9.0},5.18.0 (test)
* Add tests for patching a syscall (test)
* Combine and improve Fedora, CentOS with RHEL kpatch-build dependencies (test)
* Major revamp of README.md and documentation
* Add syscall patching macros (kmod)

* Tue Apr 12 Joe Lawrence <joe.lawrence@redhat.com> - 0.9.6
* Allow OOT modules to be built with non-distro kernels
* Add cross-arch unit testing support
* Support ELF extended symbol section indexes
* Allow setting kernel version if --sourcedir and --vmlinux are used
* Cleanup and enhance __LINE__ macro detection for all arches
* Fix segfault on .LCx string literal symbols
* Include __dyndbg section when referenced by jump table
* Honor user provided KBUILD_EXTRA_SYMBOLS
* Support .retpoline_sites section
* Add native compiler selection via CROSS_COMPILE

* Wed Oct 13 Artem Savkov <asavkov@redhat.com> - 0.9.5
- openEuler support
- kpatch-build: Do not check KLP_REPLACE for kpatch.ko-based patches
- create-diff-object: fix use after free in kpatch-check-relocations()
- kpatch-build: Handle error in create-klp-module
- create-diff-object: support ppc64le relative jump labels
- kmod/patch: clean only rebuildable objs
- kpatch-build: save environment varibles to file

* Wed Aug 25 Yannick Cote <ycote@redhat.com> - 0.9.4
- Support for multiple source files
- Makefile tweaks for handling non-replace kpatch building
- Support CONFIG_PRINTK_INDEX
- kpatch-build: set EXTRAVERSION and not localversion for RH kernels
- Make sure section symbols exist
- create-diff-object: Check that the section has a secsym
- kpatch: rmmod module of the same name before loading a module
- kpatch-build: enable option -R|--replace to build replace klp
- kpatch: use /sys/kernel/kpatch/ to check whether core module is loaded
- kpatch: Sync signal subcmd usage output with manpage
- fixes for the out-of-range relocation check

* Tue Apr 20 Yannick Cote <ycote@redhat.com> - 0.9.3
- Initial support for clang compiler
- Add support for rhel-8.4
- rhel-8.4: workaround pahole and extended ELF sections
- rhel-8.4: drop klp.arch support
- Kpatch command waits for module to fully unload
- Kpatch command informs user when signal subcommand is unnecessary
- kpatch-build skips ppc64le vdso files

* Tue Sep 8 2020 Joe Lawrence <joe.lawrence@redhat.com> - 0.9.2
- Integration test support for rhel-{7.8,7.9,8.1,8.2}, centos-8
- Better support for gcc child functions
- Batch jump label errors to report all instances
- Dynrela code cleanup
- Remove .klp.arch and add support for jump labels in v5.8+ kernels
- Mark ignored sections earlier to support functions missing ftrace hook
- Minor README.md improvements
- Add ppc64le mcount support to patched functions
- Show additional stalled process information in kpatch script
- Increased shellcheck coverage and fixes
- ppc64le plugin fixes for gcc v10
- Ignore __UNIQUE_ID_ symbol from tristate config objects
- Don't clear dmesg during integration tests
- Detect and report MODVERSIONS symbol version CRC changes

* Wed Mar 11 2020 Yannick Cote <ycote@redhat.com> - 0.9.1
- Handle ppc64le toc with only constants
- Don't strip callback section symbols
- Integration tests update
- Fix -Wconversion warnings
- Process debug sections last

* Wed Mar 11 2020 Yannick Cote <ycote@redhat.com> - 0.9.0
- Many fixes in integration tests and adding rhel-8.0
- Updates to documentation
- Many updates and additions to the patch author guide
- Fix to relocations used for ZERO_PAGE(0)
- Simplify static local variables correlation
- Make symvers reading code more flexible
- Free sections in elf teardown
- Fix kpatch-test module unloading
- Disable the build of kpatch.ko module by default
- Simplify mangled function correlation
- Use whole word filename matching in find_parent_obj()
- Simplify relocation processing

* Wed Aug 21 2019 Artem Savkov <asavkov@redhat.com> - 0.8.0
- kpatch.ko atomic replace fixes
- Fixes for potential problems found by covscan
- Remove manual signaling logic from kpatch utility
- Don't strip callback symbols
- Allow dynamic debug static keys

* Wed Jul 24 2019 Josh Poimboeuf <jpoimboe@redhat.com> - 0.7.1
- Fix several powerpc-specific bugs, including two which can result in kernel
  panics
- Use rpmbuild --nodeps for installing srpm on Fedora/RHEL
- Fix inconsistent unit test failures for FAIL tests

* Thu Jul 18 2019 Artem Savkov <asavkov@redhat.com> - 0.7.0
- Multiple memory leak fixes in kpatch-build
- livepatch-patch-hook compatability fixes for kernels 5.1+
- Making kpatch-build compatible with custom gcc names
- Added rhel-rebased integration tests
- kpatch.service will no longer unload modules on stop
- kpatch load will no longer fail if a module is already loaded and enabled
- kpatch-build will now check for *_fixup section changes on ppc64le and will
  fail on such changes
- Add support for R_X86_64_PLT32
- don't allow jump labels
- ppc64le-specific kpatch-build fixes

* Fri Apr 12 2019 Joe Lawrence <joe.lawrence@redhat.com> - 0.6.3
- Lots of integration test work
- Better support for building out-of-tree modules
- Updated manpage options, drop deprecated distro specific mentions
- README.md updates for shadow variables, out-of-tree modules
- Fix core module compilation with CONFIG_HAVE_ARCH_PREL32_RELOCATIONS
- kpatch-build detects and abort on unsupported options
  GCC_PLUGIN_LATENT_ENTROPY, GCC_PLUGIN_RANDSTRUCT
- Fix patch linking with 4.20+
- Other minor shellcheck and kpatch-build fixups

* Tue Oct 2 2018 Joe Lawrence <joe.lawrence@redhat.com> - 0.6.2
- ppc64le: relax .text section addralign value check
- gcc8: unit-tests
- gcc8: support parent/child symbol relations
- gcc8: handle functions changing subsection
- gcc8: consider ".text.hot" sections bundleable
- kpatch-build: bugfix for less aggressive clean build-cache
- ubuntu: remove "-signed" substring from the kernel source package name
- ubuntu: explicitly note elfutils dependency
- upstream 4.18: unit-tests
- upstream 4.18: KCFLAGS -mcount-record support support
- RHEL-8: don't care who provides yumdownloader
- RHEL-8: account for quirky SRPM / release name conventions

* Tue May 29 2018 Joe Lawrence <joe.lawrence@redhat.com> - 0.6.1
- Increase the transition timeout, helpful for large CPU count systems
- Miscellaneous unit testing, ppc64, etc. fixes

* Mon Apr 22 2018 Josh Poimboeuf <jpoimboe@redhat.com> - 0.6.0
- Support and converted to livepatch-style hooks.
- Lots of misc bugfixes and cleanups
- Manpage, README.md fixups
- More PPC64 work
- "Undefined reference" build failure rework
- Livepatch disable retries
- New unit testing framework

* Thu Dec 21 2017 Josh Poimboeuf <jpoimboe@redhat.com> - 0.5.0
- Basic ppc64le support
- kpatch: load automatically signals stalled processes after a timeout
- kpatch: list shows stalled processes
- kpatch: signal signals stalled processes
- kpatch-build: multiple source patches can be combined into a single binary patch module
- kpatch-build: -n|--name option for giving a custom name to the patch module
- kpatch-build: additional -d options for more verbose debug modes
- The module prefix is now either livepatch- or kpatch- depending on the underlying patching technology

* Mon Mar 13 2017 Josh Poimboeuf <jpoimboe@redhat.com> - 0.4.0
- The tools underlying kpatch-build have been made more modular, in preparation for making create-diff-object more generally useful to other use cases (kernel livepatch, Xen live patching, user space patching).
- Support for all new upstream kernels up to 4.10.
- KASLR support.
- Many other bug fixes and improvements.

* Thu Oct 11 2016 Jessica Yu - 0.3.4
- bump version to 0.3.4

* Fri Aug 19 2016 Josh Poimboeuf <jpoimboe@redhat.com> - 0.3.3
- bump version to 0.3.3

* Thu Feb 18 2016 Josh Poimboeuf <jpoimboe@redhat.com> - 0.3.2
- bump version to 0.3.2

* Thu Nov 19 2015 Josh Poimboeuf <jpoimboe@redhat.com> - 0.3.1
- Get kernel version from vmlinux if the kernel source tree is used

* Wed Nov 18 2015 Josh Poimboeuf <jpoimboe@redhat.com> - 0.3.0
- kpatch-build: fix gcc_version_check: both "GNU" and "GCC" are possible

* Wed Dec 3 2014 Josh Poimboeuf <jpoimboe@redhat.com> - 0.2.2-1
- rebased to current version

* Tue Sep 2 2014 Josh Poimboeuf <jpoimboe@redhat.com> - 0.2.1-1
- rebased to current version

* Mon Jul 28 2014 Josh Poimboeuf <jpoimboe@redhat.com> - 0.1.9-1
- moved core module to /usr/lib/kpatch
- rebased to current version

* Mon Jul 07 2014 Udo Seidel <udoseidel@gmx.de> - 0.1.7-1
- rebased to current version

* Sat May 24 2014 Udo Seidel <udoseidel@gmx.de> - 0.1.1-1
- rebased to current version

* Thu Apr 10 2014 Udo Seidel <udoseidel@gmx.de> - 0.0.1-3
- added dracut module

* Tue Mar 25 2014 Udo Seidel <udoseidel@gmx.de> - 0.0.1-2
- added man pages

* Sat Mar 22 2014 Udo Seidel <udoseidel@gmx.de> - 0.0.1-1
- initial release
