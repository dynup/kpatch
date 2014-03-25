Name: kpatch
Summary: Dynamic kernel patching
Version: 0.0.1
License: GPLv2 
Group: System Environment/Kernel
URL: http://github.com/dynup/kpatch
Release: 2%{?dist}
Source0: %{name}-%{version}.tar.gz

Requires: kmod bash
BuildRequires: gcc kernel-devel elfutils elfutils-devel
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)

# needed for the kernel specific module
%define KVER %(uname -r)

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


%prep
%setup -q 
cp Makefile.inc Makefile.inc.ORG
%{__sed} 's%/usr/local%/usr%' Makefile.inc.ORG > Makefile.inc

%build
make %{_smp_mflags} 

%install
rm -rf %{buildroot}

make install DESTDIR=%{buildroot}

%clean
rm -rf %{buildroot}

%files runtime
%defattr(-,root,root,-)
%doc COPYING README.md
%{_sbindir}/kpatch
%{_mandir}/man1/kpatch.1*

%files %{KVER}
%defattr(-,root,root,-)
%{_usr}/lib/modules/%{KVER}/%{name}/*

%files build
%defattr(-,root,root,-)
%{_bindir}/*
%{_libexecdir}/*
%{_datadir}/%{name}
%{_mandir}/man1/kpatch-build.1*

%changelog
* Tue Mar 25 2014 Udo Seidel <udoseidel@gmx.de> - 0.0.1-2
- added man pages

* Sat Mar 22 2014 Udo Seidel <udoseidel@gmx.de> - 0.0.1-1
- initial release
