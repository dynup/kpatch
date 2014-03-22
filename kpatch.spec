Name: kpatch
Summary: Dynamic kernel patching
Version: 0.0.1
License: GPLv2 
Group: System Environment/Kernel
URL: http://github.com/dynup/kpatch
Release: 1%{?dist}
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


%package devel
Requires: %{name}
Summary: Dynamic kernel patching
%description devel
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
strip %{buildroot}/%{_usr}/lib/modules/%{KVER}/%{name}/*

%clean
rm -rf %{buildroot}

%files 
%defattr(-,root,root,-)
%doc COPYING README.md
%{_sbindir}/kpatch
%{_libexecdir}/*

%files %{KVER}
%defattr(-,root,root,-)
%{_usr}/lib/modules/%{KVER}/%{name}/*

%files devel
%defattr(-,root,root,-)
%{_bindir}/*
%{_datadir}/%{name}

%changelog
* Sat Mar 22 2014 Udo Seidel <udoseidel@gmx.de> - 0.0.1-1
- initial release
