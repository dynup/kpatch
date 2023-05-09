Installation
============

Table of contents
=================

- [Prerequisites](#prerequisites)
	- [Fedora, RHEL, CentOS](#fedora-rhel-centos)
	- [Oracle Linux 7](#oracle-linux-7)
	- [Ubuntu](#ubuntu)
	- [Debian 9 (Stretch)](#debian-9-stretch)
	- [Debian 8 (Jessie)](#debian-8-jessie)
	- [Debian 7 (Lenny)](#debian-7-lenny)
	- [Gentoo](#gentoo)
	- [OpenEuler](#openeuler)
- [Build](#build)
- [Install](#install)


Prerequisites
-------------

Before starting, see [Supported
Architectures](../README.md#supported-architectures) and check if your device's
architecture is supported.

### Fedora, RHEL, CentOS

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Install the dependencies for compiling kpatch and running kpatch-build:

```bash
# Will request root privileges
make dependencies
```

### Oracle Linux 7

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Install the dependencies for compiling kpatch:

```bash
UNAME=$(uname -r)
sudo yum install gcc kernel-devel-${UNAME%.*} elfutils elfutils-devel
```

Install the dependencies for the "kpatch-build" command:

```bash
sudo yum install pesign yum-utils zlib-devel \
  binutils-devel newt-devel python-devel perl-ExtUtils-Embed \
  audit-libs numactl-devel pciutils-devel bison patchutils

# enable ol7_optional_latest repo
sudo yum-config-manager --enable ol7_optional_latest

sudo yum-builddep kernel-${UNAME%.*}

# manually install kernel debuginfo packages
rpm -ivh https://oss.oracle.com/ol7/debuginfo/kernel-debuginfo-$(uname -r).rpm
rpm -ivh https://oss.oracle.com/ol7/debuginfo/kernel-debuginfo-common-x86_64-$(uname -r).rpm

# optional, but highly recommended - enable EPEL 7
sudo yum install ccache
ccache --max-size=5G
```

### Ubuntu

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Install the dependencies for compiling kpatch and running kpatch-build

```bash
# required on ppc64le
# e.g., on Ubuntu 18.04 for gcc-7.3
apt-get install gcc-7-plugin-dev

# Will request root privileges
make dependencies
```

### Debian 9 (Stretch)

Since Stretch the stock kernel can be used without changes, however the
version of kpatch in Stretch is too old so you still need to build it
manually. Follow the instructions for Debian Jessie (next section) but skip
building a custom kernel/rebooting.

### Debian 8 (Jessie)

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

    # required on ppc64le
    # e.g., on stretch for gcc-6.3
    apt-get install gcc-6-plugin-dev

    # optional, but highly recommended
    apt-get install ccache
    ccache --max-size=5G

### Debian 7 (Lenny)

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

### Gentoo

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

### OpenEuler

*ATTENTION: openEuler maintains its own version of kpatch which work with its
own kernel. You can check this [link](https://gitee.com/src-openeuler/kpatch)
to see its documents. This document describes how to run mainline kpatch in openEuler.*

*NOTE: You'll need about 15GB of free disk space for the kpatch-build cache in
`~/.kpatch` and for ccache.*

Install the dependencies for compiling kpatch and running kpatch-build:

```bash
# Will request root privileges
make dependencies
```

#### Before running kpatch-build, two more things need to be checked:
-------
1. Ensure current kernel compiled with *CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY* set

    openEuler has two strategies to apply kernel live patches and it is decided at compile time.

    When CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY set, openEuler uses its own strategy.

    When CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY set, openEuler uses the conventional strategy.

    Only one config option can take effect at the same time.
    A [chinese blog](https://www.modb.pro/db/232858) written by the openEuler official describes
    their modifications for kernel livepatch. The main difference is CONFIG_LIVEPATCH_STOP_MACHINE_CONSISTENCY
    will disable the usage of ftrace handler in livepatch, they believe it will be faster.

    Check whether your current kernel compiled with *CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY*
    ```bash
    grep "CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY" /boot/config-$(uname -r)
    ```

    If you see any output, it means your kernel satisfies, you can go directly to check step 2.

    If not, then you need to recompile your current kernel with CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY set.

    You can reference the following steps to recompile the kernel if needed
    1. download source code of the current kernel
        ```bash
        # set working directories
        TEMPDIR=~/.tmp
        mkdir -p $TEMPDIR
        mkdir -p $TEMPDIR/buildroot

        # download kernel source rpm package
        yumdownloader --source --destdir "$TEMPDIR" kernel-$(uname -r)

        # obtain source code from package
        rpm -D "_topdir $TEMPDIR/buildroot" -ivh $TEMPDIR/kernel-*.src.rpm
        rpmbuild -D "_topdir $TEMPDIR/buildroot" -bp --nodeps --target=$(uname -m) $TEMPDIR/buildroot/SPECS/kernel.spec

        # check source code and copy config file
        cd $TEMPDIR/buildroot/BUILD/kernel-*/linux-*[sS]ource
        cp /boot/config-$(uname -r) .config
        ```

    2. set CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY
        ```bash
        make menuconfig
        ```
        select order

            -> Processor type and features
                -> Enable Livepatch
                    -> Kernel Live Patching
                        -> live patching method

        choose
        > based on ftrace

        After this step, you shoud see CONFIG_LIVEPATCH_PER_TASK_CONSISTENCY in .config file

    3. recompile kernel and install it to your running environment.

        Just to remind, after installing the recompiled kernel, the config file should also be updated.


2. Ensure */update/source* is in the rpm repo lists

    openEuler releases its source rpm package of the kernel in two places.

    One is /source and it is included in rpm repo lists by default.

    One is /update/source and it may not be included it in some release versions.

    ```bash
    grep "/update/source" /etc/yum.repos.d/openEuler.repo
    ```

    If you can't see any output, add it to the end of /etc/yum.repos.d/openEuler.repo

    For example, if you use openEuler 21.09, you will add something like:
    ```
    [update-source]
    name=update-source
    baseurl=https://repo.openeuler.org/openEuler-21.09/update/source/
    enabled=1
    gpgcheck=0
    ```

    *baseurl* is releated with your release version, be careful please!

    Goto [openEuler repo](https://repo.openeuler.org/), find your own suitable baseurl.

Build
-----

Compile kpatch:

    make


Install
-------

OPTIONAL: Install kpatch to `/usr/local`:

    sudo make install

Alternatively, the kpatch and kpatch-build scripts can be run directly from the
git tree.


