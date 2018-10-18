#!/bin/bash

kpatch_set_ccache_max_size()
{
	local ccache_max_size=${1:-10G}

	ccache --max-size="${ccache_max_size}"
}

kpatch_fedora_dependencies()
{
	local kernel_version
	kernel_version=$(uname -r)

	sudo dnf install -y gcc "kernel-devel-${kernel_version%.*}" elfutils elfutils-devel
	sudo dnf install -y pesign yum-utils openssl wget numactl-devel
	sudo dnf builddep -y "kernel-${kernel_version%.*}"
	sudo dnf debuginfo-install -y "kernel-${kernel_version%.*}"

	sudo dnf install -y ccache
}

kpatch_ubuntu_dependencies()
{
	sudo sed -i 's/# deb-src/deb-src/' /etc/apt/sources.list
	sudo apt-get update

	sudo apt-get install -y make gcc libelf-dev elfutils
	sudo apt-get install -y dpkg-dev devscripts
	sudo apt-get build-dep -y linux

	sudo apt-get install -y ccache

	# Add ddebs repository
	if ! grep -q 'ddebs.ubuntu.com' /etc/apt/sources.list.d/ddebs.list; then
		local codename
		codename=$(lsb_release -sc)
		sudo tee /etc/apt/sources.list.d/ddebs.list <<-EOF
			deb http://ddebs.ubuntu.com/ ${codename} main restricted universe multiverse
			deb http://ddebs.ubuntu.com/ ${codename}-security main restricted universe multiverse
			deb http://ddebs.ubuntu.com/ ${codename}-updates main restricted universe multiverse
			deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
		EOF

		# add APT key
		wget -Nq http://ddebs.ubuntu.com/dbgsym-release-key.asc -O- | sudo apt-key add -
		sudo apt-get update
	fi
	sudo apt-get install -y "linux-image-$(uname -r)-dbgsym"
}

kpatch_rhel_dependencies()
{
	local kernel_version
	local arch
	kernel_version=$(uname -r)
	arch=$(uname -m)

	sudo yum install -y git gcc gcc-c++ "kernel-devel-${kernel_version%.*}" elfutils elfutils-devel
	sudo yum install -y yum-utils zlib-devel binutils-devel newt-devel \
		python-devel perl-ExtUtils-Embed audit-libs-devel numactl-devel \
		pciutils-devel bison ncurses-devel rpm-build java-devel
	sudo yum-builddep -y "kernel-${kernel_version%.*}"
	sudo debuginfo-install -y "kernel-${kernel_version%.*}"

	[ "${arch}" == "x86_64" ] && sudo yum install -y pesign
	[ "${arch}" == "ppc64le" ] && sudo yum install -y gcc-plugin-devel

	sudo yum install -y "https://dl.fedoraproject.org/pub/epel/7/${arch}/Packages/c/ccache-3.3.4-1.el7.${arch}.rpm"
}

kpatch_centos_dependencies()
{
	local kernel_version
	kernel_version=$(uname -r)

	sudo yum install -y gcc gcc-c++ "kernel-devel-${kernel_version%.*}" elfutils elfutils-devel
	sudo yum install -y yum-utils zlib-devel binutils-devel newt-devel \
		python-devel perl-ExtUtils-Embed audit-libs-devel numactl-devel \
		pciutils-devel bison ncurses-devel rpm-build java-devel pesign
	sudo yum-config-manager --enable debug
	sudo yum-builddep -y "kernel-${kernel_version%.*}"
	sudo debuginfo-install -y "kernel-${kernel_version%.*}"

	sudo yum install -y ccache
}

kpatch_dependencies()
{
	# shellcheck disable=SC1091
	source /etc/os-release

	eval "kpatch_${ID}_dependencies" || { echo "Unsupported distro: ${ID}"; exit 1; }
}
