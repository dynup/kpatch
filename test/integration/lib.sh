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

kpatch_separate_partition_cache()
{
	local partition=${1}
	local mountpoint=${2}
	local reformat=${3}
	local owner=${USER}

	if [[ "${reformat}" == "y" ]]; then
		sudo mkfs.xfs -f "${partition}"
	fi

	sudo mkdir -p "${mountpoint}"
	sudo mount "${partition}" "${mountpoint}"
	sudo chown "${owner}":"${owner}" "${mountpoint}"

	rm -rf "${mountpoint}/.ccache"
	rm -rf "${mountpoint}/.kpatch"
	mkdir "${mountpoint}/.ccache"
	mkdir "${mountpoint}/.kpatch"

	rm -rf "${HOME}/.ccache"
	rm -rf "${HOME}/.kpatch"

	ln -sv "${mountpoint}/.ccache" "${HOME}/.ccache"
	ln -sv "${mountpoint}/.kpatch" "${HOME}/.kpatch"
}

kpatch_separate_disk_cache()
{
	local device=${1}
	local mountpoint=${2}
	local partition="${device}1"

	echo -e "o\\nn\\np\\n1\\n\\n\\nw\\n" | sudo fdisk "${device}"
	kpatch_separate_partition_cache "${partition}" "${mountpoint}" y
}

kpatch_install_vagrant_centos()
{
	local image_path=${1}

	sudo yum group install -y "Development Tools"
	sudo yum -y install qemu-kvm libvirt virt-install bridge-utils libvirt-devel libxslt-devel libxml2-devel libvirt-devel libguestfs-tools-c libvirt-client

	echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-ipforward.conf
	sudo sysctl -p /etc/sysctl.d/99-ipforward.conf

	sudo systemctl enable libvirtd
	sudo systemctl start libvirtd || exit 1

	if [[ -n "${image_path}" ]]; then
		mkdir -p "${image_path}/libvirt/images"
		virsh pool-define-as --target "${image_path}/libvirt/images" default dir || exit 1
		virsh pool-start default || exit 1
	fi

	sudo yum install -y https://releases.hashicorp.com/vagrant/2.1.2/vagrant_2.1.2_x86_64.rpm || exit 1

	vagrant plugin install vagrant-libvirt
}

kpatch_install_vagrant_rhel()
{
	local image_path=${1}

	kpatch_install_vagrant_centos "${image_path}"

	sudo systemctl enable nfs
	sudo systemctl start nfs || exit 1

}

kpatch_install_vagrant_fedora()
{
	local image_path=${1}

	echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-ipforward.conf
	sudo sysctl -p /etc/sysctl.d/99-ipforward.conf

	sudo dnf install -y libvirt virt-install libvirt-client nfs-utils vagrant vagrant-libvirt

	echo "[nfsd]" | sudo tee -a /etc/nfs.conf
	echo "udp=y" | sudo tee -a /etc/nfs.conf
	echo "vers3=y" | sudo tee -a /etc/nfs.conf
	sudo systemctl restart nfs

	sudo systemctl enable libvirtd
	sudo systemctl start libvirtd || exit 1

	if [[ -n "${image_path}" ]]; then
		mkdir -p "${image_path}/libvirt/images"
		virsh pool-define-as --target "${image_path}/libvirt/images" default dir || exit 1
		virsh pool-start default || exit 1
	fi
}

kpatch_install_vagrant()
{
	local image_path=${1}

	# shellcheck disable=SC1091
	source /etc/os-release

	eval "kpatch_install_vagrant_${ID} ${image_path}" || { echo "Unsupported distro: ${ID}"; exit 1; }
}

kpatch_check_install_vagrant()
{
	local image_path=${1}
	[ "$(which vagrant)" == "" ] && kpatch_install_vagrant "${image_path}"
}
