#!/bin/bash

install_pkgs() {
	## INSTALL PACKAGES
	# Disclaimer: these are a set of packages that I use across my projects. Not
	# all of them are exactly related to this repository. Have a look and decide
	# if you want to install them or not.

	PACKAGES=( htop build-essential exuberant-ctags mosh cmake \
		silversearcher-ag pkg-config libelf-dev libdw-dev gcc-multilib python3 \
		python3-pip python3-venv libpcap-dev libpci-dev libnuma-dev flex bison \
		libslang2-dev libcap-dev libssl-dev libncurses-dev jq meson ninja-build \
		python3-pyelftools libyaml-dev libcsv-dev nlohmann-json3-dev gcc g++ \
		doxygen graphviz libhugetlbfs-dev libnl-3-dev libnl-route-3-dev \
		uuid-dev git-lfs libbfd-dev libbinutils gettext libtraceevent-dev \
		libzstd-dev libunwind-dev libreadline-dev numactl neovim \
		"linux-tools-$(uname -r)" )

	sudo apt update
	sudo apt install -y "${PACKAGES[@]}"
	pip install scapy flask
}

install_clang() {
	## INSTALL CLANG
	cd "$THIRD" || exit 1
	CLANG_VERSION=14
	wget https://apt.llvm.org/llvm.sh
	chmod +x llvm.sh
	sudo ./llvm.sh $CLANG_VERSION
	# Configure the clang-14 as clang
	sudo bash "$CURDIR/update-alternatives-clang.sh" $CLANG_VERSION 100
}


install_dwarf() {
	# INSTALL DWARF (required for BTF)
	cd $THIRD || exit 1
	git clone https://github.com/acmel/dwarves.git
	cd dwarves
	git checkout v1.29
	mkdir build/
	cd build/
	cmake ../
	make -j
	sudo make install
	sudo ldconfig
}

get_kernel_source() {
	## GET Custom Kernel <-- you can apply patches to this kernel
	cd "$THIRD" || exit 1
	wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.7.tar.xz
	tar -xf linux-6.8.7.tar.xz
}

install_kernel_tools() {
	## Install BPFTOOL
	cd "$KERNEL_SOURCE_DIR/tools/bpf/" || exit 1
	make clean
	make -j
	sudo make install

	## Install perf
	cd "$KERNEL_SOURCE_DIR/tools/perf" || exit 1
	make clean
	BUILD_NONDISTRO=1 make
	target=/usr/bin/perf
	if [ -f $target ]; then
		sudo rm $target
	fi
	sudo ln -s "$KERNEL_SOURCE_DIR/tools/perf/perf" $target

	## INSTALL CPU POWER
	cd "$KERNEL_SOURCE_DIR/tools/power/cpupower" || exit 1
	make -j
	sudo make install
	sudo ldconfig

	## INSTALL x86 Energy
	cd "$KERNEL_SOURCE_DIR/tools/power/x86/x86_energy_perf_policy" || exit 1
	make
	sudo make install
}

patch_kernel() {
	## Patch kernel
	cd "$KERNEL_SOURCE_DIR"
	for p in $(ls $ROOTDIR/patches/kernel/); do
		echo "patch -p1 < $ROOTDIR/patches/kernel/$p"
		patch -p1 < "$ROOTDIR/patches/kernel/$p"
	done
}

config_kernel() {
	cd "$KERNEL_SOURCE_DIR"
	mkdir ./build/
	cd ./build/ || exit 1
	make -C ../ O=$(pwd) defconfig
	cp $CURDIR/kernel_config .config
	yes '' | make oldconfig
	# make -j 40
}

build_repo() {
	cd $ROOTDIR
	make
}

