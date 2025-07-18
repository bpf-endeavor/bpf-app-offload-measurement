#!/bin/bash

set -e

# !! DESCLAIMER NOTE:
# read the installation script, make sure the commands are compatible with
# your enviroment

CURDIR=$(realpath $(dirname $0))
ROOTDIR=$(realpath "$CURDIR/../")
THIRD=$(realpath $CURDIR/../others/)
KERNEL_SOURCE_DIR="$THIRD/linux-6.8.7"
PROGFILE="$THIRD/_progress_level.txt"
# make sure this directory exists
mkdir -p "$THIRD"

PROGRESS=$(cat $PROGFILE)
if [ -z "$PROGRESS" ];then
	PROGRESS=0
fi

if [ $PROGRESS -lt 1 ]; then
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

	echo 1 > $PROGFILE
fi

if [ $PROGRESS -lt 2 ]; then
	## INSTALL CLANG
	cd "$THIRD" || exit 1
	CLANG_VERSION=14
	wget https://apt.llvm.org/llvm.sh
	chmod +x llvm.sh
	sudo ./llvm.sh $CLANG_VERSION
	# Configure the clang-14 as clang
	sudo bash "$CURDIR/update-alternatives-clang.sh" $CLANG_VERSION 100

	echo 2 > $PROGFILE
fi

if [ $PROGRESS -lt 3 ]; then
	## GET Custom Kernel <-- you can apply patches to this kernel
	cd "$THIRD" || exit 1
	wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.7.tar.xz
	tar -xf linux-6.8.7.tar.xz

	echo 3 > $PROGFILE
fi

if [ $PROGRESS -lt 4 ]; then
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

	echo 4 > $PROGFILE
fi

if [ $PROGRESS -lt 5 ]; then
	## Patch kernel
	cd "$KERNEL_SOURCE_DIR"
	for p in $( ls $ROOTDIR/patches/kernel/ ); do
		echo "patch -p1 < $ROOTDIR/patches/kernel/$p"
		patch -p1 < "$ROOTDIR/patches/kernel/$p"
	done

	echo 5 > $PROGFILE
fi

if [ $PROGRESS -lt 6 ]; then
	## Build
	cd "$KERNEL_SOURCE_DIR"
	mkdir ./build/
	cd ./build/ || exit 1
	make -C ../ O=$(pwd) defconfig
	cp $CURDIR/kernel_config .config
	yes '' | make oldconfig
	# make -j 40

	echo 6 > $PROGFILE
fi
