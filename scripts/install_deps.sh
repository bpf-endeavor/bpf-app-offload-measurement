#!/bin/bash

# !! DESCLAIMER NOTE:
# read the installation script. You might not want all of these
# operations to happen in your environment

CURDIR=$(realpath $(dirname $0))
THIRD=$(realpath $CURDIR/../others/)

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
	libzstd-dev libunwind-dev libreadline-dev numactl neovim )

sudo apt update
sudo apt install -y "${PACKAGES[@]}"
pip install scapy flask
sudo apt install -y "linux-tools-$(uname -r)"

## INSTALL CLANG
cd "$THIRD"
CLANG_VERSION=14
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh $CLANG_VERSION
# Both install clang-15 and clang-16
# sudo ./llvm.sh 18
# Configure the clang
sudo bash "$CURDIR/update-alternatives-clang.sh" $CLANG_VERSION 100

## GET Custom Kernel <-- you can apply patches to this kernel
cd "$THIRD"
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.7.tar.xz
tar -xf linux-6.8.7.tar.xz
KERNEL_SOURCE_DIR="$THIRD/linux-6.8.7"

## Install BPFTOOL
cd "$KERNEL_SOURCE_DIR/tools/bpf/"
make clean
make -j
sudo make install

## Install perf
cd "$KERNEL_SOURCE_DIR/tools/perf"
make clean
BUILD_NONDISTRO=1 make
target=/usr/bin/perf
if [ -f $target ]; then
	sudo rm $target
fi
sudo ln -s "$KERNEL_SOURCE_DIR/tools/perf/perf" $target

## INSTALL CPU POWER
cd "$KERNEL_SOURCE_DIR/tools/power/cpupower"
make -j
sudo make install
sudo ldconfig

## INSTALL x86 Energy
cd "$KERNEL_SOURCE_DIR/tools/power/x86/x86_energy_perf_policy"
make
sudo make install

