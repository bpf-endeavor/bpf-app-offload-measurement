#!/bin/bash
set -x

CURDIR=$(realpath $(dirname $0))
PATCH_DIR=$(realpath $CURDIR/../../patches/bmc)
OLD_LIBBPF=$HOME/old_libbpf
BMC_DIR=$HOME/bmc
MEMCD_DIR=$HOME/memcached

# Memcached
sudo apt install -y libevent-dev
git clone https://github.com/memcached/memcached $MEMCD_DIR
cd $MEMCD_DIR
git checkout 1.6.31
./autogen.sh
./configure
make -j

# OLD libbpf
git clone https://github.com/libbpf/libbpf.git $OLD_LIBBPF
cd $OLD_LIBBPF/src
git checkout "v0.5.0"
make
make DESTDIR=build install

# BMC + patches
git clone https://github.com/Orange-OpenSource/bmc-cache/ $BMC_DIR
cd $BMC_DIR/bmc/
for branch_name in $(ls $PATCH_DIR); do
	git checkout -b $branch_name
	git am $PATCH_DIR/$branch_name/*.patch
	make
	BIN_DIR=$CURDIR/bins/$branch_name
	mkdir -p $BIN_DIR/
	cp ./bmc ./bmc_kern.o $BIN_DIR/
	make clean
	git checkout main
done
