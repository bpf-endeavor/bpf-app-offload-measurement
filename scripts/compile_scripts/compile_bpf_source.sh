#! /bin/bash

# THIS SCRIPT IS OLD AND IS ONLY HERE SO BMC MAKEFILE TO WORK
# THIS SCRIPT IS OLD AND IS ONLY HERE SO BMC MAKEFILE TO WORK
# THIS SCRIPT IS OLD AND IS ONLY HERE SO BMC MAKEFILE TO WORK
# THIS SCRIPT IS OLD AND IS ONLY HERE SO BMC MAKEFILE TO WORK

set -e
# set -x

CURDIR=$(realpath $(dirname $0))
OLD_LIBBPF_HEADER=$HOME/old_libbpf/src/build/usr/include/

CC=clang
LLC=llc
CFLAGS="$CFLAGS -Wall \
        -I $OLD_LIBBPF_HEADER \
        -Wno-unused-value \
        -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types \
        -O2 -emit-llvm -c -g"

OUTPUT_DIR_BPF=/tmp
SOURCE=$1
if [ $# -ge 2 ]; then
        BINARY=$2
else
        BINARY="$OUTPUT_DIR_BPF/bpf.o"
fi

if [ $# -ge 3 ]; then
        LL_FILE=$3
else
        LL_FILE="$OUTPUT_DIR_BPF/bpf.ll"
fi

$CC --version
if [ -f $LL_FILE ]; then
        rm $LL_FILE
fi

$CC -S \
        -target bpf \
        -D __BPF_TRACING__ \
        $CFLAGS \
        -o $LL_FILE $SOURCE
$LLC -mcpu=probe -march=bpf -filetype=obj -o $BINARY $LL_FILE

