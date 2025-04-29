#!/bin/bash
set -e
curdir=$(dirname $0)
src=$(realpath "$curdir/fib.c")
out=./build/xdp.o
ll_file="$out.ll"

mkdir -p $(dirname $out)
clang -target bpf -S -D __EXP_BPF_INTERFERENCE -D BPF_PROG \
	-Wall -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-O2 -g -emit-llvm -c $src -o $ll_file

llc -mcpu=v3 -march=bpf -filetype=obj -o $out $ll_file

