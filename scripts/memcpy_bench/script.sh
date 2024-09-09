#! /bin/bash
CURDIR=$(realpath $(dirname $0))
DIR=$KASHK_DIR/cost_benchmark
cd $DIR

r=100
for i in $(seq $r); do
	# sudo ./build/runner -b ./build/memcpy.o | grep "benchmark res" | awk '{print $3 / 100}' &>> $CURDIR/ebpf_samples.txt
	# sleep 1
	# ./build/memcpy_bench | awk '{print substr($3,2, length($3)-1)}' &>> $CURDIR/user_simd_samples.txt
	sleep 1
	./build/memcpy_bench_no_simd | awk '{print substr($3,2, length($3)-1)}' &>> $CURDIR/user_no_simd_samples.txt
done
