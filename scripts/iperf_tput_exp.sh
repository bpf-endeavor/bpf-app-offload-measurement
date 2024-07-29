#! /bin/bash

USER=farbod
SERVER=neat-01
# Where on server we have installed the benchamrk
BENCHMARK_INSTALL_DIR=/home/farbod/auto_kern_offload_bench
OUTPUT_FILE=$HOME/iperf_result.txt

REPEAT=100
# socket,xdp,tc,skskb
MODE=socket
echo "Running in mode=$MODE"

LOADER_COMMAND=""
case $MODE in
	socket)
		LOADER_COMMAND=""
		OUTPUT_FILE=$HOME/iperf_result.txt
		;;
	xdp)
		LOADER_COMMAND="nohup sudo ./build/loader -b ./build/bpf/bpf_pass_perf.o -i enp202s0f0np0 --xdp xdp_prog &> /dev/null &"
		OUTPUT_FILE=$HOME/xdp_iperf_result.txt
		;;
	tc)
		LOADER_COMMAND="nohup sudo ./build/loader -b ./build/bpf/bpf_pass_perf.o -i enp202s0f0np0 --tc tc_prog &> /dev/null &"
		OUTPUT_FILE=$HOME/tc_iperf_result.txt
		;;
	skskb)
		LOADER_COMMAND="nohup sudo ./build/loader -b ./build/bpf/bpf_pass_perf.o -i enp202s0f0np0 --skskb verdict &> /dev/null &"
		OUTPUT_FILE=$HOME/skskb_iperf_result.txt
		;;
	*)
		echo Invalid mode
		exit 1
		;;
esac

# NOTE: if the following function fail to setup the server it will not complain
# TODO: do complain
function setup_server {
	ssh $USER@$SERVER << EOF
		sudo pkill -SIGINT loader
		sleep 1
		sudo pkill -SIGINT iperf
		sleep 1
		nohup iperf -s 192.168.200.101 -p 8080 &> /dev/null &
		sleep 1
		cd $BENCHMARK_INSTALL_DIR/src
		$LOADER_COMMAND
EOF
}

for i in `seq $REPEAT`; do
	echo $i;
	setup_server &> /dev/null
	sleep 3
	iperf -c 192.168.200.101 -p 8080 -P 48 &>> $OUTPUT_FILE;
	sleep 1;
done
