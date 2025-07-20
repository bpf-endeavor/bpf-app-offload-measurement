#! /bin/bash
set -e

USER=farbod
# control ip of the server
SERVER=neat-01
# experiment ip of the server
SERVER_EXP=192.168.200.101
# Where on server we have installed the benchamrk
BENCHMARK_INSTALL_DIR=/home/farbod/bpf-app-offload-measurement
OUTPUT_DIR=$HOME/empty_ebpf_overhead/
OUTPUT_FILE=$OUTPUT_DIR/iperf_result.txt
SERVER_IFACE_NAME=enp202s0f0np0

# Number of parallel connections
PARALLEL=48

# NOTE: the scripts runs the experiment for all modes
# socket,xdp,tc,skskb
MODE=socket

# make sure the output directory exists
mkdir -p $OUTPUT_DIR

# How many times should repeat the measurement
REPEAT=2

get_cores() {
	r=""
	for i in $(seq 0 $((PARALLEL-1))); do
		r="$r,$i"
	done
	len=${#r}
	r=${r:1:$len} # substr to remove the initial comma
	echo $r
}

# NOTE: if the following function fail to setup the server it will not complain
# TODO: do complain
function setup_server {
	ssh $USER@$SERVER << EOF
		sudo pkill -SIGINT loader
		sleep 1
		sudo pkill -SIGINT iperf
		sleep 1
		nohup taskset -c $(get_cores) iperf -s $SERVER_EXP -p 8080 &> /dev/null &
		sleep 1
		cd $BENCHMARK_INSTALL_DIR/src
		$LOADER_COMMAND
EOF
}

do_exp() {
	setup_server &> /dev/null
	sleep 3
	iperf -c $SERVER_EXP -p 8080 -P $PARALLEL &>> $OUTPUT_FILE;
}

configure() {
	LOADER_COMMAND=""
	case $MODE in
		socket)
			LOADER_COMMAND=""
			OUTPUT_FILE=$OUTPUT_DIR/iperf_result.txt
			;;
		xdp)
			LOADER_COMMAND="nohup sudo ./build/loader -b ./build/bpf/bpf_pass_perf.o -i $SERVER_IFACE_NAME --xdp xdp_prog &> /dev/null &"
			OUTPUT_FILE=$OUTPUT_DIR/xdp_iperf_result.txt
			;;
		tc)
			LOADER_COMMAND="nohup sudo ./build/loader -b ./build/bpf/bpf_pass_perf.o -i $SERVER_IFACE_NAME --tc tc_prog &> /dev/null &"
			OUTPUT_FILE=$OUTPUT_DIR/tc_iperf_result.txt
			;;
		skskb)
			LOADER_COMMAND="nohup sudo ./build/loader -b ./build/bpf/bpf_pass_perf.o -i $SERVER_IFACE_NAME --skskb verdict &> /dev/null &"
			OUTPUT_FILE=$OUTPUT_DIR/skskb_iperf_result.txt
			;;
		*)
			echo Invalid mode
			exit 1
			;;
	esac
}

for MODE in socket xdp tc skskb; do
	configure
	echo "Running in mode=$MODE"
	for i in `seq $REPEAT`; do
		echo $i;
		do_exp
		sleep 1;
	done
done
