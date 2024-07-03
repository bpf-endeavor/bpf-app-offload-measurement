#! /bin/bash

USER=farbod
SERVER=neat-01
# Where on server we have installed the benchamrk
BENCHMARK_INSTALL_DIR=/home/farbod/auto_kern_offload_bench
OUTPUT_FILE=$HOME/skskb_iperf_result.txt

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
        nohup sudo ./build/loader -b ./build/bpf/bpf_pass_perf.o --skskb verdict &> /dev/null &
EOF
}

for i in `seq 100`; do
        echo $i;
        setup_server &> /dev/null
        sleep 2
        iperf -c 192.168.200.101 -p 8080 -P 48 &>> $OUTPUT_FILE;
        sleep 1;
done

