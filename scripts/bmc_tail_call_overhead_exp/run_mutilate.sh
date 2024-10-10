#!/bin/bash
set -e

SERVER_HOST=192.168.1.1
SERVER_PORT=11211
# NOTE: Experiment duration in seconds
TIME=10
REPEAT=40

LOCALHOST=`hostname`
AGENT=$LOCALHOST

# WORKLOAD_DESC="--records=1000000 --keysize=fb_key --valuesize=fb_value --iadist=fb_ia --update=0"
WORKLOAD_DESC="--records=1 -K 128 -V 64 -i fixed:0"

if [ $# -gt 0 ]; then
    OUTPUT_FILE=$1
else
    OUTPUT_FILE=/tmp/bmc_performance.txt
fi

trap "handle_signal" SIGINT SIGHUP

function handle_signal {
        pkill mutilateudp
}

echo Loading ...
./mutilate -s $SERVER_HOST:$SERVER_PORT $WORKLOAD_DESC --loadonly -t 1

for i in $(seq $REPEAT); do
        echo Running agents ...
        ./mutilateudp -A --threads 8 &
        echo Running experiment $i ...
        taskset -c 0 ./mutilateudp --time=$TIME --qps=0 $WORKLOAD_DESC \
                --server=$SERVER_HOST:$SERVER_PORT --noload --threads=1 --connections=16 \
                --measure_connections=1 --measure_qps=100 --agent=$AGENT | tee -a $OUTPUT_FILE
        # Terminate
        handle_signal
        sleep 1
done
