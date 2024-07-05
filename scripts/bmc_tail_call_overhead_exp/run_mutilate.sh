#!/bin/bash
set -e

SERVER_HOST=192.168.200.101
SERVER_PORT=11211
# NOTE: Experiment duration in seconds
TIME=10

LOCALHOST=`hostname`
AGENT=$LOCALHOST

# WORKLOAD_DESC="--records=1000000 --keysize=fb_key --valuesize=fb_value --iadist=fb_ia --update=0"
WORKLOAD_DESC="--records=10000 -K 128 -V 64"

trap "handle_signal" SIGINT SIGHUP


function handle_signal {
	pkill mutilateudp
}

echo Loading ...
./mutilate -s $SERVER_HOST:$SERVER_PORT $WORKLOAD_DESC --loadonly -t 1

for i in $(seq 100); do
	echo Running agents ...
	./mutilateudp -A --threads 8 &
	echo Running experiment $i ...
	./mutilateudp --time=$TIME --qps=2000000 $WORKLOAD_DESC \
		--server=$SERVER_HOST:$SERVER_PORT --noload --threads=1 --connections=32 \
		--measure_connections=1 --measure_qps=2000 --agent=$AGENT &>> /tmp/bmc_performance.txt
	# Terminate
	handle_signal
	sleep 1
done
