#!/bin/bash

MUTILATE_DIR=$HOME/mutilate
SERVER_HOST=192.168.200.101
M1_PORT=11211
M2_PORT=22122
# NOTE: Experiment duration in seconds
TIME=10
REPEAT=50

# WORKLOAD_DESC="--records=1000000 --keysize=fb_key --valuesize=fb_value --iadist=fb_ia --update=0"
WORKLOAD_DESC="--records=10000 -K 128 -V 64"

trap "handle_signal" SIGINT SIGHUP

function handle_signal {
	echo Received a signal...
	pkill -SIGINT mutilateudp
}

echo Loading ...
$MUTILATE_DIR/mutilate -s $SERVER_HOST:$M1_PORT $WORKLOAD_DESC --loadonly -t 1
$MUTILATE_DIR/mutilate -s $SERVER_HOST:$M2_PORT $WORKLOAD_DESC --loadonly -t 1

for i in $(seq $REPEAT); do
	echo Running agents ...
	taskset -c 1,3,5 $MUTILATE_DIR/mutilateudp -A --threads 3 -p 5556 &
	taskset -c 11,13,15 $MUTILATE_DIR/mutilateudp -A --threads 3 -p 5558 &
	echo Running experiment $i ...
	taskset -c 7 $MUTILATE_DIR/mutilateudp --time=$TIME --qps=10000 $WORKLOAD_DESC \
		--server=$SERVER_HOST:$M1_PORT --noload --threads=1 --connections=2 \
		--measure_connections=1 --measure_qps=2000 --agent=localhost -p '5556' &>> /tmp/m1_result.txt &

	taskset -c 17 $MUTILATE_DIR/mutilateudp --time=$TIME --qps=10000 $WORKLOAD_DESC \
		--server=$SERVER_HOST:$M2_PORT --noload --threads=1 --connections=2 \
		--measure_connections=1 --measure_qps=2000 --agent=localhost -p '5558' &>> /tmp/m2_result.txt &

	# Wait until mutilate instances close
	sleep $TIME
	sleep 2
	pkill mutilateudp
	sleep 1
done

echo ---------------------------------
echo Check results at:
echo /tmp/m1_result.txt
echo /tmp/m2_result.txt
echo Done!
