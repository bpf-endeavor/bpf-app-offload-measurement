#!/bin/bash

# set -x
# set -e

SOCKET_APP_BENCH=./main
MUTILATE_DIR=$HOME/mutilate
SERVER_HOST=192.168.200.101
M1_PORT=11211
# NOTE: Experiment duration in seconds
TIME=20
TIME_BG=$((TIME + 5))
REPEAT=1

# KEY 0 --> Large (in user-space)
# KEY 1 --> Small (in BMC)
WORKLOAD_DESC_BG="--records=2 -K 200 -V 1000"
LOAD_RATE=50000

trap "handle_signal" SIGINT SIGHUP

function handle_signal {
	echo Received a signal...
	pkill -SIGINT mutilateudp
}

echo Loading ...
$MUTILATE_DIR/mutilate -s $SERVER_HOST:$M1_PORT $WORKLOAD_DESC_BG --loadonly -t 1

for i in $(seq $REPEAT); do
	echo Running agents ...
	taskset -c 1,3,5 $MUTILATE_DIR/mutilateudp -A --threads 3 -p 5556 &

	echo Running experiment $i ...
	taskset -c 7 $MUTILATE_DIR/mutilateudp \
		--time=$TIME_BG --qps=$LOAD_RATE \
		$WORKLOAD_DESC_BG --popularity const:1 \
		--server=$SERVER_HOST:$M1_PORT --noload --connections=2 \
		--measure_connections=1 --measure_qps=10 \
		--agent=localhost -p '5556' &>> /tmp/m1_result.txt &
		# --save=/tmp/m1_lat_samples_$i.txt \

	sleep 1
	taskset -c 9 $SOCKET_APP_BENCH &>> /tmp/sock_app_bench.txt &

	# Wait until mutilate instances close
	sleep $TIME
	pkill -SIGINT main
	sleep 10
	pkill mutilateudp
	sleep 1
done

echo ---------------------------------
echo Check results at:
echo /tmp/m1_result.txt
echo /tmp/m2_result.txt
echo Done!
