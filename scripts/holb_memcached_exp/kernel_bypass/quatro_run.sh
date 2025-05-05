#!/bin/bash

# set -x
# set -e

MUTILATE_DIR=$HOME/mutilate
SERVER_HOST=192.168.200.101
M1_PORT=11211
# NOTE: Experiment duration in seconds
TIME=20
REPEAT=20
OUTPUT_DIR=$HOME/af_xdp/interference/xsk_cache/baseline/

# KEY 0 --> Large (in user-space)
# KEY 1 --> Small (in BMC)
WORKLOAD_DESC_BG="--records=2 -K 200 -V 1000"
WORKLOAD_DESC_FG="--records=1 -K 200 -V 1100"

LOAD_RATE=50000
MEASUREMENT_RATE=5000

trap "handle_signal" SIGINT SIGHUP

function handle_signal {
        echo Received a signal...
        pkill mutilateudp
        exit 0
}

if [ ! -d $OUTPUT_DIR ]; then
        mkdir -p $OUTPUT_DIR
fi

echo "Not loading anything :)"
# $MUTILATE_DIR/mutilate -s $SERVER_HOST:$M1_PORT $WORKLOAD_DESC_BG --loadonly -t 1
# $MUTILATE_DIR/mutilate -s $SERVER_HOST:$M1_PORT $WORKLOAD_DESC_FG --loadonly -t 1

for i in $(seq $REPEAT); do
        echo Running agents ...
        taskset -c 1,3,5 $MUTILATE_DIR/mutilateudp -A --threads 3 -p 5556 &

        echo Running experiment $i ...
        taskset -c 7 $MUTILATE_DIR/mutilateudp \
                --time=$TIME --qps=$LOAD_RATE \
                $WORKLOAD_DESC_BG --popularity const:1 \
                --server=$SERVER_HOST:$M1_PORT --noload --connections=2 \
                --measure_connections=1 --measure_qps=10 \
                --agent=localhost -p '5556' &>> $OUTPUT_DIR/m1_result.txt &
                # --save=$OUTPUT_DIR/m1_lat_samples_$i.txt \

        taskset -c 17 $MUTILATE_DIR/mutilateudp \
                --time=$TIME --qps=$MEASUREMENT_RATE \
                $WORKLOAD_DESC_FG  --popularity const:0 \
                --server=$SERVER_HOST:$M1_PORT --noload --threads=1 --connections=1 \
                --save=$OUTPUT_DIR/m2_lat_samples_$i.txt \
                --measure_connections=1 --measure_qps=$MEASUREMENT_RATE \
                &>> $OUTPUT_DIR/m2_result.txt &

        # Wait until mutilate instances close
        sleep $TIME
        # NOTE: wait some time to write samples to a file
        sleep 10
        pkill mutilateudp
        sleep 1
done

echo ---------------------------------
echo Check results at:
echo $OUTPUT_DIR/m1_result.txt
echo $OUTPUT_DIR/m2_result.txt
echo Done!
