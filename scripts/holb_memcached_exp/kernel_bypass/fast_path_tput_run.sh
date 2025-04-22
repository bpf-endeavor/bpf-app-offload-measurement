#!/bin/bash
# Benchmark the throughput of BMC fast-path (everything hit in BMC)

# set -x
# set -e

OUTPUT_FILE=/tmp/fast_path_tput_result.txt
MUTILATE_DIR=$HOME/mutilate
SERVER_HOST=192.168.200.101
M1_PORT=11211
# NOTE: Experiment duration in seconds
TIME=20
REPEAT=40

# KEY 0 --> Large (in user-space)
# KEY 1 --> Small (in BMC)
WORKLOAD_DESC_BG="--records=10 -K 16 -V 8"

LOAD_RATE=0

trap "handle_signal" SIGINT SIGHUP

running=1
function handle_signal {
        echo Received a signal...
        running=0
        sudo pkill mutilateudp
        exit 1
}

_next_core=0
function assign_cores {
        # $1 count
        count=$1
        tmp="$_next_core"
        if [ $count -eq 1 ]; then
                _next_core=$((_next_core + 2))
        else
                count=$((count - 1))
                for i in $(seq $count); do
                        tmp="$tmp,$_next_core"
                        _next_core=$((_next_core + 2))
                done
        fi
        echo $tmp
}

echo Loading ...
$MUTILATE_DIR/mutilate -s $SERVER_HOST:$M1_PORT $WORKLOAD_DESC_BG --loadonly -t 1

for i in $(seq $REPEAT); do
        echo Running agents ...
        _next_core=0 # reset to assign from zero again
        T=6 # number of threads
        cpu_list=$(assign_cores $T)
        taskset -c $cpu_list  $MUTILATE_DIR/mutilateudp -A --threads $T -p 5556 &

        echo Running experiment $i ...
        taskset -c $(assign_cores 1) \
                $MUTILATE_DIR/mutilateudp \
                --time=$TIME --qps=$LOAD_RATE \
                $WORKLOAD_DESC_BG --popularity const:1 \
                --server=$SERVER_HOST:$M1_PORT --noload --connections=8 \
                --measure_connections=1 --measure_qps=10 \
                --agent=localhost -p '5556' &>> $OUTPUT_FILE &
                # --save=/tmp/m1_lat_samples_$i.txt \

        # Wait until mutilate instances close
        sleep $TIME
        # NOTE: wait some time to write samples to a file
        sleep 10
        sudo pkill mutilateudp
        sleep 1
done

echo ---------------------------------
echo Check results at:
echo "$OUTPUT_FILE"
echo Done!
echo .................................
printf "\n\n"
cat $OUTPUT_FILE

