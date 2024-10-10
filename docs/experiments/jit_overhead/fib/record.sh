#!/bin/bash

# MODE=kernel
MODE=bpf

LOG=./results.txt
log () {
	echo $@ | tee -a $LOG
}

handle_signal() {
	echo "Done!"
}

trap "handle_signal" SIGINT SITHUP

echo "Fib = "
read fib
log "-------------------------------"
log "Fib = $fib"

if [ $MODE = kernel ]; then
	sudo dmesg -C
	sudo dmesg -w | tee -a $LOG
elif [ $MODE = bpf ]; then
	sudo cat /sys/kernel/tracing/trace > /dev/null
	sudo cat /sys/kernel/tracing/trace_pipe | tee -a $LOG
else
	echo "Unrecognize MODE value"
	exit 1
fi
