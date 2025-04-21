#!/bin/bash
files=( socket.txt bmc.txt af_xdp.txt )
output="summary.txt"
statscript="../../../latency_script.py"

main() {
	echo "The numbers are K-Query per second (kqps)"
	echo "-----------------------------------------"
	for file in ${files[@]}; do
		echo $file
		echo "-----------"
		cat $file | grep QPS | awk '{print $4/1000}' | $statscript
		echo ""
	done
}

main | tee $output
