#!/bin/bash

get_latency_values() {
	cat $1 | awk '/200 / {print $3}' | sort -n > $2
}

scale() {
	_T=/tmp/__t_scale
	for i in $(seq $2); do
		cat $1 >> $_T
	done
	cat $_T
	rm $_T
}

baseline=./socket_partial_offload/baseline
bmc=./socket_partial_offload/with_bmc
get_latency_values "$baseline/m2_lat_samples_*.txt" m2_lat_baseline.txt
get_latency_values "$bmc/m2_lat_samples_*.txt" m2_lat_bmc.txt

# get_latency_values "./xsk_cache/baseline/m1_lat_samples_*.txt" /tmp/m1_lat_baseline.txt
# get_latency_values "./xsk_cache/with_bmc/m1_lat_samples_*.txt" /tmp/m1_lat_bmc.txt
# scale /tmp/m1_lat_baseline.txt 500 > all_lat_baseline.txt
# scale /tmp/m1_lat_bmc.txt 500 > all_lat_bmc.txt

get_latency_values "$baseline/m*_lat_samples_*.txt" all_lat_baseline.txt
get_latency_values "$bmc/m*_lat_samples_*.txt" all_lat_bmc.txt
