#!/bin/bash
set -x
# args -- core number
sudo perf stat -C $1 \
	-e cycles \
	-e  instructions \
	-e L1-dcache-loads \
	-e L1-dcache-load-misses \
	-e l2_rqsts.all_demand_data_rd \
	-e l2_rqsts.demand_data_rd_miss \
	-e LLC-loads \
	-e LLC-load-misses \
	-r 3 -- sleep 1
