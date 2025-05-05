#!/bin/bash
cat ./xsk_cache/baseline/m2_lat_samples_*.txt | awk '{print $3}' | sort -n > m2_lat_baseline.txt
cat ./xsk_cache/with_bmc/m2_lat_samples_*.txt | awk '{print $3}' | sort -n > m2_lat_bmc.txt

