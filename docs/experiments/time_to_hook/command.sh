#!/bin/bash
curdir=$(dirname $0)
stat_script=$curdir/../../latency_script.py
echo For TC
cat hook_reach_time.txt | tail -n +100000 | awk '{print $2}' | $stat_script
echo For Verdict
cat hook_reach_time.txt | tail -n +100000 | awk '{print $4}' | $stat_script
