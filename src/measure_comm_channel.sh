#!/bin/bash
LOG_FILE=/tmp/results.txt
echo "--------------------------" >> $LOG_FILE
for i in $(seq 40); do
	sudo ./build/server_comm_map >> $LOG_FILE
done
