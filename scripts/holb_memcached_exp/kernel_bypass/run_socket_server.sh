#! /bin/bash

# Some notes
echo "1- pass \`bmc' as the first argument to also configure BMC"
echo "2- Make sure to remove steering rule"
echo "3- The interface index (ifindex), server ip, ... is hard-coded. Update it for your env"

trap 'quit=1' SIGINT
quit=0

MEMCD_DIR_BIN=$HOME/memcached/memcached
BMC_BIN=$HOME/bmc/bmc/bmc

# M1
(taskset -c 11 \
	$MEMCD_DIR_BIN -U 11211 -l 192.168.200.101 \
	-m 4096 -M -k -P /tmp/M1_PID -t 1 -C) &

HAS_BMC=0
if [ "x$1" == "xbmc" ]; then
	echo Running BMC for M1...
	HAS_BMC=1
	nohup sudo $BMC_BIN 6 &
	sleep 3
	sudo tc qdisc add dev $NET_IFACE clsact
	sudo tc filter add dev $NET_IFACE egress bpf object-pinned /sys/fs/bpf/bmc_tx_filter
fi

echo "Ctrl-C to stop..."
while [ "$quit" -ne 1 ]; do
    sleep 1
done

# Kill memcached
kill -SIGINT $(cat /tmp/M1_PID)

# Detach BMC
if [ $HAS_BMC -eq 1 ]; then
	sudo pkill -SIGINT bmc
	sudo tc filter del dev $NET_IFACE egress
	sudo tc qdisc del dev $NET_IFACE clsact
	sudo rm /sys/fs/bpf/bmc_tx_filter
fi
