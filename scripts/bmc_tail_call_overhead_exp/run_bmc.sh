#! /bin/bash

MEMCD_DIR_BIN=$HOME/memcached/memcached
taskset -c 1 $MEMCD_DIR_BIN -p 11211 -U 11211 -l 192.168.200.101 -m 1024 -M -k -P /tmp/M1_PID -d -t 1
sleep 1

BMC_BIN=$HOME/bmc/bmc/bmc
if [ -z "$NET_IFACE" ]; then
	echo "NET_IFACE has not been set"
	exit 1
fi
IFINDEX=$(ip -j addr show $NET_IFACE | jq '.[0].ifindex')

# echo Running BMC ...
$(nohup sudo $BMC_BIN $IFINDEX) &
sleep 3
sudo tc qdisc add dev $NET_IFACE clsact
sudo tc filter add dev $NET_IFACE egress bpf object-pinned /sys/fs/bpf/bmc_tx_filter

trap 'quit=1' SIGINT
quit=0
echo "Ctrl-C to stop..."
while [ $quit -ne 1 ]; do
    sleep 1
done

# Detach BMC
sudo pkill -SIGINT bmc
sudo tc filter del dev $NET_IFACE egress
sudo tc qdisc del dev $NET_IFACE clsact
sudo rm /sys/fs/bpf/bmc_tx_filter
# Stop Memcached
kill -SIGINT $(cat /tmp/M1_PID)
