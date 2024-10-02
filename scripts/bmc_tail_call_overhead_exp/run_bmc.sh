#! /bin/bash

SERVER_IP=192.168.1.1
echo "Server ip is $SERVER_IP"
MEMCD_DIR_BIN=$HOME/memcached/memcached
taskset -c 1 $MEMCD_DIR_BIN -p 11211 -U 11211 -l $SERVER_IP -m 1024 -M -k -P /tmp/M1_PID -d -t 1 -C
sleep 1

if [ $# -gt 0 ]; then
	BMC_BIN=$1
else
	BMC_BIN=$HOME/bmc/bmc/bmc
fi
if [ -z "$NET_IFACE" ]; then
	echo "NET_IFACE has not been set"
	exit 1
fi
IFINDEX=$(ip -j addr show $NET_IFACE | jq '.[0].ifindex')

# echo Running BMC ...
echo "Using $BMC_BIN and interface index: $IFINDEX" 
$(nohup sudo $BMC_BIN $IFINDEX) &
sleep 3
sudo tc qdisc add dev $NET_IFACE clsact
PINNED_FILE=/sys/fs/bpf/bmc_tx_filter
sudo tc filter add dev $NET_IFACE egress bpf object-pinned $PINNED_FILE
if [ $? -ne 0 ]; then
	# for the global version we have changed stuff
	PINNED_FILE=/sys/fs/bpf/bmc_tx_filter_main
	sudo tc filter add dev $NET_IFACE egress bpf object-pinned $PINNED_FILE
	echo "It is probably the global version"
fi

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
sudo rm $PINNED_FILE
# Stop Memcached
kill -SIGINT $(cat /tmp/M1_PID)
