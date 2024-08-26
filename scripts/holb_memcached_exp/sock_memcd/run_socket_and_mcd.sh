#! /bin/bash

# Some notes
echo "1- pass \`bmc' as the first argument to also configure BMC"
echo "2- Add steering rules (udp4/11211 & udp4/8080 --> same rx)"
echo "3- The interface index (ifindex), server ip, ... is hard-coded. Update it for your env"

trap 'quit=1' SIGINT
quit=0

SOCK_APP_DIR=../../../src
MEMCD_DIR_BIN=$HOME/memcached/memcached
BMC_BIN=$HOME/bmc/bmc/bmc

# Run socker app
# Make sure socket app is compiled
make -C $SOCK_APP_DIR
#                            core  server-ip  server-port udp(0)/tcp(1)
$SOCK_APP_DIR/build/server_bounce 7 192.168.200.101 8080 0 &> /dev/null &
SOCK_APP_PID=$!

# Run memcached
taskset -c 1 \
	$MEMCD_DIR_BIN -U 11211 -l 192.168.200.101 \
	-m 1024 -M -k -P /tmp/M1_PID -d -t 1 -C

# Run BMC if specified
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

# Kill socket-app
pkill server_bounce
