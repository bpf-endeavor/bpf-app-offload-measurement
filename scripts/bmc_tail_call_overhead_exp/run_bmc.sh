#! /bin/bash
BMC_BIN=./bmc
if [ -z "$NET_IFACE" ]; then
	echo "NET_IFACE has not been set"
	exit 1
fi

echo Running BMC ...
nohup sudo $BMC_BIN 6 &
sleep 3
sudo tc qdisc add dev $NET_IFACE clsact
sudo tc filter add dev $NET_IFACE egress bpf object-pinned /sys/fs/bpf/bmc_tx_filter

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
