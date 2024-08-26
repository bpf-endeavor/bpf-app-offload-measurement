#! /bin/bash

# Some notes
echo "1- pass \`bmc' as the first argument to also configure BMC"
echo "2- Add steering rules (udp4/11211 & udp4/8080 --> same rx)"
echo "3- The interface index (ifindex), server ip, ... is hard-coded. Update it for your env"
echo "4- seperate the queues on workload generator machine (flow director)"

quit=0

SOCK_APP_DIR=../../../src
INT2HEX=../../../scripts/int2hex.py
LOADER=$SOCK_APP_DIR/build/loader
BPFOBJS=$SOCK_APP_DIR/build/bpf
MEMCD_DIR_BIN=$HOME/memcached/memcached
BMC_BIN=$HOME/bmc/bmc/bmc

# Run socker app
# Make sure socket app is compiled
make -C $SOCK_APP_DIR &> /dev/null
# Load and attach XDP_DEMUX
$(sudo nohup taskset -c 3 $LOADER -b $BPFOBJS/bpf_demux.o -i $NET_IFACE --xdp xdp_demux) &
# Load but do not attach XDP echo program
$(sudo nohup taskset -c 5 $LOADER -b $BPFOBJS/bpf_redirect.o) &
sleep 2
# Update program map
sudo bpftool map update name map_progs_demux key $(echo 0 | $INT2HEX) value name xdp_prog

# Run memcached
nohup taskset -c 1 $MEMCD_DIR_BIN -U 11211 -l 192.168.200.101 \
	-m 1024 -M -k -P /tmp/M1_PID -d -t 1 -C

# Run BMC if specified
HAS_BMC=0
if [ "x$1" == "xbmc" ]; then
	echo Running BMC for M1...
	HAS_BMC=1
	$(sudo nohup taskset -c 9 $BMC_BIN) &
	sleep 3
	sudo tc qdisc add dev $NET_IFACE clsact
	sudo tc filter ad dev $NET_IFACE egress bpf object-pinned /sys/fs/bpf/bmc_tx_filter
	# Add BMC entry program to DEMUX map
	sudo bpftool map update name map_progs_demux key $(echo 1 | $INT2HEX) value name bmc_rx_filter_main
fi

trap 'quit=1' SIGINT SIGHUP
echo ''
echo 'Ctrl-C to stop...'
while [ $quit -ne 1 ]; do
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

# Kill and detach XDP programs
sudo pkill -SIGINT loader
