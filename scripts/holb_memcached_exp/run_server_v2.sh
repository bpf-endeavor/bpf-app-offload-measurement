#! /bin/bash

# Some notes
echo "1- pass \`bmc' as the first argument to also configure BMC"
echo "2- The interface index (ifindex), server ip, ... is hard-coded. Update it for your env"
# echo "3- Make sure to remove steering rule"

# SERVER_IP
# NET_IFACE
# NET_IFACE_INDEX

if [ -z "$SERVER_IP" ]; then
        echo SERVER_IP is not set!
        exit 1
fi

trap 'quit=1' SIGINT
quit=0

CURDIR=$(realpath $(dirname $0))
ROOTDIR=$(realpath $CURDIR/../..)
THIRD=$ROOTDIR/others

if [ -z "$NET_IFACE" ]; then
        echo NET_IFACE is not set!
        exit 1
fi

# NOTE: if you ran the `make prepare_env` then these files should exists.
# Otherwise, you can compile your own version of memcached and BMC and set the
# correct path.
MEMCD_DIR_BIN=$THIRD/memcached/memcached
BMC_BIN=$THIRD/bmc_bins/original/bmc

if [ ! -f $MEMCD_DIR_BIN ]; then
        echo Memcached is not installed at $MEMCD_DIR_BIN
        exit 1
fi

# M1
taskset -c 11,13,15,17 \
        $MEMCD_DIR_BIN -U 11211 -l $SERVER_IP \
        -m 1024 -M -k -P /tmp/M1_PID -d -t 4 -C

HAS_BMC=0
if [ "x$1" == "xbmc" ]; then
        echo Running BMC for M1...
        if [ ! -f $BMC_BIN ]; then
                echo BMC is not install at $BMC_BIN
                exit 1
        fi

        if [ -z "$NET_IFACE_INDEX" ]; then
                echo NET_IFACE_INDEX is not set!
                exit 1
        fi

        HAS_BMC=1
        nohup sudo $BMC_BIN $NET_IFACE_INDEX &
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

