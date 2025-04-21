#! /bin/bash

# set -x

# Assumptions:
# System has hugepages and it is mounted in /dev/hugepages (look at TAS readme)

mode="plain"
# mode="bmc"

if [ -z $NET_IFACE ]; then
	echo "NET_IFACE is not set"
	exit 1
fi

launch_bmc() {
	# launch bmc on the given interface
	# ifindex=$(ip -j address show dev $NET_IFACE | jq '.[0].ifindex')
	# nohup sudo $BMC_BIN $ifindex &
	echo "Launching AF_XDP Memcached + BMC ..."
	echo "The seastar library has been modified to bind to AF_XDP driver."
	echo "Unfortunately the configurations are hard-coded (look at the patch)"
	echo "After running the program, it will load the XDP program."
	echo "You need to route the traffic towards the correct queue using flow-steering"

	echo "For example:"
	printf "\tsudo ethtool -U $NET_IFACE flow-type udp4 dst-port 11211 action 26\n\tsudo ethtool -U $NET_IFACE flow-type tcp4 dst-port 11211 action 26\n\n"
}

build_type=release
# build_type=debug

main() {
case $mode in
	plain)
		Memcd="/home/farbod/seastar/build/$build_type/apps/memcached/memcached"
		;;
	bmc)
		Memcd="/home/farbod/my-seastar/build/$build_type/apps/memcached/memcached"
		launch_bmc
		;;
esac


# sudo $Memcd --help-seastar
# exit 0

sudo $Memcd -c 1 --cpuset 11 \
	-m 8G \
	--poll-mode --dpdk-pmd \
	--network-stack native \
	--host-ipv4-addr 192.168.200.101 --netmask-ipv4-addr 255.255.255.0 \
	--collectd 0

# Make sure the XDP program is deatched
sudo ip link set dev $NET_IFACE xdp off

echo Done!
}

main
