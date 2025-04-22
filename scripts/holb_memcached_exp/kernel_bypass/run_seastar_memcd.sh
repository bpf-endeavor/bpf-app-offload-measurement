#! /bin/bash

# set -x

# Assumptions:
# System has hugepages and it is mounted in /dev/hugepages (look at TAS readme)

server_ip=192.168.200.101
net_mask=255.255.255.0

# Possible values: plain, bmc, bg, bmc-bg
mode="plain"

# Seastar build type
build_type=release
# build_type=debug

if [ -z $NET_IFACE ]; then
	echo "NET_IFACE is not set"
	exit 1
fi

usage() {
	printf "Usage: $1 [options]:\n"
	printf "\t--help: show this message\n"
	printf "\t--bmc: run Seastar's Memcached implementation on with BMC support\n"
	printf "\t--bg-exp: Load Memcached + AF_XDP without BMC offload:\n\t\tbaseline configuration to investigate the affect of loading BMC on BG flows\n"
	printf "\t--bmc-bg-exp: Load Memcached + AF_XDP + BMC offload:\n\t\tconfigure the test for investigating the affect of loading BMC on BG flows\n"
	printf "\n"
}

parse_args() {
	while [ $# -gt 0 ]; do
		key=$1
		case $key in
			-h|--help)
				usage $0
				shift
				exit 0
				;;
			--bmc)
				mode="bmc"
				shift
				;;
			--bg-exp)
				mode="bg"
				shift
				;;
			--bmc-bg-exp)
				mode="bmc-bg"
				shift
				;;
			*)
				echo "Unrecognize argument: $1"
				echo "Use --help to see the usage guide for the program"
				shift
				exit 1
				;;
		esac
	done
}

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

main() {
	parse_args $@

	count_cores=1
	cpu_set=11

	case $mode in
		plain)
			Memcd="/home/farbod/seastar/build/$build_type/apps/memcached/memcached"
			;;
		bmc)
			Memcd="/home/farbod/my-seastar/build/$build_type/apps/memcached/memcached"
			launch_bmc
			;;
		bg)
			Memcd="/home/farbod/seastar/build/$build_type/apps/memcached/memcached"
			count_cores=4
			cpu_set=11,13,15,17
			;;
		"bmc-bg")
			Memcd="/home/farbod/my-seastar/build/$build_type/apps/memcached/memcached"
			count_cores=4
			cpu_set=11,13,15,17
			;;
	esac

	# sudo $Memcd --help-seastar
	# exit 0

	sudo $Memcd -c $count_cores \
		--cpuset $cpu_set -m 8G \
		--poll-mode --dpdk-pmd \
		--network-stack native \
		--host-ipv4-addr $server_ip \
		--netmask-ipv4-addr $net_mask \
		--collectd 0

	# Make sure the XDP program is deatched
	sudo ip link set dev $NET_IFACE xdp off

	echo Done!
}

main $@
