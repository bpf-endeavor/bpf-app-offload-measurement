#! /bin/bash
curdir=$(dirname $0)
server=$(realpath "$curdir/../../src/build/server_bounce")
core=11
ip=192.168.200.101
port=8080
bpf_prog=./build/xdp.o
# values: no_bpf, bpf
mode=no_bpf

usage() {
	echo "$0 [options]"
	echo "    -h --help: show this message"
	echo "    --xdp: load the XDP program"
}

parse_args() {
	while [ $# -gt 0 ]; do
		key=$1
		case $key in
			-h|--help)
				usage
				exit 0
				;;
			--xdp)
				mode=bpf
				shift
				;;
			*)
				echo "Unrecognized argument: $key"
				exit 1
		esac
	done
}

clean() {
	sudo pkill -INT server_bounce
	sudo ip link set dev $NET_IFACE xdp off
}

on_signal() {
	clean
	exit 0
}

main() {
	if [ -z "$NET_IFACE" ]; then
		echo "NET_IFACE is not set"
		exit 1
	fi

	if [! -f $server ]; then
		echo "Warning: server_bounce is not compiled yet!"
		cd $curdir/../../src
		make
		if [! -f $server ]; then
			echo "Error: failed while trying to compile it"
			exit 1
		fi
	fi

	echo "make sure traffic is routed to one queue"
	sudo ethtool -u $NET_IFACE

	# make sure there are no XDP programs attached
	clean

	# make sure we have compile the bpf program
	bash $curdir/compile.sh
	# run a echo server in background
	$server $core $ip $port 0 &> /dev/null < /dev/null &

	if [ $mode = "bpf" ]; then
		echo "Loading XDP program ... (please wait)"
		sudo ip link set dev $NET_IFACE xdp obj $bpf_prog sec xdp
	fi

	trap "on_signal" SIGINT SIGHUP
	echo "Ready!"
	echo "Hit Ctrl-C to stop"
	while [[ true ]]; do
		sleep 5
	done
}

parse_args $@
main
