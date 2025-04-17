#! /bin/bash

# Assumptions:
# System has hugepages and it is mounted in /dev/hugepages (look at TAS readme)

Memcd="/home/farbod/seastar/build/release/apps/memcached/memcached"

sudo $Memcd -c 1 --cpuset 11 \
	-m 4G \
	--poll-mode --dpdk-pmd \
	--network-stack native \
	--host-ipv4-addr 192.168.200.101 --netmask-ipv4-addr 255.255.255.0 \
	--collectd 0
