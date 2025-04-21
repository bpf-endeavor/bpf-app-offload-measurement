# Experiments

1. Comparing the Memcached AF\_XDP vs. Socket API
2. Comparing the BMC benefit for AF\_XDP vs Socket API
3. Showing the BMC slowdown for the background traffic

## Experiment Setup

**Memcached AF_XDP:**

I have changed Memcached implementation insdie the Seastar repo to (a) connect
to AF\_XDP and (b) work with BMC. Look under the `patches/memcached_seastar` for
changes.

**Enable Seastar Memcached + AF_XDP sockets:**

1. Apply the patch `0001-Attach-seastar-memcached-to-AF_XDP.patch`
	- The patch has hardcoded configuration of AF\_XDP queue (update it after applying the patch)
2. `./configure.py --mode=release --enable-dpdk`
3. `ninja -C ./build/release`
4. Use script `run_seastar_memcd.sh` to run experiment
	- The script has hardcoded configuration

**Enable Seastar Memcached + AF_XDP sockets + BMC:**

1. Use the my-seastar repository that I forked

or ...

1. Apply the patches under `patches/memcached_seastar/with_bmc/`
2. Compile as described above (for Memcached + AF\_XDP)
3. Clone BMC and apply the patches required to send packets to AF\_XDP socket
	- Patches are at `patches/bmc/send_to_af_xdp/`
4. use make to build BMC. We only need `bmc_kern.o`
5. Use script `run_seastar_memcd.sh` to run experiment (the mode is hardcoded)

**Socket Memcached:**

1. Clone and compile memcached
2. Use the `run_socket_server.sh`
