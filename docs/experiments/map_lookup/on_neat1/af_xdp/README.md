In order to measure the access time to AF\_XDP Rx ring, I modified the benchmark
program provided for the AF\_XDP paper published in LPC'18 to receive 32K
request in its ring and then consume them all at once. (Look at `patches/af_xdp_access_time`)

To generate traffic I modified the `dpdk-client-server` I have to generate 32K request and stop.

The after flooding the Rx ring, a SIGUSR1 is sent to AF\_XDP program to start
consuming and report the average time.

The experiment was repeated 100 times

> For running experiment 100 times, use the `scripts/af_xdp_rx_ring_access/repeat_exp.sh`

## Commands

run the AF\_XDP program

```
sudo ./xdpsock -i $NET_IFACE -r -q 26 -N -z --quiet
```

send signal

```
sudo kill -SIGUSR1 $(pidof xdpsock)
```

generate summary

```
cat af_xdp.txt | grep Ring | awk '{print $8}' | sort -n | ../../../../latency_script.py
```
