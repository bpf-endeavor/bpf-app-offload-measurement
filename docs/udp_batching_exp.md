# UDP Batching Experiment

## How to run

**UDP Userspace standalone:**

```bash
sudo ./build/server_lookup 7 192.168.1.1 2
```

**UDP + Batching (`SK_SKB`):**

```bash
sudo ./build/loader -b ./build/bpf/skskb_lookup_multishot.o --skskb verdict --tc tc_encap_with_source -i  ens1f0np0
sudo ./build/server_lookup 7 192.168.1.1 3 --sockmap
```

**UDP + Batching (TC):**

```bash
sudo ./build/loader -b ./build/bpf/tc_lookup_multishot.o --tc tc_prog -i  ens1f0np0
sudo ./build/server_lookup 7 192.168.1.1 3
```

**UDP + Batching (XDP):**

```bash
sudo ./build/loader -b ./build/bpf/xdp_lookup_multishot.o --xdp xdp_prog -i  ens1f0np0
sudo ./build/server_lookup 7 192.168.1.1 3
```
