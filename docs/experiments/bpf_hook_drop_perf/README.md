# About Experiment

This experiment provides the upper bound on the benefits an application can
acquire by offloading to a eBPF hook.

I have loaded an eBPF program to different hooks which would drop the traffic.
This would avoid performing any other instruction that come after the hook.
Insdie the eBPF program I measure the request dropping throughput.

## Load Generator

```
./build/udpgen --ip 192.168.122.245 --port 8080 -t 4 -P 256 --one -d 180
```

## Results

**Hook: TC**

|Measure|Packet / Sec|
|:------|:----------:|
|samples| 180|
|max| 1385162.0|
|min| 840175.0|
|mean| 1110772.84|
|@50| 1099079.0|
|@99| 953546.0|

command:
```sh
cat tc_drop_traffic.txt | tail -n +6  | awk '{print $7}' | ../../latency_script.py
```



