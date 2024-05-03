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

**UDP Socket (share irq core)**

|Measure|Packet / Sec|
|:------|:----------:|
|samples| 179|
|max| 45303.0|
|min| 497.0|
|mean| 14614.01|
|@50| 26545.0|
|@99| 619.0|

command:
```sh
cat udp_socket_share_irq_core.txt  | awk '{print $2}' | ../../latency_script.py
```


**UDP Socket (not sharing irq core)**

|Measure|Packet / Sec|
|:------|:----------:|
|samples| 180|
|max| 349111.0|
|min| 255816.0|
|mean| 287592.64|
|@50| 264493.0|
|@99| 267251.0|



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


**Hook: XDP**

|Measure|Packet / Sec|
|:------|:----------:|
|samples| 179|
|max| 1449518.0|
|min| 916868.0|
|mean| 1230702.15|
|@50| 1259985.0|
|@99| 994468.0|

command:
```sh
cat ./xdp_drop_traffic.txt | awk '{print $7}' | ../../latency_script.py
```




