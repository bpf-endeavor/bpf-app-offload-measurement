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
|@1|  523|
|@50| 14691.0|
|@99| 34042.0|

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
|@1| 256588.0|
|@50| 279936.0|
|@99| 348334.0|


**Hook: STREAM_VERDICT**

|Measure|Packet / Sec|
|:------|:----------:|
|samples| 183|
|max| 108742.0|
|min| 75788.0|
|mean| 97449.12|
|@1| 76467.0|
|@50| 99249.0|
|@99| 106975.0|

command:
```sh
cat ./stream_verdict_drop_traffic.txt  | awk '{print $7}' | ../../latency_script.py
```


**Hook: TC**

|Measure|Packet / Sec|
|:------|:----------:|
|samples| 180|
|max| 1385162.0|
|min| 840175.0|
|mean| 1110772.84|
|@1| 859938.0|
|@50| 1126743.0|
|@99| 1380377.0|

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
|@1|919936.0|
|@50| 1234000.0|
|@99| 1448861..0|

command:
```sh
cat ./xdp_drop_traffic.txt | awk '{print $7}' | ../../latency_script.py
```
