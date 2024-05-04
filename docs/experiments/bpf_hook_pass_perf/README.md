# About Experiment

For measuring the minimum cost of adding eBPF program on the path of request
that need to processed in user-space, I perform experiment as stated below. I
load a minimal eBPF program return immediately with verdict of continue the
normal path inside the kernel (PASS).


## Results

**TCP Socket (share irq)**

|Measure|Packet / Sec|
|:------|:----------:|
|samples| 168|
|max| 76351.0|
|min| 57325.0|
|mean| 65477.27|
|@1 | 57329.0|
|@50| 64880.0|
|@99| 74801.0|

```
cat tcp_socket_sharing_irq_core.txt | tail -n +20 | awk '{print $2}' | ../../latency_script.py
```

**TCP Socket (not share irq)**

|Measure|Packet / Sec|
|:------|:----------:|
|samples| 168|
|max| 81358.0|
|min| 45774.0|
|mean| 72904.12|
|@1 | 49024.0|
|@50| 74770.0|
|@99| 81243.0|

```
cat tcp_socket_not_sharing_irq_core.txt | tail -n +20 | awk '{print $2}' | ../../latency_script.py
```


**Hook: stream_parser+verdict**

??

**Hook: stream_verdict**

|Measure|Packet / Sec|
|:------|:----------:|
|samples| 168|
|max| 70055.0|
|min| 49632.0|
|mean| 56899.92|
|@1 | 50938.0|
|@50| 56703.0|
|@99| 68222.0|

```
cat stream_verdict_pass_perf.txt | tail -n +20 | awk '{print $2}' | ../../latency_script.py
```


**Hook: TC**

|Measure|Packet / Sec|
|:------|:----------:|
|samples| 169|
|max| 87283.0|
|min| 65908.0|
|mean| 77407.31|
|@1 | 68944.0|
|@50| 76380.0|
|@99| 87174.0|

```
cat tc_pass_perf.txt | tail -n +20 | awk '{print $2}' | ../../latency_script.py
```

**Hook: XDP**

|Measure|Packet / Sec|
|:------|:----------:|
|samples| 168|
|max| 86475.0|
|min| 60189.0|
|mean| 76325.33|
|@1 | 60925.0|
|@50| 76894.0|
|@99| 86277.0|

```
cat xdp_pass_perf.txt | tail -n +20 | awk '{print $2}' | ../../latency_script.py
```
