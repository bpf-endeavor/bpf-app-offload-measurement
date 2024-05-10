# About Experiment

We are trying to answer if reducing the size of requests inside the kernel can
help with the performance of applications. The experiment is conducted as
follows.
The `server_drop` is up on core zero, while the soft irq for experiment NIC
is configured on core 3. I used `udpgen` for generating request toward the
server [1].  We load a BPF program that resizes the requests to `p%` of
their original size. We measure the throughput observed in workload generator.

Since ebpf program is on a seperate core, all the eBPF experiments are enjoying
more processing power than the case in which we have just a socket application.

I am doing the test with UDP sockets because it is not possible to resize TCP
request before the network stack.

[1]  ` ./build/udpgen --ip 192.168.122.245 --port 8080 -t 1 -d 20 --one`


## Results

**Approahces:**
1. UDP Sock (not share irq)
2. stream_parser+verdict
3. stream_verdict
4. TC
5. XDP

### Request size 64

| Approach | 25% (16) | 50% (32) | 75% (48) | 100% (64) |
|:---------|:--:|:--:|:--:|:--:|
| 1        | -- | -- | -- |    |
| 2        | ?  | ?  | ?  | ?  |
| 3        | -  | -  | -  |    |
| 4        | -  | -  | -  |    |
| 5        | -  | -  | -  |    |

### Request size 256

| Approach | 25% (64) | 50% (128) | 75% (192) | 100% (256) |
|:---------|:--:|:--:|:--:|:--:|
| 1        |    |    |    |    |
| 2        |    |    |    |    |
| 3        |    |    |    |    |
| 4        |    |    |    |    |
| 5        |    |    |    |    |

### Request size 1024

| Approach | 25% (256) | 50% (512) | 75% (768) | 100% (1024) |
|:---------|:--:|:--:|:--:|:--:|
| 1        |    |    |    |    |
| 2        |    |    |    |    |
| 3        |    |    |    |    |
| 4        |    |    |    |    |
| 5        |    |    |    |    |

### Request size 2048

| Approach | 25% (512) | 50% (1024) | 75% (1536) | 100% (2048) |
|:---------|:--:|:--:|:--:|:--:|
| 1        |    |    |    |    |
| 2        |    |    |    |    |
| 3        |    |    |    |    |
| 4        |    |    |    |    |
| 5        |    |    |    |    |

### Request size 4000

| Approach | 10% (400) | 25% (1000) | 50% (2000) | 75% (3000) | 100% (4000) |
|:---------|:--:|:--:|:--:|:--:|:--:|
| 1        |    |    |    |    |    |
| 2        |    |    |    |    |    |
| 3        |    |    |    |    |    |
| 4        |    |    |    |    |    |
| 5        |    |    |    |    |    |

