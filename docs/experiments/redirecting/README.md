# What is this experiemtn

How long does it take to reply to a request.

**Target on a remote machine:**

```
[App (udp)]
[dpdk     ] <---> [DUT]

DUT: XDP, TC, SK_SKB (udp), Socket (udp)
```

**Target on a local machine:**


## Results

Results are in nanoseconds

### XDP (Native)

samples: 954855
max: 16225106.0
min: 5894.0
mean: 12626.44
@1 : 11097.0
@50: 12586.0
@99: 14248.0

### XDP (Generic)

samples: 1150214
max: 300916.0
min: 6207.0
mean: 13121.58
@1 : 11582.0
@50: 13097.0
@99: 14900.0


### TC

samples: 115515
max: 115293.0
min: 7044.0
mean: 13353.98
@1 : 11782.0
@50: 13322.0
@99: 15152.0


## VERDICT (UDP)

samples: 393047
max: 313545.0
min: 10612.0
mean: 18235.78
@1 : 15822.0
@50: 18135.0
@99: 22046.0


## Socket (UDP)

samples: 296273
max: 317760.0
min: 13869.0
mean: 24307.64
@1 : 15902.0
@50: 27000.0
@99: 30037.0

