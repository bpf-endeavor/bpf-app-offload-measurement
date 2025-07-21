# Setup DUT Machine

Our test environment is two servers connected back to back

```
  +-----------+    +-------------+                              
  | DUT       |    | Load        |                                    
  |           |    | Generator   |                                
  |  [server] |    |             |                                        
  |   [eBPF]<-|----|->[ client ] |
  |           |    |             |                                
  +-----------+    +-------------+                               
       *
      /_\
     /___\
       │
       │ 
 We are setting up this one
```

For preparing the load generator machine look at [this instructions](./LOAD_GENERATOR.md).

## Setup

Clone the repository and run `make prepare_env`.
**Make sure there are no errors!**

### XDP DROP Perf Test

To make sure everything is almost right, do a XDP drop performance test.

> TODO: ... write it

> If the performance is low there is something wrong.


### Enable Measuring Overhead of Hooks and Time to Reach to Different Hooks

*This instructions are only for reproducing Table 1 which require instrumenting kernel*

Go to `/others/linux-6.8.7/`. This directory holds the patched kernel.
We need to enable the measurements we want to do and compile and reinstall the
kernel.

Edit these files and uncomment the mentioned line (define the flags for
measuring different overhead and durations):


* ./net/core/skmsg.c (line 15)
  - `#define MEASURE_SK_SKB_OVERHEAD 1`

* ./net/sched/cls\_bpf.c (line 84)
  - `#define MEASURE_TC_OVERHEAD 1`

* ./drivers/net/virtio\_net.c (line 1051)
  - `#define MEASURE_VIRTIO_XDP_OVERHEAD 1`

* ./net/core/dev.c (line 4926)
  - `#define MEASURE_GENERIC_XDP_OVERHEAD 1`

* ./include/linux/test\_timer.h (line 118)
  - `#define MEASURE_TIME_TO_REACH_HOOK 1`


Build and install the kernel with these flags enabled.
If the `make prepare_env` has succeeded, then the kernel is already configured
and there is a `build` directory.

```
cd ./build/
make -j 40
sudo make modules_install
sudo make install
# sudo reboot # <-- reboot the system and boot with the new kernel
```

**Make sure you are using the new kernel with this command `uname -r`. The value must be `6.8.7art`.**


### OS Level Configurations

We have provided a script (`/script/setup_exp.sh`) which configures the system.
This script disables *hyperthreading*, *turbo-boost*, and irq balancer; set the
CPU governor to *performance*, and adds some flow-steering rules among other
configurations. Run the script and keep it open during experiments, hitting
Ctrl-C will exit the script and set the system configuration back to normal.

> Make sure the UDP & TCP traffic are redirected to single queue using `ethtool -u $NET_IFACE`. There must be two rules for this.


### Frequent Issues

1. **Can not attach XDP program to the interface**

Make sure the MTU of your Mellanox interface is set to 1500 (by default it can be 9000)

```
sudo ip link set dev $NET_IFACE mtu 1500
```

2. The XDP throughput is low

On machines without **cache direct technology** (e.g., DDIO) the
network driver (eBPF/XDP) will experience many cache misses limiting the
throughput.

