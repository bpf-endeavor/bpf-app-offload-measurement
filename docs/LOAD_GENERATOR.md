# Setup Load Generator Machine

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

For preparing the DUT  machine look at [this instructions](./DUT.md).

Clients we need:

* iperf (2.1.5)
* echo latency client: (source @ /scripts/echo\_latency)
* Mutilate: git@github.com:fshahinfar1/mutilate.git


## Iperf

```
sudo apt update && sudo apt install iperf
```

## Echo Latency Client

The source code of the client is provied at `/scripts/echo\_latency/`.
The server and client IP and port addresses are hard coded at the begining of the `main.c`.
Update the addresses and compile using `make`.

## Mutilate

Mutilate is a traffic generator for Memcached key-value store. Install it with
these commands.

```
sudo apt-get install -y scons libevent-dev gengetopt libzmq3-dev
mkdir -p $HOME/gen
cd $HOME/gen
git clone https://github.com/fshahinfar1/mutilate
cd mutilate/
scons
```

