# Benchmark for eBPF Runtime

This repositry hosts:

- A set of benchmark designed to shade light on some corners of eBPF runtime
  and help decide challenges in offloading an end-host application to the
  kernel.

- This repository is also the artifacts from paper ["Demystifying Performance of
  eBPF Network Applications"](./docs/paper.pdf) presented at
  [CoNEXT'25](https://conferences.sigcomm.org/co-next/2025/#!/home). Look at
  [ARTIFACT.md](./ARTIFACT.md) for reproducing different figures and tables
  from the paper.

## List of Benchmarks

* Overhead of entering and exiting eBPF for XDP, TC, and SK\_SKB
* Time since packet arrival (since received in driver / XDP) until it reachs to TC, and SK\_SKB hooks
* Report overhead of having a bound-check in a tight loop
* Comparing the overhead of hardcoding code into the driver vs. having a eBPF program
* Overhead of using Array, Hash-map, Ring, ... for communication with user program
* Measure benefit of reducing the size of packet when passing it from kernel to user program
* Demonstrate performance interference among flows belonging accelerated by eBPF and those not
* Investigate overhead of different techniques for chaining programs used to mitigate the eBPF program's complexity limit

## Cite Paper

> the paper is still under publication ...
