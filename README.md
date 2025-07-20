# Benchmark for eBPF Runtime

This repositry hosts:

- A set of benchmark designed to shade light on some corners of eBPF runtime
  and help decide challenges in offloading an end-host application to the
  kernel.

- This repository is also the artifacts from paper ["Demystifying Performance of
  eBPF Network Applications"](/docs/paper.pdf) presented at
  [CoNEXT'25](https://conferences.sigcomm.org/co-next/2025/#!/home). Look at
  [ARTIFACT.md](/docs/ARTIFACT.md) for reproducing different figures and tables
  from the paper.

## List of Benchmarks

**eBPF Hook Related:**

* Overhead of entering and exiting eBPF for XDP, TC, and SK\_SKB
* Time since packet arrival (since received in driver / XDP) until it reachs to TC, and SK\_SKB hooks
* Overhead of an empty eBPF program on throughput and latency


**eBPF API (MAPs, Helpers, ...):**

* Overhead of using Array, Hash-map, Ring, ... for communication with user program
* Investigate overhead of different techniques for chaining programs used to mitigate the eBPF program's complexity limit

**eBPF Compilation Process:**

* Report overhead of having a bound-check in a tight loop
* Comparing the overhead of hardcoding code into the driver vs. having a eBPF program

**System Design Elements:**

* Measure benefit of reducing the size of packet when passing it from kernel to user program
* Demonstrate performance interference among flows belonging accelerated by eBPF and those not


## Structure

```
.
├── c-hashmap/   <-- A library (not used)
├── deps/   <-- a local version of libbpf will be compiled and installed here
├── docs/   <-- documents on how to reproduce results, ...
│   ├── ARTIFACT.md  <-- Step-by-step guide for artifact evaluation
│   ├── experiments/ <-- Data and scripts for plotting figures
│   ├── images/   <-- Images used in documentation files
│   ├── latency_script.py   <-- Script for calculating distribution of numbers
│   ├── LOAD_GENERATOR.md   <-- How to setup load-generator machine
│   ├── paper.pdf           <-- Demystifying Performance of eBPF Network Applications
├── libbpf   <-- local libbpf (submodule)
├── Makefile
├── patches
│   ├── af_xdp_access_time/
│   ├── bmc/
│   ├── kernel/
│   └── memcached_seastar/
├── README.md
├── scripts/ <-- Many different scripts of setting up system and experimenting
├── src/  <-- source code of benchmarks
│   ├── bpf/  <-- source code of eBPF programs
│   ├── include
│   ├── Makefile
│   ├── measure_comm_channel.sh
│   └── userspace/  <-- source code of user-space program
│       ├── loader/    <-- the loader program we usually use
│       └── server/    <-- some other user-space program
└── xsk_cache/   <-- The AF_XDP program used as kernel bypass case-study
```

## Cite Paper

**BibTex**

```
@inproceedings{demystify_perf_ebpf_net_app,
title={Demystifying Performance of eBPF Network Applications},
author={Farbod Shahinfar and Sebastiano Miano and Aurojit Panda and Gianni Antichi},
year={2025},
booktitle={International Conference on Emerging Networking Experiments and Technologies (CoNEXT)},
publisher={ACM}
}
```

**Text**

```
Farbod Shahinfar, Sebastiano Miano, Aurojit Panda, and Gianni Antichi. 2025. Demystifying Performance of eBPF Network Applications. In International Conference on Emerging Networking Experiments and Technologies (CoNEXT). ACM.
```

