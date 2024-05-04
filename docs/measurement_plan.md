# Question: Can eBPF accelerate socket applications? A measurement study


## Introduction

- Why this question is important: people are offloading application to the kernel (BMC, Electrode, XRP, DINT).
- Why people are trying to offload in the first place? Is DPDK, AF_XDP, and others not suitable? Do we need a new approach?
- Does eBPF provide enough support to meet these applications needs?
- Is there any advantage in offloading more general applications or are these cases specially hand-crafted to the situation?


## Scope of study and notes to have in mind

- Socket types under study are TCP and UDP sockets.

- For TCP applications, eBPF offload must not interfere with TCP state machine
    + If the eBPF hook is before the TCP stack, then the packet size should not change (including dropping the packet)
    + The hooks after TCP stack processing are (1) SK_SKB_PARSER (2) SK_SKB_VERDICT
- For UDP applications
    + Offload to XDP (e.g., BMC) may bypass netfilter, and other eBPF programs hooking after it


## Testbed setup

- What type of machines do I need?
    + Bare-metal experiments
    + Running in containers --> The applications run in containers, what are the support what is missing How it affects the measurements?
    + Running inside a VM:
        + I run some test on my laptop inside a VM using KVM [kernel version v6.8.7]
        + I turned off some of the fearutre of the VM virtual interface
            + `sudo ethtool -K $NET_IFACE tso off gso off gro off lro off rx-gro-hw off`
            + `sudo systemctl stop irqbalance`
            + set irq for input/output to core 3

- How off is the BPF helper for getting the timer, what is the resolution?
    + Can I trust this timer or do I need to add my own?
        + I did an experiment: the `bpf_ktime_get_ns` is off by 45 ns in average. this is not a good resolution for performing micro-benchmarks. Running a BPF program is considerd to have 30 ns of overhead.


## Metrics to measure


### General socket application study

(I am not sure what to do in this part, maybe select a set of applications and see if they have access to files and send network requests)
- What type of socket applications have early exit
    + Does it access a file on data-path
    + Does it send a request (e.g., MapReduce)
    + Does it need multi-cast --> not XDP?

### eBPF Runtime study

#### Basics: Performance gain strategies and basic runtime cost

> Run experiment on different versions of Linux kernel (currently testing on 6.8.7)

- Overhead of running eBPF Program: When invoking eBPF runtime how much overhead we add
    + For different hooks (XDP, TC, SK_SKB)
        + stream_parser+verdict: `error` -  The packets get stucked for some reason
        + stream_verdict: 1020 - 1100 (ns)
        + TC: 55 (ns)
        + XDP: 37 (ns)
- What percentage of overhead (cycles) are spent on what type of operation (getting a lock, copying packet, preparing eBPF stack, ...)
    + stream_parser+verdict: ?
    + stream_verdict: ?
    + TC: ?
    + XDP: ?
- What is the maximum benefit an application can get from offloading to eBPF?
  If we drop packets in the an eBPF hook we avoid any other instruction
  happening after. It will be the maximum performance gain.
    + UDP Socket (share irq):     mean: 14614   (pps)
    + UDP Socket (not share irq): mean: 287592  (pps)
    + stream_verdict:             mean: 97449   (pps)
    + stream_parser+verdict: ?
    + TC:                         mean: 1110772 (pps)
    + XDP:                        mean: 1230702 (pps)
- What would be the minimum-cost if the eBPF program need to go to user-space?
  If we have an eBPF program that just passes the packet to next level it would
  show the minimum overhead an eBPF program can impose on the application
  performance in case of falling-back to user-space. Reported values are average result.
    + TCP Socket (sharing irq):     65477 (pps)
    + TCP Socket (not sharing irq): 72904 (pps)
    + stream_parser+verdict:        ?
    + stream_verdict:               56899 (pps)
    + TC:                           77407 (pps)
    + XDP:                          76325 (pps)
- Are there any cases, in which falling back to user-space could be beneficial?
  That is doing something in eBPF which result the eBPF+user-space perform
  better than just directly running user-space program.
    + Data summarization
    + Request batching
    + ?
- Is data summarization beneficial?
    + Throughput benchmark if we do not share any state
    + Throughput benchmark if we share some state
        + Share on the packet
        + Share on the Array map
        + Share on the Hash map
        + Share using memory-mapped region
- Is batching requests beneficial? A throughput and latency study
    + For UDP:
        + Batch in XDP
        + Batch in TC
        + Batch in SK_SKB
    + For TCP:
        + Batch in SK_SKB

#### Verifier Imposed Limitations:

- What is the cost of bound-checking?
    + Offloading a hash function is not good why?
    + I know checking in-side a loop is bad
        + Data copy from packet to map with check
        + Data copy from stack to map without check
- How many cycles we loose when we move large objects from stack to eBPF map
    + Complexity of using HASH_MAP
        + Benchmark assuming only one core
    + Using BPF_ARRAY and issues with concurrency
        + Benchmark assuming only one core
    + Using BPF_PERCPU_ARRAY
        + Benchmark assuming only one core
        + The PERCPU ARRAYs are not safe anymore if in SK_SKB
            + Benchmark by adding a spin-lock to protect the access
- Tail call and moving state from one function to another (BMC did it)


-- vim: et ts=4 sw=4 spell
