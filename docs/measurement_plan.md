# Question: Can eBPF accelerate socket applications? A measurement study


## Introduction

- Why this question is important?
    + People are offloading applications to the kernel (BMC, Electrode, XRP, DINT).
- Why people are trying to offload in the first place? Are Socket API, DPDK,
  AF_XDP, and others not suitable? Do we need a new approach?
- What patterns/optimizations are used in order to accelerate applications?
- Does eBPF provide enough support to meet the needs of applications?


## Argument in Favor of eBPF

- It allows people to ...

### Optimization patterns

- Early exit, pre-stack processing (e.g., BMC)
- Reducing system calls (e.g., Electrode when sending broadcast messages)
- Avoiding inter-process communication (e.g., Side-car proxy offload)
- Are there any cases, in which falling back to user-space could be beneficial?
  (That is doing something in eBPF which result the eBPF+user-space perform better than just directly running user-space program.)
    + Data summarization
    + Request batching
    + ?


##  Arguments Against eBPF

- There are considerable number of bugs in eBPF implementation
    + I am aware of some patch sets for these two cases, there must be more.
        - bpf_loop
        - sk_skb
    + In new versions of kernel, the interrupts are not disabled when running
      eBPF programs. I think I observed some concurrency issues even with a
      single core running the eBPF program. Need to investigate it more.
- Offloading to eBPF is seen as compliant with legacy Linux configuration and
  application, but is it true?
    + Offload to XDP (e.g., BMC) may bypass netfilter, and other eBPF programs
      hooking after it
    + Adding a eBPF in a lower hook (e.g., XDP) would bypass an eBPF program in
      a hook after that (e.g., TC). Will this cause a conflict of interest?
- eBPF is now supporting multiple programs attaching to a hook. Does
  these programs need scheduling or should them run in-order? Does head-of-line
  blocking make sense in this context? What if we have applications attached to
  these hooks?
  + I think it needs some testing.
- eBPF does not have a linker, debugger, support for libraries, writing
  unit-tests and integration tests, ... . What happened to all the progress in
  the field of software engineering
    + Actually, the eBPF verifier does also act as a very simpler linker. But,
      the argument above is still valid.
- eBPF verifier will not scale from network function to application.
  Verification of software is a hard-problem, still under study. The
  state-space that the verifier needs to explore explodes with a little bit of
  complexity.
- There is a clash between the compiler optimization phase and eBPF verifier.
  Something is not right here. The components are not placed correctly. Maybe
  the verifier should run before the optimization. But the kernel can not
  trust. There are suggested solutions, but the maintainers probably will not
  care. So let's not count on they fixing this issue.
- It is unclear why we needed a new ISA, a JIT for that and all new the
  tooling. Is it just because we need to do the verification?


## Scope of study

- The paper will consider the use-case in which a TCP or UDP socket
  applications tries to benefit from eBPF.
    + For TCP applications, eBPF offload must not interfere with TCP state machine
        - If the eBPF hook is before the TCP stack, then the packet size should not
          change (including dropping the packet)
        - The hooks after TCP stack processing are (1) SK_SKB_PARSER (2) SK_SKB_VERDICT
    + For UDP applications, we will look at XDP, TC, and SK_SKB
- Do I want to measure on multiple versions of kernel or just one?
    + Multiple would be better but it takes some time.


## Testbed setup

- What type of machines do I need?
    + Bare-metal experiments
    + Running in containers
        - The applications run in containers. What is supported? What is
          missing How it affects the measurements?
    + Running inside a VM:
        + I run some test on my laptop inside a VM using KVM [kernel version v6.8.7]
        + I turned off some of the fearutre of the VM virtual interface
            + `sudo ethtool -K $NET_IFACE tso off gso off gro off lro off rx-gro-hw off`
            + `sudo systemctl stop irqbalance`
            + set irq for input/output to core 3

**A side question:**

- How off is the eBPF helper for getting the timer, what is the resolution?
    + Can I trust this timer or do I need to add my own?
        + I did an experiment: the `bpf_ktime_get_ns` is off by 45 ns in
          average. this is not a good resolution for performing
          micro-benchmarks. Running a BPF program is considerd to have 30 ns of
          overhead.


## Metrics to measure

### General socket application study

A study of existing applications.
+ How many of them can benefit from known eBPF optimization patterns.
+ How many can have an early exit on their main path.
+ Approximately, how many tail-calls are needed to have each application or part of it run in eBPF?

### eBPF Runtime study

#### Basics: Performance gain strategies and basic runtime cost

> Run experiment on different versions of Linux kernel (currently testing on 6.8.7)

> Since the load-generator and DUT are on the same small machine there is a contention on the cores. I must redo the experiment on some-other machine.

- Overhead of running eBPF Program: When invoking eBPF runtime how much overhead we add
    + For different hooks (XDP, TC, SK_SKB)
        + stream_parser+verdict: `error` -  The packets get stucked for some reason
        + stream_verdict: 1020 - 1100 (ns)
        + TC: 55 (ns)
        + XDP: 37 (ns)
- What percentage of overhead (cycles) are spent on what type of operation
  (getting a lock, copying packet, preparing eBPF stack, ...)
    + stream_parser+verdict: ?
    + stream_verdict: ?
    + TC: ?
    + XDP: ?
- What is the maximum benefit an application can get from offloading to eBPF?
  If we drop packets in the eBPF hook, we avoid any other instruction
  happening after. It will be the maximum performance gain.
    + UDP Socket (share irq):     mean: 14614   (pps)
    + UDP Socket (not share irq): mean: 287592  (pps)
    + stream_parser+verdict: ?
    + stream_verdict:             mean: 97449   (pps)
    + TC:                         mean: 1110772 (pps)
    + XDP:                        mean: 1230702 (pps)
- What would be the minimum-cost if the eBPF program need to go to user-space?
  If we have an eBPF program that just passes the packet to next level it would
  show the minimum overhead an eBPF program can impose on the application
  performance in case of falling-back to user-space. Reported values are
  average result.  The eBPF program was not sharing a core with user-app.
    + TCP Socket (sharing irq):     65477 (pps)
    + TCP Socket (not sharing irq): 72904 (pps) [cost: 0%]
    + stream_parser+verdict:        ?
    + stream_verdict:               56899 (pps) [cost: 21.9]
    + TC:                           77407 (pps) [cost: -6.1]
    + XDP:                          76325 (pps) [cost: -4.6]
- Is data summarization beneficial? One important factor for summarization is
  the request size, specially in case of TCP, which means we might coalesce
  some segments in eBPF. I design the experiment as described below. For
  generate request of size (64, 258, 1024, 2048, 4096, 8192). Add eBPF program
  that passes `p%` of the request to app. App will drop and report throughput.
  The eBPF programs must wait until request is completely received before
  passing it to app. The for each request size we vary values of `p`.
    + TCP Socket (not sharing IRQ):
    + stream_parser+verdict: ?
    + stream_verdict: ?
    + TC:?
    + XDP: ?
- Data summarization drop request but share something on a ring/map:
    + Share on the packet
    + Share on the Array/Hash map
    + Share using memory-mapped region
    + Share on eBPF user-space ring
- Is batching requests beneficial? A throughput and latency study
    + For UDP:
        + Batch in XDP
        + Batch in TC
        + Batch in SK_SKB
    + For TCP:
        + Batch in SK_SKB


#### Verifier Imposed Limitations:

- What is the cost of bound-checking?
    + Offloading a hash function is not good. Why?
    + I know bound checking inside a loop is bad. Let's consider following
      cases both are memory copy, one requires bound checking.
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
- How hard is it to parse HTTP/1.1
- How hard is it to parse HTTP/2
- How hard is it to parse json (some restrictions)


-- vim: et ts=4 sw=4 spell
