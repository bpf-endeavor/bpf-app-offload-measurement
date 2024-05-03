# Benchmark Kernel Offload Strategies

Some bench marks for BPF environment.
Searching for good offloading strategies and trade offs.
We look into some offloading benefits and try to characterize their value.

* BPF runtime cost
* Context switch
* Data summarization
* Request-batching (multishot) [? Left inconclusive]
* Sharing state, map lookup, on the packet


## How to Build?

Run `make` in the root directory


## How is the Repo Structured

* `kernel/`: some kernel patches helping with benchmarks
* `src/bpf/`: it has the bpf programs used in benchmarks
* `src/userspace/server`: has userspace part of the benchmarks
* `src/userspace/loader`: has a bpf loader
* `src/autogen/*/`: has some benchmarks which were generated using Kashk.
Both the userspace and bpf prgorams are organized in the sub-directories under
`src/autogen`.

