# About Experiment

I modified the linux kernel to measure how many nanoseconds it takes to
prepare, invok, and run the BPF program. Look at the pacthes at `./kernel/`.

I load an empty BPF program returing a PASS verdict.


## Results

Experiment were performed on my laptop in a VM.

| Hook | Overhead (nanoseconds) |
|:----:|:----------------------:|
| TC   | 55                     |

