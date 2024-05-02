# Experiment Detail

Run `bpf_ktime_err.c` BPF program on a virtual machine on my laptop. Used a UDP
socket program (from host and not the VM) to generat traffic. Dummped the
`bpf_printk` logs to a file.

The error is about 150 ns when the load is low. and arround 50 ns when load is high.

conclusion `bpf_ktime_get_ns` is not good for our benchmarking.

## Result

```
cat experiments/bpf_ktime_resolution/bpf_ktime_tc.txt | awk '{print $6}' | ./latency_script.py
samples: 1568932
max: 27199.0
min: 0.0
mean: 45.34
@50: 70.0
@99: 34.0
```

