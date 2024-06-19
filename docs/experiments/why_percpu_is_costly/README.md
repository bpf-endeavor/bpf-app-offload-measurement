# Experiment

I used the `cost_benchmark` scripts provided in my Kashk repository.
The hypothesis was the performance difference among normal and percpu map accesses is due to the JIT optimizations.
I dissabled the JIT map lookup generation (inlining) and compare the result before and after.

* Before: Map lookup inlining is enabled
* After: Map lookup inlining is disabled


# Results


```
| Before          | After           |
| Normal | PERCPU | Normal | PERCPU |
|  2.8   |  5.9   |  5.6   |  5.6   |
```


# Detail Results

**command:**
```sh
cat after_normal_lookup.txt | grep res | awk '{print $3 / 1000'} | ../../latency_script.py
```

## Before

**Normal:**

samples: 1000
max: 3.148
min: 2.803
mean: 2.88
@1 : 2.803
@50: 2.855
@99: 3.052
std: 0.070
standard err: 0.002
median (iqr): 2.855 (0.12399999999999967)
box-plot: 2.62--[2.805-|2.855|-2.929]--3.11
meidan +- range: 2.855 +- 0.246


**PERCPU:**

samples: 1000
max: 6.322
min: 4.297
mean: 5.80
@1 : 4.528
@50: 5.948
@99: 5.956
std: 0.310
standard err: 0.010
median (iqr): 5.948 (0.16000000000000014)
box-plot: 5.55--[5.793-|5.948|-5.953]--6.19
meidan +- range: 5.948 +- 0.38400000000000034


## After

**Normal:**
```
samples: 1000
max: 6.546
min: 3.867
mean: 5.47
@1 : 4.102
@50: 5.64
@99: 5.951
std: 0.487
standard err: 0.015
median (iqr): 5.64 (0.7220000000000004)
box-plot: 4.07--[5.156-|5.64|-5.878]--6.96
meidan +- range: 5.64 +- 1.556
```


**PERCPU:**
```
samples: 1000
max: 6.546
min: 3.867
mean: 5.47
@1 : 4.102
@50: 5.64
@99: 5.951
std: 0.487
standard err: 0.015
median (iqr): 5.64 (0.7220000000000004)
box-plot: 4.07--[5.156-|5.64|-5.878]--6.96
meidan +- range: 5.64 +- 1.556
```
