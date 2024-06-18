# NOTE

I used hardware time stamps in this experiemtns.
I could not use hardware time stamps with stream verdict or parser.


## Results


**XDP:**
samples: 88
max: 9.699
min: 1.066
mean: 5.62
@1 : 1.066
@50: 5.731
@99: 9.699
std: 2.71
standard err: 0.289

**TC:**
samples: 88
max: 9.903
min: 1.853
mean: 6.41
@1 : 1.853
@50: 6.322
@99: 9.903
std: 2.09
standard err: 0.223

**Verdict:** << FROM XDP TO VERDICT

samples: 108
max: 5.727
min: 1.788
mean: 2.74
@1 : 1.874
@50: 2.518
@99: 4.842
std: 0.697
standard err: 0.0671

**PARSER + Verdict:** << FROM XDP TO PARSER+VERDICT

samples: 142
max: 7.653
min: 2.221
mean: 2.93
@1 : 2.224
@50: 2.734
@99: 7.597
std: 0.75
standard err: 0.0629



**UDP Socket:**

samples: 139
max: 57.508
min: 9.144
mean: 22.23
@1 : 10.496
@50: 22.383
@99: 32.971
std: 6.17
standard err: 0.523



## Command

```bash
cat stream_verdict.txt | awk '{print $6}' | grep -e "[0-9]" | grep -v "[0-9]\{5\}" | awk '{print $0/1000}' | ../../../latency_script.py
```
