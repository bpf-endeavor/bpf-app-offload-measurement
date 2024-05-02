#! /usr/bin/python3
import sys

count_args = len(sys.argv)
FILE='-'
if count_args > 1:
    FILE=sys.argv[1]

if FILE == '-':
    stream = sys.stdin
else:
    stream = open(FILE, 'r')

samples = []
for i, line in enumerate(stream):
    line = line.strip()
    if not line:
        continue
    try:
        v = float(line)
    except:
        print('failed to convert to fload: sample at line', i)
        continue

    samples.append(v)

stream.close()


count_smaples = len(samples)
mean = sum(samples) / count_smaples
print('samples:', count_smaples)
print('max:', max(samples))
print('min:', min(samples))
print(f'mean: {mean:.2f}')
print('@50:', samples[int(count_smaples * 0.50)])
print('@99:', samples[int(count_smaples * 0.99)])
