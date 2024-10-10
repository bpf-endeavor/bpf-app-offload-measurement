#! /usr/bin/python3
import random
random.seed(127)
file_path = './flows.txt'
num_flows = 100000
max_port_num = 65000 # exclusive; it should mach the bpf program
src_port_max = num_flows // max_port_num
tmp = []
for i in range(0, num_flows):
    src_port = i // max_port_num
    dst_port = i % max_port_num
    tmp.append([src_port, dst_port])
# random.shuffle(tmp)
with open(file_path, 'w') as f:
    for item in tmp:
        src_port, dst_port = item
        f.write(f'{src_port} {dst_port}\n')
