#! /usr/bin/python3
import sys
a = input()
a = int(a)
a = a.to_bytes(4, 'little')
a = [f'0x{b:02x}' for b in a]
a = ' '.join(a)
print(a)

