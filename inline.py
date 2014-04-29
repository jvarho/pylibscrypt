#!/usr/bin/env python

of = open('pypyscrypt_inline.py', 'w')
assert of

def indent(line):
    i = 0
    while i < len(line) and line[i] == ' ':
        i += 1
    return i

with open('pypyscrypt.py', 'r') as f:
    in_loop = False
    loop_indent = 0
    lc = 0
    for line in f:
        lc += 1
        i = indent(line)
        if line[i:].startswith('R('):
            parts = line.split(';')
            for p in parts:
                vals = p.split(',')[1:]
                vals = [int(v.strip(' )\n')) for v in vals]
                of.write(' '*i)
                of.write('a = (x[%d]+x[%d]) & 0xffffffff\n' %
                         (vals[1], vals[2]))
                of.write(' '*i)
                of.write('x[%d] ^= (a << %d) | (a >> %d)\n' %
                         (vals[0], vals[3], 32 - vals[3]))
        else:
            of.write(line)
        if lc == 1:
            of.write('\n# Automatically generated file, see inline.py\n')

