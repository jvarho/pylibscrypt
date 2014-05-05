#!/usr/bin/env python
"""Simple benchmark of python vs c scrypt"""

import time

from pylibscrypt import scrypt
from pypyscrypt_inline import scrypt as pyscrypt

# Benchmark time in seconds 
tmin = 5
Nmax = 20

t2 = time.time()
for i in xrange(1, Nmax+1):
    pyscrypt(b'password', b'NaCl', N=2**i)
    if time.time() - t2 > tmin:
        Nmax = i
        break
t2 = time.time() - t2
print('Using N = 2,4,..., 2**%d' % Nmax)
print('Python scrypt took %.2fs' % t2)

t1 = time.time()
for i in xrange(1, Nmax+1):
    scrypt(b'password', b'NaCl', N=2**i)
t1 = time.time() - t1
print('C scrypt took      %.2fs' % t1)

print('Python scrypt took %.2f times as long' % (t2 / t1))

