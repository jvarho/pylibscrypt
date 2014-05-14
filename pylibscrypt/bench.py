#!/usr/bin/env python
"""Simple benchmark of python vs c scrypt"""

import time

from common import *
from pylibscrypt import scrypt
from pypyscrypt_inline import scrypt as pyscrypt
from pylibsodium_salsa import scrypt as pcscrypt


# Benchmark time in seconds
tmin = 5
Nmax = 20

t1 = time.time()
for i in xrange(1, Nmax+1):
    pyscrypt(b'password', b'NaCl', N=2**i)
    if time.time() - t1 > tmin:
        Nmax = i
        break
t1 = time.time() - t1
print('Using N = 2,4,..., 2**%d' % Nmax)
print('Python scrypt took %.2fs' % t1)

t2 = time.time()
for i in xrange(1, Nmax+1):
    pcscrypt(b'password', b'NaCl', N=2**i)
t2 = time.time() - t2
print('Py + C scrypt took %.2fs' % t2)

t3 = time.time()
for i in xrange(1, Nmax+1):
    scrypt(b'password', b'NaCl', N=2**i)
t3 = time.time() - t3
print('C scrypt took      %.2fs' % t3)

print('Python scrypt took %.2f times as long as C' % (t1 / t3))
print('Py + C scrypt took %.2f times as long as C' % (t2 / t3))

