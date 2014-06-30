#!/usr/bin/env python

# Copyright (c) 2014, Jan Varho
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""Simple benchmark of python vs c scrypt"""

import time
import platform

from .common import *
from .pylibscrypt import scrypt
from .pypyscrypt_inline import scrypt as pyscrypt
from . import pypyscrypt_inline


print('%s %s' % (platform.python_implementation(), platform.python_version()))

# Benchmark time in seconds
tmin = 10
Nmin = 8
Nmax = 20

# Benched defaults
kwargs = dict(password=b'password', salt=b'NaCl', p=4)
print('Using %s' % kwargs)


pp = pypyscrypt_inline.parallelize_p
pypyscrypt_inline.parallelize_p = False
t1 = time.time()
for i in xrange(Nmin, Nmax+1):
    pyscrypt(N=2**i, **kwargs)
    if time.time() - t1 > tmin:
        Nmax = i
        break
t1 = time.time() - t1
print('Using N = 2**%d,..., 2**%d' % (Nmin, Nmax))
print('Single-threaded scrypt took %.2fs' % t1)

pypyscrypt_inline.parallelize_p = pp
t2 = time.time()
for i in xrange(Nmin, Nmax+1):
    a = pyscrypt(N=2**i, **kwargs)
t2 = time.time() - t2
print('Multiprocessing scrypt took %.2fs' % t2)

pypyscrypt_inline.parallelize_p = False
t2 = time.time()
for i in xrange(Nmin, Nmax+1):
    b = pyscrypt(N=2**i, **kwargs)
t2 = time.time() - t2
print('Single-threaded scrypt took %.2fs' % t2)

assert a == b

