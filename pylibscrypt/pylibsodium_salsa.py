#!/usr/bin/env python

# Copyright (c) 2014 Richard Moore
# Copyright (c) 2014 Jan Varho
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Scrypt implementation that calls into system libsodium"""


import base64
import ctypes, ctypes.util
from ctypes import c_char_p, c_size_t, c_uint64, c_uint32, c_void_p
import hashlib, hmac
import numbers
import struct

import mcf as mcf_mod
from consts import *


_libsodium_soname = ctypes.util.find_library('sodium')
if _libsodium_soname is None:
    raise ImportError('Unable to find libsodium')

try:
    _libsodium = ctypes.CDLL(_libsodium_soname)
    _libsodium_salsa20_8 = _libsodium.crypto_core_salsa208
except OSError:
    raise ImportError('Unable to load libsodium: ' + _libsodium_soname)
except AttributeError:
    raise ImportError('Incompatible libscrypt: ' + _libsodium_soname)

_libsodium_salsa20_8.argtypes = [
    c_void_p,  # out (16*4 bytes)
    c_void_p,  # in  (4*4 bytes)
    c_void_p,  # k   (8*4 bytes)
    c_void_p,  # c   (4*4 bytes)
]


# Python 3.4+ have PBKDF2 in hashlib, so use it...
if 'pbkdf2_hmac' in dir(hashlib):
    _pbkdf2 = hashlib.pbkdf2_hmac
else:
    # but fall back to Python implementation in < 3.4
    from pbkdf2 import pbkdf2_hmac as _pbkdf2


def scrypt(password, salt, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p, olen=64):
    """Derives a 64-byte hash using the scrypt key-derivarion function

    N must be a power of two larger than 1 but no larger than 2 ** 63 (insane)
    r and p must be positive numbers such that r * p < 2 ** 30

    The default values are:
    N -- 2**14 (~16k)
    r -- 8
    p -- 1

    Memory usage is proportional to N*r. Defaults require about 16 MiB.
    Time taken is proportional to N*p. Defaults take <100ms of a recent x86.

    The last one differs from libscrypt defaults, but matches the 'interactive'
    work factor from the original paper. For long term storage where runtime of
    key derivation is not a problem, you could use 16 as in libscrypt or better
    yet increase N if memory is plentiful.
    """
    def array_overwrite(source, s_start, dest, d_start, length):
        dest[d_start:d_start + length] = source[s_start:s_start + length]


    def blockxor(source, s_start, dest, d_start, length):
        for i in xrange(length):
            dest[d_start + i] ^= source[s_start + i]


    def integerify(B, r):
        """A bijection from ({0, 1} ** k) to {0, ..., (2 ** k) - 1"""

        Bi = (2 * r - 1) * 16
        return B[Bi]


    def salsa20_8(B, x):
        """Salsa 20/8 using libsodium

        NaCL/libsodium includes crypto_core_salsa208, but unfortunately it
        expects the data in a different order, so we need to mix it up a bit.
        """
        struct.pack_into('<16I', x, 0,
            B[0],  B[5],  B[10], B[15], # c
            B[6],  B[7],  B[8],  B[9],  # in
            B[1],  B[2],  B[3],  B[4],  # k
            B[11], B[12], B[13], B[14],
        )

        c = ctypes.addressof(x)
        i = c + 4*4
        k = c + 8*4

        _libsodium_salsa20_8(c, i, k, c)

        B[:] = struct.unpack('<16I', x)


    def blockmix_salsa8(BY, Yi, r):
        """Blockmix; Used by SMix"""

        start = (2 * r - 1) * 16
        X = BY[start:start+16]                             # BlockMix - 1
        x = ctypes.create_string_buffer(16*4)

        for i in xrange(2 * r):                            # BlockMix - 2
            blockxor(BY, i * 16, X, 0, 16)                 # BlockMix - 3(inner)
            salsa20_8(X, x)                                # BlockMix - 3(outer)
            array_overwrite(X, 0, BY, Yi + (i * 16), 16)   # BlockMix - 4

        for i in xrange(r):                                # BlockMix - 6
            array_overwrite(BY, Yi + (i * 2) * 16, BY, i * 16, 16)
            array_overwrite(BY, Yi + (i*2 + 1) * 16, BY, (i + r) * 16, 16)


    def smix(B, Bi, r, N, V, X):
        """SMix; a specific case of ROMix based on Salsa20/8"""

        array_overwrite(B, Bi, X, 0, 32 * r)               # ROMix - 1

        for i in xrange(N):                                # ROMix - 2
            array_overwrite(X, 0, V, i * (32 * r), 32 * r) # ROMix - 3
            blockmix_salsa8(X, 32 * r, r)                  # ROMix - 4

        for i in xrange(N):                                # ROMix - 6
            j = integerify(X, r) & (N - 1)                 # ROMix - 7
            blockxor(V, j * (32 * r), X, 0, 32 * r)        # ROMix - 8(inner)
            blockmix_salsa8(X, 32 * r, r)                  # ROMix - 9(outer)

        array_overwrite(X, 0, B, Bi, 32 * r)               # ROMix - 10


    if not isinstance(password, bytes):
        raise TypeError('password must be a byte string')
    if not isinstance(salt, bytes):
        raise TypeError('salt must be a byte string')
    if not isinstance(N, numbers.Integral):
        raise TypeError('N must be an integer')
    if not isinstance(r, numbers.Integral):
        raise TypeError('r must be an integer')
    if not isinstance(p, numbers.Integral):
        raise TypeError('p must be an integer')

    if N < 2 or (N & (N - 1)):
        raise ValueError('scrypt N must be a power of 2 greater than 1')
    if N > 2 ** 63:
        raise ValueError('N value cannot be larger than 2**63')
    if r <= 0:
        raise ValueError('scrypt r must be positive')
    if p <= 0:
        raise ValueError('scrypt p must be positive')

    # Everything is lists of 32-bit uints for all but pbkdf2
    try:
        B  = _pbkdf2('sha256', password, salt, 1, p * 128 * r)
        B  = list(struct.unpack('<%dI' % (len(B) // 4), B))
        XY = [0] * (64 * r)
        V  = [0] * (32 * r * N)
    except (MemoryError, OverflowError):
        raise ValueError("scrypt parameters don't fit in memory")

    for i in xrange(p):
        smix(B, i * 32 * r, r, N, V, XY)

    B = struct.pack('<%dI' % len(B), *B)
    return _pbkdf2('sha256', password, B, 1, olen)


def scrypt_mcf(password, salt=None, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p):
    """Derives a Modular Crypt Format hash using the scrypt KDF

    Parameter space is smaller than for scrypt():
    N must be a power of two larger than 1 but no larger than 2 ** 31
    r and p must be positive numbers between 1 and 255
    Salt must be a byte string 1-16 bytes long.

    If no salt is given, 16 random bytes are generated using os.urandom.
    """
    return mcf_mod.scrypt_mcf(scrypt, password, salt, N, r, p)


def scrypt_mcf_check(mcf, password):
    """Returns True if the password matches the given MCF hash"""
    return mcf_mod.scrypt_mcf_check(scrypt, mcf, password)


if __name__ == "__main__":
    import sys
    import tests
    tests.run_scrypt_suite(sys.modules[__name__])

