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


# This is a pure-Python implementation of the Scrypt password-based key
# derivation function (PBKDF); see:
# http://en.wikipedia.org/wiki/Scrypt
# http://www.tarsnap.com/scrypt/scrypt.pdf

# It was originally written for a pure-Python Litecoin CPU miner, see:
# https://github.com/ricmoo/nightminer

# Imported to this project from:
# https://github.com/ricmoo/pyscrypt
# but modified since.


import base64, hashlib, hmac, os, struct

import tests

from consts import *


def scrypt(password, salt, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p, olen=64):
    """Returns the result of the scrypt password-based key derivation function.

    Constraints:
        r * p < (2 ** 30)
        olen <= (((2 ** 32) - 1) * 32
        N must be a power of 2 greater than 1 (eg. 2, 4, 8, 16, 32...)
        N, r, p must be positive
    """

    def array_overwrite(source, s_start, dest, d_start, length):
        dest[d_start:d_start + length] = source[s_start:s_start + length]


    def blockxor(source, s_start, dest, d_start, length):
        '''Performs xor on arrays source and dest, storing the result back in dest.'''

        for i in xrange(length):
            dest[d_start + i] ^= source[s_start + i]


    def pbkdf2(passphrase, salt, count, olen, prf):
        '''Returns the result of the Password-Based Key Derivation Function 2.

        See http://en.wikipedia.org/wiki/PBKDF2
        '''

        def f(block_number):
            '''The function "f".'''

            U = prf(passphrase, salt + struct.pack('>L', block_number))

            # Count is always 1 in scrypt
            assert count == 1
            if False:#count > 1:
                U = bytearray(U)
                for i in xrange(2, 1 + count):
                    p = bytearray(prf(passphrase, U))
                    blockxor(p, 0, U, 0, len(U))

            return U

        # PBKDF2 implementation
        size = 0

        block_number = 0
        blocks = []

        # The iterations
        while size < olen:
            block_number += 1
            block = f(block_number)

            blocks.append(block)
            size += len(block)

        if size > olen:
            blocks[-1] = blocks[-1][:olen-size]
        return b''.join(blocks)


    def integerify(B, r):
        '''"A bijective function from ({0, 1} ** k) to {0, ..., (2 ** k) - 1".'''

        Bi = (2 * r - 1) * 16
        return B[Bi]


    def R(X, destination, a1, a2, b):
        '''A single round of Salsa.'''

        a = (X[a1] + X[a2]) & 0xffffffff
        X[destination] ^= ((a << b) | (a >> (32 - b)))


    def salsa20_8(B):
        '''Salsa 20/8 http://en.wikipedia.org/wiki/Salsa20'''

        x = B[:]

        # Salsa... Time to dance.
        for i in xrange(4):
            R(x, 4, 0, 12, 7);   R(x, 8, 4, 0, 9);    R(x, 12, 8, 4, 13);   R(x, 0, 12, 8, 18)
            R(x, 9, 5, 1, 7);    R(x, 13, 9, 5, 9);   R(x, 1, 13, 9, 13);   R(x, 5, 1, 13, 18)
            R(x, 14, 10, 6, 7);  R(x, 2, 14, 10, 9);  R(x, 6, 2, 14, 13);   R(x, 10, 6, 2, 18)
            R(x, 3, 15, 11, 7);  R(x, 7, 3, 15, 9);   R(x, 11, 7, 3, 13);   R(x, 15, 11, 7, 18)
            R(x, 1, 0, 3, 7);    R(x, 2, 1, 0, 9);    R(x, 3, 2, 1, 13);    R(x, 0, 3, 2, 18)
            R(x, 6, 5, 4, 7);    R(x, 7, 6, 5, 9);    R(x, 4, 7, 6, 13);    R(x, 5, 4, 7, 18)
            R(x, 11, 10, 9, 7);  R(x, 8, 11, 10, 9);  R(x, 9, 8, 11, 13);   R(x, 10, 9, 8, 18)
            R(x, 12, 15, 14, 7); R(x, 13, 12, 15, 9); R(x, 14, 13, 12, 13); R(x, 15, 14, 13, 18)

        # Coerce into nice happy 32-bit integers
        for i in xrange(16):
            B[i] = (x[i] + B[i]) & 0xffffffff


    def blockmix_salsa8(BY, Bi, Yi, r):
        '''Blockmix; Used by SMix.'''

        start = Bi + (2 * r - 1) * 16
        X = BY[start:start+16]                             # BlockMix - 1

        for i in xrange(2 * r):                            # BlockMix - 2
            blockxor(BY, i * 16, X, 0, 16)                 # BlockMix - 3(inner)
            salsa20_8(X)                                   # BlockMix - 3(outer)
            array_overwrite(X, 0, BY, Yi + (i * 16), 16)   # BlockMix - 4

        for i in xrange(r):                                # BlockMix - 6
            array_overwrite(BY, Yi + (i * 2) * 16, BY, Bi + (i * 16), 16)

        for i in xrange(r):
            array_overwrite(BY, Yi + (i * 2 + 1) * 16, BY, Bi + (i + r) * 16, 16)


    def smix(B, Bi, r, N, V, X):
        '''SMix; a specific case of ROMix. See scrypt.pdf in the links above.'''

        array_overwrite(B, Bi, X, 0, 32 * r)               # ROMix - 1

        for i in xrange(N):                                # ROMix - 2
            array_overwrite(X, 0, V, i * (32 * r), 32 * r) # ROMix - 3
            blockmix_salsa8(X, 0, 32 * r, r)               # ROMix - 4

        for i in xrange(N):                                # ROMix - 6
            j = integerify(X, r) & (N - 1)                 # ROMix - 7
            blockxor(V, j * (32 * r), X, 0, 32 * r)        # ROMix - 8(inner)
            blockmix_salsa8(X, 0, 32 * r, r)               # ROMix - 9(outer)

        array_overwrite(X, 0, B, Bi, 32 * r)               # ROMix - 10


    # Scrypt implementation. Significant thanks to https://github.com/wg/scrypt
    if not isinstance(salt, bytes):
        raise TypeError('scrypt salt must be a byte string')
    if N < 2 or (N & (N - 1)):
        raise ValueError('Scrypt N must be a power of 2 greater than 1')

    prf = lambda k, m: hmac.new(key=k, msg=m, digestmod=hashlib.sha256).digest()

    B  = pbkdf2(password, salt, 1, p * 128 * r, prf)
    B  = list(struct.unpack('<%dI' % (len(B) // 4), B))

    XY = [0] * (64 * r)
    V  = [0] * (32 * r * N)

    for i in xrange(p):
        smix(B, i * 32 * r, r, N, V, XY)

    B = struct.pack('<%dI' % len(B), *B)
    return pbkdf2(password, B, 1, olen, prf)


_scrypt_dbs = [
    0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
    31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
]

def scrypt_mcf(password, salt=None, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p):
    """Derives a Modular Crypt Format hash using the scrypt KDF.

    If no salt is given, 16 random bytes are generated using os.urandom."""
    if salt is None:
        salt = os.urandom(16)

    if not 0 < r < 255:
        raise ValueError('scrypt_mcf r out of range [1,255]')
    if not 0 < p < 255:
        raise ValueError('scrypt_mcf p out of range [1,255]')

    hash = scrypt(password, salt, N, r, p)

    h64 = base64.b64encode(hash)
    s64 = base64.b64encode(salt)

    t = _scrypt_dbs[((N * 0x077CB531) & 0xffffffff) >> 27]
    params = p + (r << 8) + (t << 16)

    return '%s$%06x$%s$%s' % (SCRYPT_MCF_ID, params, s64, h64)


def scrypt_mcf_check(mcf, password):
    """Returns True if the password matches the given MCF hash"""
    if not isinstance(mcf, bytes):
        raise TypeError
    if not isinstance(password, bytes):
        raise TypeError

    s = mcf.split('$')
    if not (mcf.startswith(SCRYPT_MCF_ID) and len(s) == 5):
        raise ValueError('Unrecognized MCF hash')

    params, s64, h64 = s[2:]
    params = base64.b16decode(params, True)
    salt = base64.b64decode(s64)
    hash = base64.b64decode(h64)

    if len(params) != 3:
        raise ValueError('Unrecognized MCF parameters')
    t, r, p = struct.unpack('3B', params)
    N = 2 ** t

    h = scrypt(password, salt, N=N, r=r, p=p)

    return hash == h


if __name__ == "__main__":
    print('Testing scrypt...')
    tests.run_tests(scrypt, scrypt_mcf, scrypt_mcf_check)

