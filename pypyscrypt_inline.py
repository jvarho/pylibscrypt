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


SCRYPT_MCF_ID = "$s1"
SCRYPT_MCF_LEN = 125

SCRYPT_N = 1<<14
SCRYPT_r = 8
SCRYPT_p = 1 # Note: Value differs from libscrypt.


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

            if count > 1:
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
            a = (x[0]+x[12]) & 0xffffffff
            x[4] ^= (a << 7) | (a >> 25)
            a = (x[4]+x[0]) & 0xffffffff
            x[8] ^= (a << 9) | (a >> 23)
            a = (x[8]+x[4]) & 0xffffffff
            x[12] ^= (a << 13) | (a >> 19)
            a = (x[12]+x[8]) & 0xffffffff
            x[0] ^= (a << 18) | (a >> 14)
            a = (x[5]+x[1]) & 0xffffffff
            x[9] ^= (a << 7) | (a >> 25)
            a = (x[9]+x[5]) & 0xffffffff
            x[13] ^= (a << 9) | (a >> 23)
            a = (x[13]+x[9]) & 0xffffffff
            x[1] ^= (a << 13) | (a >> 19)
            a = (x[1]+x[13]) & 0xffffffff
            x[5] ^= (a << 18) | (a >> 14)
            a = (x[10]+x[6]) & 0xffffffff
            x[14] ^= (a << 7) | (a >> 25)
            a = (x[14]+x[10]) & 0xffffffff
            x[2] ^= (a << 9) | (a >> 23)
            a = (x[2]+x[14]) & 0xffffffff
            x[6] ^= (a << 13) | (a >> 19)
            a = (x[6]+x[2]) & 0xffffffff
            x[10] ^= (a << 18) | (a >> 14)
            a = (x[15]+x[11]) & 0xffffffff
            x[3] ^= (a << 7) | (a >> 25)
            a = (x[3]+x[15]) & 0xffffffff
            x[7] ^= (a << 9) | (a >> 23)
            a = (x[7]+x[3]) & 0xffffffff
            x[11] ^= (a << 13) | (a >> 19)
            a = (x[11]+x[7]) & 0xffffffff
            x[15] ^= (a << 18) | (a >> 14)
            a = (x[0]+x[3]) & 0xffffffff
            x[1] ^= (a << 7) | (a >> 25)
            a = (x[1]+x[0]) & 0xffffffff
            x[2] ^= (a << 9) | (a >> 23)
            a = (x[2]+x[1]) & 0xffffffff
            x[3] ^= (a << 13) | (a >> 19)
            a = (x[3]+x[2]) & 0xffffffff
            x[0] ^= (a << 18) | (a >> 14)
            a = (x[5]+x[4]) & 0xffffffff
            x[6] ^= (a << 7) | (a >> 25)
            a = (x[6]+x[5]) & 0xffffffff
            x[7] ^= (a << 9) | (a >> 23)
            a = (x[7]+x[6]) & 0xffffffff
            x[4] ^= (a << 13) | (a >> 19)
            a = (x[4]+x[7]) & 0xffffffff
            x[5] ^= (a << 18) | (a >> 14)
            a = (x[10]+x[9]) & 0xffffffff
            x[11] ^= (a << 7) | (a >> 25)
            a = (x[11]+x[10]) & 0xffffffff
            x[8] ^= (a << 9) | (a >> 23)
            a = (x[8]+x[11]) & 0xffffffff
            x[9] ^= (a << 13) | (a >> 19)
            a = (x[9]+x[8]) & 0xffffffff
            x[10] ^= (a << 18) | (a >> 14)
            a = (x[15]+x[14]) & 0xffffffff
            x[12] ^= (a << 7) | (a >> 25)
            a = (x[12]+x[15]) & 0xffffffff
            x[13] ^= (a << 9) | (a >> 23)
            a = (x[13]+x[12]) & 0xffffffff
            x[14] ^= (a << 13) | (a >> 19)
            a = (x[14]+x[13]) & 0xffffffff
            x[15] ^= (a << 18) | (a >> 14)

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

    t = _scrypt_dbs[((n * 0x077CB531) & 0xffffffff) >> 27]
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
    t, r, p = struct.unpack('3B', base64.b16decode(params, True))
    N = 2 ** t
    salt = base64.b64decode(s64)
    hash = base64.b64decode(h64)

    if not 0 < r < 255:
        raise ValueError('scrypt_mcf_check r out of range [1,255]')
    if not 0 < p < 255:
        raise ValueError('scrypt_mcf_check p out of range [1,255]')

    h = scrypt(password, salt, N=N, r=r, p=p)

    #print((mcf, password, salt, N, r, p))
    #print((hash, h, hash == h))

    return hash == h


if __name__ == "__main__":
    print('Testing scrypt...')

    test_vectors = (
        (b'password', b'NaCl', 1024, 8, 16,
          b'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162'
          b'2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
          b'$s1$0e0801$TmFDbA==$qEMNflgfnKA8lS31Bqxmx1eJnWeiHXHA8ZAL13isHRTK'
          b'DtWIP2jrleFuZRPU1OraoUTE8l1tDKpPhxz1HG6c7w=='),
        (b'pleaseletmein', b'SodiumChloride', 16384, 8, 1,
          b'7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2'
          b'd5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887',
          b'$s1$0e0801$U29kaXVtQ2hsb3JpZGU=$cCO9yzr9c0hGHAbNgf046/2o+7qQT44+'
          b'qbVD9lRdofLVQylVYT8Pz2LUlwUkKpr55h6F3A1lHkDfzwF7RVdYhw=='),
    )
    i = fails = 0
    for pw, s, n, r, p, h, m in test_vectors:
        i += 1
        h2 = scrypt(pw, s, n, r, p)
        if h2 != base64.b16decode(h, True):
            print("Test %d.1 failed!" % i)
            print("  scrypt('%s', '%s', %d, %d, %d)" % (pw, s, n, r, p))
            print("  Expected: %s" % h)
            print("  Got:      %s" % base64.b16encode(h2))
            fails += 1
        m2 = scrypt_mcf(pw, s, N=n, r=r, p=p)
        if not (scrypt_mcf_check(m, pw) and scrypt_mcf_check(m2, pw)):
            print("Test %d.2 failed!" % i)
            print("  scrypt_mcf('%s', '%s', %d, %d, %d)" % (pw, s, n, r, p))
            print("  Expected: %s" % m)
            print("  Got:      %s" % m2)
            print("  scrypt_mcf_check failed!")
            fails += 1
        if scrypt_mcf_check(m, b'X' + pw) or scrypt_mcf_check(m2, b'X' + pw):
            print("Test %d.3 failed!" % i)
            print("  scrypt_mcf_check succeeded with wrong password!")
            fails += 1

    i += 1
    try:
        scrypt(u'password', b'salt')
    except TypeError:
        pass
    else:
        print("Test %d failed!" % i)
        print("  Unicode password accepted")
        fails += 1

    i += 1
    try:
        scrypt(b'password', u'salt')
    except TypeError:
        pass
    else:
        print("Test %d failed!" % i)
        print("  Unicode salt accepted")
        fails += 1

    i += 1
    try:
        scrypt(b'password', b'salt', N=-1)
    except ValueError:
        pass
    else:
        print("Test %d failed!" % i)
        print("  Invalid N value accepted")
        fails += 1

    i += 1
    if scrypt_mcf(b'password', b'salt') != scrypt_mcf(b'password', b'salt'):
        print("Test %d.1 failed!" % i)
        print("  Inconsistent MCF!")
        fails += 1
    if scrypt_mcf(b'password') == scrypt_mcf(b'password'):
        print("Test %d.2 failed!" % i)
        print("  Random salts match!")
        fails += 1

    i += 1
    try:
        mcf = scrypt_mcf(b'password', b's'*100)
    except ValueError:
        pass
    else:
        if len(mcf) < 150:
            print("Test %d failed!" % i)
            print("  Long salt truncated by scrypt_mcf")
            fails += 1

    i += 1
    try:
        scrypt_mcf_check(42, b'password')
    except TypeError:
        pass
    else:
        print("Test %d failed!" % i)
        print("  Non-string MCF accepted")
        fails += 1

    i += 1
    try:
        scrypt_mcf_check(b'mcf', 42)
    except TypeError:
        pass
    else:
        print("Test %d failed!" % i)
        print("  Non-string password accepted")
        fails += 1

    i += 1
    try:
        scrypt_mcf_check(b'mcf', b'password')
    except ValueError:
        pass
    else:
        print("Test %d failed!" % i)
        print("  Invalid MCF not reported")
        fails += 1

    if fails:
        print("%d tests failed!" % fails)
    else:
        print("All tests successful!")

