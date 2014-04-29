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


import base64, hashlib, hmac, struct


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
        blocks = bytearray()

        # The iterations
        while size < olen:
            block_number += 1
            block = f(block_number)

            blocks.extend(block)
            size += len(block)

        return blocks[:olen]


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
    return bytes(pbkdf2(password, B, 1, olen, prf))


# Simple test harness
if __name__ == '__main__':

    Tests = [
        dict(password = 'password', salt = 'salt', N = 2, r = 1, p = 1, olen = 32, result = '6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa'),
        dict(password = 'password', salt = 'salt', N = 32, r = 4, p = 15, olen = 128, result = '19f255f7dbcc4128e3467c78c795cb934a82bb813793d2634f6e3adbaee1f54b118fca8b067ab4aad3f6557c716b3734bb93a5cb40500b5e42dc96ccee260fc64d8e660b80e7aecd81c83fefedaf1319b6265e6ef37ca268247052f0b5cac91d14800c1b6f8cb23a28f4620aa0a8e12de88906ec5755a4a643917947a010b7bf'),
        dict(password = 'password', salt = 'salt', N = 128, r = 3, p = 3, olen = 45, result = 'bdbefc353d2145625af2d8f86dad13d6bd993daabbb39a740887ff985803a22675284ad4c3ab5f68a779d0b71a'),
        dict(password = 'password', salt = 'salt', N = 256, r = 6, p = 2, olen = 100, result = '08d4bd8bc6a0db2d3afb86e14bb3e219c7e067add953576ebc4678f86c85f5bc819de1fe22877c7d98c2ee11fef9f3a1ca0047a079b3ee35152c31d51b8db57f267050255065b933d65edfc65203e9b964c5c54507eba8b990c8c9106274fa105237550a'),
        dict(password = "You're a master of Karate", salt = 'And friendship for Everyone', N = 1024, r = 1, p = 1, olen = 256, result = '3a3cbca04456f6ee5295460171a2a2b27e1c28163999f19ab1e2eeda01e355d904627c6baa185087f99f3fee33e4a9ccad1f4230681d77301d2b4f6543023e090faf6e86431a1071f64b693402ceb485469ef33308af104fb1f87b39ecaf733ebc3d73b184c0914fbc4e8eff90777c60172596de79070418f3c9998b6b60640f1d8f3019904b3e20f2920d26c21daf81d0652ffcaffccf734773e0730900204b56b5bebbfb8c3a31d543f6e3ac5f4e1431a864da87c239eefec8e462d458ee2d214646864e9207e15f66a3782b52bb5158152d757d0ca25d2062235ee76c431e5016b3a52cd5b575e3a26aba95654d5b9a991527f5a19d7275ac4f9889081ee9'),
    ]

    # Use the C wrapper to help generate results against a known-correct implementation
    if True:
        import pylibscrypt

        for test in Tests:
            result = test['result']
            del test['result']
            h = pylibscrypt.scrypt(**test).encode('hex')
            if h != result:
                print "Unexcepted result from libscrypt, overwriting original"
            test['result'] = h

    # Run each test case
    index = 0
    for test in Tests:
        index += 1

        # Store and remove the expected result
        result = test['result']
        del test['result']

        # Perform the hash
        h = scrypt(**test).encode('hex')

        # How'd we do?
        print "Test %d: %s" % (index, { True: "pass", False: "FAIL" }[h == result])

