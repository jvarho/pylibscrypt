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

import struct

from consts import *


def pbkdf2(passphrase, salt, count, olen, prf):
    '''Returns the result of the Password-Based Key Derivation Function 2

    See http://en.wikipedia.org/wiki/PBKDF2
    '''

    def f(block_number):
        '''The function "f".'''

        U = prf(passphrase, salt + struct.pack('>L', block_number))

        # Count is always 1 in scrypt, but supported here
        if count > 1:
            U = bytearray(U)
            Ui = U[:]
            for i in xrange(2, 1 + count):
                Ui = bytearray(prf(passphrase, bytes(Ui)))
                for j in xrange(len(U)):
                    U[j] ^= Ui[j]

        return U

    # PBKDF2 implementation
    size = 0

    block_number = 0
    blocks = []

    while size < olen:
        block_number += 1
        block = f(block_number)

        blocks.append(block)
        size += len(block)

    if size > olen:
        blocks[-1] = blocks[-1][:olen-size]
    return b''.join(blocks)

