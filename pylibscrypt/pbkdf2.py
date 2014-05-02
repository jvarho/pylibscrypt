#!/usr/bin/env python

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

"""PBKDF2 in pure Python, compatible with Python3.4 hashlib.pbkdf2_hmac"""


import hashlib
import hmac
import struct

from consts import *


def pbkdf2_hmac(name, password, salt, rounds, dklen=None):
    """Returns the result of the Password-Based Key Derivation Function 2"""
    h = hmac.new(key=password, digestmod=lambda:hashlib.new(name))
    hs = h.copy()
    hs.update(salt)

    blocks = bytearray()
    dklen = hs.digest_size if dklen is None else dklen
    block_count, last_size = divmod(dklen, hs.digest_size)
    block_count += last_size > 0

    for block_number in xrange(1, block_count + 1):
        hb = hs.copy()
        hb.update(struct.pack('>L', block_number))
        U = bytearray(hb.digest())

        if rounds > 1:
            Ui = U
            for i in xrange(rounds - 1):
                hi = h.copy()
                hi.update(Ui)
                Ui = bytearray(hi.digest())
                for j in xrange(hs.digest_size):
                    U[j] ^= Ui[j]

        blocks.extend(U)

    if last_size:
        del blocks[dklen:]
    return bytes(blocks)

