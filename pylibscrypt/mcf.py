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

"""Modular Crypt Format support for scrypt, compatible with libscrypt"""


import base64
import os
import struct


from consts import *


def scrypt_mcf(scrypt, password, salt=None, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p):
    """Derives a Modular Crypt Format hash using the scrypt KDF given

    Expects the signature:
    scrypt(password, salt, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p, olen=64)

    If no salt is given, 16 random bytes are generated using os.urandom."""
    if salt is None:
        salt = os.urandom(16)
    elif not (1 <= len(salt) <= 16):
        raise ValueError('salt must be 1-16 bytes')
    if r > 255:
        raise ValueError('scrypt_mcf r out of range [1,255]')
    if p > 255:
        raise ValueError('scrypt_mcf p out of range [1,255]')
    if N > 2**31:
        raise ValueError('scrypt_mcf N out of range [2,2**31]')

    hash = scrypt(password, salt, N, r, p)

    h64 = base64.b64encode(hash)
    s64 = base64.b64encode(salt)

    t = 1
    while 2**t < N:
        t += 1
    params = p + (r << 8) + (t << 16)

    return (
        SCRYPT_MCF_ID +
        ('$%06x' % params).encode() +
        b'$' + s64 +
        b'$' + h64
    )


def scrypt_mcf_check(scrypt, mcf, password):
    """Returns True if the password matches the given MCF hash"""
    if not isinstance(mcf, bytes):
        raise TypeError
    if not isinstance(password, bytes):
        raise TypeError

    s = mcf.split(b'$')
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

