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

"""Scrypt implementation that calls into system libscrypt"""


import base64
import ctypes, ctypes.util
import os

from ctypes import c_char_p, c_size_t, c_uint64, c_uint32


from consts import *


_libscrypt_soname = ctypes.util.find_library('scrypt')
if _libscrypt_soname is None:
    raise ImportError('Unable to find libscrypt')

try:
    _libscrypt = ctypes.CDLL(_libscrypt_soname)
except OSError:
    raise ImportError('Unable to load libscrypt: ' + _libscrypt_soname)


try:
    _libscrypt_scrypt = _libscrypt.libscrypt_scrypt
except AttributeError:
    raise ImportError('Incompatible libscrypt: ' + _libscrypt_soname)

_libscrypt_scrypt.argtypes = [
    c_char_p,  # password
    c_size_t,  # password length
    c_char_p,  # salt
    c_size_t,  # salt length
    c_uint64,  # N
    c_uint32,  # r
    c_uint32,  # p
    c_char_p,  # out
    c_size_t,  # out length
]


try:
    _libscrypt_mcf = _libscrypt.libscrypt_mcf
except AttributeError:
    raise ImportError('Incompatible libscrypt: ' + _libscrypt_soname)

_libscrypt_mcf.argtypes = [
    c_uint64,  # N
    c_uint32,  # r
    c_uint32,  # p
    c_char_p,  # salt
    c_char_p,  # hash
    c_char_p,  # out (125+ bytes)
]


try:
    _libscrypt_check = _libscrypt.libscrypt_check
except AttributeError:
    raise ImportError('Incompatible libscrypt: ' + _libscrypt_soname)

_libscrypt_check.argtypes = [
    c_char_p,  # mcf (modified)
    c_char_p,  # hash
]


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
    if not isinstance(password, bytes):
        raise TypeError
    if not isinstance(salt, bytes):
        raise TypeError
    if N > 2**63:
        raise ValueError('N value cannot be larger than 2**63')
    if N < 2:
        raise ValueError('N must be a power of two larger than 1')
    if r == 0 or p == 0:
        raise ValueError('r and p must be positive')

    out = ctypes.create_string_buffer(olen)
    ret = _libscrypt_scrypt(password, len(password), salt, len(salt),
                          N, r, p, out, len(out))
    if ret:
        raise ValueError

    return out.raw


def scrypt_mcf(password, salt=None, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p):
    """Derives a Modular Crypt Format hash using the scrypt KDF

    Parameter space is smaller than for scrypt():
    N must be a power of two larger than 1 but no larger than 2 ** 31
    r and p must be positive numbers between 1 and 255
    Salt must be a byte string 1-16 bytes long.

    If no salt is given, 16 random bytes are generated using os.urandom.
    """
    if salt is None:
        salt = os.urandom(16)
    elif not (1 <= len(salt) <= 16):
        raise ValueError('salt must be 1-16 bytes')
    if N > 2**31:
        raise ValueError('N > 2**31 not supported')
    hash = scrypt(password, salt, N, r, p)

    h64 = base64.b64encode(hash)
    s64 = base64.b64encode(salt)

    out = ctypes.create_string_buffer(SCRYPT_MCF_LEN)
    ret = _libscrypt_mcf(N, r, p, s64, h64, out)
    if not ret:
        raise ValueError

    out = out.raw.strip(b'\0')
    # XXX: Hack to support old libscrypt (like in Ubuntu 14.04)
    if len(out) == 123:
        out = out + b'='

    return out


def scrypt_mcf_check(mcf, password):
    """Returns True if the password matches the given MCF hash"""
    if not isinstance(mcf, bytes):
        raise TypeError
    if not isinstance(password, bytes):
        raise TypeError

    mcfbuf = ctypes.create_string_buffer(mcf)
    ret = _libscrypt_check(mcfbuf, password)
    if ret < 0:
        raise ValueError

    return bool(ret)


if __name__ == "__main__":
    import tests
    print('Testing scrypt...')
    tests.run_tests(scrypt, scrypt_mcf, scrypt_mcf_check)

