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

"""Scrypt implementation that calls into system libsodium"""


import base64
import ctypes, ctypes.util
from ctypes import c_char_p, c_size_t, c_uint64, c_uint32, c_void_p
import hashlib, hmac
import numbers
import platform
import struct

import mcf as mcf_mod
from common import *

if platform.python_implementation() == 'PyPy':
    import pypyscrypt_inline as scr_mod
else:
    import pylibsodium_salsa as scr_mod


_libsodium_soname = ctypes.util.find_library('sodium')
if _libsodium_soname is None:
    raise ImportError('Unable to find libsodium')

try:
    _libsodium = ctypes.CDLL(_libsodium_soname)
    _scrypt = _libsodium.crypto_pwhash_scryptxsalsa208sha256
    _scrypt_str = _libsodium.crypto_pwhash_scryptxsalsa208sha256_str
    _scrypt_str_chk = _libsodium.crypto_pwhash_scryptxsalsa208sha256_str_verify
    _scrypt_str_bytes = _libsodium.crypto_pwhash_scryptxsalsa208sha256_strbytes
    _scrypt_salt = _libsodium.crypto_pwhash_scryptxsalsa208sha256_saltbytes
    _scrypt_salt = _scrypt_salt()
    if _scrypt_str_bytes() != 102:
        raise ImportError('Incompatible libsodium: ' + _libsodium_soname)
except OSError:
    raise ImportError('Unable to load libsodium: ' + _libsodium_soname)
except AttributeError:
    raise ImportError('Incompatible libsodium: ' + _libsodium_soname)

_scrypt.argtypes = [
    c_void_p,  # out
    c_uint64,  # outlen
    c_void_p,  # passwd
    c_uint64,  # passwdlen
    c_void_p,  # salt
    c_uint64,  # opslimit
    c_size_t,  # memlimit
]

_scrypt_str.argtypes = [
    c_void_p,  # out (102 bytes)
    c_void_p,  # passwd
    c_uint64,  # passwdlen
    c_uint64,  # opslimit
    c_size_t,  # memlimit
]

_scrypt_str_chk.argtypes = [
    c_char_p,  # str (102 bytes)
    c_void_p,  # passwd
    c_uint64,  # passwdlen
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
    check_args(password, salt, N, r, p, olen)

    if len(salt) != _scrypt_salt or r != 8 or (p & (p - 1)) or (N*p <= 512):
        return scr_mod.scrypt(password, salt, N, r, p, olen)

    for s in range(1, 64):
        if 2**s == N:
            break
    for t in range(0, 30):
        if 2**t == p:
            break
    m = 2**(10 + s)
    o = 2**(5 + t + s)
    if s > 53 or t + s > 58:
        raise ValueError
    out = ctypes.create_string_buffer(olen)
    if _scrypt(out, olen, password, len(password), salt, o, m) != 0:
        raise ValueError
    return out.raw


def scrypt_mcf(password, salt=None, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p,
               prefix=SCRYPT_MCF_PREFIX_DEFAULT):
    """Derives a Modular Crypt Format hash using the scrypt KDF

    Parameter space is smaller than for scrypt():
    N must be a power of two larger than 1 but no larger than 2 ** 31
    r and p must be positive numbers between 1 and 255
    Salt must be a byte string 1-16 bytes long.

    If no salt is given, a random salt of 128+ bits is used. (Recommended.)
    """
    if N < 2 or (N & (N - 1)):
        raise ValueError('scrypt N must be a power of 2 greater than 1')
    if p > 255 or p < 1:
        raise ValueError('scrypt_mcf p out of range [1,255]')
    if N > 2**31:
        raise ValueError('scrypt_mcf N out of range [2,2**31]')

    if (salt is not None or r != 8 or (p & (p - 1)) or (N*p <= 512) or
        prefix not in (SCRYPT_MCF_PREFIX_7, SCRYPT_MCF_PREFIX_s1,
                       SCRYPT_MCF_PREFIX_ANY)):
        return mcf_mod.scrypt_mcf(scrypt, password, salt, N, r, p, prefix)

    for s in range(1, 32):
        if 2**s == N:
            break
    for t in range(0, 8):
        if 2**t == p:
            break
    m = 2**(10 + s)
    o = 2**(5 + t + s)
    mcf = ctypes.create_string_buffer(102)
    if _scrypt_str(mcf, password, len(password), o, m) != 0:
        return mcf_mod.scrypt_mcf(scrypt, password, salt, N, r, p, prefix)

    if prefix in (SCRYPT_MCF_PREFIX_7, SCRYPT_MCF_PREFIX_ANY):
        return mcf.raw.strip(b'\0')

    _N, _r, _p, salt, hash, olen = mcf_mod._scrypt_mcf_decode_7(mcf.raw[:-1])
    assert _N == N and _r == r and _p == p, (_N, _r, _p, N, r, p, o, m)
    return mcf_mod._scrypt_mcf_encode_s1(N, r, p, salt, hash)


def scrypt_mcf_check(mcf, password):
    """Returns True if the password matches the given MCF hash"""
    if mcf_mod._scrypt_mcf_7_is_standard(mcf):
        return _scrypt_str_chk(mcf, password, len(password)) == 0
    return mcf_mod.scrypt_mcf_check(scrypt, mcf, password)


if __name__ == "__main__":
    import sys
    import tests
    try:
        import pylibscrypt
        scr_mod = pylibscrypt
    except ImportError:
        pass
    tests.run_scrypt_suite(sys.modules[__name__])

