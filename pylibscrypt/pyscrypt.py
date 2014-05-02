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


# Scrypt implementation that calls into the 'scrypt' python module.


from scrypt import hash as _scrypt


import mcf as mcf_mod

from consts import *


# scrypt < 0.6 doesn't support hash length
try:
    _scrypt(b'password', b'NaCl', N=2, r=1, p=1, buflen=42)
except TypeError:
    raise ImportError('scrypt module version unsupported, 0.6+ required')


def scrypt(password, salt, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p, olen=64):
    """Returns the result of the scrypt password-based key derivation function

    Constraints:
        r * p < (2 ** 30)
        olen <= (((2 ** 32) - 1) * 32
        N must be a power of 2 greater than 1 (eg. 2, 4, 8, 16, 32...)
        N, r, p must be positive
    """
    if not isinstance(password, bytes):
        raise TypeError('scrypt password must be a byte string')
    if not isinstance(salt, bytes):
        raise TypeError('scrypt salt must be a byte string')
    if N > 2**63:
        raise ValueError('N value cannot be larger than 2**63')
    try:
        return _scrypt(password=password, salt=salt, N=N, r=r, p=p, buflen=olen)
    except:
        raise ValueError


def scrypt_mcf(password, salt=None, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p):
    """Derives a Modular Crypt Format hash using the scrypt KDF

    If no salt is given, 16 random bytes are generated using os.urandom."""
    return mcf_mod.scrypt_mcf(scrypt, password, salt, N, r, p)


def scrypt_mcf_check(mcf, password):
    """Returns True if the password matches the given MCF hash"""
    return mcf_mod.scrypt_mcf_check(scrypt, mcf, password)


if __name__ == "__main__":
    import tests
    print('Testing scrypt...')
    tests.run_tests(scrypt, scrypt_mcf, scrypt_mcf_check)

