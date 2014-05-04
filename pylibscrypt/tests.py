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

"""Tests scrypt and PBKDF2 implementations"""


import base64
import hashlib, hmac


def run_tests(scrypt, scrypt_mcf, scrypt_mcf_check, verbose=False, fast=False):
    test_vectors = (
        (b'password', b'NaCl', 1024, 8, 16,
         b'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162'
         b'2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
         b'$s1$0a0810$TmFDbA==$/bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWIu'
         b'rzDZLiKjiG/xCSedmDDaxyevuUqD7m2DYMvfoswGQA=='),
        (b'pleaseletmein', b'SodiumChloride', 16384, 8, 1,
         b'7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2'
         b'd5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887',
         b'$s1$0e0801$U29kaXVtQ2hsb3JpZGU=$cCO9yzr9c0hGHAbNgf046/2o+7qQT44+'
         b'qbVD9lRdofLVQylVYT8Pz2LUlwUkKpr55h6F3A1lHkDfzwF7RVdYhw=='),
    )
    i = fails = 0
    if fast:
        test_vectors = (
            (b'password', b'NaCl', 2, 8, 1,
             b'e5ed8edc019edfef2d3ced0896faf9eec6921dcc68125ce81c10d53474ce'
             b'1be545979159700d324e77c68d34c553636a8429c4f3c99b9566466877f9'
             b'dca2b92b',
             b'$s1$010801$TmFDbA==$5e2O3AGe3+8tPO0Ilvr57saSHcxoElzoHBDVNHTO'
             b'G+VFl5FZcA0yTnfGjTTFU2NqhCnE88mblWZGaHf53KK5Kw=='),
            (b'pleaseletmein', b'SodiumChloride', 4, 1, 1,
             b'BB1D77016C543A99FE632C9C43C60180FD05E0CAC8B29374DBD1854569CB'
             b'534F487240CFC069D6A59A35F2FA5C7428B21D9BE9F84315446D5371119E'
             b'016FEDF7',
             b'$s1$020101$U29kaXVtQ2hsb3JpZGU=$ux13AWxUOpn+YyycQ8YBgP0F4MrI'
             b'spN029GFRWnLU09IckDPwGnWpZo18vpcdCiyHZvp+EMVRG1TcRGeAW/t9w=='),
        )
    for pw, s, n, r, p, h, m in test_vectors:
        i += 1
        h2 = scrypt(pw, s, n, r, p)
        if h2 != base64.b16decode(h, True):
            print("Test %d.1 failed!" % i)
            print("  scrypt('%s', '%s', %d, %d, %d)" % (pw, s, n, r, p))
            print("  Expected: %s" % h)
            print("  Got:      %s" % base64.b16encode(h2))
            fails += 1
        elif verbose:
            print("Test %d.1 successful!" % i)
        m2 = scrypt_mcf(pw, s, N=n, p=p, r=r)
        if m != m2:
            print("Test %d.2 failed!" % i)
            print("  scrypt_mcf('%s', '%s', %d, %d, %d)" % (pw, s, n, r, p))
            print("  Expected: %s" % m)
            print("  Got:      %s" % m2)
            fails += 1
        elif verbose:
            print("Test %d.2 successful!" % i)
        if not (scrypt_mcf_check(m, pw) and scrypt_mcf_check(m2, pw)):
            print("Test %d.3 failed!" % i)
            print("  scrypt_mcf('%s', '%s', %d, %d, %d)" % (pw, s, n, r, p))
            print("  Expected: %s" % m)
            print("  Got:      %s" % m2)
            print("  scrypt_mcf_check failed!")
            fails += 1
        elif verbose:
            print("Test %d.3 successful!" % i)
        if scrypt_mcf_check(m, b'X' + pw) or scrypt_mcf_check(m2, b'X' + pw):
            print("Test %d.4 failed!" % i)
            print("  scrypt_mcf_check succeeded with wrong password!")
            fails += 1
        elif verbose:
            print("Test %d.4 successful!" % i)

    i += 1
    try:
        scrypt(u'password', b'salt', N=2)
    except TypeError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  Unicode password accepted")
        fails += 1

    i += 1
    try:
        scrypt(b'password', u'salt', N=2)
    except TypeError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  Unicode salt accepted")
        fails += 1

    i += 1
    try:
        scrypt(b'password', b'salt', N=-1)
    except ValueError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  Invalid N value -1 accepted")
        fails += 1

    i += 1
    try:
        scrypt(b'password', b'salt', N=1)
    except ValueError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  Invalid N value 1 accepted")
        fails += 1

    i += 1
    if (scrypt_mcf(b'password', b'salt', N=2) !=
            scrypt_mcf(b'password', b'salt', N=2)):
        print("Test %d.1 failed!" % i)
        print("  Inconsistent MCF!")
        fails += 1
    elif verbose:
        print("Test %d.1 successful!" % i)
    if scrypt_mcf(b'password', N=2) == scrypt_mcf(b'password', N=2):
        print("Test %d.2 failed!" % i)
        print("  Random salts match!")
        fails += 1
    elif verbose:
        print("Test %d.2 successful!" % i)

    i += 1
    try:
        mcf = scrypt_mcf(b'password', b's'*100, N=2)
    except ValueError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        if len(mcf) < 150:
            print("Test %d failed!" % i)
            print("  Long salt truncated by scrypt_mcf")
            fails += 1
        elif not scrypt_mcf_check(mcf, b'password'):
            print("Test %d failed!" % i)
            print("  scrypt_mcf[_check] failed with long salt")
        elif scrypt_mcf_check(mcf, b'xpassword'):
            print("Test %d failed!" % i)
            print("  scrypt_mcf[_check] failed with long salt")
            print("  scrypt_mcf_check succeeded with wrong password!")
        elif verbose:
            print("Test %d successful!" % i)

    i += 1
    try:
        scrypt_mcf_check(42, b'password')
    except TypeError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  Non-string MCF accepted")
        fails += 1

    i += 1
    try:
        scrypt_mcf_check(b'mcf', 42)
    except TypeError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  Non-string password accepted")
        fails += 1

    i += 1
    try:
        scrypt_mcf_check(b'mcf', b'password')
    except ValueError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  Invalid MCF not reported")
        fails += 1

    i += 1
    try:
        scrypt_mcf(b'password', b'NaCl', N=2, r=256)
    except ValueError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  scrypt_mcf accepted invalid r")
        fails += 1

    i += 1
    try:
        scrypt_mcf(b'password', b'NaCl', N=2, p=256)
    except ValueError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  scrypt_mcf accepted invalid p")
        fails += 1

    i += 1
    try:
        scrypt_mcf_check(b'$s1$ffffffff$aaaa$bbbb', b'password')
    except ValueError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  scrypt_mcf_check accepted invalid MCF")
        fails += 1

    i += 1
    if len(scrypt(b'pass', b'salt', N=2, olen=42)) != 42:
        print("Test %d failed!" % i)
        print("  scrypt didn't support irregular length 42")
    elif verbose:
        print("Test %d successful!" % i)

    i += 1
    try:
        scrypt_mcf(b'password', b'NaCl', N=2**42)
    except ValueError:
        if verbose:
            print("Test %d successful!" % i)
    except MemoryError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  N == 2**42 accepted by scrypt_mcf")
        fails += 1

    i += 1
    try:
        scrypt(b'password', b'NaCl', N=2**66+2)
    except ValueError:
        if verbose:
            print("Test %d succeeded!" % i)
    else:
        print("Test %d failed!" % i)
        print("  N == 2**66 + 2 interpreted as 2")
        fails += 1

    i += 1
    try:
        scrypt(b'password', b'NaCl', N=2**66)
    except ValueError:
        if verbose:
            print("Test %d succeeded!" % i)
    else:
        print("Test %d failed!" % i)
        print("  N == 2**66 accepted")
        fails += 1

    i += 1
    try:
        scrypt(b'password', b'NaCl', N=2, r=0)
    except ValueError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  Invalid r accepted")
        fails += 1

    i += 1
    try:
        scrypt_mcf(b'password', b'NaCl', N=2, p=0)
    except ValueError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  Invalid p accepted")
        fails += 1

    i += 1
    try:
        scrypt_mcf(b'password', b'', N=2, r=1, p=1)
    except ValueError:
        if verbose:
            print("Test %d successful!" % i)
    else:
        print("Test %d failed!" % i)
        print("  Empty salt accepted!")
        fails += 1

    if fails:
        print("%d tests failed!" % fails)
    else:
        print("All tests successful!")


def run_tests_pbkdf2(f, verbose=False):
    test_vectors = (
        ('sha1', b'password', b'salt', 1, 20,
         base64.b16decode(b'0c60c80f961f0e71f3a9b524af6012062fe037a6', True)),
        ('sha1', b'pass\0word', b'sa\0lt', 4096, 16,
         base64.b16decode(b'56fa6aa75548099dcc37d7f03425e0c3', True)),
        ('sha256', b'password', b'NaCl', 7, 42,
         base64.b16decode(b'8cb94b8721e20e643be099f3c31d332456b4c'
         b'26f55b6403950267dc2b3c0806bda709a3f2d7f6107db73', True)),
    )
    fails = 0
    for i, param in enumerate(test_vectors):
        if f(*param[:-1]) != param[-1]:
            print("Test %d failed!" % i)
            print("  PBKDF output mismatch")
            print("  Expected: %s" % param[-1])
            print("  Got: %s" % f(*param[:-1]))
            fails += 1
        elif verbose:
            print("Test %d successful!" % i)

    if fails:
        print("%d tests failed!" % fails)
    else:
        print("All tests successful!")



if __name__ == "__main__":
    try:
        import pylibscrypt as cs
        print('Testing C scrypt...')
        run_tests(cs.scrypt, cs.scrypt_mcf, cs.scrypt_mcf_check, fast=True)
    except ImportError:
        print('C scrypt not tested!')

    try:
        import pyscrypt as ms
        print('Testing scrypt module...')
        run_tests(ms.scrypt, ms.scrypt_mcf, ms.scrypt_mcf_check, fast=True)
    except ImportError:
        print('scrypt module not tested!')

    try:
        import pypyscrypt_inline as ps
        print('Testing pure Python scrypt...')
        run_tests(ps.scrypt, ps.scrypt_mcf, ps.scrypt_mcf_check, fast=True)
    except ImportError:
        print('Pure Python scrypt not tested!')

    try:
        import pbkdf2 as pk
        print('Testing pbkdf2...')
        run_tests_pbkdf2(pk.pbkdf2_hmac)
    except ImportError:
        print('Pure Python PBKDF2 not tested!')

    if 'pbkdf2_hmac' in dir(hashlib):
        print('Testing hashlib pbkdf2...')
        run_tests_pbkdf2(hashlib.pbkdf2_hmac)

