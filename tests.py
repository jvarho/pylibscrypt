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

import base64


def run_tests(scrypt, scrypt_mcf, scrypt_mcf_check):
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
    for pw, s, n, r, p, h, m in test_vectors:
        i += 1
        h2 = scrypt(pw, s, n, r, p)
        if h2 != base64.b16decode(h, True):
            print("Test %d.1 failed!" % i)
            print("  scrypt('%s', '%s', %d, %d, %d)" % (pw, s, n, r, p))
            print("  Expected: %s" % h)
            print("  Got:      %s" % base64.b16encode(h2))
            fails += 1
        m2 = scrypt_mcf(pw, s, N=n, p=p, r=r)
        if m != m2:
            print("Test %d.1.5 failed!" % i)
            print("  scrypt_mcf('%s', '%s', %d, %d, %d)" % (pw, s, n, r, p))
            print("  Expected: %s" % m)
            print("  Got:      %s" % m2)
            print("  scrypt_mcf_check failed!")
            fails += 1
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

