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
import hashlib
import unittest


class ScryptTests(unittest.TestCase):
    """Tests an scrypt implementation from module"""
    def setUp(self):
        if not self.module:
            self.skipTest('module not tested')

    def _test_vector(self, vector):
        pw, s, N, r, p, h, m = vector
        self.assertEqual(
            self.module.scrypt(pw, s, N, r, p),
            base64.b16decode(h, True)
        )
        if m is not None:
            self.assertEqual(
                self.module.scrypt_mcf(pw, s, N, r, p),
                m
            )
            self.assertTrue(self.module.scrypt_mcf_check(m, pw))
            self.assertFalse(self.module.scrypt_mcf_check(m, b'x' + pw))

    def test_vector0(self):
        self._test_vector((
            b'', b'', 16, 1, 1,
            b'77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442'
            b'fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906',
            None
        ))

    def test_vector1(self):
        if self.fast:
            self.skipTest('slow testcase')
        self._test_vector((
            b'password', b'NaCl', 1024, 8, 16,
            b'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162'
            b'2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
            b'$s1$0a0810$TmFDbA==$/bq+HJ00cgB4VucZDQHp/nxq18vII3gw53N2Y0s3MWIu'
            b'rzDZLiKjiG/xCSedmDDaxyevuUqD7m2DYMvfoswGQA=='
        ))

    def test_vector2(self):
        if self.fast:
            self.skipTest('slow testcase')
        self._test_vector((
            b'pleaseletmein', b'SodiumChloride', 16384, 8, 1,
            b'7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2'
            b'd5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887',
            b'$s1$0e0801$U29kaXVtQ2hsb3JpZGU=$cCO9yzr9c0hGHAbNgf046/2o+7qQT44+'
            b'qbVD9lRdofLVQylVYT8Pz2LUlwUkKpr55h6F3A1lHkDfzwF7RVdYhw=='
        ))

    def test_vector3(self):
        self._test_vector((
            b'password', b'NaCl', 2, 8, 1,
            b'e5ed8edc019edfef2d3ced0896faf9eec6921dcc68125ce81c10d53474ce'
            b'1be545979159700d324e77c68d34c553636a8429c4f3c99b9566466877f9'
            b'dca2b92b',
            b'$s1$010801$TmFDbA==$5e2O3AGe3+8tPO0Ilvr57saSHcxoElzoHBDVNHTO'
            b'G+VFl5FZcA0yTnfGjTTFU2NqhCnE88mblWZGaHf53KK5Kw=='
        ))

    def test_vector4(self):
        self._test_vector((
            b'pleaseletmein', b'SodiumChloride', 4, 1, 1,
            b'BB1D77016C543A99FE632C9C43C60180FD05E0CAC8B29374DBD1854569CB'
            b'534F487240CFC069D6A59A35F2FA5C7428B21D9BE9F84315446D5371119E'
            b'016FEDF7',
            b'$s1$020101$U29kaXVtQ2hsb3JpZGU=$ux13AWxUOpn+YyycQ8YBgP0F4MrI'
            b'spN029GFRWnLU09IckDPwGnWpZo18vpcdCiyHZvp+EMVRG1TcRGeAW/t9w=='
        ))

    def test_bytes_enforced(self):
        self.assertRaises(TypeError, self.module.scrypt, u'pass', b'salt')
        self.assertRaises(TypeError, self.module.scrypt, 42, b'salt')
        self.assertRaises(TypeError, self.module.scrypt, b'pass', None)
        self.assertRaises(TypeError, self.module.scrypt_mcf, u'mcf', b'pass')
        self.assertRaises(TypeError, self.module.scrypt_mcf, object, b'pass')

    def test_salt_length_mcf(self):
        pw = b'pass'
        self.assertRaises(ValueError, self.module.scrypt_mcf, pw, b'')
        self.assertRaises(ValueError, self.module.scrypt_mcf, pw, b'a'*17)

    def test_salt_generation(self):
        pw, N = b'pass', 2
        m1 = self.module.scrypt_mcf(pw, N=N)
        m2 = self.module.scrypt_mcf(pw, N=N)
        self.assertNotEqual(m1, m2)
        self.assertTrue(self.module.scrypt_mcf_check(m1, pw))
        self.assertTrue(self.module.scrypt_mcf_check(m2, pw))

    def test_invalid_N(self):
        pw, s = b'password', b'salt'
        self.assertRaises(TypeError, self.module.scrypt, pw, s, 7.5)
        self.assertRaises(ValueError, self.module.scrypt, pw, s, -1)
        self.assertRaises(ValueError, self.module.scrypt, pw, s, 1)
        self.assertRaises(ValueError, self.module.scrypt, pw, s, 42)
        self.assertRaises(ValueError, self.module.scrypt, pw, s, 2**66)
        self.assertRaises(ValueError, self.module.scrypt, pw, s, 2**66+2)
        self.assertRaises(ValueError, self.module.scrypt_mcf, pw, s, 2**32)

    def test_huge_N(self):
        pw, s = b'password', b'salt'
        self.assertRaises(ValueError, self.module.scrypt, pw, s, 2**50)
        self.assertRaises(ValueError, self.module.scrypt, pw, s, 2**60)

    def test_invalid_r(self):
        pw, s, N = b'password', b'salt', 2
        self.assertRaises(ValueError, self.module.scrypt, pw, s, N, 0)
        self.assertRaises(ValueError, self.module.scrypt, pw, s, N, -1)
        self.assertRaises(TypeError, self.module.scrypt, pw, s, N, 7.5)
        self.assertRaises(ValueError, self.module.scrypt, pw, s, N, 2**31)
        self.assertRaises(ValueError, self.module.scrypt_mcf, pw, s, N, 256)

    def test_invalid_p(self):
        pw, s, N = b'password', b'salt', 2
        self.assertRaises(ValueError, self.module.scrypt, pw, s, N, 1, 0)
        self.assertRaises(ValueError, self.module.scrypt, pw, s, N, 1, -2**31)
        self.assertRaises(TypeError, self.module.scrypt, pw, s, N, 1, 7.5)
        self.assertRaises(ValueError, self.module.scrypt, pw, s, N, 2**35)
        self.assertRaises(ValueError, self.module.scrypt_mcf, pw, s, N, 1, 256)

    def test_olen(self):
        pw, s, N = b'password', b'salt', 2
        self.assertEquals(len(self.module.scrypt(pw, s, N, olen=42)), 42)
        self.assertEquals(len(self.module.scrypt(pw, s, N, olen=100)), 100)

    def test_mcf(self):
        pw = b'password'
        self.assertRaises(ValueError, self.module.scrypt_mcf_check, b'', pw)
        self.assertRaises(ValueError, self.module.scrypt_mcf_check,
                          b'$s1$ffffffff$aaaa$bbbb', pw)
        self.assertRaises(TypeError, self.module.scrypt_mcf_check, u'mcf', pw)
        self.assertRaises(TypeError, self.module.scrypt_mcf_check, b'mcf', 42)


def load_scrypt_suite(name, module, fast=True):
    loader = unittest.defaultTestLoader
    tests = type(name, (ScryptTests,), {'module': module, 'fast': fast})
    return unittest.defaultTestLoader.loadTestsFromTestCase(tests)


def run_scrypt_suite(module, fast=False):
    suite = unittest.TestSuite()
    suite.addTest(load_scrypt_suite('scryptTests', module, fast))
    unittest.TextTestRunner().run(suite)


class PBKDF2Tests(unittest.TestCase):
    """Tests a PBKDF2 implementation from module"""
    def setUp(self):
        if not self.module:
            self.skipTest('module not tested')

    def _test_vector(self, vector):
        n, p, s, c, l, h = vector
        h = base64.b16decode(h, True)
        self.assertEquals(self.module.pbkdf2_hmac(n, p, s, c, l), h)

    def test_vector1(self):
        self._test_vector(('sha1', b'password', b'salt', 1, 20,
                           b'0c60c80f961f0e71f3a9b524af6012062fe037a6'))

    def test_vector2(self):
        self._test_vector(('sha1', b'pass\0word', b'sa\0lt', 4096, 16,
                           b'56fa6aa75548099dcc37d7f03425e0c3'))

    def test_vector3(self):
        self._test_vector(('sha256', b'password', b'NaCl', 7, 42,
                           b'8cb94b8721e20e643be099f3c31d332456b4c26f55'
                           b'b6403950267dc2b3c0806bda709a3f2d7f6107db73'))


def load_pbkdf2_suite(name, module):
    loader = unittest.defaultTestLoader
    tests = type(name, (PBKDF2Tests,), {'module': module})
    return unittest.defaultTestLoader.loadTestsFromTestCase(tests)


def run_pbkdf2_suite(module, fast=False):
    suite = unittest.TestSuite()
    suite.addTest(load_pbkdf2_suite('scryptTests', module))
    unittest.TextTestRunner().run(suite)


if __name__ == "__main__":
    suite = unittest.TestSuite()
    try:
        import pylibscrypt
        suite.addTest(load_scrypt_suite('pylibscryptTests', pylibscrypt, True))
    except ImportError:
        suite.addTest(load_scrypt_suite('pylibscryptTests', None, True))

    try:
        import pyscrypt
        suite.addTest(load_scrypt_suite('pyscryptTests', pyscrypt, True))
    except ImportError:
        suite.addTest(load_scrypt_suite('pyscryptTests', None, True))

    try:
        import pylibsodium
        suite.addTest(load_scrypt_suite('pylibsodiumTests', pylibsodium, True))
    except ImportError:
        suite.addTest(load_scrypt_suite('pylibsodiumTests', None, True))

    try:
        import pypyscrypt_inline as pypyscrypt
        suite.addTest(load_scrypt_suite('pypyscryptTests', pypyscrypt, True))
    except ImportError:
        suite.addTest(load_scrypt_suite('pypyscryptTests', None, True))

    try:
        import pbkdf2
        suite.addTest(load_pbkdf2_suite('pbkdf2', pbkdf2))
    except ImportError:
        suite.addTest(load_pbkdf2_suite('pbkdf2', None))

    if 'pbkdf2_hmac' in dir(hashlib):
        suite.addTest(load_pbkdf2_suite('hashlib_pbkdf2', hashlib))
    else:
        suite.addTest(load_pbkdf2_suite('hashlib_pbkdf2', None))

    unittest.TextTestRunner().run(suite)

