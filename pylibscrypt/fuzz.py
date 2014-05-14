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

"""Fuzzes scrypt function input, comparing two implementations"""

import itertools
import random
from random import randrange as rr
import unittest


class Skip(Exception):
    pass


class Fuzzer(object):
    """Fuzzes function input"""
    def __init__(self, f, args, g=None):
        self.f = f
        self.g = g
        self.args = args

    def get_random_int(self):
        return int((1<<rr(66)) * 1.3)

    def get_random_bytes(self):
        v = bytearray(rr(2**rr(20)))
        for i in range(len(v)):
            v[i] = rr(256)
        return bytes(v)

    def get_good_args(self):
        kwargs = {}
        for a in self.args:
            assert isinstance(a, dict)
            if 'opt' in a and a['opt'] and random.randrange(2):
                continue
            if 'val' in a:
                kwargs[a['name']] = a['val']
            elif 'vals' in a:
                kwargs[a['name']] = random.choice(a['vals'])
            elif 'valf' in a:
                kwargs[a['name']] = a['valf']()
            elif 'type' in a and a['type'] == 'int':
                kwargs[a['name']] = self.get_random_int()
            elif 'type' in a and a['type'] == 'bytes':
                kwargs[a['name']] = self.get_random_bytes()
            else:
                raise ValueError
            if 'skip' in a and a['skip'](kwargs[a['name']]):
                if 'opt' in a and a['opt']:
                    del kwargs[a['name']]
                else:
                    raise Skip
        return kwargs

    def get_bad_args(self, kwargs=None):
        kwargs = kwargs or self.get_good_args()
        a = random.choice(self.args)
        if not 'opt' in a:
            if not random.randrange(10):
                del kwargs[a['name']]
                return kwargs, a['name']
        if not 'type' in a:
            return self.get_bad_args(kwargs)

        if not random.randrange(10):
            wrongtype = [
                self.get_random_int(), self.get_random_bytes(), None,
                1.1*self.get_random_int()
            ]
            if a['type'] == 'int':
                del wrongtype[0]
            elif a['type'] == 'bytes':
                del wrongtype[1]
            v = random.choice(wrongtype)
            try:
                if 'valf' in a:
                    if a['valf'](v):
                        return self.get_bad_args(kwargs)
                if 'skip' in a and a['skip'](v):
                    return self.get_bad_args(kwargs)
            except TypeError:
                pass # Surely bad enough
            kwargs[a['name']] = v
            return kwargs, a['name']

        if a['type'] == 'int':
            v = self.get_random_int()
            if 'valf' in a:
                if a['valf'](v):
                    return self.get_bad_args(kwargs)
            if 'skip' in a and a['skip'](v):
                return self.get_bad_args(kwargs)
            kwargs[a['name']] = v
            return kwargs, a['name']
        return self.get_bad_args(kwargs)

    def fuzz_good(self):
        try:
            kwargs = self.get_good_args()
            r1 = self.f(**kwargs)
            if self.g is not None:
                r2 = self.g(**kwargs)
                assert r1 == r2, ('f and g mismatch', kwargs, r1, r2)
            return r1
        except Skip:
            return Skip
        except Exception as e:
            assert False, ('unexpected exception', kwargs, e)

    def fuzz_good_run(self, tc):
        r = self.fuzz_good()
        if r == Skip:
            tc.skipTest('slow')
        tc.assertTrue(r)

    def fuzz_bad(self, f=None, kwargs=None):
        f = f or self.f
        kwargs = kwargs or self.get_bad_args()
        return self.f(**kwargs)

    def fuzz_bad_run(self, tc):
        assert self.g
        if not self.g:
            try:
                r = self.fuzz_bad()
                assert False, ('no exception', kwargs, r)
            except Skip:
                tc.skipTest('slow')
            except AssertionError:
                raise
            except Exception:
                return
        kwargs = self.get_bad_args()
        try:
            r = self.fuzz_bad(self.g, kwargs)
            assert False, ('no exception', kwargs, r)
        except Skip:
            tc.skipTest('slow')
        except AssertionError:
            raise
        except Exception as e1:
            tc.assertRaises(type(e1), self.fuzz_bad, None, kwargs)

    def testcase_good(self, tests=1, name='FuzzTestGood'):
        testfs = {}
        for i in range(tests):
            testfs['test_fuzz_good_%d' % i] = lambda s: self.fuzz_good_run(s)
        t = type(name, (unittest.TestCase,), testfs)
        return t

    def testcase_bad(self, tests=1, name='FuzzTestBad'):
        testfs = {}
        for i in range(tests):
            testfs['test_fuzz_bad_%d' % i] = lambda s: self.fuzz_bad_run(s)
        t = type(name, (unittest.TestCase,), testfs)
        return t

    def generate_tests(self, suite, count):
        loader = unittest.defaultTestLoader
        suite.addTest(loader.loadTestsFromTestCase(self.testcase_good(count)))
        suite.addTest(loader.loadTestsFromTestCase(self.testcase_bad(count)))


if __name__ == "__main__":
    modules = []
    try:
        import pylibscrypt
        modules.append(pylibscrypt)
    except ImportError:
        pass

    try:
        import pyscrypt
        modules.append(pyscrypt)
    except ImportError:
        pass

    try:
        import pylibsodium_salsa
        modules.append(pylibsodium_salsa)
    except ImportError:
        pass

    try:
        import pylibsodium
        modules.append(pylibsodium)
    except ImportError:
        pass

    try:
        import pypyscrypt_inline as pypyscrypt
        modules.append(pypyscrypt)
    except ImportError:
        pass

    scrypt_args = (
        {'name':'password', 'type':'bytes'},
        {'name':'salt', 'type':'bytes'},
        {
            'name':'N', 'type':'int', 'opt':False,
            'valf':(lambda N=None: 2**rr(1,6) if N is None else
                    1 < N < 2**64 and not (N & (N - 1))),
            'skip':(lambda N: (N & (N - 1)) == 0 and N > 32 and N < 2**64)
        },
        {
            'name':'r', 'type':'int', 'opt':True,
            'valf':(lambda r=None: rr(1, 16) if r is None else 0<r<2**30),
            'skip':(lambda r: r > 16 and r < 2**30)
        },
        {
            'name':'p', 'type':'int', 'opt':True,
            'valf':(lambda p=None: rr(1, 16) if p is None else 0<p<2**30),
            'skip':(lambda p: p > 16 and p < 2**30)
        },
        {
            'name':'olen', 'type':'int', 'opt':True,
            'valf':(lambda l=None: rr(1, 1000) if l is None else l >= 0),
            'skip':(lambda l: l < 0 or l > 1024)
        },
    )

    count = 50
    random.shuffle(modules)
    suite = unittest.TestSuite()
    loader = unittest.defaultTestLoader
    for m, prev in itertools.combinations(modules, 2):
        Fuzzer(m.scrypt, scrypt_args, prev.scrypt).generate_tests(suite, count)
    unittest.TextTestRunner().run(suite)

