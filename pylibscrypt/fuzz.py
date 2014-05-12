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

import random
from random import randrange as rr
import sys


class Skip(Exception):
    pass


class Fuzzer(object):
    """Fuzzes function input"""
    def __init__(self, f, args, g=None):
        self.f = f
        self.g = g
        self.args = args

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
                kwargs[a['name']] = random.randrange(-2**32, 2**32)
            else:
                raise ValueError
            if 'skip' in a and a['skip'](kwargs[a['name']]):
                if 'opt' in a:
                    del kwargs[a['name']]
                else:
                    raise Skip
        return kwargs

    def get_bad_args(self, kwargs=None):
        kwargs = kwargs or self.get_good_args()
        a = random.choice(self.args)
        if not 'opt' in a:
            if random.randrange(2):
                del kwargs[a['name']]
                return kwargs, a['name']
        if not 'type' in a:
            return self.get_bad_args(kwargs)
        if a['type'] == 'int':
            v = long((1<<random.randrange(66)) * 1.3)
            if 'valf' in a:
                if a['valf'](v):
                    return self.get_bad_args(kwargs)
            if 'skip' in a and a['skip'](v):
                return self.get_bad_args(kwargs)
            kwargs[a['name']] = v
            return kwargs, a['name']
        else:
            raise TypeError

    def fuzz_good(self):
        try:
            kwargs = self.get_good_args()
            #print('good', kwargs)
            r1 = self.f(**kwargs)
            if self.g is not None:
                r2 = self.g(**kwargs)
                if r1 != r2:
                    print('F')
                    print(kwargs)
                    print(r1)
                    print(r2)
                    print('f and g return mismatch!')
            sys.stdout.write('p')
            sys.stdout.flush()
        except Skip:
            sys.stdout.write('s')
        except:
            print('F')
            print(kwargs)
            raise

    def fuzz_bad(self):
        try:
            kwargs, mod = self.get_bad_args()
            #print('bad', kwargs)
            sys.stdout.flush()
            r1 = self.f(**kwargs)
            print('F')
            print(kwargs)
            print('fuzzed %s', mod)
            print(r1)
            print('Expected an exception!')
            assert False
        except Skip:
            sys.stdout.write('s')
            sys.stdout.flush()
        except AssertionError:
            raise
        except:
            sys.stdout.write('p')
            sys.stdout.flush()


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
        import pylibsodium
        modules.append(pylibsodium)
    except ImportError:
        pass

    try:
        import pypyscrypt_inline as pypyscrypt
        modules.append(pypyscrypt)
    except ImportError:
        pass

    prev = None
    for m in modules:
        print('Testing %s...' % m.__name__)
        g = None if prev is None else prev.scrypt
        f = Fuzzer(m.scrypt, g=g, args=(
            {'name':'password', 'val':'pass'},
            {'name':'salt', 'val':'salt'},
            {
                'name':'N', 'type':'int', 'opt':False,
                'valf':(lambda N=None: 4 if N is None else
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
        ))
        for i in range(1000):
            f.fuzz_good()
            f.fuzz_bad()
        print('')

