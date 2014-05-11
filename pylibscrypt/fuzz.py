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
            if 'opt' in a and random.randrange(2):
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
                    print kwargs, a
                    sys.exit(1)
                    raise OverflowError
        return kwargs

    def fuzz_good(self):
        try:
            kwargs = self.get_good_args()
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
        except OverflowError:
            print('s')
        except:
            print('F')
            print(kwargs)
            raise


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
                'name':'N', 'type':'int',
                'valf':(lambda N=None: 4 if N is None else not (N & (N - 1))),
                'skip':(lambda N: (N & (N - 1)) and N > 32)
            },
            {
                'name':'r', 'type':'int', 'opt':True,
                'valf':(lambda r=None: rr(1, 16) if r is None else 0<r<2**30),
                'skip':(lambda r: r > 16)
            },
            {
                'name':'p', 'type':'int', 'opt':True,
                'valf':(lambda p=None: rr(1, 16) if p is None else 0<p<2**30),
                'skip':(lambda p: p > 16)
            },
            {
                'name':'olen', 'type':'int', 'opt':True,
                'skip':(lambda l: l < 0 or l > 1024)
            },
        ))
        for i in range(1000):
            f.fuzz_good()
        print('')

