#!/usr/bin/env python

# Copyright (c) 2014, Jan Varho
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import platform
import sys

platform.python_implementation = lambda:'PyPy'

def unimport():
    del sys.modules['pylibscrypt']
    sys.modules.pop('pylibscrypt.common', None)
    sys.modules.pop('pylibscrypt.mcf', None)

sys.modules['pylibscrypt.pylibscrypt'] = None
import pylibscrypt

unimport()
sys.modules['pylibscrypt.pyscrypt'] = None
import pylibscrypt

unimport()
sys.modules['pylibscrypt.pylibsodium'] = None
import pylibscrypt

unimport()
platform.python_implementation = lambda:'CPython'
import pylibscrypt

unimport()
sys.modules['pylibscrypt.pylibsodium_salsa'] = None
import pylibscrypt

