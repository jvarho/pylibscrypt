# Copyright (c) 2014-2017, Jan Varho
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

"""Scrypt for Python"""

__version__ = '1.7.1'

# First, try hashlib
_done = False
try:
    from .hashlibscrypt import *
except ImportError:
    pass
else:
    _done = True

# If that didn't work, try loading libscrypt
if not _done:
    try:
        from .pylibscrypt import *
    except ImportError:
        pass
    else:
        _done = True

# Next: try the scrypt module
if not _done:
    try:
        from .pyscrypt import *
    except ImportError:
        pass
    else:
        _done = True

# Next: libsodium
if not _done:
    try:
        from .pylibsodium import *
    except ImportError:
        pass
    else:
        _done = True

# Unless we are on pypy, we want to try libsodium_salsa as well
if not _done:
    import platform
    if platform.python_implementation() != 'PyPy':
        try:
            from .pylibsodium_salsa import *
        except ImportError:
            pass
        else:
            _done = True

# If that didn't work either, the inlined Python version
if not _done:
    from .pypyscrypt_inline import *

__all__ = ['scrypt', 'scrypt_mcf', 'scrypt_mcf_check']


