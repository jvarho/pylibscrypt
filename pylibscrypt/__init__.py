"""Scrypt for Python"""

__version__ = '1.2.1'

# First, try loading libscrypt
_done = False
try:
    from .pylibscrypt import *
except ImportError:
    pass
else:
    _done = True

# If that didn't work, try the scrypt module
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


