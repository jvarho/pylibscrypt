'Scrypt for Python'

__version__ = '1.0.3'

# First, try loading libscrypt
_done = False
try:
    from pylibscrypt import *
except ImportError:
    pass
else:
    _done = True

# If that didn't work, try the scrypt module
if not _done:
    try:
        from pyscrypt import *
    except ImportError:
        pass
    else:
        _done = True

# If that didn't work either, the inlined Python version
if not _done:
    try:
        from pypyscrypt_inline import *
    except ImportError:
        pass
    else:
        _done = True

# Finally the non-inlined
if not _done:
    from pypyscrypt import *

__all__ = ['scrypt', 'scrypt_mcf', 'scrypt_mcf_check']

# Clean up pydoc output
del __path__
del consts

