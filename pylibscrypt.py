
import base64
import ctypes, ctypes.util
from ctypes import c_char_p, c_size_t, c_uint64, c_uint32


_libscrypt_soname = ctypes.util.find_library('scrypt')
if _libscrypt_soname is None:
    raise ImportError('Unable to find libscrypt')

try:
    _libscrypt = ctypes.CDLL(_libscrypt_soname)
except OSError:
    raise ImportError('Unable to load libscrypt: ' + _libscrypt_soname)


try:
    _libscrypt_scrypt = _libscrypt.libscrypt_scrypt
except AttributeError:
    raise ImportError('Incompatible libscrypt: ' + _libscrypt_soname)

_libscrypt_scrypt.argtypes = [
    c_char_p,  # password
    c_size_t,  # password length
    c_char_p,  # salt
    c_size_t,  # salt length
    c_uint64,  # N
    c_uint32,  # r
    c_uint32,  # p
    c_char_p,  # out
    c_size_t,  # out length
]


try:
    _libscrypt_mcf = _libscrypt.libscrypt_mcf
except AttributeError:
    raise ImportError('Incompatible libscrypt: ' + _libscrypt_soname)

_libscrypt_mcf.argtypes = [
    c_uint64,  # N
    c_uint32,  # r
    c_uint32,  # p
    c_char_p,  # salt
    c_char_p,  # hash
    c_char_p,  # out (125+ bytes)
]


try:
    _libscrypt_check = _libscrypt.libscrypt_check
except AttributeError:
    raise ImportError('Incompatible libscrypt: ' + _libscrypt_soname)

_libscrypt_check.argtypes = [
    c_char_p,  # mcf (modified)
    c_char_p,  # hash
]


SCRYPT_MCF_ID = "$s1"
SCRYPT_MCF_LEN = 125

SCRYPT_N = 1<<14
SCRYPT_r = 8
SCRYPT_p = 1 # Note: Value differs from libscrypt, see below.


def scrypt(password, salt, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p):
    """Derives a 64-byte hash using the scrypt key-derivarion function.

    Memory usage is proportional to N*r. Defaults require about 16 MiB.
    Time taken is proportional to N*p. Defaults take <100ms of a recent x86.

    The default values are:
    N -- 2**14 (~16k)
    r -- 8
    p -- 1

    The last one differs from libscrypt defaults, but matches the 'interactive'
    work factor from the original paper. For long term storage where runtime of
    key derivation is not a problem, you could use 16 as in libscrypt or better
    yet increase N if memory is plentiful.
    """
    if not isinstance(password, bytes):
        raise TypeError
    if not isinstance(salt, bytes):
        raise TypeError

    out = ctypes.create_string_buffer(64)
    r = _libscrypt_scrypt(password, len(password), salt, len(salt),
                          N, r, p, out, len(out))
    if r:
        raise ValueError

    return out.raw


def scrypt_mcf(password, salt, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p):
    """Derives a Modular Crypt Format hash using the scrypt KDF"""
    hash = scrypt(password, salt, N, r, p)

    h64 = base64.b64encode(hash)
    s64 = base64.b64encode(salt)

    out = ctypes.create_string_buffer(SCRYPT_MCF_LEN)
    r = _libscrypt_mcf(N, r, p, s64, h64, out)
    if not r:
        raise ValueError

    return out.raw.strip('\0')


def scrypt_mcf_check(mcf, password):
    """Returns True if the password matches the given MCF hash"""
    if not isinstance(mcf, bytes):
        raise TypeError
    if not isinstance(password, bytes):
        raise TypeError

    mcfbuf = ctypes.create_string_buffer(mcf)
    r = _libscrypt_check(mcfbuf, password)
    if r < 0:
        raise ValueError

    return bool(r)


