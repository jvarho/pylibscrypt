
import ctypes, ctypes.util
from ctypes import c_char_p, c_size_t, c_uint64, c_uint32


SCRYPT_MCF_LEN = 125

SCRYPT_N = 1<<14
SCRYPT_r = 8
SCRYPT_p = 16


def scrypt(password, salt=None, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p):
    raise NotImplementedError


_libscrypt = ctypes.CDLL(ctypes.util.find_library('scrypt'))


if _libscrypt:

    _libscrypt_scrypt = _libscrypt.libscrypt_scrypt
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


    def scrypt(password, salt, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p):
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


