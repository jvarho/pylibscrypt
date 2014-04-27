
import base64
import ctypes, ctypes.util
from ctypes import c_char_p, c_size_t, c_uint64, c_uint32

SCRYPT_MCF_ID = "$s1"
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


    _libscrypt_mcf = _libscrypt.libscrypt_mcf
    _libscrypt_mcf.argtypes = [
        c_uint64,  # N
        c_uint32,  # r
        c_uint32,  # p
        c_char_p,  # salt
        c_char_p,  # hash
        c_char_p,  # out (125+ bytes)
    ]


    _libscrypt_check = _libscrypt.libscrypt_check
    _libscrypt_check.argtypes = [
        c_char_p,  # mcf (modified)
        c_char_p,  # hash
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


    def scrypt_mcf(password, salt, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p):
        hash = scrypt(password, salt, N, r, p)

        h64 = base64.b64encode(hash)
        s64 = base64.b64encode(salt)

        out = ctypes.create_string_buffer(SCRYPT_MCF_LEN)
        r = _libscrypt_mcf(N, r, p, s64, h64, out)
        if not r:
            raise ValueError

        return out.raw.strip('\0')


    def scrypt_mcf_check(mcf, password):
        if not isinstance(mcf, bytes):
            raise TypeError
        if not isinstance(password, bytes):
            raise TypeError
        mcfbuf = ctypes.create_string_buffer(mcf)
        r = _libscrypt_check(mcfbuf, password)
        if r < 0:
            raise ValueError
        return bool(r)


