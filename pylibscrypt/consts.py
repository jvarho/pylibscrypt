
"""Constants used by scrypt"""

SCRYPT_MCF_PREFIX_7 = b'$7$'
SCRYPT_MCF_PREFIX_s1 = b'$s1$'
SCRYPT_MCF_PREFIX_DEFAULT = b'$s1$'
SCRYPT_MCF_PREFIX_ANY = None

SCRYPT_N = 1<<14
SCRYPT_r = 8
SCRYPT_p = 1

# The last one differs from libscrypt defaults, but matches the 'interactive'
# work factor from the original paper. For long term storage where runtime of
# key derivation is not a problem, you could use 16 as in libscrypt or better
# yet increase N if memory is plentiful.

xrange = xrange if 'xrange' in globals() else range

