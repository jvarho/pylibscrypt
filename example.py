#!/usr/bin/env python

from base64 import b16encode

from pylibscrypt import *

# Print a raw scrypt hash in hex
print(b16encode(scrypt(b'Hello World', b'salt')))

# Generate an MCF hash with random salt
mcf = scrypt_mcf(b'Hello World')

# Test it
print(scrypt_mcf_check(mcf, b'Hello World'))
print(scrypt_mcf_check(mcf, b'HelloPyWorld'))

