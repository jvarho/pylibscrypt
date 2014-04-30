#!/usr/bin/env python

from pylibscrypt import *

# Print a raw scrypt hash in hex
print(scrypt('Hello World', 'salt').encode('hex'))

# Generate an MCF hash with random salt
mcf = scrypt_mcf('Hello World')

# Test it
print(scrypt_mcf_check(mcf, 'Hello World'))
print(scrypt_mcf_check(mcf, 'HelloPyWorld'))

