#!/usr/bin/env bash
PYTHON=python3
$PYTHON -m coverage run -m pylibscrypt.tests
$PYTHON -m coverage run -a -m pylibscrypt.pylibscrypt
$PYTHON -m coverage run -a -m pylibscrypt.pylibsodium
$PYTHON -m coverage run -a -m pylibscrypt.pbkdf2
$PYTHON -m coverage run -a test_fallback.py
PYTHON=python
$PYTHON -m coverage run -a -m pylibscrypt.tests
$PYTHON -m coverage run -a -m pylibscrypt.pylibscrypt
$PYTHON -m coverage run -a -m pylibscrypt.pylibsodium
$PYTHON -m coverage run -a -m pylibscrypt.pbkdf2
$PYTHON -m coverage run -a test_fallback.py
$PYTHON -m coverage report
$PYTHON -m coverage annotate

