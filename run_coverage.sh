#!/usr/bin/env bash
PYTHON=python3
$PYTHON -m coverage run --branch -m pylibscrypt.tests
$PYTHON -m coverage run --branch -a -m pylibscrypt.pylibscrypt
$PYTHON -m coverage run --branch -a -m pylibscrypt.pylibsodium
$PYTHON -m coverage run --branch -a -m pylibscrypt.pbkdf2
$PYTHON -m coverage run --branch -a test_fallback.py
PYTHON=python
$PYTHON -m coverage run --branch -a -m pylibscrypt.tests
$PYTHON -m coverage run --branch -a -m pylibscrypt.pylibscrypt
$PYTHON -m coverage run --branch -a -m pylibscrypt.pylibsodium
$PYTHON -m coverage run --branch -a -m pylibscrypt.pbkdf2
$PYTHON -m coverage run --branch -a test_fallback.py
$PYTHON -m coverage html --omit='/usr/*'
$PYTHON -m coverage report --omit='/usr/*'
#$PYTHON -m coverage annotate

