#!/usr/bin/env bash
PYTHON=python3
$PYTHON -m coverage run pylibscrypt/tests.py
PYTHON=python
$PYTHON -m coverage run -a pylibscrypt/tests.py
$PYTHON -m coverage run -a pylibscrypt/pylibscrypt.py
$PYTHON -m coverage run -a pylibscrypt/pbkdf2.py
$PYTHON -m coverage report
$PYTHON -m coverage annotate

