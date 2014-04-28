#!/usr/bin/env bash
PYTHON=python
$PYTHON -m coverage run pylibscrypt.py
$PYTHON -m coverage report
$PYTHON -m coverage annotate

