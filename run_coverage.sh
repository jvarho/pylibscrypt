#!/usr/bin/env bash
python -m coverage run pylibscrypt.py
python -m coverage report
python -m coverage annotate

