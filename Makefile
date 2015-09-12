
all: inline


inline: pylibscrypt/pypyscrypt_inline.py

pylibscrypt/pypyscrypt_inline.py: pylibscrypt/inline.py pylibscrypt/pypyscrypt.py
	env python -m pylibscrypt.inline


clean:
	rm -f *~ *.pyc *,cover pylibscrypt/*~ pylibscrypt/*.pyc pylibscrypt/*,cover
	rm -rf __pycache__/ pylibscrypt/__pycache__/


distclean: clean
	rm -rf MANIFEST build/ dist/


test:
	env python -m pylibscrypt.tests


fuzz:
	env python -m pylibscrypt.fuzz


coverage:
	./run_coverage.sh


bench:
	env python -m pylibscrypt.bench


pypi-upload:
	env python setup.py sdist upload

