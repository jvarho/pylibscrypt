
all: inline


inline: pylibscrypt/pypyscrypt_inline.py

pylibscrypt/pypyscrypt_inline.py: pylibscrypt/inline.py pylibscrypt/pypyscrypt.py
	pylibscrypt/inline.py
	chmod +x pylibscrypt/pypyscrypt_inline.py


clean:
	rm -f *~ *.pyc pylibscrypt/*~ pylibscrypt/*.pyc
	rm -rf __pycache__/ pylibscrypt/__pycache__/


distclean: clean
	rm -rf MANIFEST build/ dist/


test:
	env python -m pylibscrypt.tests


fuzz:
	env python -m pylibscrypt.fuzz


coverage:
	./run_coverage.sh


pypi-upload:
	env python setup.py sdist upload

