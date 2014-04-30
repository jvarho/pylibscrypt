Scrypt for Python
==

There are a lot of different scrypt modules for Python, but none of them have
everything that I'd like, so here's One More[1].

Features
--
* Uses system libscrypt[2] – as up to date as your distro is.
* Offers a pure Python scrypt implementation for when there's no libscrypt.
* Not unusably slow, even in pure Python... at least with pypy[3]. (More than
  one tenth the C speed, anyway.)

Requirements
--
* Python 2.7 or 3.4 or so. Pypy 2.2 also works. Older versions may or may not.
* If you want speed: libscrypt 1.8 (older may work).

Usage
--

    from pylibscrypt import * # or from pypyscrypt import *
    # Print a raw scrypt hash in hex
    print(scrypt('Hello World', 'salt').encode('hex'))
    # Generate an MCF hash with random salt
    mcf = scrypt_mcf('Hello World')
    # Test it
    print(scrypt_mcf_check(mcf, 'Hello World'))
    print(scrypt_mcf_check(mcf, 'HelloPyWorld'))

Testing
--
tests.py tests both implementations with some quick tests. Running either
implementation directly will also compare to scrypt test vectors from the paper
but this is slow for the Python version unless you have pypy.

run_coverage.sh uses coverage.py[4] to report test coverage.

TODO
--
* Automate the choice of which implementation to use.
* Embed C implementation for when there's no system library?
* ~~Numpy implementation sounds interesting.~~ (is not worth it)

[1]:https://xkcd.com/927/
[2]:https://github.com/technion/libscrypt
[3]:http://pypy.org/
[4]:http://nedbatchelder.com/code/coverage/

