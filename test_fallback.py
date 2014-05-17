
import sys

def unimport():
    del sys.modules['pylibscrypt']
    sys.modules.pop('pylibscrypt.common', None)
    sys.modules.pop('pylibscrypt.mcf', None)

sys.modules['pylibscrypt.pylibscrypt'] = None
import pylibscrypt

unimport()
sys.modules['pylibscrypt.pyscrypt'] = None
import pylibscrypt

unimport()
sys.modules['pylibscrypt.pylibsodium'] = None
import pylibscrypt

unimport()
sys.modules['pylibscrypt.pylibsodium_salsa'] = None
import pylibscrypt

