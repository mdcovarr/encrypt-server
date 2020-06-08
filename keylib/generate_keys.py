from keys import e, KEY_BIT_SIZE
from Crypto.PublicKey import RSA
import os

CWD = os.path.dirname(os.path.realpath(__file__))
PRIVATE_KEY_FILE = os.path.join(CWD, 'testkey.pem')

def main():
    """
    Main Execution of generating keys
    """
    print('Generating RSA Keys of size: {0}'.format(KEY_BIT_SIZE))
    print('With e: {0}'.format(e))

    key = RSA.generate(KEY_BIT_SIZE, e=e)
    pub_key = key.publickey()

    # Export Keys
    f = open(PRIVATE_KEY_FILE, 'wb')
    f.write(key.export_key('PEM'))
    f.close()

if __name__ == '__main__':
    main()
