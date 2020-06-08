import hashlib
import base64
import json
from encryptlib.SimonCTR import countermode_encrypt
from encryptlib.dh import DH
#file is encrypted using simon in counter mode using k1
#hash is calculated using k2
#k1 = 0x000000...000 for 256 bits
#k2 = 0x010000...000 for 256 bits

#Assuming k2 is an int, encrypted_message is a string of hex digits
#Returns string encoded in base64

#k1 = 0x0000000000000000000000000000000000000000000000000000000000000000
#k2 = 0x0100000000000000000000000000000000000000000000000000000000000000

def create_header(data, nonce, diffie):
    k1, k2 = produce_k1_k2(diffie)

    "produce header"
    message = bin(int(data.hex(), 16))[2:]
    encrypted_message = countermode_encrypt(message, nonce, k1) # binary bit string
    b = hex(k2)[2:]
    b += hex(int(encrypted_message, 2))[2:]
    if len(b) % 2 != 0:
        b = '0' + b
    bytestring = bytes.fromhex(b)
    T = hashlib.sha3_256(bytestring).digest()
    value = base64.b64encode(T)  # byte format, needs to be decoded to str
    tag_value = {"tag": value.decode()}
    tag_value_str = json.dumps(tag_value)
    length = len(tag_value_str)
    length_str = '{:08d}'.format(length)
    header = '{0}{1}{2}'.format('3', length_str, tag_value_str)
    return header

def produce_k1_k2(diffie):  # input is int, outputs are int
    diffie_hex = hex(diffie)[2:]
    if len(diffie_hex) % 2 != 0:
        diffie_hex = '0' + diffie_hex
    diffie_byte = bytes.fromhex(diffie_hex)
    k1_k2 = hashlib.sha3_512(diffie_byte).hexdigest()
    k1_k2_bin = bin(int(k1_k2, 16))[2:]
    k1 = k1_k2_bin[:-256]
    k2 = k1_k2_bin[-256:]
    k1, k2 = int(k1, 2), int(k2, 2)
    return k1, k2


if __name__ == '__main__':
    Alice = DH()
    A = Alice.pub_key()
    Bob = DH()
    B = Bob.pub_key()
    diffie = Alice.produce_key(B)

    with open("recording.m4a", 'rb') as file:
        data = file.read()
        nonce = 0
        print(create_header(data, nonce, diffie))
