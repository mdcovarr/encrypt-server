import hashlib
import base64
#file is encrypted using simon in counter mode using k1
#hash is calculated using k2
#k1 = 0x000000...000 for 256 bits
#k2 = 0x010000...000 for 256 bits


#Assuming k2 is an int, encrypted_message is a string of hex digits
#Returns string encoded in base64
k2 = 0x0100000000000000000000000000000000000000000000000000000000000000
def create_header(k2,encrypted_message):
    b = hex(k2)[2:]
    b += encrypted_message
    if len(b) % 2 != 0:
        b = '0' + b
    bytestring = bytes.fromhex(b)
    value = hashlib.sha3_256(bytestring).digest()
    b64 = base64.b64encode(value)
    return b64.decode()


with open("../recording.encrypted", 'rb') as file:
    data = file.read()
    print(data[:100])
    message = data.hex()
    print(create_header(k2, message))









