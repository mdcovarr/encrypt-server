#Code taken from https://github.com/bozhu/NSA-ciphers/blob/master/simon.py by Bo Zhu
import time
import random
class SIMON:
    """
    one of the two lightweight block ciphers designed by NSA
    this one is optimized for hardware implementation
    """
    def __init__(self, block_size, key_size, master_key=None):
        self.block_size = block_size
        self.key_size = key_size
        self.__num_rounds = 72
        self.__const_seq = (1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1)
        assert len(self.__const_seq) == 62
        self.__dim = block_size // 2
        self.__mod = 1 << self.__dim
        if master_key is not None:
            self.change_key(master_key)

    def __lshift(self, x, i=1):
        return ((x << i) % self.__mod) | (x >> (self.__dim - i))

    def __rshift(self, x, i=1):
        return ((x << (self.__dim - i)) % self.__mod) | (x >> i)

    def change_key(self, master_key):
        assert 0 <= master_key < (1 << self.key_size)
        c = (1 << self.__dim) - 4
        m = self.key_size // self.__dim
        self.__round_key = []
        for i in range(m):
            self.__round_key.append(master_key % self.__mod)
            master_key >>= self.__dim
        for i in range(m, self.__num_rounds):
            k = self.__rshift(self.__round_key[-1], 3)
            if m == 4:
                k ^= self.__round_key[-3]
            k ^= self.__rshift(k) ^ self.__round_key[-m]
            k ^= c ^ self.__const_seq[(i - m) % 62]
            self.__round_key.append(k)

    def __feistel_round(self, l, r, k):
        f = (self.__lshift(l) & self.__lshift(l, 8)) ^ self.__lshift(l, 2)
        return r ^ f ^ k, l

    def encrypt(self, plaintext):
        l = plaintext >> self.__dim
        r = plaintext % self.__mod
        for i in range(self.__num_rounds):
            l, r = self.__feistel_round(l, r, self.__round_key[i])
        ciphertext = (l << self.__dim) | r
        return ciphertext

    def decrypt(self, ciphertext):
        l = ciphertext >> self.__dim
        r = ciphertext % self.__mod
        for i in range(self.__num_rounds - 1, -1, -1):
            r, l = self.__feistel_round(r, l, self.__round_key[i])
        plaintext = (l << self.__dim) | r
        return plaintext


#input is string of binary digits - no leading 0s since we're encrypting
#returns as string of binary digits
def countermode_encrypt(message,nonce,key):
    n = len(message)
    remainder = n%128
    number_of_blocks = n//128
    #splitting message into 128-bit blocks
    if remainder != 0:
        number_of_blocks += 1
    list_of_blocks = []
    if number_of_blocks == 1:
        list_of_blocks.append(message)
    if number_of_blocks > 1 and remainder == 0:
        for i in range(number_of_blocks):
            list_of_blocks.append(message[i*128 : (i+1)*128])
    if number_of_blocks > 1 and remainder != 0:
        for i in range(number_of_blocks-1):
            list_of_blocks.append(message[i*128 : (i+1)*128])
        list_of_blocks.append(message[-remainder:])

    simon = SIMON(128,256,key)
    ciphertext = ''
    for i in list_of_blocks:
        ek = simon.encrypt(nonce)
        #full block of plaintext (128 bits)
        if len(i) == 128:
            cipher = ek ^ int(i,2)
            cipher = bin(cipher)[2:]
            while len(cipher) < len(i):
                cipher = '0' + cipher
            ciphertext += cipher
        #partial block of plaintext (< 128 bits)
        else:
            cipher = int(bin(ek)[2:len(i)+2],2) ^ int(i,2)
            #cipher = int(i,2) ^ int(bin(ek)[2 : len(i)+2],2)
            cipher = bin(cipher)[2:]
            while len(cipher) < len(i):
                cipher = '0' + cipher
            ciphertext += cipher

        nonce += 1
    return ciphertext

#ciphertext is string of binary digits INCLUDING LEADING 0s!!!
def countermode_decrypt(ciphertext,nonce,key):
    n = len(ciphertext)
    remainder = n%128
    number_of_blocks = n//128
    if remainder != 0:
        number_of_blocks += 1
    list_of_blocks = []
    if number_of_blocks == 1:
        list_of_blocks.append(ciphertext)
    if number_of_blocks > 1 and remainder == 0:
        for i in range(number_of_blocks):
            list_of_blocks.append(ciphertext[i*128 : (i+1)*128])
    if number_of_blocks > 1 and remainder != 0:
        for i in range(number_of_blocks-1):
            list_of_blocks.append(ciphertext[i*128 : (i+1)*128])
        list_of_blocks.append(ciphertext[-remainder:])
    simon = SIMON(128,256,key)
    plaintext = ''
    for i in list_of_blocks:
        dk = simon.encrypt(nonce)
        if len(i) == 128:
            plain = dk ^ int(i,2)
            plain = bin(plain)[2:]
            while len(plain) < len(i):
                plain = '0' + plain
            plaintext += plain
        else:
            plain = int(bin(dk)[2:len(i)+2],2) ^ int(i,2)
            #plain = int(i,2) ^ int(bin(dk)[2 : len(i)+2],2)
            plain = bin(plain)[2:]
            while len(plain) < len(i):
                plain = '0' + plain
            plaintext += plain
        nonce += 1
    return plaintext

# with open("recording.m4a",'rb') as file:
#     data = file.read()
#     message = bin(int(data.hex(),16))[2:]
#     cipher = countermode_encrypt(message,0,0)
#     plain = countermode_decrypt(cipher,0,0)


def string_to_binary(a):
    sol = ''
    for i in a:
        k = ord(i)
        str = bin(k)[2:]
        while len(str) < 8:
            str = '0'+str
        sol += str
    return sol

def binary_to_string(binarystring):
    sol = ''
    i = 0
    while i < len(binarystring):
        a = binarystring[i:i+8]
        b = int(a,2)
        c = chr(b)
        sol += c
        i += 8
    return sol









