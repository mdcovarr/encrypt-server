#!/usr/bin/env python3
"""
    Script to handle client connection as a server
"""
import threading
import json
import sys
import os
import math
import hashlib
import copy
import logging
from subprocess import check_call
from Crypto.Random import get_random_bytes
from encryptlib.json_message import JsonMessage
from encryptlib.print_helper import PrintHelper
from encryptlib.SimonCTR import countermode_decrypt, countermode_encrypt
from keylib.keys import g, p

BUFFER_SIZE = 32768
HEADER_SIZE = 9
OUTFILE = 'audio.m4a'

class ClientThread(threading.Thread):
    def __init__(self,clientsocket, client_address, public_key, private_key):
        """
        Default constructor or class handling client socket thread
        """
        threading.Thread.__init__(self)
        self.clientd = clientsocket
        self.public_key = public_key
        self.private_key = private_key
        self.audio_file = OUTFILE
        self.pprint = PrintHelper()


    def run(self):
        """
        Function to handle client socket thread execution
        """
        while True:
            data = self.clientd.recv(BUFFER_SIZE)
            logging.info('Received Request')
            bytes_recv = len(data)
            msg = data.decode()

            if self.is_valid_request(msg):
                # 1. Process Response
                is_valid = self.process_request()

                if not is_valid:
                    self.clientd.close()

                # 2. Build Response
                self.build_response()

                # 3. Send Response
                self.clientd.send(bytes(self.response, 'UTF-8'))

                # 4. generate agreed key
                self.generate_agreed_diffie_key()
                logging.info("Generated agreed DH key.")

                # 5. generate k1 and k2
                self.generate_k1_k2()
                logging.info("Generated k_1 and k_2")
            else:
                self.clientd.close()
                break

            """
                Need to wait for encrypted audio now
            """
            self.read_fileheader_message()

            self.read_audio_message()

            self.decrypt_audio()
            logging.info("Audio decrypted and written as '{0}'".format(OUTFILE))
            self.sample_audio()
            self.clientd.close()
            logging.info('Closing client connection...')
            break

    def sample_audio(self):
        """
        Function to sample audio after it has been decrypted
        """
        say_string = 'Audio content has been decrypted to file {0}.'.format(self.audio_file)
        command = 'say -v Alex \'{0}\''.format(say_string)
        check_call(command, shell=True)

        cont = input('Would you like to hear a sample? [y/n]: ')

        if ('y' in cont) or ('Y' in cont):
            check_call('say -v Alex \'Here is a sample\'', shell=True)

            command = 'afplay {0}'.format(self.audio_file)
            check_call(command, shell=True)


    def decrypt_audio(self):
        """
        Function to decrypt audio
        """
        data_int_in_binary = self.encrypted_audio

        """
            Checking to see if binary data is divisible by 8
        """
        decrypt_val = countermode_decrypt(data_int_in_binary, self.t, self.k1)
        decrypt_val = '1' + decrypt_val
        decrypt_hex = hex(int(decrypt_val, 2))[3:]
        decrypt_bytes = bytes.fromhex(decrypt_hex)

        f = open('audio.m4a', 'wb')

        f.write(decrypt_bytes)
        f.close()

    def read_audio_message(self):
        """
        Function to read the D packet with encrypted audio
        """
        curr_payload_read = 0
        read_amount = BUFFER_SIZE
        data = self.clientd.recv(read_amount)
        msg = data.decode()
        data_type = msg[0]
        data_length = int(msg[1:9])
        curr_payload_read = len(msg[9:])

        tag_left = data_length - curr_payload_read

        while curr_payload_read < data_length:
            if tag_left < BUFFER_SIZE:
                read_amount = tag_left
            else:
                read_amount = BUFFER_SIZE

            data = self.clientd.recv(read_amount)
            curr_msg = data.decode()
            curr_length = len(curr_msg)

            msg = '{0}{1}'.format(msg, curr_msg)

            curr_payload_read += curr_length
            tag_left = data_length - curr_payload_read

        self.encrypted_audio = msg[9:]

    def read_fileheader_message(self):
        """
        Function used to keep reading from socket in order to read the entire
        encrypted audio message
        """
        curr_payload_read = 0
        read_amount = 64
        data = self.clientd.recv(read_amount)
        msg = data.decode()
        data_type = msg[0]
        data_length = int(msg[1:9])
        curr_payload_read = len(msg[9:])

        tag_left = data_length - curr_payload_read

        while curr_payload_read < data_length:
            if tag_left < 64:
                read_amount = tag_left
            else:
                read_amount = 64

            data = self.clientd.recv(read_amount)
            curr_msg = data.decode()
            curr_length = len(curr_msg)

            msg = '{0}{1}'.format(msg, curr_msg)

            curr_payload_read += curr_length
            tag_left = data_length - curr_payload_read

        json_message = json.loads(msg[9:])
        self.fileheader_message = json_message


    def is_valid_request(self, request):
        """
        Function to validate request
        """
        if len(request) < 9:
            return False

        req_type = request[0]
        req_length = request[1:9]

        if req_type != '1':
            return False

        try:
            length = int(req_length)
        except ValueError:
            # sent us data that is NOT just digits 0-9
            return False

        # Attempt to get json object
        payload = request[9: length + 9]

        try:
            self.json_request = json.loads(payload)
        except json.JSONDecodeError:
            # invalid JSON object
            return False

        # self.pprint.received('\nRequest >>>\n----------\n{0}\n----------'.format(request))
        return True

    def generate_agreed_diffie_key(self):
        """
        Function used to generate the agreed upon diffie key
        """
        self.D_ab = pow(int(self.json_request["payload"]["agreement_data"]["diffie_pub_k"]), self.d_b, p)

    def generate_k1_k2(self):
        """
        Function used to create k1 and k2 keys
        """
        # D_ab int to bytes
        D_ab = copy.copy(self.D_ab)

        data_int_in_binary = bin(D_ab)[2:]
        remainder = len(data_int_in_binary) % 8

        if remainder != 0:
            pad = '0' * (8 - remainder)
            data_int_in_binary = '{0}{1}'.format(pad, data_int_in_binary)

        concat_bytes = '{0}{1}'.format('00000001', data_int_in_binary)
        length = int(len(concat_bytes) / 8)
        concat_int = int(concat_bytes, 2)
        concat_bytes = concat_int.to_bytes(length, byteorder='little')

        m = hashlib.sha3_256()
        m.update(concat_bytes)
        self.k1 = int(m.hexdigest(), 16)

        concat_bytes = '{0}{1}'.format('00000010', data_int_in_binary)
        length = int(len(concat_bytes) / 8)
        concat_int = int(concat_bytes, 2)
        concat_bytes = concat_int.to_bytes(length, byteorder='little')

        m = hashlib.sha3_256()
        m.update(concat_bytes)
        self.k2 = int(m.hexdigest(), 16)

        self.t = int(self.json_request["sess_key"]["ToD"])

    def build_response(self):
        """
        Function to handle sending a response to the client
        """
        self.json_response = JsonMessage()
        self.create_sess_key()
        self.hash_sess_key()
        self.encrypt_sess_key()
        self.generate_diffie_pub_key()
        logging.info("Generated DH public key.")
        self.sign_agreement_data()

        self.encrypt_agreement_data()
        logging.info("Signed and encrypted agreement data.")
        # Determine length of JSON payload
        length = len(self.json_response.__str__())
        length_str = '{:08d}'.format(length)

        # form entire request
        self.response = '{0}{1}{2}'.format('2', length_str, self.json_response.__str__())
        # self.pprint.sent('\nResponse <<<\n----------\n{0}\n----------'.format(self.response))

    def encrypt_agreement_data(self):
        """
        Function used to encrypt the agreement data using conter mode.
        """
        data_raw = json.dumps(self.json_response.dhke_data["payload"])
        data_bytes = bytes(data_raw,'UTF-8')
        data_int = int.from_bytes(data_bytes, byteorder='little')
        data_int_in_binary = bin(data_int)[2:]

        """
            Check to see if binary data is divisible by 8
        """
        remainder = len(data_int_in_binary) % 8

        if remainder != 0:
            pad = '0' * (8 - remainder)
            data_int_in_binary = '{0}{1}'.format(pad, data_int_in_binary)

        nonce = int(self.json_request["sess_key"]["ToD"])
        m1_c = countermode_encrypt(data_int_in_binary, nonce, self.sess_key["key"])
        m1_c_dec = int(m1_c, 2)
        m1_c_str = str(m1_c_dec)

        self.json_response.dhke_data["payload"] = m1_c_str

    def sign_agreement_data(self):
        """
        Function used to sign the payload messgae before encryption
        """
        # get raw data_agreement info
        data_raw = json.dumps(self.json_response.dhke_data["payload"]["agreement_data"])

        m = hashlib.sha3_256()
        m.update(bytes(data_raw, 'UTF-8'))

        hash_bytes = m.digest()
        hash_int = int.from_bytes(hash_bytes, byteorder='little')

        signature = str(pow(hash_int, self.private_key.d, self.private_key.n))
        self.json_response.dhke_data["payload"]["signature"] = signature

    def generate_diffie_pub_key(self):
        """
        Function used to generate the our public diffie hellman key based on g and p values
        """
        self.d_b = int.from_bytes(get_random_bytes(512), byteorder='little')

        diffie_pub_key = pow(g, self.d_b, p)
        diffie_pub_key_str = str(diffie_pub_key)

        self.json_response.dhke_data["payload"]["agreement_data"]["diffie_pub_k"] = diffie_pub_key_str

    def encrypt_sess_key(self):
        """
        Function used to encrypt the sess_key object by the receivers public key
        """
        sess_key = json.dumps(self.json_response.dhke_data["sess_key"])

        raw_bytes = sess_key.encode('utf-8')
        sess_key_int = int.from_bytes(raw_bytes, byteorder='little')

        sess_key_encrypted = pow(sess_key_int, self.public_key.e, self.public_key.n)

        self.json_response.dhke_data["sess_key"] = str(sess_key_encrypted)

    def hash_sess_key(self):
        """
        Function used to hash the sess key
        """
        m = hashlib.sha3_256()
        raw_sess_key = json.dumps(self.json_response.dhke_data["sess_key"])
        m.update(bytes(raw_sess_key, 'UTF-8'))

        byte_value = m.digest()
        hash_sess_str = str(int.from_bytes(byte_value, byteorder='little'))

        self.json_response.dhke_data["payload"]["agreement_data"]["hash_sess_key"] = hash_sess_str

    def process_request(self):
        """
        Function used to process the request get contents from payload
        """
        """
            Begin Processing request JSON object
        """
        self.decrypt_sess_key()
        self.decrypt_payload()
        is_valid_sign = self.verify_sign()

        if not is_valid_sign:
            return False

        is_valid_hash = self.verify_hash()

        if not is_valid_hash:
            return False

        return True

    def create_sess_key(self):
        """
        Function to create sess_key.key value
        """
        # 1. create a 256 bit session key
        key_int = int.from_bytes(get_random_bytes(32), byteorder='little')

        self.sess_key = {
            "key": key_int
        }

        key_str = str(key_int)

        sess_key = {
            "key": key_str
        }

        self.json_response.dhke_data["sess_key"] = sess_key

    def verify_hash(self):
        """
        Function to verify sess_key_hash
        """
        raw_sess_key = json.dumps(self.json_request["sess_key"])

        m = hashlib.sha3_256()
        m.update(bytes(raw_sess_key, 'utf-8'))
        byte_value = m.digest()
        hash_sess_str = str(int.from_bytes(byte_value, byteorder='little'))

        if hash_sess_str == self.json_request["payload"]["agreement_data"]["hash_sess_key"]:
            return True
        else:
            return False

    def verify_sign(self):
        """
        Function to verify signature of packet 1 from talker
        """
        signature_raw = self.json_request["payload"]["signature"]
        int_val = int(signature_raw)

        sign_val = pow(int_val, self.public_key.e, self.public_key.n)

        data_raw = json.dumps(self.json_request["payload"]["agreement_data"])
        m = hashlib.sha3_256()
        m.update(bytes(data_raw, 'utf-8'))

        hash_bytes = m.digest()
        hash_int = int.from_bytes(hash_bytes, byteorder='little')

        if sign_val == hash_int:
            return True
        else:
            return False

    def decrypt_payload(self):
        """
        Function used to decrypt payload of request
        """
        key = int(self.json_request["sess_key"]["key"])
        nonce = int(self.json_request["sess_key"]["ToD"])

        data_raw = self.json_request["payload"]
        data_int = int(data_raw)

        length = int(math.ceil(data_int.bit_length() / 8))
        data_int_in_binary = bin(data_int)[2:]

        """
            Check to see if binary data is divisible by 8
        """
        remainder = len(data_int_in_binary) % 8

        if remainder != 0:
            pad = '0' * (8 - remainder)
            data_int_in_binary = '{0}{1}'.format(pad, data_int_in_binary)

        m1_c = countermode_decrypt(data_int_in_binary, nonce, key)
        m1_c_dec = int(m1_c, 2)
        m1_c_str = str(m1_c_dec)

        length = int(math.ceil(m1_c_dec.bit_length() / 8))

        payload_str = m1_c_dec.to_bytes(length, byteorder='little')
        # TODO: passes but maybe we should add a try catch in case decode fails
        payload_str = payload_str.decode('utf-8')

        self.json_request["payload"] = json.loads(payload_str)

    def decrypt_sess_key(self):
        """
        Function used to decrypt the sess_key we received in request
        """
        data_raw = self.json_request["sess_key"]
        data_int = int(data_raw)

        sess_key_decrypted = pow(data_int, self.private_key.d, self.private_key.n)

        length = int(math.ceil(sess_key_decrypted.bit_length() / 8))

        sess_str = sess_key_decrypted.to_bytes(length, byteorder='little')
        sess_str = sess_str.decode('utf-8')

        self.json_request["sess_key"] = json.loads(sess_str)

    def is_valid_file_header(self, message):
        """
        Function to determine if File Header is valid
        """
        if len(message) < 9:
            return False

        header_type = message[0]
        length_str = message[1:9]

        if header_type != '3':
            return False

        try:
            length = int(length_str)
        except ValueError:
            return False

        # Attempt to get json object
        payload = message[9: length + 9]

        try:
            self.json_header = json.loads(payload)
        except json.JSONDecodeError:
            # invalid JSON object
            return False

        return True
