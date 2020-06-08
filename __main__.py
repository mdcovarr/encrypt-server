#!/usr/bin/env python3
"""
    Script to handle server / client socket implementation for CSE 234 Project
"""
import argparse
import logging, coloredlogs
import sys
from subprocess import check_call
from Crypto.PublicKey import RSA
from server.server import Server
from client.client import Client

PRI_KEY_PATH = 'keylib/key.pem'
LOG_FILE = 'logging.log'

def handle_arguments():
    """
    Function used to set and handle arguments
    """
    parser = argparse.ArgumentParser(description='Server Accepting and Sending Encrypt/Decrypt Request')

    parser.add_argument('IP', help='IP Address to use for client to connect to, or server to listen on')

    parser.add_argument('PORT', type=int,
                        help='Port for server to listen on')

    parser.add_argument('-t', '--talker', action='store_true', default=False, dest='talker',
                        help='Flag used to specify the server is will send request to encrpyt data')

    parser.add_argument('-l', '--listener', action='store_true', default=False, dest='listener',
                        help='Flag used to specify the server is will send request to encrpyt data')

    parser.add_argument('-k', '--keyfile', dest='keyfile', help='location of the private keyfile')

    parser.add_argument('-p', '--pubfile', dest='pubfile', help='location of the public keyfile of Bob')

    parser.add_argument('-f', '--file', dest='audiofile', help='location of audio file to encrypt')

    parser.add_argument('--verbose', '-v', dest='verbose', action='count')

    return parser.parse_args()

def handle_logger():
    """
    Function used to set up logging file
    """
    command = 'rm -f {0}'.format(LOG_FILE)

    try:
        check_call(command, shell=True)
    except subprocess.CalledProcessError as e:
        print('Error deleting old log file')
        exit(1)

    coloredlogs.install(level='DEBUG', fmt='%(asctime)s [%(process)d] %(levelname)s %(message)s')
    logging.basicConfig(stream=sys.stdout,
            level=logging.DEBUG)

def main():
    """
        Main Entrance of the Server
    """
    args  = handle_arguments()

    handle_logger()

    if (args.listener and args.talker):
        print('You can either be a listener or talker, not both!')
        exit(1)

    if (not args.listener and not args.talker):
        """
        Default to being a 'listener' If user does not specify
        """
        args.listener = True

    """
        Need to load RSA private and public keys
    """
    keyfile_path = PRI_KEY_PATH

    if (args.keyfile):
        keyfile_path = args.keyfile

    f = open(keyfile_path, 'r')
    key = RSA.import_key(f.read())
    f.close()

    f = open(args.pubfile, 'r')
    tempkey = RSA.import_key(f.read())
    pubkey = tempkey.publickey()

    if args.listener:
        """
            We are the server and we are open to accepting requests
        """
        server = Server(args.IP, args.PORT, pubkey, key)
        server.init()
        server.run()

    if (args.talker):
        """
            We are a client and we want to send a request
        """
        client = Client(args.IP, args.PORT, pubkey, key, args.audiofile)
        client.init()
        client.run()

if __name__ == '__main__':
    main()
