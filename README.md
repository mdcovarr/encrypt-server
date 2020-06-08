# encrypt-server
Sever used to send and receive requests for encrypting audio

# Requirements
### 1.Software requirements, python version 3 or greater.
```
python >= 3
```

### 2. Virtual Environment (Optional)
Setting up a virtual enviorment is a good idea in case we need to install
packages that are specific for the application
```
cd encrypt-server
virtualenv --system-site-packages -p python3 ./venv
source ./venv/bin/activate
```

To exit out of virtual enviornment run the following command:
```
deactivate
```

### 3. Install Requirements.txt
You will also need to install the packages in requirements.txt
```
pip install -r requirements.txt
```

# Repo Structure
```
.
├── Makefile
├── README.md
├── __init__.py
├── __main__.py
├── client
│   ├── __init__.py
│   └── client.py
├── encryptlib
│   ├── HashHeader.py
│   ├── SimonCTR.py
│   ├── __init__.py
│   ├── dh.py
│   ├── diffie_ephemeral_to_k1_k2.py
│   ├── ecdh.py
│   ├── file_header.py
│   ├── json_message.py
│   ├── print_helper.py
│   ├── recording.encrypted
│   └── recording.m4a
├── keylib
│   ├── __init__.py
│   ├── generate_keys.py
│   ├── key.pem
│   ├── keys.py
│   └── pubkey.pem
├── requirements.txt
└── server
    ├── __init__.py
    ├── client_thread.py
    └── server.py

4 directories, 26 files
```

# Documentation
Here is a small description of the different directories that are included in this
software package


## encrypt-server/keylib
Library where key and key parameters are kept


## encryptlib
Location of where encryption methods and ciphers


# Run Software
## Run Server (Listener)
In order to run the listener run the following command where 8080 is the PORT
we are listening on
```
python __main__.py 127.0.0.1 8080 --listener -k KEY.pem -p OTHER_KEY.pem
```
Where OTHER_KEY.pem is the private key of the listening client.
The **encrypt-server/server** directory handles the setting up of the server (Listener)

## Run Client (Talker)
In order to run the talker run the following command where 8080 is the PORT
that the listener is listening on, and the port we want to connect to. Meaning
the port we want to send data to the listener on
```
python __main__.py 127.0.0.1 8080 --talker -k KEY.pem -p OTHER_KEY.pem -f AUDIOFILE
```
Where OTHER_KEY.pem is the private key of the listening server. And AUDIOFILE is the
audio file we are interested in encrypting and sending to the server.
The **encrypt-server/client** directory handles the setting up of the client connection (Talker)

# Software Help
Run the following command to get a help menu output of valid parameters
```
usage: __main__.py [-h] [-t] [-l] [-k KEYFILE] [-p PUBFILE] [-f AUDIOFILE] [--verbose] IP PORT

Server Accepting and Sending Encrypt/Decrypt Request

positional arguments:
  IP                    IP Address to use for client to connect to, or server to listen on
  PORT                  Port for server to listen on

optional arguments:
  -h, --help            show this help message and exit
  -t, --talker          Flag used to specify the server is will send request to encrpyt data
  -l, --listener        Flag used to specify the server is will send request to encrpyt data
  -k KEYFILE, --keyfile KEYFILE
                        location of the private keyfile
  -p PUBFILE, --pubfile PUBFILE
                        location of the public keyfile of Bob
  -f AUDIOFILE, --file AUDIOFILE
                        location of audio file to encrypt
  --verbose, -v
```

## Appendix
```
Code was developed by the ShelterInPlaceHackers for project in couse CSE234: Cryptography

Team Members

============

Jason Huang
Jamie Deng
Michael Covarrubias
```