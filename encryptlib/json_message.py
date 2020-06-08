"""
    Object to handle json message Request and Response
"""
import json
import datetime
import encryptlib.SimonCTR as ctr

WHO_SENT = "ShelterInPlaceHackers"

class JsonMessage(object):
    def __init__(self):
        """
        Default constructor for JsonMessage class object
        """
        self.dhke_data = {
            "payload": {
                "agreement_data": {
                    "hash_sess_key": "",
                    "diffie_pub_k": ""
                },
                "signature": ""
            },
            "sess_key": {
                "key": "", # 256 bits
                "nonce": "" # ToD
            }
       }

        """
        Alice -> Bob

        dhke = {
            "payload": "<encrypted_request_payload>",
            "sess_key"" "<encrypted_with_bobs_pub_key>"
        }
        """

    def set_json_payload(self):
        """
        Function used to handle creating the json message
        response or request
        """
        # Currently not passing parameters, but might need to change
        self.set_agreement_data()
        self.set_signature()
        self.set_sess_key()

    def encrypt_payload(self):
        """
        Function to encrypt the message payload
        """
        payload_str = json.dumps(self.dhke_data["payload"])
        payload_binary_str = ctr.string_to_binary(payload_str)
        binary_str_encrypted = ctr.countermode_encrypt(payload_binary_str, 0, 0)
        self.dhke_data["payload"] = binary_str_encrypted

    def decrypt_payload(self):
        """
        Function to decrypt payload message
        """
        payload_str = json.dumps(self.dhke_data["payload"])
        binary_str_decrypted = ctr.countermode_decrypt(self.dhke_data["payload"], 0, 0)
        self.dhke_data["payload"] = ctr.binary_to_string(binary_str_decrypted)

    def set_agreement_data(self):
        """
        Function used to handle setting agreement data parameters
        """
        self.dhke_data["payload"]["agreement_data"]["diffie_pub_k"] = 696969
        self.dhke_data["payload"]["agreement_data"]["hash_sess_key"] = 696969

    def set_signature(self):
        """
        Function used to handle setting signature
        """
        self.dhke_data["payload"]["signature"] = 696969

    def set_sess_key(self):
        """
        Function used to set sess key parameters
        """
        self.dhke_data["sess_key"]["key"] = 696969
        self.dhke_data["sess_key"]["nonce"] = 696969

    def __str__(self):
        """
        Function to return json object as string
        """
        return json.dumps(self.dhke_data)
