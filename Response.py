import struct

from Crypto.Random import get_random_bytes
from UtilizationRequestResponse import *
from Utilization import *

REGISTRATION_SUCCEED = 1600
REGISTRATION_FAILED = 1601
SEND_SYMMETRIC_KEY = 1603
SYMMETRIC_KEY_RECEIVED = 1604
MESSAGE_RECEIVED = 1605
GENERAL_RESPONSE_ERROR = 1609


class Response:
    def __init__(self, version, response_code, payload):
        self.version = version
        self.response_code = response_code
        self.payload = payload

    def pack(self):
        packed_version = struct.pack('B', self.version)
        packed_response_code = struct.pack('H', self.response_code)
        if self.response_code == REGISTRATION_SUCCEED:
            packed_client_id = bytes.fromhex(self.payload['client_id'])
            packed_payload = packed_client_id
            packed_payload_size = struct.pack('I', len(packed_payload))
        elif self.response_code == REGISTRATION_FAILED:
            packed_payload = get_random_bytes(16)
            packed_payload_size = struct.pack('I', 0)
        elif self.response_code == SEND_SYMMETRIC_KEY:
            '''
            Sending Encrypted Symmetric Key
            Response Structure:
                Client ID (16 Bytes) - client unique ID
                Encrypted Key - encrypted AES key for the client:
                    Encrypted_Key_IV (16 Bytes)
                    Nonce (8 Bytes) - Encrypted Nonce (16 Bytes)
                    AES Key (32 Bytes) - Padded (48 Bytes)
                Ticket - encrypted ticket for the message servers:
                    Version (1 Bytes) - server version
                    Client_ID (16 Bytes) - client unique ID
                    Server_ID (16 Bytes) - server unique ID
                    Creation Time (8 Bytes) - timestamp; creation time of the ticket
                    Ticket IV (16 Bytes)
                    AES Key (32 Bytes) - Padded (48 Bytes)
                    Expirations Time (8 Bytes) - Encrypted Time (32 Bytes)
            '''
            packed_client_id = bytes.fromhex(self.payload['client_id'])
            packed_encrypted_key = pack_encrypted_key(self.payload['encrypted_key'])
            packed_ticket = pack_ticket(self.payload['ticket'])
            packed_payload = packed_client_id + packed_encrypted_key + packed_ticket
            packed_payload_size = struct.pack('I', len(packed_payload))
        elif self.response_code == GENERAL_RESPONSE_ERROR:
            # Fictive Payload
            packed_payload = get_random_bytes(16)
            packed_payload_size = struct.pack('I', 0)
        elif self.response_code == SYMMETRIC_KEY_RECEIVED:
            # Fictive Payload
            packed_payload = get_random_bytes(16)
            packed_payload_size = struct.pack('I', 0)
        else:
            raise ValueError(f"Invalid request code: {self.response_code}")
        return packed_version + packed_response_code + packed_payload_size + packed_payload

    @classmethod
    def unpack(cls, packed_response):
        version = struct.unpack('B', packed_response[:1])[0]
        response_code = struct.unpack('H', packed_response[1:3])[0]
        if response_code == REGISTRATION_SUCCEED:
            payload_size = packed_response[3:7]
            client_id = packed_response[7:23].hex()
            payload = {'client_id': client_id}
        elif response_code == REGISTRATION_FAILED:
            payload = None
            payload_size = 0
        elif response_code == SEND_SYMMETRIC_KEY:
            payload_size = struct.unpack('I', packed_response[3:7])
            client_id = packed_response[7:23].hex()
            packed_encrypted_key = packed_response[23:103]
            packed_ticket = packed_response[103:240]
            encrypted_key = unpack_encrypted_key(packed_encrypted_key)
            ticket = unpack_ticket(packed_ticket)
            payload = {'client_id': client_id, 'encrypted_key': encrypted_key, 'ticket': ticket}
        elif response_code == GENERAL_RESPONSE_ERROR:
            payload = None
            payload_size = 0
        elif response_code == SYMMETRIC_KEY_RECEIVED:
            payload = None
            payload_size = 0
        else:
            raise ValueError(f"Invalid request code: {response_code}")
        return cls(version, response_code, payload)
