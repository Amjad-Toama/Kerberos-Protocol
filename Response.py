from UtilizationRequestResponse import *

###########################################################################
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# ########################## Constants Section ########################## #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
###########################################################################

REGISTRATION_SUCCEED = 1600     # registration succeed response code
REGISTRATION_FAILED = 1601      # registration failed response code
SEND_SYMMETRIC_KEY = 1603       # send symmetric key response code
SYMMETRIC_KEY_RECEIVED = 1604   # symmetric key received response code
MESSAGE_RECEIVED = 1605         # message received response code
GENERAL_RESPONSE_ERROR = 1609   # general error response code


class Response:
    """
    Response class facilitate into converting response to bytes representation and vice versa.

    ################## Attributes ##################

    version     :   int
        protocol version.

    response_code:   int
        response code.

    payload     :   dictionary
        content of payload for specific response.

    #################### Methods ###################

    def pack()  :   return bytes
        pack the response instance into bytes representation.

    def unpack(cls, packed_response) : return response
        unpack the response from bytes to the structure of original response.
    """
    def __init__(self, version, response_code, payload):
        self.version = version
        self.response_code = response_code
        self.payload = payload

    def pack(self):
        """
        pack the response instance into bytes representation.
        :return: response as concatenated bytes
        """
        '''
        Response structure:
            version      : 1 bytes
            response_code: 2 bytes
            payload_size : 4 bytes
            payload isn't constant, see each condition
        '''
        # pack unsigned integer (1 bytes)
        packed_version = struct.pack('B', self.version)
        # pack unsigned integer (2 bytes)
        packed_response_code = struct.pack('H', self.response_code)
        if self.response_code == REGISTRATION_SUCCEED:
            '''
            registration succeed
                client_uuid: 16 bytes
            '''
            packed_client_uuid = bytes.fromhex(self.payload['client_uuid'])
            packed_payload = packed_client_uuid
            packed_payload_size = struct.pack('I', len(packed_payload))
        elif self.response_code == SEND_SYMMETRIC_KEY:
            '''
            sending encrypted symmetric key
            
            client ID    :   16 bytes
            encrypted key: 80 bytes (total)
                    iv     :   16 bytes
                    nonce  :   16 bytes
                    aes_key:   48 bytes
            ticket       :  137 bytes (total)
                    version                  : 1 bytes
                    client_uuid              : 16 bytes
                    server_uuid              : 16 bytes
                    creation_time            : 8 bytes
                    ticket_iv                : 16 bytes
                    encrypted_aes_key        : 48 bytes
                    encrypted_expiration_time: 32 bytes
            '''
            packed_client_uuid = bytes.fromhex(self.payload['client_uuid'])
            packed_encrypted_key = pack_encrypted_key(self.payload['encrypted_key'])
            packed_ticket = pack_ticket(self.payload['ticket'])
            packed_payload = packed_client_uuid + packed_encrypted_key + packed_ticket
            packed_payload_size = struct.pack('I', len(packed_payload))
        elif self.response_code == REGISTRATION_FAILED:
            '''
            registration failed - no payload -> size = 0
            '''
            packed_payload = b''
            packed_payload_size = struct.pack('I', 0)
        elif self.response_code == GENERAL_RESPONSE_ERROR:
            '''
            general error response - no payload -> size = 0
            '''
            packed_payload = b''
            packed_payload_size = struct.pack('I', 0)
        elif self.response_code == MESSAGE_RECEIVED:
            '''
            message received - no payload -> size = 0
            '''
            packed_payload = b''
            packed_payload_size = struct.pack('I', 0)
        elif self.response_code == SYMMETRIC_KEY_RECEIVED:
            '''
            symmetric key received - no payload -> size = 0
            '''
            packed_payload = b''
            packed_payload_size = struct.pack('I', 0)
        else:
            raise ValueError(f"Invalid response code: {self.response_code}")
        # concatenate response
        return packed_version + packed_response_code + packed_payload_size + packed_payload

    @classmethod
    def unpack(cls, packed_response):
        """
        unpack the response from bytes to the structure of original response
        :param packed_response: response in original structure
        :return:
        """
        '''
        response structure:
            version     : 1 bytes
            response_code: 2 bytes
            payload_size: 4 bytes
            payload isn't constant see each condition
        '''
        # unsigned integer (1 bytes)
        version = struct.unpack('B', packed_response[:1])[0]
        # unsigned integer (2 bytes)
        response_code = struct.unpack('H', packed_response[1:3])[0]
        # slicing start with the value 3
        if response_code == REGISTRATION_SUCCEED:
            '''
            registration succeed
                client_uuid: 16 bytes
            '''
            payload_size = packed_response[3:7]
            client_uuid = packed_response[7:23].hex()
            payload = {'client_uuid': client_uuid}
        elif response_code == SEND_SYMMETRIC_KEY:
            '''
            sending encrypted symmetric key

            client ID    :   16 bytes
            encrypted key: 80 bytes (total)
                    iv     :   16 bytes
                    nonce  :   16 bytes
                    aes_key:   48 bytes
            ticket       :  137 bytes (total)
                    version                  : 1 bytes
                    client_uuid              : 16 bytes
                    server_uuid              : 16 bytes
                    creation_time            : 8 bytes
                    ticket_iv                : 16 bytes
                    encrypted_aes_key        : 48 bytes
                    encrypted_expiration_time: 32 bytes
            '''
            # unsigned integer (4 bytes)
            payload_size = struct.unpack('I', packed_response[3:7])
            client_uuid = packed_response[7:23].hex()
            packed_encrypted_key = packed_response[23:103]
            packed_ticket = packed_response[103:240]
            encrypted_key = unpack_encrypted_key(packed_encrypted_key)
            ticket = unpack_ticket(packed_ticket)
            # create the payload
            payload = {'client_uuid': client_uuid, 'encrypted_key': encrypted_key, 'ticket': ticket}
        elif response_code == REGISTRATION_FAILED:
            '''
            registration failed - no payload -> size = 0
            '''
            payload = None
            payload_size = 0
        elif response_code == GENERAL_RESPONSE_ERROR:
            '''
            general error response - no payload -> size = 0
            '''
            payload = None
            payload_size = 0
        elif response_code == MESSAGE_RECEIVED:
            '''
            message received - no payload -> size = 0
            '''
            payload = None
            payload_size = 0
        elif response_code == SYMMETRIC_KEY_RECEIVED:
            '''
            symmetric key received - no payload -> size = 0
            '''
            payload = None
            payload_size = 0
        else:
            raise ValueError(f"Invalid response code: {response_code}")

        # return response instance (initialized)
        return cls(version, response_code, payload)
