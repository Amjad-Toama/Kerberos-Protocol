from UtilizationRequestResponse import *

###########################################################################
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# ########################## Constants Section ########################## #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
###########################################################################

REGISTRATION_REQUEST_CODE = 1024        # Registration request code
SYMMETRIC_REQUEST_CODE = 1027           # Symmetric key request code
SEND_TICKET_REQUEST_CODE = 1028         # Sending Symmetric Key to message server
SEND_MESSAGE_REQUEST_CODE = 1029        # Sending Message to message server


class Request:
    """
    Request class facilitate into converting request to bytes representation and vice versa.

    ################## Attributes ##################

    client_id   :   hex
        client id of the request sender.

    version     :   int
        protocol version.

    request_code:   int
        request code.

    payload     :   dictionary
        content of payload for specific request.

    #################### Methods ###################

    def pack()  :   return bytes
        pack the request instance into bytes representation.

    def unpack(cls, packed_request) : return request
        unpack the request from bytes to the structure of original request.
    """
    def __init__(self, client_id, version, request_code, payload):
        self.client_id = client_id
        self.version = version
        self.request_code = request_code
        self.payload = payload

    def pack(self):
        """
        pack the request into bytes representation
        :return: request as concatenated bytes
        """
        # Pack the request components into bytes (request header).
        # from hex representation to bytes
        packed_client_id = bytes.fromhex(self.client_id)
        # unsigned integer (1 bytes)
        packed_version = struct.pack('B', self.version)
        # unsigned integer (2 bytes)
        packed_request_code = struct.pack('H', self.request_code)
        # pack the payload
        if self.request_code == REGISTRATION_REQUEST_CODE:
            '''
            registration request: 310 bytes (total)
                name    : 255 bytes
                password: 255 bytes
            '''
            # mask to name and password with 255 size
            format_string = f'255s'
            packed_name = struct.pack(format_string, self.payload['name'].encode('utf-8'))
            packed_password = struct.pack(format_string, self.payload['password'].encode('utf-8'))
            # payload size - unsigned integer (4 bytes)
            packed_payload_size = struct.pack('I', len(packed_name) + len(packed_password))
            # concatenate packed payload content
            packed_payload = packed_name + packed_password
        elif self.request_code == SYMMETRIC_REQUEST_CODE:
            '''
            symmetric request code
                server_id: 16 bytes
                nonce    : 8 bytes
            '''
            packed_server_id = bytes.fromhex(self.payload['server_id'])
            packed_nonce = self.payload['nonce']
            # unsigned integer (4 bytes)
            packed_payload_size = struct.pack('I', len(packed_server_id) + len(packed_nonce))
            # concatenate packed payload content
            packed_payload = packed_server_id + packed_nonce
        elif self.request_code == SEND_TICKET_REQUEST_CODE:
            '''
            authenticator: 128 bytes (total)
                authenticator_iv       : 16 bytes
                encrypted_version      : 16 bytes
                encrypted_client_id    : 32 bytes
                encrypted_server_id    : 32 bytes
                encrypted_creation_time: 32 bytes
            ticket: 137 bytes (total)
                version                  : 1 bytes
                client_id                : 16 bytes
                server_id                : 16 bytes
                creation_time            : 8 bytes
                ticket_iv                : 16 bytes
                encrypted_aes_key        : 48 bytes
                encrypted_expiration_time: 32 bytes
            '''
            packed_authenticator = pack_encrypted_authenticator(self.payload['authenticator'])
            packed_ticket = pack_ticket(self.payload['ticket'])
            # concatenate packed payload content
            packed_payload = packed_authenticator + packed_ticket
            # unsigned integer (4 bytes)
            packed_payload_size = struct.pack('I', len(packed_payload))
        elif self.request_code == SEND_MESSAGE_REQUEST_CODE:
            # concatenate packed payload content
            packed_payload = pack_message_header(self.payload)
            # unsigned integer (4 bytes)
            packed_payload_size = struct.pack('I', len(packed_payload))
        else:
            raise ValueError("Invalid request code.")
        # concatenate packed request content
        packed_request = packed_client_id + packed_version + packed_request_code + packed_payload_size + packed_payload
        return packed_request

    @classmethod
    def unpack(cls, packed_request):
        """
        unpack the request from bytes to the structure of original request
        :param packed_request: request as bytes
        :return: request in original structure
        """

        '''
        Request structure:
            client_id   : 16 bytes
            version     : 1 bytes
            request_code: 2 bytes
            payload_size: 4 bytes
            payload isn't constant, see each condition
        '''
        # unpack the header of packed request
        client_id = packed_request[:16].hex()
        # unsigned integer (1 bytes)
        version = struct.unpack('B', packed_request[16:17])[0]
        # unsigned integer (2 bytes)
        request_code = struct.unpack('H', packed_request[17:19])[0]
        # unsigned integer (4 bytes)
        payload_size = struct.unpack('I', packed_request[19:23])[0]
        # slicing start with the value 23
        if request_code == REGISTRATION_REQUEST_CODE:
            '''
            name    : 255 bytes
            password: 255 bytes
            '''
            name = packed_request[23:278].decode('utf-8').rstrip('\x00')
            password = packed_request[278:533].decode('utf-8').rstrip('\x00')
            payload = {'name': name, 'password': password}
        elif request_code == SYMMETRIC_REQUEST_CODE:
            '''
            server_id: 16 bytes
            nonce    : 8 bytes
            '''
            server_id = packed_request[23:39].hex()
            nonce = packed_request[39:47]
            payload = {'server_id': server_id, 'nonce': nonce}
        elif request_code == SEND_TICKET_REQUEST_CODE:
            '''
            authenticator: 128 bytes (total)
                authenticator_iv       : 16 bytes
                encrypted_version      : 16 bytes
                encrypted_client_id    : 32 bytes
                encrypted_server_id    : 32 bytes
                encrypted_creation_time: 32 bytes
            ticket: 137 bytes (total)
                version                  : 1 bytes
                client_id                : 16 bytes
                server_id                : 16 bytes
                creation_time            : 8 bytes
                ticket_iv                : 16 bytes
                encrypted_aes_key        : 48 bytes
                encrypted_expiration_time: 32 bytes
            '''
            # slice the elements of the packed request (payload)
            packed_authenticator = packed_request[23:151]
            packed_ticket = packed_request[151:288]
            # unpack the elements of the payload
            authenticator = unpack_encrypted_authenticator(packed_authenticator)
            ticket = unpack_ticket(packed_ticket)
            payload = {'authenticator': authenticator, 'ticket': ticket}
        elif request_code == SEND_MESSAGE_REQUEST_CODE:
            '''
            message_header:
                message_size: 4 bytes
                message_iv  : 16 bytes
            '''
            payload = unpack_message_header(packed_request[23:])
        else:
            raise ValueError("Invalid request code.")
        payload_size += 1
        # return request instance (initialized)
        return cls(client_id, version, request_code, payload)
