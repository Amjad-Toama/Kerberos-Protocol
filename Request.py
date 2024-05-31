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
    def __init__(self, client_id, version, request_code, payload):
        self.client_id = client_id
        self.version = version
        self.request_code = request_code
        self.payload = payload

    def pack(self):
        # Pack the request components into bytes.
        packed_client_id = bytes.fromhex(self.client_id)
        packed_version = struct.pack('B', self.version)
        packed_request_code = struct.pack('H', self.request_code)
        if self.request_code == REGISTRATION_REQUEST_CODE:
            format_string = f'255s'
            packed_name = struct.pack(format_string, self.payload['name'].encode('utf-8'))
            packed_password = struct.pack(format_string, self.payload['password'].encode('utf-8'))
            packed_payload_size = struct.pack('I', len(packed_name) + len(packed_password))
            packed_payload = packed_name + packed_password
        elif self.request_code == SYMMETRIC_REQUEST_CODE:
            packed_server_id = bytes.fromhex(self.payload['server_id'])
            packed_nonce = struct.pack('Q', self.payload['nonce'])
            packed_payload_size = struct.pack('I', len(packed_server_id) + len(packed_nonce))
            packed_payload = packed_server_id + packed_nonce
        elif self.request_code == SEND_TICKET_REQUEST_CODE:
            packed_authenticator = pack_authenticator(self.payload['authenticator'])
            packed_ticket = pack_ticket(self.payload['ticket'])
            packed_payload = packed_authenticator + packed_ticket
            packed_payload_size = struct.pack('I', len(packed_payload))
        elif self.request_code == SEND_MESSAGE_REQUEST_CODE:
            packed_message = pack_message(self.payload)
            packed_payload = packed_message
            packed_payload_size = struct.pack('I', len(packed_payload))
        else:
            raise ValueError("Invalid request code.")
        packed_request = packed_client_id + packed_version + packed_request_code + packed_payload_size + packed_payload
        return packed_request

    @classmethod
    def unpack(cls, packed_request):
        client_id = packed_request[:16].hex()
        version = struct.unpack('B', packed_request[16:17])[0]
        request_code = struct.unpack('H', packed_request[17:19])[0]
        payload_size = struct.unpack('I', packed_request[19:23])[0]
        if request_code == REGISTRATION_REQUEST_CODE:
            name = packed_request[23:278].decode('utf-8').rstrip('\x00')
            password = packed_request[278:533].decode('utf-8').rstrip('\x00')
            payload = {'name': name, 'password': password}
        elif request_code == SYMMETRIC_REQUEST_CODE:
            server_id = packed_request[23:39].hex()
            nonce = struct.unpack('Q', packed_request[39:47])[0]
            payload = {'server_id': server_id, 'nonce': nonce}
        elif request_code == SEND_TICKET_REQUEST_CODE:
            packed_authenticator = packed_request[23:80]
            packed_ticket = packed_request[80:177]
            authenticator = unpack_authenticator(packed_authenticator)
            ticket = unpack_ticket(packed_ticket)
            payload = {'authenticator': authenticator, 'ticket': ticket}
        elif request_code == SEND_MESSAGE_REQUEST_CODE:
            message = unpack_message(packed_request[23:])
            payload = message
        else:
            raise ValueError("Invalid request code.")

        return cls(client_id, version, request_code, payload)
