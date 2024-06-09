"""
This module check legibility of Request and Response, in context of structure and content.
In terms of content, the values are in range and system can expect and handle without crashing
In terms of structure, the system can parse the structure.
later can be verified when creating object of the required (request or response)
"""

from validators import *

# request header size
REQUEST_HEADER = UUID_LEN + VERSION_LEN + CODE_LEN + PAYLOAD_SIZE_LEN
# registration request bytes length
REGISTRATION_REQUEST_PAYLOAD_LEN = NAME_MAX_LEN + PASSWORD_MAX_LEN
# send ticket request size
SEND_TICkET_REQUEST_LEN = AUTHENTICATOR_LEN + TICKET_LEN
# symmetric key request size
SYMMETRIC_REQUEST_LEN = UUID_LEN + NONCE_LEN
# send message request size
MESSAGE_REQUEST_MAX_LENGTH = MESSAGE_HEADER_LEN + MESSAGE_MAX_SIZE

# response header length
RESPONSE_HEADER_LEN = VERSION_LEN + CODE_LEN + PAYLOAD_SIZE_LEN
# length of successful registration response
SUCCESSFUL_REGISTRATION_RESPONSE_LEN = UUID_LEN
# length of failure registration response
FAILED_REGISTRATION_RESPONSE_LEN = 0
# length of symmetric key response key
SEND_SYMMETRIC_KEY_RESPONSE_LEN = UUID_LEN + ENCRYPTED_KEY_BLOCK_LEN + TICKET_LEN
# length of general error response
GENERAL_RESPONSE_ERROR_LEN = 0
# length of message received response
MESSAGE_RECEIVED_RESPONSE_LEN = 0
# length of symmetric key received successfully response
SYMMETRIC_KEY_RECEIVED_RESPONSE_LEN = 0


class RequestValidity:
    """ Check request validity structure and content"""
    @staticmethod
    def is_valid_request(uuid, version, code, payload):
        # check request values legibility
        return (is_valid_uuid(uuid)             # validity of uuid
                and is_valid_version(version)   # validity of version
                and is_valid_code(code)         # validity of code
                and RequestValidity.is_valid_payload(payload, code))    # validity of payload

    @staticmethod
    def is_valid_packed_request_header(request):
        # check packed request header
        if not isinstance(request, bytes) or len(request) < REQUEST_HEADER:
            return False
        return True

    @staticmethod
    def is_valid_payload(payload, code):
        # check validity of payload
        # dictionary payload
        if isinstance(payload, dict) and (code in request_payload.keys()):
            # execute proper function to validate payload, which stored in dictionary called 'request_payload'
            # dictionary called 'request_payload'. see below
            return request_payload[code]['validity_function'](payload)
        # packed payload
        elif isinstance(payload, bytes):
            # execute proper function to validate payload, which stored in dictionary called 'request_payload'
            # dictionary called 'request_payload'. see below
            return request_payload[code]['packed_validity'](payload)
        else:
            return False

    @staticmethod
    def is_valid_registration_request(payload):
        # check registration request content validity
        keys = request_payload[REGISTRATION_REQUEST_CODE]['keys']
        # check if keys in payload and the defined keys for request are compatible
        if isinstance(payload, dict) and keys == list(payload.keys()):
            # check each of the fields - already check if they are exist in payload
            return is_valid_name(payload['name']) and is_valid_password(payload['password'])
        return False

    @staticmethod
    def is_valid_packed_registration_request(payload, payload_size):
        # check registration request structure
        if isinstance(payload, bytes):
            return payload_size == len(payload) == REGISTRATION_REQUEST_PAYLOAD_LEN

    @staticmethod
    def is_valid_symmetric_key_request(payload):
        # check symmetric key request content validity
        keys = request_payload[SYMMETRIC_REQUEST_CODE]['keys']
        # check if keys in payload and the defined keys for request are compatible
        if isinstance(payload, dict) and keys == list(payload.keys()):
            # check each of the fields - already check if they are exist in payload
            return (is_valid_uuid(payload['server_uuid'])
                    and is_valid_nonce(payload['nonce']))
        return False

    @staticmethod
    def is_valid_packed_symmetric_key_request(payload, payload_size):
        # check structure of symmetric key request
        if isinstance(payload, bytes):
            return payload_size == len(payload) == SYMMETRIC_REQUEST_LEN

    @staticmethod
    def is_valid_send_ticket_request(payload):
        # check send ticket request content
        keys = request_payload[SEND_TICKET_REQUEST_CODE]['keys']
        # check if keys in payload and the defined keys for request are compatible
        if isinstance(payload, dict) and keys == list(payload.keys()):
            # check each of the fields - already check if they are exist in payload
            return (RequestValidity.is_valid_authenticator(payload['authenticator'])
                    and RequestValidity.is_valid_ticket(payload['ticket']))
        return False

    @staticmethod
    def is_valid_packed_send_ticket_request(payload, payload_size):
        # check structure of send ticket request
        if isinstance(payload, bytes):
            return payload_size == len(payload) == SEND_TICkET_REQUEST_LEN
        return False

    @staticmethod
    def is_valid_authenticator(authenticator):
        # check content or structure of authenticator
        if (isinstance(authenticator, dict)
                and list(authenticator.keys()) == utilize_request_payload['authenticator']['keys']):
            # check each of the fields - already check if they are exist in payload
            return utilize_request_payload['authenticator']['validity_function'](authenticator)
        elif isinstance(authenticator, bytes):
            # check structure length
            return utilize_request_payload['authenticator']['packed_validity'](authenticator)
        return False

    @staticmethod
    def is_valid_ticket(ticket):
        # check ticket content or structure depend on the input
        if isinstance(ticket, dict) and list(ticket.keys()) == utilize_request_payload['ticket']['keys']:
            # check each of the fields - already check if they are exist in payload
            return utilize_request_payload['ticket']['validity_function'](ticket)
        elif isinstance(ticket, bytes):
            # check structure length
            return utilize_request_payload['ticket']['packed_validity'](ticket)
        return False

    @staticmethod
    def is_valid_unpacked_authenticator(authenticator):
        # check authenticator content validity
        return (is_valid_iv(authenticator['authenticator_iv'])
                and is_valid_encrypted_version(authenticator['version'])
                and is_valid_encrypted_uuid(authenticator['client_uuid'])
                and is_valid_encrypted_uuid(authenticator['server_uuid'])
                and is_valid_encrypted_time(authenticator['creation_time']))

    @staticmethod
    def is_valid_packed_authenticator(authenticator):
        # check the structure of authenticator
        return len(authenticator) == AUTHENTICATOR_LEN

    @staticmethod
    def is_valid_unpacked_ticket(ticket):
        # check content of ticket values
        return (is_valid_version(ticket['version'])
                and is_valid_uuid(ticket['client_uuid'])
                and is_valid_uuid(ticket['server_uuid'])
                and is_valid_time(ticket['creation_time'])
                and is_valid_iv(ticket['ticket_iv'])
                and is_valid_encrypted_key(ticket['aes_key'])
                and is_valid_encrypted_time(ticket['expiration_time']))

    @staticmethod
    def is_valid_packed_ticket(ticket):
        # check ticket structure
        return isinstance(ticket, bytes) and len(ticket) == TICKET_LEN

    @staticmethod
    def is_valid_message_request(message):
        # check message request content
        return (isinstance(message, dict)
                and list(message.keys()) == request_payload[SEND_MESSAGE_REQUEST_CODE]['keys']
                and is_valid_iv(message['message_iv']) and is_valid_message_size(message['message_size']))

    @staticmethod
    def is_valid_packed_message_request(message):
        # check message request structure
        return isinstance(message, bytes) and len(message) == MESSAGE_HEADER_LEN


# key is request code, values if function to verify content, another to verify structure, and the keys of payload
request_payload = {
    REGISTRATION_REQUEST_CODE: {
        'validity_function': RequestValidity.is_valid_registration_request,
        'keys': ['name', 'password'],
        'packed_validity': RequestValidity.is_valid_packed_registration_request,
    },
    SYMMETRIC_REQUEST_CODE: {
        'validity_function': RequestValidity.is_valid_symmetric_key_request,
        'keys': ['server_uuid', 'nonce'],
        'packed_validity': RequestValidity.is_valid_packed_symmetric_key_request,
    },
    SEND_TICKET_REQUEST_CODE: {
        'validity_function': RequestValidity.is_valid_send_ticket_request,
        'keys': ['authenticator', 'ticket'],
        'packed_validity': RequestValidity.is_valid_packed_send_ticket_request,
    },
    SEND_MESSAGE_REQUEST_CODE: {
        'validity_function': RequestValidity.is_valid_message_request,
        'keys': ['message_size', 'message_iv'],
        'packed_validity': RequestValidity.is_valid_packed_message_request,
    }
}

# payloads large components
utilize_request_payload = {
    'authenticator': {
        'validity_function': RequestValidity.is_valid_unpacked_authenticator,
        'keys': ['authenticator_iv', 'version', 'client_uuid', 'server_uuid', 'creation_time'],
        'packed_validity': RequestValidity.is_valid_packed_authenticator,
    },
    'ticket': {
        'validity_function': RequestValidity.is_valid_unpacked_ticket,
        'keys': ['version', 'client_uuid', 'server_uuid', 'creation_time', 'ticket_iv', 'aes_key', 'expiration_time'],
        'packed_validity': RequestValidity.is_valid_packed_ticket,
    }
}


class ResponseValidity:
    """ Check response validity structure and content"""
    @staticmethod
    def is_valid_response(version, code, payload):
        # check response values validity
        return (is_valid_version(version)
                and is_valid_code(code)
                and ResponseValidity.is_valid_payload(payload, code))

    @staticmethod
    def is_valid_packed_response_header(response):
        # check header structure
        return isinstance(response, bytes) and len(response) >= RESPONSE_HEADER_LEN

    @staticmethod
    def is_valid_payload(payload, code):
        # check valid payload structure or content depend on input
        if isinstance(payload, dict) and (code in response_payload.keys()):
            # check content
            # execute proper function to validate payload, which stored in
            # dictionary called 'response_payload'. see below
            verifier = response_payload[code]['validity_function']
            return verifier(payload)
        elif isinstance(payload, bytes):
            # check structure
            # execute proper function to validate payload, which stored in
            # dictionary called 'response_payload'. see below
            verifier = response_payload[code]['packed_validity']
            return verifier(payload)
        else:
            return False

    @staticmethod
    def is_valid_registration_succeed_response(payload):
        # check registration succeed response content
        return (isinstance(payload, dict)
                and response_payload[REGISTRATION_SUCCEED]['keys'] == list(payload.keys())
                and is_valid_uuid(payload['client_uuid']))

    @staticmethod
    def is_valid_packed_registration_succeed_response(payload):
        # check registration succeed response structure
        return (isinstance(payload, bytes)
               and (len(payload) == SUCCESSFUL_REGISTRATION_RESPONSE_LEN))

    @staticmethod
    def is_valid_registration_failure_response(payload):
        # check registration failure response content
        return (isinstance(payload, dict)
                and list(payload.keys()) == response_payload[REGISTRATION_FAILED]['keys'])

    @staticmethod
    def is_valid_packed_registration_failure_response(payload):
        # check registration failure response structure
        return (isinstance(payload, bytes)
                and len(payload) == FAILED_REGISTRATION_RESPONSE_LEN)

    @staticmethod
    def is_valid_send_symmetric_key_response(payload):
        # check send symmetric key response content
        return (isinstance(payload, dict)
                and response_payload[SEND_SYMMETRIC_KEY]['keys'] == list(payload.keys())
                and is_valid_uuid(payload['client_uuid'])
                and ResponseValidity.is_valid_encrypted_key(payload['encrypted_key'])
                and RequestValidity.is_valid_ticket(payload['ticket']))

    @staticmethod
    def is_valid_packed_send_symmetric_key_response(payload):
        # check send symmetric key response structure
        return isinstance(payload, bytes) and len(payload) == SEND_SYMMETRIC_KEY_RESPONSE_LEN

    @staticmethod
    def is_valid_encrypted_key(encrypted_key):
        # check encrypted key structure or content depend on input
        if isinstance(encrypted_key, dict):
            return ResponseValidity.is_valid_unpacked_encrypted_key(encrypted_key)
        elif isinstance(encrypted_key, bytes):
            return len(encrypted_key) == ENCRYPTED_KEY_BLOCK_LEN
        else:
            return False

    @staticmethod
    def is_valid_general_error_response(payload):
        # check response content
        return (isinstance(payload, dict)
                and list(payload.keys()) == response_payload[GENERAL_RESPONSE_ERROR]['keys'])

    @staticmethod
    def is_valid_packed_general_error_response(payload):
        # check response structure
        return (isinstance(payload, bytes)
                and len(payload) == GENERAL_RESPONSE_ERROR_LEN)

    @staticmethod
    def is_valid_message_received_response(payload):
        # check response content
        return (isinstance(payload, dict)
                and list(payload.keys()) == response_payload[MESSAGE_RECEIVED]['keys'])

    @staticmethod
    def is_valid_packed_message_received_response(payload):
        # check response structure
        return isinstance(payload, bytes) and len(payload) == MESSAGE_RECEIVED_RESPONSE_LEN

    @staticmethod
    def is_valid_symmetric_key_received_response(payload):
        # check response content
        return (isinstance(payload, dict)
                and list(payload.keys()) == response_payload[SYMMETRIC_KEY_RECEIVED]['keys'])

    @staticmethod
    def is_valid_packed_symmetric_key_received_response(payload):
        # check response structure
        return (isinstance(payload, bytes)
                and len(payload) == SYMMETRIC_KEY_RECEIVED_RESPONSE_LEN)

    @staticmethod
    def is_valid_unpacked_encrypted_key(payload):
        # check response content
        return (isinstance(payload, dict)
                and list(payload.keys()) == utilize_response_payload['encrypted_key']['keys']
                and is_valid_iv(payload['encrypted_key_iv'])
                and is_valid_encrypted_nonce(payload['nonce'])
                and is_valid_encrypted_key(payload['aes_key']))

    @staticmethod
    def is_valid_packed_encrypted_key(payload):
        # check response structure
        return isinstance(payload, bytes) and len(payload) == ENCRYPTED_KEY_BLOCK_LEN


# key is response code, values if function to verify content, another to verify structure, and the keys of payload
response_payload = {
    REGISTRATION_SUCCEED: {
        'validity_function': ResponseValidity.is_valid_registration_succeed_response,
        'keys': ['client_uuid'],
        'packed_validity': ResponseValidity.is_valid_packed_registration_succeed_response,
    },
    REGISTRATION_FAILED: {
        'validity_function': ResponseValidity.is_valid_registration_failure_response,
        'keys': [],
        'packed_validity': ResponseValidity.is_valid_packed_registration_failure_response,
    },
    SEND_SYMMETRIC_KEY: {
        'validity_function': ResponseValidity.is_valid_send_symmetric_key_response,
        'keys': ['client_uuid', 'encrypted_key', 'ticket'],
        'packed_validity': ResponseValidity.is_valid_packed_send_symmetric_key_response,
    },
    GENERAL_RESPONSE_ERROR: {
        'validity_function': ResponseValidity.is_valid_general_error_response,
        'keys': [],
        'packed_validity': ResponseValidity.is_valid_packed_general_error_response,
    },
    MESSAGE_RECEIVED: {
        'validity_function': ResponseValidity.is_valid_message_received_response,
        'keys': [],
        'packed_validity': ResponseValidity.is_valid_packed_message_received_response,
    },
    SYMMETRIC_KEY_RECEIVED: {
        'validity_function': ResponseValidity.is_valid_symmetric_key_received_response,
        'keys': [],
        'packed_validity': ResponseValidity.is_valid_packed_symmetric_key_received_response,
    }
}

# payloads large components
utilize_response_payload = {
    'encrypted_key': {
        'validity_function': ResponseValidity.is_valid_unpacked_encrypted_key,
        'keys': ['encrypted_key_iv', 'nonce', 'aes_key'],
        'packed_validity': ResponseValidity.is_valid_packed_encrypted_key,
    },
    'ticket': {
        'validity_function': RequestValidity.is_valid_unpacked_ticket,
        'keys': ['version', 'client_uuid', 'server_uuid', 'creation_time', 'ticket_iv', 'aes_key', 'expiration_time'],
        'packed_validity': RequestValidity.is_valid_packed_ticket,
    }
}
