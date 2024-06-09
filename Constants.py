"""
Contain constant that used in the whole system.
"""

VERSION = 24                           # server and client version
BUFFER_SIZE = 4096                     # The maximum size of buffer, to transfer or receive.
BITS_PER_BYTE = 8                      # bits per byte
# *************************** Message Length **************************** #

MESSAGE_MAX_BYTES_SIZE = 4      # maximum size of encrypted message in bytes
MESSAGE_MIN_SIZE = 0            # minumum size of encrypted message
# calculate message max size in characters
MESSAGE_MAX_SIZE = (2 ** (MESSAGE_MAX_BYTES_SIZE * BITS_PER_BYTE)) - 1

###########################################################################
# ########################## Responses Section ########################## #
###########################################################################

REGISTRATION_SUCCEED = 1600     # registration succeed response code
REGISTRATION_FAILED = 1601      # registration failed response code
SEND_SYMMETRIC_KEY = 1603       # send symmetric key response code
SYMMETRIC_KEY_RECEIVED = 1604   # symmetric key received response code
MESSAGE_RECEIVED = 1605         # message received response code
GENERAL_RESPONSE_ERROR = 1609   # general error response code

###########################################################################
# ########################## Requests Section ########################### #
###########################################################################

REGISTRATION_REQUEST_CODE = 1024        # Registration request code
SYMMETRIC_REQUEST_CODE = 1027           # Symmetric key request code
SEND_TICKET_REQUEST_CODE = 1028         # Sending Symmetric Key to message server
SEND_MESSAGE_REQUEST_CODE = 1029        # Sending Message to message server

###########################################################################
# ########################## Validators Section ######################### #
###########################################################################

ENDPOINT_COMPONENT = 2              # Endpoint consist of port and ip address
DEFAULT_AUTHENTICATION_PORT = 1256  # Authentication Server default port
PORT_MAX_VALUE = 65535              # Ports range
NAME_MAX_LEN = 255                  # Name length
PASSWORD_MAX_LEN = 255              # Password length
PASSWORD_SHA256_LEN = 32            # SHA256 of password length
UUID_LEN = 16                       # uuid length of client and server
IV_LEN = 16                         # iv length
NONCE_LEN = 8                       # nonce length in bytes
KEY_LEN = 32                        # symmetric key max length
VERSION_LEN = 1                     # version length in bytes
CODE_LEN = 2                        # code bytes length
PAYLOAD_SIZE_LEN = 4                # payload size bytes length
TIME_LEN = 8                        # datetime bytes length

ENCRYPTED_VERSION_LEN = 16      # encrypted version bytes length
ENCRYPTED_UUID_LEN = 32         # encrypted uuid bytes length
ENCRYPTED_TIME_LEN = 32         # encrypted time bytes length
ENCRYPTED_KEY_LEN = 48          # encrypted key bytes length
ENCRYPTED_NONCE_LEN = 16        # encrypted nonce length

# authenticator size
AUTHENTICATOR_LEN = (IV_LEN + ENCRYPTED_VERSION_LEN + (2 * ENCRYPTED_UUID_LEN)
                        + ENCRYPTED_TIME_LEN)
# ticket size
TICKET_LEN = (VERSION_LEN + (2 * UUID_LEN) + TIME_LEN + IV_LEN
                 + ENCRYPTED_KEY_LEN + ENCRYPTED_TIME_LEN)
# message header size
MESSAGE_HEADER_LEN = IV_LEN + MESSAGE_MAX_BYTES_SIZE
# encrypted key block
ENCRYPTED_KEY_BLOCK_LEN = IV_LEN + ENCRYPTED_NONCE_LEN + ENCRYPTED_KEY_LEN


# ######################## Values Range section ####################### #

VERSION_MAX_VALUE = 2 ** (VERSION_LEN * BITS_PER_BYTE) - 1
VERSION_MIN_VALUE = 0
CODE_MAX_VALUE = 2 ** (CODE_LEN * BITS_PER_BYTE) - 1
CODE_MIN_VALUE = 0
NONCE_MAX_VALUE = 2 ** (NONCE_LEN * BITS_PER_BYTE) - 1
NONCE_MIN_VALUE = 0
