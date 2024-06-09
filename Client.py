import os.path
from Crypto.Random import get_random_bytes
from fileValidity import *
from Request import *
from Response import *
from Utilization import *

SERVERS_FILENAME = "srv.info"
CLIENT_FILENAME = "me.info"
SERVER_ERROR_MESSAGE = "server responded with an error"

SESSION_EXPIRED = 600
SESSION_ENDED_INITIATIVE = 601
MAX_TRIES = 3

MESSAGE_SERVER_UUID = "64f3f63985f04beb81a0e43321880182"
AS_SOCKET_CRASH_ERROR_MESSAGE = "Authentication Server connection crash. Try again Later!"
MSG_SOCKET_CRASH_ERROR_MESSAGE = "Message Server connection crash. Try again Later!"


class Client:
    """
    Request class facilitate into converting request to bytes representation and vice versa.

    ################## Attributes ##################

    name                :   string
        client name

    uuid                :   hex
        uuid received from authentication server in registration stage

    key                 :   hex
        symmetric key shared with message key, that generated from authenticator server.

    message_server_uuid :   Server
        message server details.
    """

    def __init__(self, name, uuid, key=None):
        self.name = name
        self.uuid = uuid
        self.key = key
        self.message_server_uuid = MESSAGE_SERVER_UUID

    def set_key(self, password):
        """
        Set the client symmetric key with Authentication server that extracted from user password
        :param password: user password
        :return:
        """
        self.key = get_password_hash(password)

    @classmethod
    def load_client_info(cls, filename):
        """
        Load the client info if exist from info_filename, otherwise return None
        file structure:
            name
            user_uuid
        :param filename: client info file
        :return: Client initialized instance if succeeded, otherwise return None
        """
        # Open the file and read its contents
        if filename == CLIENT_FILENAME and os.path.exists(filename):
            if is_valid_me_info(filename):
                with open(filename, "r") as file:
                    lines = file.readlines()
                    name = lines[0].strip()
                    uuid = lines[1].strip()
                    # Return client instance
                    return cls(name, uuid)
            else:
                print(f"Error occur in {filename} file.")
                exit()
        return None

    def store_client_info(self):
        """
        Create info file CLIENT_FILENAME with the structure:
            client_name
            client_uuid
        :return:
        """
        try:
            with open(CLIENT_FILENAME, "w") as file:
                # Write the info to the file
                file.write(self.name + "\n")
                file.write(self.uuid + "\n")
        except ValueError as e:
            print("unexpected error occur", e)
            exit()
        file.close()

    def msg_srv_connection_request(self, aes_key, ticket):
        """
        Create ticket request to Message Server including Authenticator, and attach the ticket
        :param aes_key: symmetric key shared with Message Server, to encrypt values
        :param ticket: Authenticator Server ticket to message server
        :return: packet ticket request (bytes representation)
        """
        # Create authenticator
        authenticator = self.get_encrypted_authenticator(aes_key)
        # Create the payload
        payload = {'authenticator': authenticator, 'ticket': ticket}
        # Prepare the request to send.
        request = Request(self.uuid, VERSION, SEND_TICKET_REQUEST_CODE, payload)
        return request.pack()

    def get_encrypted_authenticator(self, aes_key):
        """
        Create an authenticator
        :param aes_key: symmetric key shared with Message server to encrypt values
        :return: Dictionary authenticator
        """
        # generate initial vector
        iv = get_random_bytes(IV_LEN)
        # encrypt values
        encrypted_version = Client.encrypt_version(aes_key, iv)
        encrypted_client_uuid = Client.encrypt_client_uuid(self.uuid, aes_key, iv)
        encrypted_server_uuid = Client.encrypt_server_uuid(bytes.fromhex(self.message_server_uuid),
                                                           aes_key, iv)
        encrypted_creation_time = encrypt_time(datetime.now(), aes_key, iv)
        # Create authenticator
        authenticator = {
            'authenticator_iv': iv,
            'version': encrypted_version,
            'client_uuid': encrypted_client_uuid,
            'server_uuid': encrypted_server_uuid,
            'creation_time': encrypted_creation_time
        }
        return authenticator

    @staticmethod
    def encrypt_version(aes_key, iv):
        """
        Encrypt the version value
        :param aes_key: Symmetric Key shared with the message server
        :param iv: Initial vector
        :return:
        """
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        version_byte = VERSION.to_bytes(1, byteorder='big')
        encrypted_version = cipher.encrypt(pad(version_byte, AES.block_size))
        return encrypted_version

    @staticmethod
    def encrypt_client_uuid(client_uuid, aes_key, iv):
        """
        encrypt client UUID Padded
        :param client_uuid:
        :param aes_key: symmetric sey shared with the message server
        :param iv: initial vector
        :return: encrypted Client UUID
        """
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_client_uuid = cipher.encrypt(pad(bytes.fromhex(client_uuid), AES.block_size))
        return encrypted_client_uuid

    @staticmethod
    def encrypt_server_uuid(server_uuid, aes_key, iv):
        """
        encrypt server UUID Padded
        :param server_uuid:
        :param aes_key: symmetric key shared with the message server
        :param iv: initial vector
        :return: encrypt server UUID
        """
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_server_uuid = cipher.encrypt(pad(server_uuid, AES.block_size))
        return encrypted_server_uuid

    @staticmethod
    def registration_request():
        """
        Create registration request to Authenticator Server
        :return: packed request (bytes) and password (str)
        """
        # Get name and password from user
        name, password = get_client_info()
        # Fictive Client UUID (Used in unpacking)
        client_uuid = "00000000000000000000000000000000"
        # Create the payload
        payload = {'name': name, 'password': password}
        # Create the request to send
        request = Request(client_uuid, VERSION, REGISTRATION_REQUEST_CODE, payload)
        return request.pack(), password

    @classmethod
    def registration_response(cls, packed_response, packed_request):
        """
        Handle registration response from the authentication server
        :param packed_response: response received from authentication server
        :param packed_request: request of client in registration request
        :return: Instance of initialized client or None if registration failed
        """
        # validate that response is legal with correct structure and content
        try:
            # unpack the response
            response = Response.unpack(packed_response)
        except ValueError:
            return None
        # registration failed
        if response.response_code == REGISTRATION_FAILED:
            print(f"{REGISTRATION_FAILED}: Registration Failed")
            exit(REGISTRATION_FAILED)
        # response.response_code == REGISTRATION_SUCCEED
        else:
            # unpack request to extract the values
            request = Request.unpack(packed_request)
            name = request.payload['name']
            client_uuid = response.payload['client_uuid']
            # create initialized client instance
            client = cls(name, client_uuid)
            # store the client info into file.
            client.store_client_info()
            print(f"{REGISTRATION_SUCCEED}: Registration Succeed")
            return client

    def symmetric_key_request(self):
        """
        Send symmetric key request to authentication server
        :return: packed request
        """
        # Generate nonce value
        nonce = get_random_bytes(NONCE_LEN)
        # create the payload
        payload = {
            'server_uuid': self.message_server_uuid,
            'nonce': nonce
        }
        # create request to send.
        request = Request(self.uuid, VERSION, SYMMETRIC_REQUEST_CODE, payload)
        return request.pack()

    def symmetric_key_response(self, packed_response, packed_request):
        """
        Handle symmetric key response received from the authentication server
        :param packed_response: response received from authentication server
        :param packed_request: request of client in registration request
        :return:
        """
        # validate that response is legal with correct structure and content
        try:
            response = Response.unpack(packed_response)
        except ValueError:
            return None, None
        request = Request.unpack(packed_request)
        # check code compatibility
        if response.response_code == SEND_SYMMETRIC_KEY:
            # extract the data from the payload
            encrypted_key = response.payload['encrypted_key']
            ticket = response.payload['ticket']
            # decrypt the encrypted key
            aes_key, updated_nonce = self.decrypt_encrypted_key(encrypted_key)
            # aes is none when password incorrect and check replay attack potential
            if aes_key is None:
                return None, None
            if nonce_update(request.payload['nonce']) != updated_nonce:
                print(f"{GENERAL_RESPONSE_ERROR}: Potential of Replay Attack")
                return None, None
            print(f"{SEND_SYMMETRIC_KEY}: Symmetric Key Request Succeed")
            return aes_key, ticket
        else:
            print(f"{GENERAL_RESPONSE_ERROR}: {SERVER_ERROR_MESSAGE}")
            exit(GENERAL_RESPONSE_ERROR)

    def decrypt_encrypted_key(self, encrypted_key):
        """
        decrypt encrypted key received from the authenticator server due to symmetric key request
        :param encrypted_key: encrypted_key received from the authenticator server
        :return: aes key and nonce, if decryption exit
        """
        # extract info from the encrypted key
        iv = encrypted_key['encrypted_key_iv']
        encrypted_aes_key = encrypted_key['aes_key']
        encrypted_nonce = encrypted_key['nonce']
        # decrypt the aes key
        cipher = AES.new(bytes.fromhex(self.key), AES.MODE_CBC, iv)
        # according to the password the user provide try to decrypt encrypted key, No Login Process
        try:
            aes_key = unpad(cipher.decrypt(encrypted_aes_key), AES.block_size)
            # decrypt the nonce
            cipher = AES.new(bytes.fromhex(self.key), AES.MODE_CBC, iv)
            nonce = unpad(cipher.decrypt(encrypted_nonce), AES.block_size)
        except ValueError:
            print(f"{GENERAL_RESPONSE_ERROR}: Incorrect Password")
            return None, None
        # There is alert reference before assignment in (PYCHARM) - however the program exit if assignment fails.
        return aes_key, nonce

    def message_request(self, aes_key, msg_server_client):
        """
        create message request to message server
        :param aes_key: symmetric sey shared with the message server
        :param msg_server_client: socket to send the request.
        :return: if client initiative session end returned SESSION_ENDED_INITIATIVE, or SESSION_EXPIRED if session
        expired
        """
        # Firstly, send the header request that includes encrypted message length, then send the message content
        while True:
            encrypted_message, message, iv = Client.get_user_encrypted_message(aes_key)
            if encrypted_message is None:
                continue
            # create the payload header
            payload = {'message_size': len(encrypted_message), 'message_iv': iv}
            # header of message request to send to message server
            request = Request(self.uuid, VERSION, SEND_MESSAGE_REQUEST_CODE, payload)
            packed_request = request.pack()
            sending_succeed = secured_sending_packet(msg_server_client, packed_request, MSG_SOCKET_CRASH_ERROR_MESSAGE)
            if not sending_succeed:
                return
            # send the encrypted message
            is_msg_sent = self.send_encrypted_message(msg_server_client, encrypted_message)
            if not is_msg_sent:
                return GENERAL_RESPONSE_ERROR
            # receive response
            response_code = Client.message_response(msg_server_client)
            if response_code != MESSAGE_RECEIVED:
                return response_code
            # check initiative end session by client
            if message == 'exit':
                print("Session Exit")
                return SESSION_ENDED_INITIATIVE

    @staticmethod
    def send_encrypted_message(msg_server_client, encrypted_message):
        """
        send long encrypted message
        :param msg_server_client: socket to send on
        :param encrypted_message: the message
        :return: True if message sent, otherwise False
        """
        message_length = len(encrypted_message)
        # count bytes sent amount
        sent_bytes = 0
        while sent_bytes < message_length:
            send_succeed = secured_sending_packet(msg_server_client,
                                                  encrypted_message[sent_bytes: sent_bytes + BUFFER_SIZE],
                                                  MSG_SOCKET_CRASH_ERROR_MESSAGE)
            if not send_succeed:
                return False
            # update the counter
            sent_bytes += BUFFER_SIZE
        return True

    @staticmethod
    def message_response(msg_server_client):
        """
        Handle message response received from message server
        :param msg_server_client:
        :return:
        """
        # receive the response
        packed_response = msg_server_client.recv(BUFFER_SIZE)
        # validate that response is legal with correct structure and content
        try:
            # unpack the response
            response = Response.unpack(packed_response)
        except ValueError:
            return GENERAL_RESPONSE_ERROR
        # check if the message receive successfully
        if response.response_code == MESSAGE_RECEIVED:
            print(f"{MESSAGE_RECEIVED}: Message Received")
            return MESSAGE_RECEIVED
        # check if session expired.
        elif response.response_code == GENERAL_RESPONSE_ERROR:
            print("Session Expired")
            return SESSION_EXPIRED

    @staticmethod
    def get_user_encrypted_message(aes_key):
        """
        get a message from the user and check if length is valid after encryption
        :param: symmetric sey shared with the message server
        :return: encrypted message, message, and the iv. if message not valid return False
        """
        cipher = AES.new(aes_key, AES.MODE_CBC)
        message = input("message: ")
        encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
        # Check if the size of the encrypted message exceeds its limits
        if len(encrypted_message) > MESSAGE_MAX_SIZE:
            print(f"Unsupported message length: {len(encrypted_message)}")
            return None, None, None
        return encrypted_message, message, cipher.iv

    @staticmethod
    def msg_server_symmetric_key_response(packed_response):
        """
        Handle response due to symmetric key request to message server
        :param packed_response: response received from the message server
        :return: response code
        """
        response = Response.unpack(packed_response)
        return response.response_code

    @staticmethod
    def authorization_process(auth_server_socket):
        """
        grant access to user if registered, otherwise start registration process
        :param auth_server_socket: auth_server_socket
        :return: Client | if process fails return None, otherwise return Client
        """
        # Load client info if existed.
        client = Client.load_client_info(CLIENT_FILENAME)
        # If client is new, send registration request.
        if client is None:
            print("Registration to System")
            # Send Registration Request to Authentication Server.
            packed_request, password = Client.registration_request()
            sending_succeed = secured_sending_packet(auth_server_socket, packed_request, AS_SOCKET_CRASH_ERROR_MESSAGE)
            if not sending_succeed:
                return None
            packed_response = secured_receiving_packet(auth_server_socket)
            if packed_response is None:
                return None
            client = Client.registration_response(packed_response, packed_request)
            # registration failed
            if client is None:
                return None
            # set the password
            client.set_key(password)
            print()
        return client


def parse_servers_file(endpoint_file):
    """
    parse endpoint file of the structure:
        authenticator_ip:authenticator_port
        message_ip:message_port
    :param endpoint_file: file
    :return: two endpoint, (authenticator ip, authenticator port)encrypted_message: and (message ip, message port)
    """
    # Initialize variables for authentication server and message server IP and port
    auth_server_ip = ""
    auth_server_port = ""
    msg_server_ip = ""
    msg_server_port = ""
    # Open the file and read its contents
    try:
        with open(endpoint_file, "r") as file:
            lines = file.readlines()
            # Check if there are at least two lines in the file
            if len(lines) >= 2:
                # Extract authentication server IP and port from the first line
                auth_server_ip, auth_server_port = lines[0].strip().split(":")
                # Extract message server IP and port from the second line
                msg_server_ip, msg_server_port = lines[1].strip().split(":")
            else:
                print("File does not contain enough lines.")
    except FileNotFoundError:
        print("File not found.")
    return (auth_server_ip, int(auth_server_port)), (msg_server_ip, int(msg_server_port))


def connect_to_server(endpoint):
    """
    Establish connection with provided endpoint
    :param endpoint: endpoint is tuple (ip, port)
    :return:
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(endpoint)
        return client
    except ConnectionRefusedError:
        print("Connection Failed.")
        exit(GENERAL_RESPONSE_ERROR)


def connect_to_authentication_server(endpoint):
    """
    Establish connection with provided endpoint
    :param endpoint: endpoint is tuple (ip, port)
    :return:
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(endpoint)
        return client
    except ConnectionRefusedError:
        try:
            client.connect((endpoint[0], DEFAULT_AUTHENTICATION_PORT))
            return client
        except ConnectionRefusedError:
            print("Connection Failed.")
            exit(GENERAL_RESPONSE_ERROR)


def renew_session_prompt():
    """
    Ask user if renew session needed.
    :return: True if user want to renew, otherwise False
    """
    tries = 1
    prompt = input("Would you like to renew the connection with the message server(Y/n)?").lower()
    while not prompt == 'y' and not prompt == 'n':
        if tries > MAX_TRIES:
            return False
        tries += 1
        prompt = input(f"Try again {tries}/{MAX_TRIES}, one of the options(Y/n)? ").lower()
    if prompt == 'y':
        return True
    return False


def main():
    # Parse Servers endpoints.
    auth_server_endpoint, message_server_endpoint = parse_servers_file(SERVERS_FILENAME)
    # Establishing connection with Authentication Server.
    auth_server_socket = connect_to_authentication_server(auth_server_endpoint)
    # check if connection fails.
    if auth_server_socket is None:
        print(SERVER_ERROR_MESSAGE)
        return

    # login or registration process
    client = Client.authorization_process(auth_server_socket)
    # authorization process failed.
    if client is None:
        return
    while True:
        print(f"Hi {client.name}!")
        # Get the password from the client in order to decrypt the key.
        password = get_password()
        # check case of Client application crash before providing password.
        if password is None:
            return
        client.set_key(password)
        # Send symmetric key request to Authentication Server.
        packed_request = client.symmetric_key_request()
        # check if socket crashes
        sending_succeed = secured_sending_packet(auth_server_socket, packed_request, AS_SOCKET_CRASH_ERROR_MESSAGE)
        if not sending_succeed:
            break
        packed_response = secured_receiving_packet(auth_server_socket)
        if packed_response is None:
            break
        aes_key, ticket = client.symmetric_key_response(packed_response, packed_request)
        # Check error occur
        if aes_key is None:
            return
        # authentication socket close
        auth_server_socket.close()

        # Connect to the message server.
        msg_server_client = connect_to_server(message_server_endpoint)
        if msg_server_client is None:
            print(SERVER_ERROR_MESSAGE)
            return
        # initiate message request with message server
        packed_request = client.msg_srv_connection_request(aes_key, ticket)
        # check if socket crashes
        sending_succeed = secured_sending_packet(msg_server_client, packed_request, MSG_SOCKET_CRASH_ERROR_MESSAGE)
        if not sending_succeed:
            break
        # receive response
        packed_response = secured_receiving_packet(msg_server_client)
        if packed_response is None:
            return
        response_code = Client.msg_server_symmetric_key_response(packed_response)

        if response_code == GENERAL_RESPONSE_ERROR:
            print(SERVER_ERROR_MESSAGE)
            msg_server_client.close()
            break
        # sending messages
        end_code = client.message_request(aes_key, msg_server_client)

        if end_code == SESSION_EXPIRED and renew_session_prompt():
            auth_server_socket = connect_to_authentication_server(auth_server_endpoint)
            continue
        else:
            break


if __name__ == '__main__':
    main()
