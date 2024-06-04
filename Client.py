import os.path
import socket
from Crypto.Hash import SHA256
from Request import *
from Response import *
from Utilization import *

INFO_FILENAME = "me.info"
SERVERS_FILENAME = "srv.info"
SERVER_ERROR_MESSAGE = "server responded with an error"
MESSAGE_MAX_BYTES_SIZE = 1
BITS_PER_BYTE = 8
MESSAGE_MAX_SIZE = (2 ** (MESSAGE_MAX_BYTES_SIZE * BITS_PER_BYTE)) - 1

IV_LENGTH = 16
NONCE_SIZE = 8

SESSION_EXPIRED = 600
SESSION_ENDED_INITIATIVE = 601


class Server:
    def __init__(self, ip, port, name, uuid, key):
        self.ip, self.port, self.name, self.uuid, self.key = ip, port, name, uuid, key

    def __str__(self):
        return f"{self.ip}:{self.port}\n{self.name}\n{self.uuid}\n{self.key}"


class Client:
    def __init__(self, name, id, key=None):
        self.name = name
        self.id = id
        self.key = key

    def set_key(self, key):
        """
        Set the client symmetric key with Authentication server that extracted from user password
        :param key: user password
        :return:
        """
        # Extract the symmetric key from the password
        h = SHA256.new()
        h.update(key.encode('utf=8'))
        self.key = h.hexdigest()

    @classmethod
    def load_client_info(cls, info_filename):
        """
        Load the client info if exist from info_filename, otherwise return None
        file structure:
            name
            user_id
        :param info_filename: client info file
        :return: Client initialized instance if succeeded, otherwise return None
        """
        # Open the file and read its contents
        if os.path.exists(info_filename):
            with open(info_filename, "r") as file:
                lines = file.readlines()
                # Extract file info
                name = lines[0].strip()
                id = lines[1].strip()
                # Return client instance
                return cls(name, id)
        return None

    def store_client_info(self):
        """
        Create info file "me.info" with the structure:
            client_name
            client_id
        :return:
        """
        with open("me.info", "w") as file:
            # Write the info to the file
            file.write(self.name + "\n")
            file.write(self.id + "\n")
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
        request = Request(self.id, VERSION, SEND_TICKET_REQUEST_CODE, payload)
        return request.pack()

    def get_encrypted_authenticator(self, aes_key):
        """
        Create an authenticator
        :param aes_key: symmetric key shared with Message server to encrypt values
        :return: Dictionary authenticator
        """
        # generate initial vector
        iv = get_random_bytes(IV_LENGTH)
        # encrypt values
        encrypted_version = Client.encrypt_version(aes_key, iv)
        encrypted_client_id = Client.encrypt_client_id(self.id, aes_key, iv)
        encrypted_server_id = Client.encrypt_server_id(bytes.fromhex("64f3f63985f04beb81a0e43321880182"), aes_key, iv)
        encrypted_creation_time = encrypt_time(datetime.now(), aes_key, iv)
        # Create authenticator
        authenticator = {
            'authenticator_iv': iv,
            'version': encrypted_version,
            'client_id': encrypted_client_id,
            'server_id': encrypted_server_id,
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
    def encrypt_client_id(client_id, aes_key, iv):
        """
        encrypt client ID Padded
        :param client_id:
        :param aes_key: symmetric sey shared with the message server
        :param iv: initial vector
        :return: encrypted Client ID
        """
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_client_id = cipher.encrypt(pad(bytes.fromhex(client_id), AES.block_size))
        return encrypted_client_id

    @staticmethod
    def encrypt_server_id(server_id, aes_key, iv):
        """
        encrypt server ID Padded
        :param server_id:
        :param aes_key: symmetric key shared with the message server
        :param iv: initial vector
        :return: encrypt server ID
        """
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_server_id = cipher.encrypt(pad(server_id, AES.block_size))
        return encrypted_server_id

    @staticmethod
    def registration_request():
        """
        Create registration request to Authenticator Server
        :return: packed request
        """
        # Get name and password from user
        name, password = get_client_info()
        # Fictive Client ID (Used in unpacking)
        client_id = "00000000000000000000000000000000"
        # Create the payload
        payload = {'name': name, 'password': password}
        # Create the request to send
        request = Request(client_id, VERSION, REGISTRATION_REQUEST_CODE, payload)
        return request.pack()

    @classmethod
    def registration_response(cls, packed_response, packed_request):
        """
        Handle registration response from the authentication server
        :param packed_response: response received from authentication server
        :param packed_request: request of client in registration request
        :return: Instance of initialized client or None if registration failed
        """
        # unpack the response
        response = Response.unpack(packed_response)
        # registration failed
        if response.response_code == REGISTRATION_FAILED:
            print(SERVER_ERROR_MESSAGE)
            return None
        # response.response_code == REGISTRATION_SUCCEED
        else:
            # unpack request to extract the values
            request = Request.unpack(packed_request)
            name = request.payload['name']
            client_id = response.payload['client_id']
            # create initialized client instance
            client = cls(name, client_id)
            # store the client info into file.
            client.store_client_info()
            return client

    def symmetric_key_request(self):
        """
        Send symmetric key request to authentication server
        :return: packed request
        """
        # Generate nonce value
        nonce = get_random_bytes(NONCE_SIZE)
        # create the payload
        payload = {
            # TODO: server_id shouldn't exist in the code.
            'server_id': "64f3f63985f04beb81a0e43321880182",
            'nonce': nonce
        }
        # create request to send.
        request = Request(self.id, VERSION, SYMMETRIC_REQUEST_CODE, payload)
        return request.pack()

    def symmetric_key_response(self, packed_response, packed_request):
        """
        Handle symmetric key response received from the authentication server
        :param packed_response: response received from authentication server
        :param packed_request: request of client in registration request
        :return:
        """
        response = Response.unpack(packed_response)
        request = Request.unpack(packed_request)
        if response.response_code == SEND_SYMMETRIC_KEY:
            # extract the data from the payload
            encrypted_key = response.payload['encrypted_key']
            ticket = response.payload['ticket']
            # decrypt the encrypted key
            aes_key, updated_nonce = self.decrypt_encrypted_key(encrypted_key)
            # check replay attack potential
            if nonce_update(request.payload['nonce']) != updated_nonce:
                print("Potential of Replay Attack")
            return aes_key, ticket
        else:
            print(SERVER_ERROR_MESSAGE)
            return None, None

    def decrypt_encrypted_key(self, encrypted_key):
        """
        decrypt encrypted key received from the authenticator server due to symmetric key request
        :param encrypted_key: encrypted_key received from the authenticator server
        :return: aes key and nonce
        """
        # extract info from the encrypted key
        iv = encrypted_key['encrypted_key_iv']
        encrypted_aes_key = encrypted_key['aes_key']
        encrypted_nonce = encrypted_key['nonce']
        # decrypt the aes key
        cipher = AES.new(bytes.fromhex(self.key), AES.MODE_CBC, iv)
        aes_key = unpad(cipher.decrypt(encrypted_aes_key), AES.block_size)
        # decrypt the nonce
        cipher = AES.new(bytes.fromhex(self.key), AES.MODE_CBC, iv)
        nonce = unpad(cipher.decrypt(encrypted_nonce), AES.block_size)
        return aes_key, nonce

    def message_request(self, aes_key, msg_server_client):
        """
        create message request to message server
        :param aes_key: symmetric sey shared with the message server
        :param msg_server_client: socket to send the request.
        :return: if the session end initiatively returned SESSION_ENDED_INITIATIVE, or SESSION_EXPIRED if session
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
            request = Request(self.id, VERSION, SEND_MESSAGE_REQUEST_CODE, payload)
            packed_request = request.pack()
            msg_server_client.send(packed_request)
            # send the encrypted message
            self.send_encrypted_message(msg_server_client, encrypted_message)
            # receive response
            response_code = Client.message_response(msg_server_client)
            if response_code != MESSAGE_RECEIVED:
                return response_code
            # check if the user initiatively end session
            if message == 'exit':
                print("Session Exit")
                return SESSION_ENDED_INITIATIVE

    @staticmethod
    def send_encrypted_message(msg_server_client, encrypted_message):
        """
        send long encrypted message
        :param msg_server_client: socket to send on
        :param encrypted_message: the message
        :return:
        """
        message_length = len(encrypted_message)
        # count bytes sent amount
        sent_bytes = 0
        while sent_bytes < message_length:
            msg_server_client.send(encrypted_message[sent_bytes: sent_bytes + BUFFER_SIZE])
            # update the counter
            sent_bytes += BUFFER_SIZE

    @staticmethod
    def message_response(msg_server_client):
        """
        Handle message response received from message server
        :param msg_server_client:
        :return:
        """
        # receive the response
        packed_response = msg_server_client.recv(BUFFER_SIZE)
        # unpack the response
        response = Response.unpack(packed_response)
        # check if the message receive successfully
        if response.response_code == MESSAGE_RECEIVED:
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


def parse_servers_file(endpoint_file):
    """
    parse endpoint file of the structure:
        authenticator_ip:authenticator_port
        message_ip:message_port
    :param endpoint_file: file
    :return: two endpoint, (authenticator ip, authenticator port) and (message ip, message port)
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


def main():
    # Parse Servers endpoints.
    auth_server_endpoint, message_server_endpoint = parse_servers_file(SERVERS_FILENAME)
    # Establishing connection with Authentication Server.
    auth_server_client = connect_to_server(auth_server_endpoint)
    if auth_server_client is None:
        print(SERVER_ERROR_MESSAGE)
        return
    # Load client info if existed.
    client = Client.load_client_info(INFO_FILENAME)
    # If client is new, send registration request.
    if client is None:
        print("Registration to System")
        # Send Registration Request to Authentication Server.
        packed_request = Client.registration_request()
        auth_server_client.send(packed_request)
        packed_response = auth_server_client.recv(BUFFER_SIZE)
        client = Client.registration_response(packed_response, packed_request)
        # registration error
        if client is None:
            return
        clear_console()

    while True:
        print(f"Hi {client.name}!")
        # Get the password from the client in order to decrypt the key.
        password = client.get_password()
        client.set_key(password)
        # Send symmetric key request to Authentication Server.
        packed_request = client.symmetric_key_request()
        auth_server_client.send(packed_request)
        packed_response = auth_server_client.recv(BUFFER_SIZE)
        aes_key, ticket = client.symmetric_key_response(packed_response, packed_request)
        auth_server_client.close()

        # Connect to the message server.
        msg_server_client = connect_to_server(message_server_endpoint)
        if msg_server_client is None:
            print(SERVER_ERROR_MESSAGE)
            return
        packed_request = client.msg_srv_connection_request(aes_key, ticket)
        msg_server_client.send(packed_request)
        packed_response = msg_server_client.recv(BUFFER_SIZE)
        response_code = Client.msg_server_symmetric_key_response(packed_response)

        if response_code == GENERAL_RESPONSE_ERROR:
            print(SERVER_ERROR_MESSAGE)
            msg_server_client.close()
        else:
            # sending messages
            end_code = client.message_request(aes_key, msg_server_client)

        if end_code == SESSION_EXPIRED:
            prompt = input("Would you like to renew the connection with the message server(Y/n)?").lower()
            while not prompt == 'y' and not prompt == 'n':
                prompt = input("Try again, one of the options(Y/n)?").lower()
            if prompt == 'y':
                auth_server_client = connect_to_server(auth_server_endpoint)
                continue
            else:
                break
        else:
            break


if __name__ == '__main__':
    main()
