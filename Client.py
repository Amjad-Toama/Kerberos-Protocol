import os.path
import socket
from Crypto.Hash import SHA256
from Request import *
from Response import *
from Utilization import *

MAX_NAME_LEN = 255
MAX_PASSWORD_LEN = 255
INFO_FILENAME = "me.info"
SERVERS_FILENAME = "srv.info"
SERVER_ERROR_MESSAGE = "server responded with an error"
MESSAGE_MAX_BYTES_SIZE = 4
BITS_PER_BYTE = 8
MESSAGE_MAX_SIZE = (2 ** (MESSAGE_MAX_BYTES_SIZE * BITS_PER_BYTE)) - 1


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
        h = SHA256.new()
        h.update(key.encode('utf=8'))
        self.key = h.hexdigest()

    @classmethod
    def load_client_info(cls, info_filename):
        # Open the file and read its contents
        if os.path.exists(info_filename):
            with open(info_filename, "r") as file:
                lines = file.readlines()
                name = lines[0].strip()
                id = lines[1].strip()
                return cls(name, id)
        else:
            None

    def store_client_info(self):
        with open("me.info", "w") as file:
            file.write(self.name + "\n")
            file.write(self.id + "\n")
        file.close()

    @staticmethod
    def get_client_info():
        name = Client.get_name()
        password = Client.get_password()
        return name, password

    @staticmethod
    def get_name():
        name = input("Enter name: ")
        while not Client.legal_name(name):
            name = input("Enter name: ")
        return name

    @staticmethod
    def get_password():
        password = input("Enter password: ")
        while not Client.legal_password(password):
            password = input("Enter password: ")
        return password

    @staticmethod
    def legal_name(name):
        if not name.isalpha():
            print(f"{name} must contain letters only. Try Again.\n")
            return False
        elif len(name) > MAX_NAME_LEN:
            print(f"{name} too long (maximum length {MAX_NAME_LEN}). Try Again.\n")
            return False
        else:
            return True

    @staticmethod
    def legal_password(password):
        if len(password) > MAX_PASSWORD_LEN:
            print(f"{password} too long (maximum length {MAX_PASSWORD_LEN}). Try Again.\n")
            return False
        else:
            return True

    def msg_srv_connection_request(self, aes_key, ticket):
        authenticator = self.get_encrypted_authenticator(aes_key)
        payload = {'authenticator': authenticator, 'ticket': ticket}
        request = Request(self.id, VERSION, SEND_TICKET_REQUEST_CODE, payload)
        return request.pack()

    def get_encrypted_authenticator(self, aes_key):
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        version_byte = VERSION.to_bytes(1, byteorder='big')
        encrypted_version = cipher.encrypt(pad(version_byte, AES.block_size))
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_client_id = cipher.encrypt(pad(bytes.fromhex(self.id), AES.block_size))
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_server_id = cipher.encrypt(pad(bytes.fromhex("64f3f63985f04beb81a0e43321880182"), AES.block_size))
        creation_time = datetime.now()
        encrypted_creation_time = encrypt_time(creation_time, aes_key, iv)
        authenticator = {
            'authenticator_iv': iv,
            'version': encrypted_version,
            'client_id': encrypted_client_id,
            'server_id': encrypted_server_id,
            'creation_time': encrypted_creation_time
        }
        return authenticator

    @staticmethod
    def registration_request():
        name, password = Client.get_client_info()
        client_id = "00000000000000000000000000000000"  # Fictive Client ID
        payload = {'name': name, 'password': password}
        request = Request(client_id, VERSION, REGISTRATION_REQUEST_CODE, payload)
        return request.pack()

    @classmethod
    def registration_response(cls, packed_response, packed_request):
        response = Response.unpack(packed_response)
        request = Request.unpack(packed_request)
        # Registration failed
        if response.response_code == REGISTRATION_FAILED:
            print(SERVER_ERROR_MESSAGE)
            return None
        elif response.response_code == REGISTRATION_SUCCEED:
            name = request.payload['name']
            client_id = response.payload['client_id']
            client = cls(name, client_id)
            client.store_client_info()
            return client
        else:
            # TODO: Unexpected response code received.
            pass

    # # # # # # # # # # # # # Symmetric Key # # # # # # # # # # # # # #

    def symmetric_key_request(self):
        nonce = get_random_bytes(8)
        payload = {
            # TODO: server_id shouldn't exist in the code.
            'server_id': "64f3f63985f04beb81a0e43321880182",
            'nonce': nonce
        }
        request = Request(self.id, VERSION, SYMMETRIC_REQUEST_CODE, payload)
        return request.pack()

    def symmetric_key_response(self, packed_response, packed_request):
        response = Response.unpack(packed_response)
        request = Request.unpack(packed_request)
        if response.response_code == SEND_SYMMETRIC_KEY:
            encrypted_key = response.payload['encrypted_key']
            ticket = response.payload['ticket']
            aes_key, updated_nonce = self.decrypt_encrypted_key(encrypted_key)
            if nonce_update(request.payload['nonce']) != updated_nonce:
                print("Potential of Replay Attack")
            return aes_key, ticket
        else:
            # TODO: Unexpected response code received.
            return None, None

    # - - - - - - - - - - - End Symmetric Key - - - - - - - - - - - - #

    def message_request(self, aes_key, msg_server_client):
        while True:
            cipher = AES.new(aes_key, AES.MODE_CBC)
            message = input("message: ")
            encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
            # Check if the size of the encrypted message exceeds its limits
            if len(encrypted_message) > MESSAGE_MAX_SIZE:
                print(f"Unsupported message length: {len(encrypted_message)}")
                continue
            payload = {'message_size': len(encrypted_message), 'message_iv': cipher.iv}
            request = Request(self.id, VERSION, SEND_MESSAGE_REQUEST_CODE, payload)
            packed_request = request.pack()
            msg_server_client.send(packed_request)
            self.send_encrypted_message(msg_server_client, encrypted_message)
            if message == 'exit':
                return

    def decrypt_encrypted_key(self, encrypted_key):
        iv = encrypted_key['encrypted_key_iv']
        encrypted_aes_key = encrypted_key['aes_key']
        encrypted_nonce = encrypted_key['nonce']
        cipher = AES.new(bytes.fromhex(self.key), AES.MODE_CBC, iv)
        aes_key = unpad(cipher.decrypt(encrypted_aes_key), AES.block_size)
        cipher = AES.new(bytes.fromhex(self.key), AES.MODE_CBC, iv)
        nonce = unpad(cipher.decrypt(encrypted_nonce), AES.block_size)
        return aes_key, nonce

    @staticmethod
    def msg_server_symmetric_key_response(packed_response):
        response = Response.unpack(packed_response)
        return response.response_code

    @staticmethod
    def send_encrypted_message(msg_server_client, encrypted_message):
        message_length = len(encrypted_message)
        sent_bytes = 0
        while sent_bytes < message_length:
            msg_server_client.send(encrypted_message[sent_bytes: sent_bytes + BUFFER_SIZE])
            sent_bytes += BUFFER_SIZE

    @staticmethod
    def nonce_verify(nonce):
        return nonce - 1


def parse_servers_file(endpoint_file):
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


# Used to authentication and message servers.
def connect_to_server(endpoint):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(endpoint)
        return client
    except ConnectionRefusedError:
        print("Connection Failed.")


def clear_console():
    print("\n" * 100)


def menu():
    menu_options = """
        Menu:
        0. Close
        1. Get Symmetric Key
        2. Registration
        3. Connect to Message Server
        """
    return menu_options


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
        client.message_request(aes_key, msg_server_client)


if __name__ == '__main__':
    main()
