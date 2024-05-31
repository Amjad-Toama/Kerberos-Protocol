import os.path
import socket
import threading
from datetime import time
from random import randint

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

from Request import *
from Response import *

VERSION = 24
MAX_NAME_LEN = 255
MAX_PASSWORD_LEN = 255
INFO_FILENAME = "me.info"
SERVERS_FILENAME = "srv.info"
BUFFER_SIZE = 4096


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

    def msg_srv_connection_request(self, ticket):
        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_CBC)
        # TODO: Encrypt later.
        # encrypted_version = cipher.encrypt(pad(str(VERSION).encode(), AES.block_size))
        # encrypted_client_id = cipher.encrypt(pad(self.id.encode(), AES.block_size))
        # encrypted_server_id = cipher.encrypt(pad("64f3f63985f04beb81a0e43321880182".encode(), AES.block_size))
        # TODO: creation time encryption needed.
        creation_time = datetime.now()
        authenticator = {
            'authenticator_iv': cipher.iv,
            'version': VERSION,
            'client_id': self.id,
            'server_id': "64f3f63985f04beb81a0e43321880182",
            'creation_time': creation_time
        }
        payload = {'authenticator': authenticator, 'ticket': ticket}
        request = Request(self.id, VERSION, SEND_TICKET_REQUEST_CODE, payload)
        return request.pack()

    @staticmethod
    def registration_request():
        name, password = Client.get_client_info()
        # client_id = bytes.fromhex("00000000000000000000000000000000")  # Fictive Client ID
        client_id = "00000000000000000000000000000000"  # Fictive Client ID
        payload = {'name': name, 'password': password}
        request = Request(client_id, VERSION, REGISTRATION_REQUEST_CODE, payload)
        return request.pack()

    @classmethod
    def registration_response(cls, packed_response, packed_request):
        response = Response.unpack(packed_response)
        request = Request.unpack(packed_request)
        if response.response_code == REGISTRATION_FAILED:
            name = request.payload['name']
            print(f"{REGISTRATION_FAILED} ERROR: The name {name} is already exists\n")
            return None
        elif response.response_code == REGISTRATION_SUCCEED:
            print(f"{REGISTRATION_SUCCEED} SUCCEED.\n")
            name = request.payload['name']
            client_id = response.payload['client_id']
            client = cls(name, client_id)
            client.store_client_info()
            return client
        else:
            # TODO: Unexpected response code received.
            pass

    def symmetric_key_request(self):
        nonce = randint(0, 2 ** 64 - 1)
        payload = {
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
            aes_key, nonce = self.decrypt_aes_key(encrypted_key)
            # TODO: treat nonce value
            return aes_key, ticket
        else:
            # TODO: Unexpected response code received.
            return None, None

    def message_request(self, aes_key, msg_server_client):
        while True:
            cipher = AES.new(aes_key, AES.MODE_CBC)
            message = input("message: ")
            encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
            payload = {'message_size': len(encrypted_message), 'message_iv': cipher.iv,
                       'encrypted_message': encrypted_message}
            request = Request(self.id, VERSION, SEND_MESSAGE_REQUEST_CODE, payload)
            packed_request = request.pack()
            msg_server_client.send(packed_request)

    def decrypt_aes_key(self, encrypted_key):
        iv = encrypted_key['encrypted_key_iv']
        encrypted_nonce = encrypted_key['nonce']
        encrypted_aes_key = encrypted_key['aes_key']
        cipher = AES.new(bytes.fromhex(self.key), AES.MODE_CBC, iv)
        # nonce = cipher.decrypt(encrypted_nonce)
        aes_key = cipher.decrypt(encrypted_aes_key)
        return aes_key, encrypted_nonce

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
    except ConnectionRefusedError:
        print("Connection Failed.")
    return client


def main():
    # Parse Servers endpoints.
    auth_server_endpoint, message_server_endpoint = parse_servers_file(SERVERS_FILENAME)
    # Establishing connection with Authentication Server.
    auth_server_client = connect_to_server(auth_server_endpoint)
    # Load client info if existed.

    client1 = Client.load_client_info(INFO_FILENAME)
    # If client is new, send registration request.
    if client1 is None:
        # Send Registration Request to Authentication Server.
        packed_request = Client.registration_request()
        auth_server_client.send(packed_request)
        packed_response = auth_server_client.recv(BUFFER_SIZE)
        client1 = Client.registration_response(packed_response, packed_request)
    # Get the password from the client in order to decrypt the key.
    password = client1.get_password()
    client1.set_key(password)
    # Send symmetric key request to Authentication Server.
    packed_request = client1.symmetric_key_request()
    auth_server_client.send(packed_request)
    packed_response = auth_server_client.recv(BUFFER_SIZE)
    aes_key, ticket = client1.symmetric_key_response(packed_response, packed_request)
    auth_server_client.close()

    # Connect to the message server.
    msg_server_client = connect_to_server(message_server_endpoint)
    packed_request = client1.msg_srv_connection_request(ticket)
    msg_server_client.send(packed_request)
    # sending messages
    client1.message_request(aes_key, msg_server_client)


if __name__ == '__main__':
    main()
