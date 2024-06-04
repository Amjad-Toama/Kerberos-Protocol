import socket
import threading
from Crypto.Hash import SHA256
from datetime import timedelta
from Request import *
from Response import *
from Utilization import *

########################################################################
# ######################## Constants Section ######################### #
########################################################################
# USERNAME_LENGTH     : username max length (include null character)   #
# PASSWORD_LENGTH     : password max length (include null character)   #
# ID_LENGTH           : user id max length                             #
# KEY_LENGTH          : symmetric key max length                       #
# IV_LENGTH           : iv length (16 is default length)               #
# VERSION             : protocol version                               #
# TICKET_TIME_DURATION: duration of ticket validity (in hours)         #
########################################################################

USERNAME_LENGTH = 255
PASSWORD_LENGTH = 255
ID_LENGTH = 16
KEY_LENGTH = 32
IV_LENGTH = 16
VERSION = 24
TICKET_TIME_DURATION = 1


class Client:
    def __init__(self, uuid, name, password_hash, last_seen):
        self.uuid, self.name, self.password_hash, self.last_seen = uuid, name, password_hash, last_seen

    def __str__(self):
        return f"{self.uuid}:{self.name}:{self.password_hash}:{self.last_seen}"

    def set_last_seen(self, now):
        self.last_seen = now


class Server:
    def __init__(self, ip, port, name, uuid, key):
        self.ip, self.port, self.name, self.uuid, self.key = ip, port, name, uuid, key

    def __str__(self):
        return f"{self.ip}:{self.port}\n{self.name}\n{self.uuid}\n{self.key}"

###################################################################
# ########## Instruction to add requests to the server ########## #
###################################################################
# 1. implement the request method in requests section.            #
# 2. specify the request number to menu() method as string.       #
# 3. implement "if" statement with number in the main method.     #
# NOTE: utilization methods implementation in utilization section.#
###################################################################


class AuthenticationServer:
    def __init__(self):
        # Loopback IP Address
        self.ip_address = "127.0.0.1"
        # Default port number
        self.port_number = 1256
        # Endpoint and Clients file path
        self.endpoint_file_path, self.clients_file_path, self.clients_dict = None, None, None
        self.msg_server = None

    ###################################################################
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ################### Initialization Methods #################### #
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    ###################################################################

    # load authentication endpoint.
    def load_endpoint(self, endpoint_filepath):
        self.endpoint_file_path = endpoint_filepath
        try:
            fd = open(self.endpoint_file_path, "r")
            # TODO: Check the content type and range.
            self.port_number = int(fd.read())
            fd.close()  # Make sure to close the file after reading it.
        except FileNotFoundError:
            print("File not found.")
        except PermissionError:
            print("Permission denied to read the file.")
        except Exception as e:
            print("An error occurred:", e)

    # load clients from file to memory.
    def load_clients_list(self, clients_filepath):
        self.clients_file_path = clients_filepath
        fd = open(clients_filepath, "r")
        lines = fd.readlines()
        self.clients_dict = dict()
        for line in lines:
            c_details = line.strip().split(':')
            self.clients_dict[c_details[0]] = Client(c_details[0], c_details[1], c_details[2], c_details[3])
        fd.close()
        return self.clients_dict

    # load message server details.
    def load_msg_server(self, msg_server_filepath):
        fd = open(msg_server_filepath, "r")
        lines = fd.readlines()
        ip, port = lines[0].strip().split(":")
        port = int(port)
        name = lines[1].strip()
        uuid = lines[2].strip()
        key = lines[3].strip()
        self.msg_server = Server(ip, port, name, uuid, key)
        fd.close()

    ###################################################################
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ###################### Requests Methods ####################### #
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    ###################################################################

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # # # # # # # # # # # # Registration  # # # # # # # # # # # # # # #
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def registration_request(self, username, password):
        if self.username_is_exist(username):    # registration failed.
            return self.registration_failed_response(), REGISTRATION_FAILED, None
        else:   # registration succeed.
            password_hash = AuthenticationServer.get_password_hash(password)
            client_id = self.get_new_client_id()    # get new client id
            new_client = Client(client_id, username, password_hash, datetime.now())
            self.clients_dict[client_id] = new_client    # store new client to memory.
            self.save_new_client(new_client)    # save new client details to file.
            return self.registration_succeed_response(client_id), REGISTRATION_SUCCEED, client_id

    def is_client(self, client_id):
        if client_id in self.clients_dict:
            return True
        print(f"{client_id}: Unauthorized client")
        return False

    def is_authorized_server(self, server_uuid):
        if self.msg_server.uuid == server_uuid:
            return True
        print(f"{server_uuid}: Unauthorized server")
        return False

    @staticmethod
    def registration_failed_response():
        response = Response(VERSION, REGISTRATION_FAILED, {})
        return response.pack()

    @staticmethod
    def registration_succeed_response(client_id):
        response = Response(VERSION, REGISTRATION_SUCCEED, {'client_id': client_id})
        return response.pack()

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # # # # # # # # # # # # # Symmetric Key # # # # # # # # # # # # # #
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def symmetric_key_request(self, request):
        client_id = request.client_id
        server_id = request.payload['server_id']
        # Check if symmetric key request received from authorized entity.
        if not self.is_client(client_id) or not self.is_authorized_server(server_id):
            response = Response(VERSION, GENERAL_RESPONSE_ERROR, {})
        else:
            nonce = request.payload['nonce']
            # TODO: update last check in file.
            self.update_client_last_seen(client_id)
            # Generate symmetric key for client and required server.
            aes_key = get_random_bytes(KEY_LENGTH)
            encrypted_key = self.get_encrypted_key(aes_key, self.clients_dict[client_id], nonce)
            ticket = self.get_ticket(aes_key, self.msg_server, client_id)
            payload = {
                'client_id': client_id,
                'encrypted_key': encrypted_key,
                'ticket': ticket
            }
            response = Response(VERSION, SEND_SYMMETRIC_KEY, payload)
        return response.pack()

    @staticmethod
    def get_encrypted_key(aes_key, client, nonce):
        key = bytes.fromhex(client.password_hash)
        iv = get_random_bytes(IV_LENGTH)
        # encrypt the aes key
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_aes_key = cipher.encrypt(pad(aes_key, AES.block_size))
        # update the nonce value and encrypt it
        cipher = AES.new(key, AES.MODE_CBC, iv)
        nonce = nonce_update(nonce)
        encrypted_nonce = cipher.encrypt(pad(nonce, AES.block_size))
        encrypted_key = {
            'encrypted_key_iv': iv,
            'nonce': encrypted_nonce,
            'aes_key': encrypted_aes_key
        }
        return encrypted_key

    @staticmethod
    def get_ticket(aes_key, msg_server, client_id):
        # Generate Key and Initial Vector
        key = bytes.fromhex(msg_server.key)
        iv = get_random_bytes(IV_LENGTH)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Encrypt symmetric key.
        encrypted_aes_key = cipher.encrypt(pad(aes_key, AES.block_size))
        # Time stamp
        creation_time = datetime.now()
        # Add duration time
        expiration_time = creation_time + timedelta(hours=TICKET_TIME_DURATION)
        encrypted_expiration_time = encrypt_time(expiration_time, key, iv)
        ticket = {
            'version': VERSION,
            'client_id': client_id,
            'server_id': msg_server.uuid,
            'creation_time': creation_time,
            'ticket_iv': iv,
            'aes_key': encrypted_aes_key,
            'expiration_time': encrypted_expiration_time
        }
        return ticket

    ###################################################################
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ##################### Utilization Methods ##################### #
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    ###################################################################

    def update_client_last_seen(self, client):
        now = datetime.now()
        self.clients_dict[client].set_last_seen(now)
        # TODO: update the file.

    # disconnect client.
    @staticmethod
    def disconnect(client, addr):
        print(f"{addr[0]} Disconnected")
        client.send("Disconnected".encode())
        client.close()

    # generate encrypted symmetric key to client.
    @staticmethod
    def get_encrypted_symmetric_key(encryption_key, symmetric_key):
        # key is hex format (64 bit)
        key = bytes.fromhex(encryption_key)
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted_symmetric_key = cipher.encrypt(pad(symmetric_key, AES.block_size))
        return cipher.iv, encrypted_symmetric_key

    @staticmethod
    def get_password_hash(password):
        h = SHA256.new()
        h.update(password.encode('utf-8'))
        return h.hexdigest()

    def save_new_client(self, new_client):
        f = open(self.clients_file_path, "a")
        f.write(str(new_client) + "\n")
        f.close()

    # get username and password from new client, in registration process.
    def get_new_user_details(self, client):
        username = self.get_new_username(client)
        if username is None:
            return None, None
        password = self.get_password(client)
        if password is None:
            return None, None
        return username, password

    def get_new_client_id(self):
        client_id = get_random_bytes(ID_LENGTH).hex()
        while client_id in self.clients_dict.keys():
            client_id = get_random_bytes(ID_LENGTH).hex()
        return client_id

    # listen on the socket.
    def listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.ip_address, self.port_number))
        server.listen()
        client, addr = server.accept()
        return client, addr

    def username_is_exist(self, username):
        for client in self.clients_dict.keys():
            if self.clients_dict[client].name == username:
                return True
        return False

    # return menu
    @staticmethod
    def menu():
        menu_options = """
            Menu:
            0. Close
            1. Get Symmetric Key
            2. Registration
            Note: Submit 0 anytime to stop the process.
            """
        return menu_options


def provide_service(client, addr, auth_server):
    packed_request = secured_receiving_packet(client)
    if packed_request is None:
        return
    # Unpack the received request
    request = Request.unpack(packed_request)
    request_code = request.request_code
    if request_code == REGISTRATION_REQUEST_CODE:
        print(f"{addr[0]} - Registration Request")
        # Client Registration
        username = request.payload['name']
        password = request.payload['password']
        registration_response, response_code, client_id = auth_server.registration_request(username, password)
        client.send(registration_response)
        # After registration client need to sign in
        if response_code == REGISTRATION_SUCCEED:
            print(f"{addr[0]}:{client_id} Registration Succeed")
            packed_request = client.recv(BUFFER_SIZE)
            request = Request.unpack(packed_request)
            symmetric_key_response = auth_server.symmetric_key_request(request)
            client.send(symmetric_key_response)
        else:
            print(f"{addr[0]}: Registration Failed.")
    elif request_code == SYMMETRIC_REQUEST_CODE:
        print(f"{addr[0]}:{request.client_id} - Symmetric Key Request")
        symmetric_key_response = auth_server.symmetric_key_request(request)
        client.send(symmetric_key_response)
    else:
        raise ValueError("Invalid request code.")
    client.close()


def main():
    auth_server = AuthenticationServer()
    auth_server.load_endpoint("port.info")
    auth_server.load_msg_server("msg.info")
    auth_server.load_clients_list("clients")
    print("Waiting to Connection...")
    while True:
        # Listening for connection request
        client, addr = auth_server.listen()
        threading.Thread(target=provide_service, args=(client, addr, auth_server)).start()


if __name__ == "__main__":
    main()