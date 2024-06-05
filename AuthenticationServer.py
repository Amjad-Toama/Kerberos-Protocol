import socket
import threading
from datetime import timedelta

from Crypto.Random import get_random_bytes

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

    # # # # # # # # # # # # Registration  # # # # # # # # # # # # # # #

    def registration_request(self, request):
        """
        handle registration request from new client, check if registration is valid (username is valid), if so
        return success response, code, and client id otherwise, failed response, code, and None.
        :param request: Request | registration request
        :return: tuple | (packed Response - bytes, int, hex) - response, code, client ID
        """
        # extract new client info
        username = request.payload['name']
        password = request.payload['password']
        # check if the username is invalid
        if self.username_is_exist(username):    # registration failed.
            # failed response, failed code, and None as no client ID provided.
            return self.registration_failed_response(), REGISTRATION_FAILED, None
        else:   # registration succeed.
            # extract symmetric key from the password
            password_hash = get_password_hash(password)
            # generate unique client id
            client_id = self.get_new_client_id()
            # create new instant of client
            new_client = Client(client_id, username, password_hash, datetime.now())
            # store new client to memory.
            self.clients_dict[client_id] = new_client
            # save new client details to file.
            self.save_new_client(new_client)
            # success response, success code, and new client id
            return self.registration_succeed_response(client_id), REGISTRATION_SUCCEED, client_id

    @staticmethod
    def registration_failed_response():
        """
        return packed failed response
        :return: failed response as bytes
        """
        response = Response(VERSION, REGISTRATION_FAILED, {})
        return response.pack()

    @staticmethod
    def registration_succeed_response(client_id):
        """
        return packed success response
        :return: success response as bytes
        """
        response = Response(VERSION, REGISTRATION_SUCCEED, {'client_id': client_id})
        return response.pack()

    # # # # # # # # # # # # # Symmetric Key # # # # # # # # # # # # # #

    def symmetric_key_request(self, request):
        """
        Handle symmetric key request received from client
        :param request: Request | symmetric key request
        :return: packed Response - bytes | SEND_SYMMETRIC_KEY or GENERAL_RESPONSE_ERROR response
        """
        # Extract info for authentication process
        client_id = request.client_id
        server_id = request.payload['server_id']
        # Check if symmetric key request received from authorized entity.
        if not self.is_client(client_id) or not self.is_authorized_server(server_id):
            # unauthorized request
            response = Response(VERSION, GENERAL_RESPONSE_ERROR, {})
        else:
            # authentication process - succeed
            # extract details to generate aes key as response
            nonce = request.payload['nonce']
            # update client last seen.
            self.update_client_last_seen(client_id)
            # Generate symmetric key for client and required server.
            aes_key = get_random_bytes(KEY_LENGTH)
            # create encrypted key to client
            encrypted_key = self.get_encrypted_key(aes_key, self.clients_dict[client_id], nonce)
            # create ticket to message server
            ticket = self.get_ticket(aes_key, self.msg_server, client_id)
            # create payload
            payload = {
                'client_id': client_id,
                'encrypted_key': encrypted_key,
                'ticket': ticket
            }
            # prepare proper response
            response = Response(VERSION, SEND_SYMMETRIC_KEY, payload)
        # return packed response
        return response.pack()

    @staticmethod
    def get_encrypted_key(aes_key, client, nonce):
        """
        Create encrypted key encrypted using client password (extracted), update nonce value
        :param aes_key: aes key to be encrypted
        :param client: client to encrypt for
        :param nonce: nonce sent from client
        :return: dictionary encrypted key
        """
        # convert password to bytes
        key = bytes.fromhex(client.password_hash)
        # generate initial vector
        iv = get_random_bytes(IV_LENGTH)
        # encrypt the aes key
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_aes_key = cipher.encrypt(pad(aes_key, AES.block_size))
        # update the nonce value and encrypt it
        cipher = AES.new(key, AES.MODE_CBC, iv)
        nonce = nonce_update(nonce)
        encrypted_nonce = cipher.encrypt(pad(nonce, AES.block_size))  # encrypt nonce
        # create encrypted key
        encrypted_key = {
            'encrypted_key_iv': iv,
            'nonce': encrypted_nonce,
            'aes_key': encrypted_aes_key
        }
        return encrypted_key

    @staticmethod
    def get_ticket(aes_key, msg_server, client_id):
        """
        Create encrypted ticket using message server symmetric key
        :param aes_key: aes key to be encrypted
        :param msg_server: message server to encrypt for
        :param client_id: client ask for the request
        :return: dictionary | ticket
        """
        # Convert message server key to bytes
        key = bytes.fromhex(msg_server.key)
        # generate initial vector
        iv = get_random_bytes(IV_LENGTH)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Encrypt symmetric key.
        encrypted_aes_key = cipher.encrypt(pad(aes_key, AES.block_size))
        # Time stamp
        creation_time = datetime.now()
        # Add duration time TICKET_TIME_DURATION
        expiration_time = creation_time + timedelta(hours=TICKET_TIME_DURATION)
        encrypted_expiration_time = encrypt_time(expiration_time, key, iv)
        # create a ticket
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
        """
        update last seen of client in memory and on the file
        :param client: client entity
        :return:
        """
        # Current time
        now = datetime.now()
        # update the datetime in the memory
        self.clients_dict[client].set_last_seen(now)
        # TODO: update the file.

    def save_new_client(self, new_client):
        """
        store new client info into "client.info" file
        :param new_client:
        :return:
        """
        f = open(self.clients_file_path, "a")
        # write the new client info to file
        f.write(str(new_client) + "\n")
        f.close()

    def get_new_client_id(self):
        """
        Generate unique hex client ID of length ID_LENGTH
        :return: hex client ID
        """
        # generate random bytes of ID_LENGTH length
        client_id = get_random_bytes(ID_LENGTH).hex()
        # check if the generated client ID already exist.
        while client_id in self.clients_dict.keys():
            # generate random bytes of ID_LENGTH length
            client_id = get_random_bytes(ID_LENGTH).hex()
        return client_id

    def is_client(self, client_id):
        """
        check if client id is authorized to access the system
        :param client_id: hex client ID
        :return: true if registered, otherwise false
        """
        if client_id in self.clients_dict:
            return True
        print(f"{client_id}: Unauthorized client")
        return False

    def is_authorized_server(self, server_uuid):
        """
        check if the server_uuid is authorized and registered as server
        :param server_uuid: hex uuid
        :return: true if authorized, otherwise false
        """
        # check if provided uuid is equal to the one the authenticator server support
        if self.msg_server.uuid == server_uuid:
            return True
        print(f"{server_uuid}: Unauthorized server")
        return False

    def username_is_exist(self, username):
        """
        Check if client is registered in the system, if so return true. otherwise false.
        :param username: str, username
        :return: return true if user already registered. otherwise false
        """
        # check if the client exist in the memory.
        for client in self.clients_dict.keys():
            if self.clients_dict[client].name == username:
                return True
        return False

    def listen(self):
        """
        Listen to the defined endpoint
        :return: socket and address
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.ip_address, self.port_number))
        server.listen()
        client, addr = server.accept()
        return client, addr


def provide_service(client, addr, auth_server):
    packed_request = secured_receiving_packet(client)
    if packed_request is None:
        return
    # Unpack the received request
    request = Request.unpack(packed_request)
    request_code = request.request_code
    if request_code == REGISTRATION_REQUEST_CODE:
        print(f"{addr[0]} - Registration Request")
        registration_response, response_code, client_id = auth_server.registration_request(request)
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
