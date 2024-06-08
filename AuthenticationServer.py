import os.path
import socket
import threading
from datetime import timedelta
from fileValidity import *

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
UUID_LENGTH = 16
KEY_LENGTH = 32
IV_LENGTH = 16
VERSION = 24
TICKET_TIME_DURATION = 1

CLIENTS_FILENAME = 'clients'
MESSAGE_SERVER_FILENAME = 'msg.info'
PORT_FILENAME = 'port.info'



class Client:
    """
    Client class used by Authentication Server, to manage system clients

    ################## Attributes ##################
     uuid           :   str in hex representation - client uuid
     name           :   str - client name
     password_hash  :   bytes - client password hash 32 bytes
     last_seen      :   datetime - last seen of client in system
    """
    def __init__(self, uuid, name, password_hash, last_seen):
        self.uuid, self.name, self.password_hash, self.last_seen = uuid, name, password_hash, last_seen

    def __str__(self):
        return f"{self.uuid}:{self.name}:{self.password_hash}:{self.last_seen}"

    def set_last_seen(self, now):
        """
        set client last seen
        :param now: datetime type
        :return:
        """
        self.last_seen = now


class Server:
    """
    Server class used by Authentication Server, to manage system servers

    ################## Attributes ##################
     uuid           :   str in hex representation - client uuid
     name           :   str - client name
     key            :   bytes - symmetric key between the registered server and the Authentication Server
     ip             :   str - server ip
     port           :   int - server port
    """
    def __init__(self, ip, port, name, uuid, key):
        self.ip, self.port, self.name, self.uuid, self.key = ip, port, name, uuid, key

    def __str__(self):
        return f"{self.ip}:{self.port}\n{self.name}\n{self.uuid}\n{self.key}"


class AuthenticationServer:
    """
    Authentication Server allow registered client and servers connect and securely communicate.
    By having symmetric keys of servers and clients, AS send client session key and ticket to be passed to server,
    in order to make them communicate.

    ################## Attributes ##################
    ip                  :   str - host ip
    port                :   int - AS port to listen on
    endpoint_filename   :   str - AS endpoint file
    clients_filename    :   str - registered clients.
    clients             :   dict - store clients details in memory which contain Client objects.
    msg_server          :   Server - the message server.
    """
    def __init__(self):
        # Loopback IP Address
        self.ip = "127.0.0.1"
        # Default port number
        self.port = 1256
        # Endpoint and Clients file path
        self.endpoint_filename, self.clients_filename, self.clients = None, None, None
        self.msg_server = None

    ###################################################################
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ################### Initialization Methods #################### #
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    ###################################################################

    def load_endpoint(self, filename):
        """
        load server endpoint from filename
        :param filename: filename contain networking details.
        :return:
        """
        # check if port file is valid.
        if filename == PORT_FILENAME and is_valid_port_file(filename):
            self.endpoint_filename = filename
            # store port number
            with open(filename) as file:
                self.port = int(file.read().strip())
        # in case of port file error use default port.
        else:
            print(f"Something went wrong with {filename} - Using default port {self.port}")

    def load_clients_list(self, filename):
        """
        load clients entities to memory
        :param filename: file contain clients details.
        :return: dict - clients dictionary contain clients details.
        """
        # check if clients file open.
        if filename == CLIENTS_FILENAME and is_valid_file_to_open(filename, "r"):
            self.clients_filename = filename
            with open(filename, "r") as file:
                # read file lines
                lines = file.readlines()
                self.clients = dict()
                # parse each line to store client into memory - dict
                for line in lines:
                    c_details = line.strip().split(':')
                    # client_uuid:client_name:client_passwordSHA256_hex_last_seen
                    self.clients[c_details[0]] = Client(c_details[0], c_details[1], c_details[2], c_details[3])
            return self.clients
        # file doesn't exist - create file and empty client dictionary
        elif not os.path.exists(filename):
            with open(filename, "w") as file:
                self.clients_filename = filename
                self.clients = dict()
                return self.clients
        # file error
        else:
            print(f"file error: {filename}")
            exit()

    def load_msg_server(self, filename):
        """
        Load message server details include ip, port, name, symmetric key, server uuid
        :param filename: file contain message server details
        :return:
        """
        # check if message file is valid.
        if filename == MESSAGE_SERVER_FILENAME and is_valid_msg_file(filename):
            with open(filename, "r") as file:
                lines = file.readlines()
                # parse message server details
                ip, port = lines[0].strip().split(":")
                port = int(port)
                name = lines[1].strip()
                uuid = lines[2].strip()
                # key stored in base 64 - stored as bytes in memory.
                key = base64.b64decode(lines[3].strip())
                self.msg_server = Server(ip, port, name, uuid, key)
        # error will halt the system.
        else:
            print(f"file error: {filename}")
            exit()

    ##################################################################
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ###################### Requests Methods ####################### #
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    ###################################################################

    # # # # # # # # # # # # Registration  # # # # # # # # # # # # # # #

    def registration_request(self, request):
        """
        handle registration request from new client, check if registration is valid (username is valid), if so
        return success response, code, and client uuid otherwise, failed response, code, and None.
        :param request: Request | registration request
        :return: tuple | (packed Response - bytes, int, hex) - response, code, client UUID
        """
        # extract new client info
        username = request.payload['name']
        password = request.payload['password']
        # check if the username is invalid
        if self.username_is_exist(username):    # registration failed.
            # failed response, failed code, and None as no client UUID provided.
            return self.registration_failed_response(), REGISTRATION_FAILED, None
        else:   # registration succeed.
            # extract symmetric key from the password
            password_hash = get_password_hash(password)
            # generate unique client uuid
            client_uuid = self.get_new_client_uuid()
            # create new instant of client
            new_client = Client(client_uuid, username, password_hash, datetime.now())
            # store new client to memory.
            self.clients[client_uuid] = new_client
            # save new client details to file.
            self.save_new_client(new_client)
            # success response, success code, and new client uuid
            return self.registration_succeed_response(client_uuid), REGISTRATION_SUCCEED, client_uuid

    @staticmethod
    def registration_failed_response():
        """
        return packed failed response
        :return: failed response as bytes
        """
        response = Response(VERSION, REGISTRATION_FAILED, {})
        return response.pack()

    @staticmethod
    def registration_succeed_response(client_uuid):
        """
        return packed success response
        :return: success response as bytes
        """
        response = Response(VERSION, REGISTRATION_SUCCEED, {'client_uuid': client_uuid})
        return response.pack()

    # # # # # # # # # # # # # Symmetric Key # # # # # # # # # # # # # #

    def symmetric_key_request(self, request):
        """
        Handle symmetric key request received from client
        :param request: Request | symmetric key request
        :return: packed Response - bytes | SEND_SYMMETRIC_KEY or GENERAL_RESPONSE_ERROR response
        """
        # Extract info for authentication process
        client_uuid = request.client_uuid
        server_uuid = request.payload['server_uuid']
        # Check if symmetric key request received from authorized entity.
        if not self.is_client(client_uuid) or not self.is_authorized_server(server_uuid):
            # unauthorized request
            response = Response(VERSION, GENERAL_RESPONSE_ERROR, {})
        else:
            # authentication process - succeed
            # extract details to generate aes key as response
            nonce = request.payload['nonce']
            # update client last seen.
            self.update_client_last_seen(client_uuid)
            # Generate symmetric key for client and required server.
            aes_key = get_random_bytes(KEY_LENGTH)
            # create encrypted key to client
            encrypted_key = self.get_encrypted_key(aes_key, self.clients[client_uuid], nonce)
            # create ticket to message server
            ticket = self.get_ticket(aes_key, self.msg_server, client_uuid)
            # create payload
            payload = {
                'client_uuid': client_uuid,
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
    def get_ticket(aes_key, msg_server, client_uuid):
        """
        Create encrypted ticket using message server symmetric key
        :param aes_key: aes key to be encrypted
        :param msg_server: message server to encrypt for
        :param client_uuid: client ask for the request
        :return: dictionary | ticket
        """
        # Convert message server key to bytes
        key = msg_server.key
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
            'client_uuid': client_uuid,
            'server_uuid': msg_server.uuid,
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
        self.clients[client].set_last_seen(now)
        # TODO: update the file.

    def save_new_client(self, new_client):
        """
        store new client info into "client.info" file
        :param new_client:
        :return:
        """
        f = open(self.clients_filename, "a")
        # write the new client info to file
        f.write(str(new_client) + "\n")
        f.close()

    def get_new_client_uuid(self):
        """
        Generate unique hex client UUID of length UUID_LENGTH
        :return: hex client UUID
        """
        # generate random bytes of ID_LENGTH length
        client_uuid = get_random_bytes(UUID_LENGTH).hex()
        # check if the generated client UUID already exist.
        while client_uuid in self.clients.keys():
            # generate random bytes of ID_LENGTH length
            client_uuid = get_random_bytes(UUID_LENGTH).hex()
        return client_uuid

    def is_client(self, client_uuid):
        """
        check if client id is authorized to access the system
        :param client_uuid: hex client ID
        :return: true if registered, otherwise false
        """
        if client_uuid in self.clients:
            return True
        print(f"{client_uuid}: Unauthorized client")
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
        for client in self.clients.keys():
            if self.clients[client].name == username:
                return True
        return False

    def listen(self):
        """
        Listen to the defined endpoint
        :return: socket and address
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.ip, self.port))
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
        registration_response, response_code, client_uuid = auth_server.registration_request(request)
        client.send(registration_response)
        # After registration client need to sign in
        if response_code == REGISTRATION_SUCCEED:
            print(f"{addr[0]}:{client_uuid} Registration Succeed")
            packed_request = client.recv(BUFFER_SIZE)
            request = Request.unpack(packed_request)
            symmetric_key_response = auth_server.symmetric_key_request(request)
            client.send(symmetric_key_response)
        else:
            print(f"{addr[0]}: Registration Failed.")
    elif request_code == SYMMETRIC_REQUEST_CODE:
        print(f"{addr[0]}:{request.client_uuid} - Symmetric Key Request")
        symmetric_key_response = auth_server.symmetric_key_request(request)
        client.send(symmetric_key_response)
    else:
        raise ValueError("Invalid request code.")
    client.close()


def main():
    auth_server = AuthenticationServer()
    auth_server.load_endpoint(PORT_FILENAME)
    auth_server.load_msg_server(MESSAGE_SERVER_FILENAME)
    auth_server.load_clients_list(CLIENTS_FILENAME)
    print("Waiting to Connection...")
    while True:
        # Listening for connection request
        client, addr = auth_server.listen()
        threading.Thread(target=provide_service, args=(client, addr, auth_server)).start()


if __name__ == "__main__":
    main()
