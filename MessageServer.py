import socket
import threading
from Request import *
from Response import *
from Utilization import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


class MessageServer:
    """
    Functionality of Message Server

    ################## Attributes ##################

    server_ip : str
        The IP that the server on.

    server_port : int
        The port the server listening on.

    server_name : str
        Message server name

    server_id : str
        Server uuid

    symmetric_key : str
        Symmetric key shared between message server and authentication server

    #################### Methods ###################

    parse_endpoint_file(endpoint_file_path)
        Parse the information file and initialize the message server details.

    symmetric_key_request(packed_request)
        Received Request from user to connect and start communicate with message server

    decrypt_authenticator(aes_key, encrypted_authenticator)
        Decrypt the authenticator received from the user.

    """
    def __init__(self, endpoint_file_path="msg.info"):
        """
        Create a Message Server instance, initialize the attributes according to the information provided in
        endpoint_file_path file.
        file structure:
            ip:port
            server_name
            server_uuid
            symmetric key between Message server and the Authentication Server
        :param endpoint_file_path: File include the information to initialize the Message server.
        """
        self.server_ip = None
        self.server_port = None
        self.server_name = None
        self.server_id = None
        self.symmetric_key = None
        self.parse_endpoint_file(endpoint_file_path)

    ###################################################################
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ############### Initialization Utility Methods ################ #
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    ###################################################################

    def parse_endpoint_file(self, endpoint_file_path):
        """
        Parse the information file and initialize the message server details
        file structure:
            ip:port
            server_name
            server_uuid
            symmetric key between Message server and the Authentication Server
        :param endpoint_file_path: message server details to initialize.
        :return:
        """
        # Open the file
        try:
            with open(endpoint_file_path, "r") as file:
                lines = file.readlines()
                # Parse details line by line
                self.server_ip, self.server_port = lines[0].strip().split(":")
                self.server_port = int(self.server_port)
                self.server_name = lines[1].strip()
                self.server_id = lines[2].strip()
                self.symmetric_key = lines[3].strip()
        except FileNotFoundError:
            print(f"{endpoint_file_path} file not found.")

    ###################################################################
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ##################### Utilization Methods ##################### #
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    ###################################################################

    def symmetric_key_request(self, packed_request):
        """
        Handle connection request from user, check potential of replay attack
        :param packed_request: packed request from the user
        :return: In valid case, return decrypted ticket, decrypted authenticator, packet response, and Response code.
        """
        # unpack the request
        request = Request.unpack(packed_request)
        payload = request.payload
        # Extract the aes_key and decrypt it
        ticket = self.decrypt_ticket(payload['ticket'])
        # Decrypt authenticator values
        authenticator = MessageServer.decrypt_authenticator(ticket['aes_key'], payload['authenticator'])
        # Check Potential of replay attack
        if ticket['expiration_time'] <= datetime.now():
            packed_response = Response(VERSION, GENERAL_RESPONSE_ERROR, None).pack()
            ticket = authenticator = None
        # The request is legal
        else:
            packed_response = Response(VERSION, SYMMETRIC_KEY_RECEIVED, None).pack()
        return ticket, authenticator, packed_response, SYMMETRIC_KEY_RECEIVED

    def decrypt_ticket(self, encrypted_ticket):
        """
        decrypt ticket
        :param encrypted_ticket: a ticket from Authenticator Server.
        :return: decrypted ticket
        """
        key = bytes.fromhex(self.symmetric_key)
        ticket_iv = encrypted_ticket['ticket_iv']
        cipher = AES.new(key, AES.MODE_CBC, ticket_iv)
        aes_key = unpad(cipher.decrypt(encrypted_ticket['aes_key']), AES.block_size)
        expiration_time = decrypt_time(encrypted_ticket['expiration_time'], key, ticket_iv)
        # update ticket keys with decrypted values
        encrypted_ticket['aes_key'] = aes_key
        encrypted_ticket['expiration_time'] = expiration_time
        ticket = encrypted_ticket
        return ticket

    @staticmethod
    def decrypt_authenticator(aes_key, encrypted_authenticator):
        """
        Decrypted the authenticator
        :param aes_key: symmetric key shared between the user and the message server
        :param encrypted_authenticator: the encrypted authenticator
        :return: decrypted authenticator
        """
        iv = encrypted_authenticator['authenticator_iv']
        # Decrypt version
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        # Decrypt the version
        version = int.from_bytes(unpad(cipher.decrypt(encrypted_authenticator['version']), AES.block_size),
                                 byteorder='big')
        # Decrypt client_id
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        client_id = unpad(cipher.decrypt(encrypted_authenticator['client_id']), AES.block_size).hex()
        # Decrypt server_id
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        server_id = unpad(cipher.decrypt(encrypted_authenticator['server_id']), AES.block_size).hex()
        # Decrypt creation time
        encrypted_creation_time = encrypted_authenticator['creation_time']
        creation_time = decrypt_time(encrypted_creation_time, aes_key, iv)
        # Building decrypted authenticator
        authenticator = {
            'authenticator_iv': iv,
            'version': version,
            'client_id': client_id,
            'server_id': server_id,
            'creation_time': creation_time
        }
        return authenticator

    def provide_service(self, client):
        """
        Provide services to clients
        :param client: client to communicate with
        :return:
        """
        # Receive request SEND_TICKET_REQUEST
        packed_request = client.recv(BUFFER_SIZE)
        # Extract request details for messages request.
        ticket, authenticator, packed_response, response_code = self.symmetric_key_request(packed_request)
        client.send(packed_response)
        if response_code == GENERAL_RESPONSE_ERROR:
            client.close()
        else:
            # response_code == SYMMETRIC_KEY_RECEIVED
            MessageServer.receiving_messages(client, ticket['aes_key'], ticket['expiration_time'])

    @staticmethod
    def receiving_messages(client, key, expiration_time):
        """
        Receive Message Request from the client which is encrypted with symmetric key between Message server and
        the client print the message to the screen. if the user want to stop the connection type 'exit'
        :param client: Active socket to receive message from
        :param key: symmetric key between Message server and the client
        :param expiration_time: Expiration time of connection
        :return:
        """

        # Firstly, receive the message header (excluding the message content), to be aware of the message content
        # length. Then, start receiving the message content using receive_long_encrypted_message method that receive
        # long messages.
        while expiration_time > datetime.now():
            # receive the message header
            packed_request = secured_receiving_packet(client)
            # check if the connection failed.
            if packed_request is not None:
                # unpack the request content.
                request = Request.unpack(packed_request)
                # Extract important details.
                message_length = request.payload['message_size']
                message_iv = request.payload['message_iv']
                client_id = request.client_id
                # Receive messages support any message length
                encrypted_message = receive_long_encrypted_message(client, message_length)
                # Message content decryption
                cipher = AES.new(key, AES.MODE_CBC, message_iv)
                msg = unpad(cipher.decrypt(encrypted_message), AES.block_size).decode()
                # The client want to exit.
                # Time of check expiration_time earlier than enforcement time, so message sent after
                # expiration time will
                # be dismissed.
                if expiration_time <= datetime.now():
                    packed_response = Response(VERSION, GENERAL_RESPONSE_ERROR, {}).pack()
                    client.send(packed_response)
                    return
                if msg == 'exit':
                    return
                # print the message
                print(f"{client_id}: {msg}")
                packed_response = Response(VERSION, MESSAGE_RECEIVED, {}).pack()
                client.send(packed_response)
            else:
                # error case
                return


def main():
    # msg_srv - message server instance
    msg_srv = MessageServer()
    # bind a socket to bind incoming connection.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((msg_srv.server_ip, msg_srv.server_port))
    print("Waiting to Connection...")
    while True:
        server.listen()
        client, addr = server.accept()
        # Handle parallel requests.
        threading.Thread(target=msg_srv.provide_service, args=(client, )).start()


if __name__ == '__main__':
    main()
