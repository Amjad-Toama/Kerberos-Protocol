import threading
from datetime import timedelta
from fileValidity import is_valid_msg_file
from Request import *
from Response import *
from Utilization import *

MESSAGE_SERVER_FILENAME = 'msg.info'
AUTHENTICATOR_LIFETIME = 1 / 12        # lifetime of authenticator : 5 minutes


class MessageServer:
    """
    Functionality of Message Server

    ################## Attributes ##################

    ip : str
        The IP that the server on.

    port : int
        The port the server listening on.

    name : str
        Message server name

    uuid : str
        Server uuid

    key : str
        Symmetric key shared between message server and authentication server

    #################### Methods ###################

    parse_endpoint_file(endpoint_file_path)
        Parse the information file and initialize the message server details.

    symmetric_key_request(packed_request)
        Received Request from user to connect and start communicate with message server

    decrypt_authenticator(aes_key, encrypted_authenticator)
        Decrypt the authenticator received from the user.

    """
    def __init__(self, endpoint_file_path=MESSAGE_SERVER_FILENAME):
        """
        Create a Message Server instance, initialize the attributes according to the information provided in
        endpoint_file_path file.
        file structure:
            ip:port
            name
            uuid
            symmetric key between Message server and the Authentication Server
        :param endpoint_file_path: File include the information to initialize the Message server.
        """
        self.ip = None
        self.port = None
        self.name = None
        self.uuid = None
        self.key = None
        self.parse_endpoint_file(endpoint_file_path)

    ###################################################################
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ############### Initialization Utility Methods ################ #
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    ###################################################################

    def parse_endpoint_file(self, filename):
        """
        Parse the information file and initialize the message server details
        file structure:
            ip:port
            name
            uuid
            symmetric key between Message server and the Authentication Server
        :param filename: message server details to initialize.
        :return:
        """
        # Open the file
        if filename == MESSAGE_SERVER_FILENAME and is_valid_msg_file(filename):
            with open(filename, "r") as file:
                lines = file.readlines()
                # Parse details line by line
                self.ip, self.port = lines[0].strip().split(":")
                self.port = int(self.port)
                self.name = lines[1].strip()
                self.uuid = lines[2].strip()
                self.key = base64.b64decode(lines[3].strip())
        else:
            print(f"Error occur in {filename} file.")

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
        print(f"{SEND_TICKET_REQUEST_CODE}: Send Symmetric Key Request")
        # check if request is valid, if legal client send it: avoid case of change on its way
        try:
            # unpack the request
            request = Request.unpack(packed_request)
        except ValueError:
            return None, None, None, GENERAL_RESPONSE_ERROR
        payload = request.payload
        # Extract the aes_key and decrypt it
        ticket = self.decrypt_ticket(payload['ticket'])
        # check if fake ticket send
        if ticket is None:
            packed_response = Response(VERSION, GENERAL_RESPONSE_ERROR, {}).pack()
            return None, None, packed_response, SYMMETRIC_KEY_RECEIVED
        # Decrypt authenticator values
        authenticator = MessageServer.decrypt_authenticator(ticket['aes_key'], payload['authenticator'])
        # Check Potential of replay attack, of fake authenticator.
        if (authenticator is None
                or ticket['expiration_time'] <= datetime.now()
                or not MessageServer.is_valid_authenticator(authenticator, ticket)):
            packed_response = Response(VERSION, GENERAL_RESPONSE_ERROR, {}).pack()
            return None, None, packed_response, GENERAL_RESPONSE_ERROR
        # The request is legal
        else:
            packed_response = Response(VERSION, SYMMETRIC_KEY_RECEIVED, {}).pack()
            return ticket, authenticator, packed_response, SYMMETRIC_KEY_RECEIVED

    def decrypt_ticket(self, encrypted_ticket):
        """
        decrypt ticket with the symmetric key, if decryption fails (fake ticket) return None
        :param encrypted_ticket: a ticket from Authenticator Server.
        :return: decrypted ticket, if decrypting fails return None
        """
        ticket_iv = encrypted_ticket['ticket_iv']
        cipher = AES.new(self.key, AES.MODE_CBC, ticket_iv)
        # try to decrypt the ticket, avoiding fake ticket sent by third part.
        try:
            aes_key = unpad(cipher.decrypt(encrypted_ticket['aes_key']), AES.block_size)
            expiration_time = decrypt_time(encrypted_ticket['expiration_time'], self.key, ticket_iv)
        except ValueError:
            return None
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
        # check case of fake authenticator sent by third party.
        try:
            # Decrypt version
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            # Decrypt the version
            version = int.from_bytes(unpad(cipher.decrypt(encrypted_authenticator['version']), AES.block_size),
                                     byteorder='big')
            # Decrypt client_uuid
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            client_uuid = unpad(cipher.decrypt(encrypted_authenticator['client_uuid']), AES.block_size).hex()
            # Decrypt uuid
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            server_uuid = unpad(cipher.decrypt(encrypted_authenticator['server_uuid']), AES.block_size).hex()
            # Decrypt creation time
            encrypted_creation_time = encrypted_authenticator['creation_time']
            creation_time = decrypt_time(encrypted_creation_time, aes_key, iv)
        except ValueError:
            return None
        # Building decrypted authenticator
        authenticator = {
            'authenticator_iv': iv,
            'version': version,
            'client_uuid': client_uuid,
            'server_uuid': server_uuid,
            'creation_time': creation_time
        }
        return authenticator

    @staticmethod
    def is_valid_authenticator(authenticator, ticket):
        """
        check if the authenticator session is valid, to prevent replay attack.
        :param authenticator: dictionary - client authenticator.
        :param ticket: dictionary - server ticket
        :return: boolean - true if authenticator and ticket values compatible and authenticator not expired.
        """
        if not ((authenticator['version'] == ticket['version'])
                and (authenticator['client_uuid'] == ticket['client_uuid'])
                and (authenticator['server_uuid'] == ticket['server_uuid'])
                and (authenticator['creation_time'] + timedelta(hours=AUTHENTICATOR_LIFETIME) > datetime.now())):
            print(f"{GENERAL_RESPONSE_ERROR}: Invalid Authenticator.")
            return False
        return True


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
        # in case socket crash
        send_succeed = secured_sending_packet(client, packed_response)
        if not send_succeed:
            return
        # error occur while extracting symmetric key - message appear in early stage.
        if response_code == GENERAL_RESPONSE_ERROR:
            client.close()
        else:
            # response_code == key_RECEIVED
            MessageServer.receiving_messages(client, ticket['aes_key'], ticket['expiration_time'])

    @staticmethod
    def receiving_messages(client, key, expiration_time):
        """
        Receive Message Request from the client which is encrypted with symmetric key between Message server and
        the client print the message to the screen. if the user want to stop the connection type 'exit'
        :param client: Active socket to receive message from
        :param key: symmetric key between Message server and the client
        :param expiration_time: Expiration time of connection\
        :return:
        """
        # Firstly, receive the message header (excluding the message content), to be aware of the message content
        # length. Then, start receiving the message content using receive_long_encrypted_message method that receive
        # long messages.
        while expiration_time > datetime.now():
            # receive the message header
            packed_request = secured_receiving_packet(client)
            # if packed request have issue
            if packed_request is None:
                return
            # check if request is valid, if legal client send it: avoid case of change on its way
            try:
                # unpack the request content.
                request = Request.unpack(packed_request)
            except ValueError:
                return
            print(f"{SEND_MESSAGE_REQUEST_CODE}: Send Message Request")
            # Extract important details.
            message_length = request.payload['message_size']
            message_iv = request.payload['message_iv']
            client_uuid = request.client_uuid
            # Receive messages support any message length
            encrypted_message = receive_long_encrypted_message(client, message_length)
            # Message content decryption
            cipher = AES.new(key, AES.MODE_CBC, message_iv)
            msg = unpad(cipher.decrypt(encrypted_message), AES.block_size).decode()
            """
            The client want to exit.
            Time of check expiration_time earlier than enforcement time, so message sent after
            expiration time will
            be dismissed.
            """
            # if session key expired.
            if expiration_time <= datetime.now():
                packed_response = Response(VERSION, GENERAL_RESPONSE_ERROR, {}).pack()
                # in case socket crash
                secured_sending_packet(client, packed_response)
                return
            # if client decide to end session
            if msg == 'exit':
                packed_response = Response(VERSION, MESSAGE_RECEIVED, {}).pack()
                secured_sending_packet(client, packed_response)
                return
            # if message received - replay with ack and print the message
            print(f"{client_uuid}: {msg}")
            packed_response = Response(VERSION, MESSAGE_RECEIVED, {}).pack()
            secured_sending_packet(client, packed_response)


def main():
    # msg_srv - message server instance
    msg_srv = MessageServer()
    # bind a socket to bind incoming connection.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((msg_srv.ip, msg_srv.port))
    print("Waiting to Connection...")
    while True:
        server.listen()
        client, addr = server.accept()
        # Handle parallel requests.
        threading.Thread(target=msg_srv.provide_service, args=(client, )).start()


if __name__ == '__main__':
    main()
