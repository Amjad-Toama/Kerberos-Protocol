import socket
import threading
import time
from datetime import timedelta

from Request import *
from Response import *
from Utilization import *

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


class MessageServer:
    def __init__(self, endpoint_file_path="msg.info"):
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
        fd = open(endpoint_file_path, "r")
        lines = fd.readlines()
        self.server_ip, self.server_port = lines[0].strip().split(":")
        self.server_port = int(self.server_port)
        self.server_name = lines[1].strip()
        self.server_id = lines[2].strip()
        self.symmetric_key = lines[3].strip()

    ###################################################################
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    # ##################### Utilization Methods ##################### #
    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
    ###################################################################

    def symmetric_key_request(self, packed_request):
        # unpack the request
        request = Request.unpack(packed_request)
        payload = request.payload
        ticket = payload['ticket']
        # Extract the aes_key and decrypt it
        ticket_iv = ticket['ticket_iv']
        key = bytes.fromhex(self.symmetric_key)
        cipher = AES.new(key, AES.MODE_CBC, ticket_iv)
        # TODO: unpad after adding the padding in the AS class.
        aes_key = cipher.decrypt(ticket['aes_key'])
        expiration_time = decrypt_time(ticket['expiration_time'], key, ticket_iv)
        # update ticket keys with decrypted values
        ticket['aes_key'] = aes_key
        ticket['expiration_time'] = expiration_time
        # Decrypt authenticator values
        authenticator = MessageServer.decrypt_authenticator(aes_key, payload['authenticator'])
        if expiration_time <= datetime.now():
            packed_response = Response(VERSION, GENERAL_RESPONSE_ERROR, None).pack()
            return None, None, packed_response, GENERAL_RESPONSE_ERROR
        packed_response = Response(VERSION, SYMMETRIC_KEY_RECEIVED, None).pack()
        return ticket, authenticator, packed_response, SYMMETRIC_KEY_RECEIVED

    @staticmethod
    def decrypt_authenticator(aes_key, encrypted_authenticator):
        iv = encrypted_authenticator['authenticator_iv']
        # Decrypt version
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        version = int.from_bytes(unpad(cipher.decrypt(encrypted_authenticator['version']), AES.block_size), byteorder='big')
        # Decrypt client_id
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        client_id = unpad(cipher.decrypt(encrypted_authenticator['client_id']), AES.block_size).hex()
        # Decrypt server_id
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        server_id = unpad(cipher.decrypt(encrypted_authenticator['server_id']), AES.block_size).hex()
        encrypted_creation_time = encrypted_authenticator['creation_time']
        creation_time = decrypt_time(encrypted_creation_time, aes_key, iv)
        authenticator = {
            'authenticator_iv': iv,
            'version': version,
            'client_id': client_id,
            'server_id': server_id,
            'creation_time': creation_time
        }
        return authenticator

    def extract_symmetric_key(self, data):
        pass


def receiving_messages(client, address, key):
    while True:
        packed_request = client.recv(BUFFER_SIZE)
        request = Request.unpack(packed_request)
        message_length = request.payload['message_size']
        message_iv = request.payload['message_iv']
        client_id = request.client_id
        encrypted_message = receive_encrypted_message(client, message_length)
        cipher = AES.new(key, AES.MODE_CBC, message_iv)
        msg = unpad(cipher.decrypt(encrypted_message), AES.block_size).decode()
        print(f"{client_id}: {msg}")


def receive_encrypted_message(client, message_length):
    received_bytes = 0
    encrypted_message = b''
    while received_bytes < message_length:
        packed_message = client.recv(BUFFER_SIZE)
        encrypted_message += packed_message
        received_bytes += len(packed_message)
    return encrypted_message

# load message server details.
def get_symmetric_key(msg_server_file_path):
    fd = open(msg_server_file_path, "r")
    lines = fd.readlines()
    symmetric_key = lines[3].strip()
    fd.close()
    return symmetric_key


def main():
    msg_srv = MessageServer()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((msg_srv.server_ip, msg_srv.server_port))
    while True:
        server.listen()
        client, addr = server.accept()
        # Receive request SEND_TICKET_REQUEST
        packed_request = client.recv(BUFFER_SIZE)
        ticket, authenticator, packed_response, response_code = msg_srv.symmetric_key_request(packed_request)
        client.send(packed_response)
        if response_code == GENERAL_RESPONSE_ERROR:
            client.close()
        else:
            # response_code == SYMMETRIC_KEY_RECEIVED
            threading.Thread(target=receiving_messages, args=(client, addr[0], ticket['aes_key'])).start()


if __name__ == '__main__':
    main()


