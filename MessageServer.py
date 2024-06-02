import socket
import threading
import time
from Request import *
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
        # TODO: to decrypt creation_time
        creation_time = encrypted_authenticator['creation_time']
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
        packed_request = client.recv(1024)
        request = Request.unpack(packed_request)
        payload = request.payload
        iv = payload['message_iv']
        encrypted_message = payload['encrypted_message']
        cipher = AES.new(key, AES.MODE_CBC, iv)
        msg = unpad(cipher.decrypt(encrypted_message), AES.block_size).decode()
        print(f"{address[0]}: {msg}")


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
    auth_msg_symmetric_key = bytes.fromhex(get_symmetric_key("msg.info"))
    while True:
        server.listen()
        client, addr = server.accept()
        client.send("Connection Established".encode())
        # Receive request
        packed_request = client.recv(1024)
        request = Request.unpack(packed_request)
        ticket = request.payload['ticket']
        cipher = AES.new(auth_msg_symmetric_key, AES.MODE_CBC, ticket['ticket_iv'])
        aes_key = cipher.decrypt(ticket['aes_key'])
        authenticator = MessageServer.decrypt_authenticator(aes_key, request.payload['authenticator'])
        print(authenticator) # delete
        threading.Thread(target=receiving_messages, args=(client, addr[0], aes_key)).start()


if __name__ == '__main__':
    main()


