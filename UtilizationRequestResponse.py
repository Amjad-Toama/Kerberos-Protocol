import struct
from datetime import datetime


def pack_encrypted_key(encrypted_key):
    packed_encrypted_key_iv = encrypted_key['encrypted_key_iv']
    packed_nonce = encrypted_key['nonce']
    packed_aes_key = encrypted_key['aes_key']
    packed_encrypted_key = packed_encrypted_key_iv + packed_nonce + packed_aes_key
    return packed_encrypted_key


def unpack_encrypted_key(packed_encrypted_key):
    encrypted_key_iv = packed_encrypted_key[:16]
    nonce = packed_encrypted_key[16:32]
    aes_key = packed_encrypted_key[32:64]
    encrypted_key = {'encrypted_key_iv': encrypted_key_iv, 'nonce': nonce, 'aes_key': aes_key}
    return encrypted_key


def pack_ticket(ticket):
    packed_version = struct.pack('B', ticket['version'])
    packed_client_id = bytes.fromhex(ticket['client_id'])
    packed_server_id = bytes.fromhex(ticket['server_id'])
    packet_creation_time = struct.pack('Q', int(ticket['creation_time'].timestamp()))
    packet_ticket_iv = ticket['ticket_iv']
    packed_aes_key = ticket['aes_key']
    packed_expiration_time = struct.pack('Q', int(ticket['expiration_time'].timestamp()))
    packed_ticket = (packed_version + packed_client_id + packed_server_id + packet_creation_time + packet_ticket_iv
                     + packed_aes_key + packed_expiration_time)
    return packed_ticket


def unpack_ticket(packed_ticket):
    version = struct.unpack('B', packed_ticket[:1])[0]
    client_id = packed_ticket[1:17].hex()
    server_id = packed_ticket[17:33].hex()
    creation_time = datetime.fromtimestamp(struct.unpack('Q', packed_ticket[33:41])[0])
    ticket_iv = packed_ticket[41:57]
    aes_key = packed_ticket[57:89]
    expiration_time = datetime.fromtimestamp(struct.unpack('Q', packed_ticket[89:97])[0])
    ticket = {
        'version': version,
        'client_id': client_id,
        'server_id': server_id,
        'creation_time': creation_time,
        'ticket_iv': ticket_iv,
        'aes_key': aes_key,
        'expiration_time': expiration_time
    }
    return ticket


def pack_encrypted_authenticator(authenticator):
    packed_authenticator_iv = authenticator['authenticator_iv']
    packed_version = authenticator['version']
    packed_client_id = authenticator['client_id']
    packed_server_id = authenticator['server_id']
    # TODO: Will changed after encrypting the creation_time
    packed_creation_time = struct.pack('Q', int(authenticator['creation_time'].timestamp()))
    packed_authenticator = (packed_authenticator_iv + packed_version + packed_client_id + packed_server_id +
                            packed_creation_time)
    print(len(packed_authenticator))
    return packed_authenticator


def unpack_encrypted_authenticator(packed_authenticator):
    authenticator_iv = packed_authenticator[:16]
    version = packed_authenticator[16:32]
    client_id = packed_authenticator[32:64]
    server_id = packed_authenticator[64:96]
    # TODO: Will be changed after encrypting the creation_time
    creation_time = datetime.fromtimestamp(struct.unpack('Q', packed_authenticator[96:104])[0])
    encrypted_authenticator = {
        'authenticator_iv': authenticator_iv,
        'version': version,
        'client_id': client_id,
        'server_id': server_id,
        'creation_time': creation_time
    }
    return encrypted_authenticator


def pack_message(message):
    packed_message_size = struct.pack('I', len(message['encrypted_message']))
    packed_message_iv = message['message_iv']
    packed_encrypted_message = message['encrypted_message']
    packed_message = packed_message_size + packed_message_iv + packed_encrypted_message
    return packed_message


def unpack_message(packed_message):
    message_size = struct.unpack('I', packed_message[:4])[0]
    message_iv = packed_message[4:20]
    encrypted_message = packed_message[20:]
    message = {
        'message_iv': message_iv,
        'encrypted_message': encrypted_message
    }
    return message
