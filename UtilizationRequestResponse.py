"""
Facilitate in packing and unpacking both requests and responses, which include common functionality.
"""

import struct
from datetime import datetime


def pack_encrypted_key(encrypted_key):
    """
    pack encrypted key
    :param encrypted_key: encrypted_key as dictionary
    :return: encrypted_key as concatenated bytes
    """
    '''
    encrypted key: 80 bytes (total)
        iv     :   16 bytes
        nonce  :   16 bytes
        aes_key:   48 bytes
    '''
    packed_encrypted_key_iv = encrypted_key['encrypted_key_iv']
    packed_nonce = encrypted_key['nonce']
    packed_aes_key = encrypted_key['aes_key']
    # concatenate encrypted key as bytes
    packed_encrypted_key = packed_encrypted_key_iv + packed_nonce + packed_aes_key
    return packed_encrypted_key


def unpack_encrypted_key(packed_encrypted_key):
    """
    unpack the encrypted_key from bytes to the structure of original encrypted_key
    :param packed_encrypted_key: encrypted_key as bytes
    :return: encrypted_key in original structure
    """
    '''
    encrypted key: 80 bytes (total)
        iv     :   16 bytes
        nonce  :   16 bytes
        aes_key:   48 bytes
    '''
    encrypted_key_iv = packed_encrypted_key[:16]
    nonce = packed_encrypted_key[16:32]
    aes_key = packed_encrypted_key[32:80]
    encrypted_key = {'encrypted_key_iv': encrypted_key_iv, 'nonce': nonce, 'aes_key': aes_key}
    return encrypted_key


def pack_ticket(ticket):
    """
    pack ticket
    :param ticket: ticket as dictionary
    :return: ticket as concatenated bytes
    """
    '''
        ticket       :  137 bytes (total)
            version                  : 1 bytes
            client_uuid              : 16 bytes
            server_uuid              : 16 bytes
            creation_time            : 8 bytes
            ticket_iv                : 16 bytes
            encrypted_aes_key        : 48 bytes
            encrypted_expiration_time: 32 bytes
    '''
    # extract values from ticket
    packed_version = struct.pack('B', ticket['version'])
    # convert from hex representation to bytes
    packed_client_uuid = bytes.fromhex(ticket['client_uuid'])
    packed_server_uuid = bytes.fromhex(ticket['server_uuid'])
    # convert unsigned integer (4 bytes) to bytes
    packet_creation_time = struct.pack('Q', int(ticket['creation_time'].timestamp()))
    packet_ticket_iv = ticket['ticket_iv']
    packed_aes_key = ticket['aes_key']
    packed_expiration_time = ticket['expiration_time']
    packed_ticket = (packed_version + packed_client_uuid + packed_server_uuid + packet_creation_time + packet_ticket_iv
                     + packed_aes_key + packed_expiration_time)
    return packed_ticket


def unpack_ticket(packed_ticket):
    """
    unpack the ticket from bytes to the structure of original ticket
    :param packed_ticket: ticket as bytes
    :return: ticket in original structure
    """
    '''
    ticket: 137 bytes (total)
                version                  : 1 bytes
                client_uuid              : 16 bytes
                server_uuid              : 16 bytes
                creation_time            : 8 bytes
                ticket_iv                : 16 bytes
                encrypted_aes_key        : 48 bytes
                encrypted_expiration_time: 32 bytes
    '''
    # convert bytes to unsigned integer (1 bytes)
    version = struct.unpack('B', packed_ticket[:1])[0]
    # convert bytes to hex
    client_uuid = packed_ticket[1:17].hex()
    server_uuid = packed_ticket[17:33].hex()
    # convert bytes to datetime type
    creation_time = datetime.fromtimestamp(struct.unpack('Q', packed_ticket[33:41])[0])
    ticket_iv = packed_ticket[41:57]
    aes_key = packed_ticket[57:105]
    encrypted_expiration_time = packed_ticket[105:137]
    # create ticket
    ticket = {
        'version': version,
        'client_uuid': client_uuid,
        'server_uuid': server_uuid,
        'creation_time': creation_time,
        'ticket_iv': ticket_iv,
        'aes_key': aes_key,
        'expiration_time': encrypted_expiration_time
    }
    return ticket


def pack_encrypted_authenticator(authenticator):
    """
    pack encrypted_authenticator
    :param authenticator: encrypted_authenticator as dictionary
    :return: encrypted_authenticator as concatenated bytes
    """
    '''
    authenticator: 128 bytes (total)
        authenticator_iv       : 16 bytes
        encrypted_version      : 16 bytes
        encrypted_client_uuid  : 32 bytes
        encrypted_server_uuid  : 32 bytes
        encrypted_creation_time: 32 bytes
    '''
    packed_authenticator_iv = authenticator['authenticator_iv']
    packed_version = authenticator['version']
    packed_client_uuid = authenticator['client_uuid']
    packed_server_uuid = authenticator['server_uuid']
    packed_creation_time = authenticator['creation_time']
    packed_authenticator = (packed_authenticator_iv + packed_version + packed_client_uuid + packed_server_uuid +
                            packed_creation_time)
    return packed_authenticator


def unpack_encrypted_authenticator(packed_authenticator):
    """
    unpack the encrypted_authenticator from bytes to the structure of original encrypted_authenticator
    :param packed_authenticator: encrypted_authenticator as bytes
    :return: encrypted_authenticator in original structure
    """

    '''
    authenticator: 128 bytes (total)
        authenticator_iv       : 16 bytes
        encrypted_version      : 16 bytes
        encrypted_client_uuid  : 32 bytes
        encrypted_server_uuid  : 32 bytes
        encrypted_creation_time: 32 bytes
    '''
    # slicing packet
    authenticator_iv = packed_authenticator[:16]
    version = packed_authenticator[16:32]
    client_uuid = packed_authenticator[32:64]
    server_uuid = packed_authenticator[64:96]
    encrypted_creation_time = packed_authenticator[96:128]
    # create encrypted_authenticator
    encrypted_authenticator = {
        'authenticator_iv': authenticator_iv,
        'version': version,
        'client_uuid': client_uuid,
        'server_uuid': server_uuid,
        'creation_time': encrypted_creation_time
    }
    return encrypted_authenticator


def pack_message_header(message):
    """
    pack message_header
    :param message: message_header as dictionary
    :return: message_header as concatenated bytes
    """
    # convert 4 bytes unsigned integer to bytes
    packed_message_size = struct.pack('I', message['message_size'])
    packed_message_iv = message['message_iv']
    return packed_message_size + packed_message_iv


def unpack_message_header(packed_message):

    """
    unpack the message_header from bytes to the structure of original message_header
    :param packed_message: message_header as bytes
    :return: message_header in original structure
    """
    '''
    message_header:
        message_size: 4 bytes
        message_iv  : 16 bytes
    '''

    # convert bytes to unsigned integer 4 byte
    message_size = struct.unpack('I', packed_message[:4])[0]
    message_iv = packed_message[4:20]
    message_header = {
        'message_size': message_size,
        'message_iv': message_iv
    }
    return message_header
