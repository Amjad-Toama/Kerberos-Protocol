"""
Utilization module provide repeated functionality used by various modules.

    * def convert_bytes_to_integer(nonce) - return integer
        - Convert nonce bytes representation to integer representation.

    * def nonce_update(nonce) - return bytes
        - Update the value of nonce

    * def bytes_to_datetime(dt) - return datetime
        - Convert bytes type to datetime type representation

    * def datetime_to_bytes(dt) - return bytes
        - Convert datetime type to bytes representation

    * def encrypt_time(dt, key, iv) - return bytes
        - Encrypt the datetime

    * def decrypt_time(encrypted_dt, key, iv) - return datetime
        - decrypt datetime type

    * secured_receiving_packet(client) - return bytes
        - Receiving packet and ensure prevent crashing to the receiver

    * def receive_long_encrypted_message(client, message_length) - return bytes
        - Handle long messages content, support any length

    * def get_client_info() - return string, string
        - Ask for user info and check correctness

    * def get_name() - return string
        - Ask user for legal client name

    * def get_password() - return string
        - Ask user for legal client password

    * def legal_name(name) - return boolean
        - Check client name is legal

    * def legal_password(password) - return boolean
        - Check if password is legal

    * def get_password_hash(password): return hex
        - given string password, extract the 32 byte key in hex

    * def clear_console() - return void
        - Clean the console

"""

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

VERSION = 24
# The maximum size of buffer, to transfer or receive.
BUFFER_SIZE = 4096

MAX_NAME_LEN = 255
MAX_PASSWORD_LEN = 255


def convert_bytes_to_integer(nonce):
    """
    Convert nonce bytes representation to integer representation
    :param nonce: Bytes representation of the nonce value
    :return: Integer representation of the updated value
    """
    return int.from_bytes(nonce, byteorder='big')


def nonce_update(nonce):
    """
    Update the value of nonce
    :param nonce: Bytes representation of the nonce value
    :return: Bytes representation of the updated value
    """
    # The challenge is to increment the nonce value by 1
    new_nonce = convert_bytes_to_integer(nonce) + 1
    return new_nonce.to_bytes(8, byteorder='big')


def datetime_to_bytes(dt):
    """
    Convert datetime type to bytes representation
    :param dt: datetime type to be converted
    :return: bytes type representation
    """
    return dt.isoformat().encode('utf-8')


def bytes_to_datetime(dt):
    """
    Convert bytes type to datetime type representation
    :param dt: datetime represented in bytes to be converted
    :return: datetime type representation
    """
    return datetime.fromisoformat(dt.decode('utf-8'))


def encrypt_time(dt, key, iv):
    """
    Encrypt the datetime
    :param dt: datetime type to encrypt
    :param key: key to encrypt the datetime
    :param iv: initial vector to use in encryption
    :return: encrypted padded datetime
    """
    # Convert datetime to bytes.
    dt_bytes = datetime_to_bytes(dt)
    # Encrypt datetime
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_dt = cipher.encrypt(pad(dt_bytes, AES.block_size))
    return encrypted_dt


def decrypt_time(encrypted_dt, key, iv):
    """
    decrypt datetime type
    :param encrypted_dt: encrypted datetime by key and iv
    :param key: the key to decrypt
    :param iv:  the initial vector
    :return: decrypted datetime
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypting and undo padding the encrypted datetime
    dt_bytes = unpad(cipher.decrypt(encrypted_dt), AES.block_size)
    # Convert the datetime bytes representation to datetime type.
    dt = bytes_to_datetime(dt_bytes)
    return dt


def secured_receiving_packet(client):
    """
    Receiving packet and ensure prevent crashing to the receiver
    :param client: The client side
    :return: if message received return the message otherwise, return None
    """
    # receive a message.
    try:
        packet = client.recv(BUFFER_SIZE)
        if not packet:
            print("Disconnected from the server.")
        else:
            return packet
    except OSError:
        print("Connection closed")
    except Exception as e:
        print(f"An error occurred {e}")
    return None


def receive_long_encrypted_message(client, message_length):
    """
    Handle long messages content, support any length
    :param client: the client socket to receive the message
    :param message_length: the message length to receive.
    :return: the content of encrypted message
    """
    # count the received bytes.
    received_bytes = 0
    # the message to be concatenated to and then returned
    encrypted_message = b''
    # while whole message doesn't receive
    while received_bytes < message_length:
        # receive the message.
        packed_message = secured_receiving_packet(client)
        # Concatenate the messages
        encrypted_message += packed_message
        # Update the received bytes amounts
        received_bytes += len(packed_message)
    return encrypted_message


def get_client_info():
    """
    Ask for user info and check correctness
    :return: client name and password as tuple
    """
    name = get_name()
    password = get_password()
    return name, password


def get_name():
    """
    Ask user for legal client name
    :return: legal client name
    """
    name = input("Enter name: ").lower()
    while not legal_name(name):
        name = input("Enter name: ")
    return name


def get_password():
    """
    Ask user for legal client password
    :return: legal client password
    """
    password = input("Enter password: ")
    while not legal_password(password):
        password = input("Enter password: ")
    return password


def legal_name(name):
    """
    Check client name is legal
    :param name: name as string
    :return: Return true if name is legal otherwise false
    """
    # Check if the name consist of letters only.
    if not name.isalpha():
        print(f"{name} must contain letters only. Try Again.\n")
        return False
    # name password is legal
    elif len(name) > MAX_NAME_LEN:
        print(f"{name} too long (maximum length {MAX_NAME_LEN}). Try Again.\n")
        return False
    else:
        return True


def legal_password(password):
    """
    Check if password is legal
    :param password: user password
    :return: Return true if password is legal otherwise false
    """
    # Check legal length
    if len(password) > MAX_PASSWORD_LEN:
        print(f"{password} too long (maximum length {MAX_PASSWORD_LEN}). Try Again.\n")
        return False
    else:
        return True


def clear_console():
    """
    Clean the console
    :return:
    """
    print("\n" * 100)


def get_password_hash(password):
    """
    given string password, extract the 32 byte key
    :param password: str, password
    :return: 32 bytes key in hex
    """
    h = SHA256.new()
    h.update(password.encode('utf-8'))
    return h.hexdigest()
