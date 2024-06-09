"""
Check values validity, in type, range contexts
"""

import base64
import re
from datetime import datetime
from Constants import *
from Utilization import convert_bytes_to_integer


def is_valid_ipv4(ip):
    # Regular expression for validating an IPv4 address
    ipv4_pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    return ipv4_pattern.match(ip) is not None


def is_valid_port(port_str):
    return isinstance(port_str, str) and port_str.isdigit() and 0 <= int(port_str) <= PORT_MAX_VALUE


def is_valid_name(name):
    """
    Check client username is legal
    :param name: username as string
    :return: Return true if name is legal otherwise false
    """
    # Check if the name consist of letters only.
    return isinstance(name, str) and 0 < len(name) <= NAME_MAX_LEN


def is_valid_password(password):
    """
    Check if password is legal
    :param password: user password
    :return: Return true if password is legal otherwise false
    """
    # check legibility of length and type
    return isinstance(password, str) and 0 < len(password) <= PASSWORD_MAX_LEN


def is_valid_password_sha256(password_hash):
    return isinstance(password_hash, str) and len(password_hash) == PASSWORD_SHA256_LEN


def is_valid_uuid(uuid):
    return isinstance(uuid, str) and len(bytes.fromhex(uuid)) == UUID_LEN


def is_valid_iv(iv):
    if isinstance(iv, str):
        return len(bytes.fromhex(iv)) == IV_LEN
    elif isinstance(iv, bytes):
        return len(iv) == IV_LEN
    else:
        return False


def is_valid_datetime(datetime_str):
    if not isinstance(datetime_str, str):
        return False
    try:
        datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S.%f")
        return True
    except ValueError:
        return False


def is_valid_64base_symmetric_key(symmetric_key):
    try:
        # Decode the base64 string
        decoded_key = base64.b64decode(symmetric_key, validate=True)
        # Check if the decoded key length is 32 bytes
        if len(decoded_key) == 32:
            return True
        else:
            return False
    except (ValueError, TypeError):
        # If decoding fails, it's not a valid base64 string
        return False


def is_valid_endpoint(endpoint_str):
    if isinstance(endpoint_str, str) and len(endpoint_str.strip().split(':')) == ENDPOINT_COMPONENT:
        ip_str, port_str = endpoint_str.strip().split(':')
        return is_valid_ipv4(ip_str) and is_valid_port(port_str)
    return False


def is_valid_version(version):
    if isinstance(version, str) and version.isdigit():
        version = int(version)
    elif isinstance(version, bytes) and len(version) == VERSION_LEN:
        version = convert_bytes_to_integer(version)
    if isinstance(version, int):
        return VERSION_MIN_VALUE <= version <= VERSION_MAX_VALUE
    return False


def is_valid_code(code):
    if isinstance(code, str) and code.isdigit():
        code = int(code)
    elif isinstance(code, bytes) and len(code) == CODE_LEN:
        code = convert_bytes_to_integer(code)
    if isinstance(code, int):
        return CODE_MIN_VALUE <= code <= CODE_MAX_VALUE
    return False


def is_valid_nonce(nonce):
    if isinstance(nonce, str) and nonce.isdigit():
        nonce = int(nonce)
    elif isinstance(nonce, bytes):
        nonce = convert_bytes_to_integer(nonce)
    if isinstance(nonce, int):
        return NONCE_MIN_VALUE <= nonce <= NONCE_MAX_VALUE
    return False


def is_valid_encrypted_nonce(encrypted_nonce):
    return isinstance(encrypted_nonce, bytes) and len(encrypted_nonce) == ENCRYPTED_NONCE_LEN


def is_valid_encrypted_version(version):
    return isinstance(version, bytes) and len(version) == ENCRYPTED_VERSION_LEN


def is_valid_encrypted_uuid(uuid):
    return isinstance(uuid, bytes) and len(uuid) == ENCRYPTED_UUID_LEN


def is_valid_encrypted_time(time):
    return isinstance(time, bytes) and len(time) == ENCRYPTED_TIME_LEN


def is_valid_time(time):
    return (isinstance(time, datetime)
            or (isinstance(time, bytes) and len(time) == TIME_LEN))


def is_valid_encrypted_key(key):
    return isinstance(key, bytes) and len(key) == ENCRYPTED_KEY_LEN


def is_valid_message_size(message_size):
    if isinstance(message_size, bytes):
        message_size = convert_bytes_to_integer(message_size)
    if isinstance(message_size, int):
        return MESSAGE_MIN_SIZE <= message_size <= MESSAGE_MAX_SIZE
    return False
