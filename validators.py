import base64
import re
from datetime import datetime

MAX_PORT = 65535
MAX_NAME_LEN = 255
MAX_PASSWORD_LEN = 255
PASSWORD_SHA256_LEN = 32
CLIENT_ID_LENGTH = 16
ENDPOINT_COMPONENT = 2


def is_valid_ipv4(ip):
    # Regular expression for validating an IPv4 address
    ipv4_pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    return ipv4_pattern.match(ip) is not None


def is_valid_port(port_str):
    return isinstance(port_str, str) and port_str.isdigit() and 0 <= int(port_str) <= MAX_PORT


def is_valid_name(name):
    """
    Check client username is legal
    :param name: username as string
    :return: Return true if name is legal otherwise false
    """
    # Check if the name consist of letters only.
    return isinstance(name, str) and 0 < len(name) <= MAX_NAME_LEN


def is_valid_password(password):
    """
    Check if password is legal
    :param password: user password
    :return: Return true if password is legal otherwise false
    """
    # check legibility of length and type
    return isinstance(password, str) and 0 < len(password) <= MAX_PASSWORD_LEN


def is_valid_password_sha256(password_hash):
    return isinstance(password_hash, str) and len(password_hash) == PASSWORD_SHA256_LEN


def is_valid_uuid(uuid):
    return isinstance(uuid, str) and len(bytes.fromhex(uuid)) == CLIENT_ID_LENGTH


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
