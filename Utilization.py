from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

VERSION = 24

def nonce_update(nonce):
    new_nonce = get_value(nonce) - 1
    return new_nonce.to_bytes(8, byteorder='big')


def get_value(nonce):
    return int.from_bytes(nonce, byteorder='big')


def encrypt_time(dt, key, iv):
    # Convert datetime to bytes
    dt_bytes = datetime_to_bytes(dt)
    # Encrypt datetime
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_dt = cipher.encrypt(pad(dt_bytes, AES.block_size))
    return encrypted_dt


def decrypt_time(encrypted_dt, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dt_bytes_padded = cipher.decrypt(encrypted_dt)
    dt_bytes = unpad(dt_bytes_padded, AES.block_size)
    dt = bytes_to_datetime(dt_bytes)
    return dt


def datetime_to_bytes(dt):
    return dt.isoformat().encode('utf-8')


def bytes_to_datetime(dt):
    return datetime.fromisoformat(dt.decode('utf-8'))

