from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta
from Utilization import *
import base64

def main():
    """Start: Encryption and Decryption"""
    # # Encryption
    # plain_text = "hello world"
    # key = get_random_bytes(32)
    # cipher = AES.new(key, AES.MODE_CBC)
    # encrypted_text = cipher.encrypt(pad(str(plain_text).encode(), AES.block_size))
    # print(encrypted_text)
    # print(cipher.iv)
    #
    # # Decryption
    # iv = cipher.iv
    # cipher = AES.new(key, AES.MODE_CBC, iv)
    # plain_text = unpad(cipher.decrypt(encrypted_text), AES.block_size).decode()
    # print(plain_text)
    """End: Encryption and Decryption"""


    """Start: Encyrpting time"""
    # key = get_random_bytes(32)
    # iv = get_random_bytes(16)
    # # Sample datetime.
    # current_time = datetime.now()
    # print(current_time)
    # encrypted_ct = encrypt_time(current_time, key, iv)
    # current_time = decrypt_time(encrypted_ct, key, iv)
    # print(current_time)
    """End: Encyrpting time"""

    # password = "amjad123"
    # h = SHA256.new()
    # h.update(password.encode('utf-8'))
    # key = h.digest()
    # iv = get_random_bytes(16)
    # plain_text = "credit number 1234 5678 1234 1234"
    #
    # cipher = AES.new(key, AES.MODE_CBC, iv)
    # encrypted_text = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    #
    # password = "amjad123"
    # h = SHA256.new()
    # h.update(password.encode('utf-8'))
    # key = h.digest()
    # cipher = AES.new(key, AES.MODE_CBC, iv)
    # print(unpad(cipher.decrypt(encrypted_text), AES.block_size).decode(('utf-8')))

    key = get_random_bytes(32)
    print(key)
    key_b64 = base64.b64encode(key).decode()
    print(len(key_b64))
    print(base64.b64decode(key_b64))


if __name__ == '__main__':
    main()