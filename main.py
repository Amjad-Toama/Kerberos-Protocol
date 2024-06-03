from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta
from Utilization import *

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

    message = b''
    message += get_random_bytes(1)
    print(type(message))

if __name__ == '__main__':
    main()