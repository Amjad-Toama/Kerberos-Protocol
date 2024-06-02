from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta

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
    # datetime type
    creation_time = datetime.now()
    # print(creation_time)
    # print(type(creation_time))
    # string type
    to_be_encrypted = str(creation_time)
    # print(to_be_encrypted)
    # print(type(to_be_encrypted))
    # bytes type
    to_be_encrypted = to_be_encrypted.encode()
    print(to_be_encrypted)
    # encrypting
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_time = cipher.encrypt(pad(to_be_encrypted, AES.block_size))
    print(encrypted_time)

    # decrypting
    iv = cipher.iv
    cipher = AES.new(key, AES.MODE_CBC, iv)
    my_time = unpad(cipher.decrypt(encrypted_time), AES.block_size)
    print(my_time)
    print(my_time.decode())
    """End: Encyrpting time"""

if __name__ == '__main__':
    main()