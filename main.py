import os
import subprocess
import threading
import socket
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta

import Client
from Utilization import *
import base64
import Client

CLIENTS_FOLDER_DDOS_ATTACK = "DDOS_CLIENTS"
MESSAGE_SERVER_UUID = "64f3f63985f04beb81a0e43321880182"
CLIENTS_AMOUNT = 1


def main():
    if not os.path.exists(CLIENTS_FOLDER_DDOS_ATTACK):
        os.mkdir(CLIENTS_FOLDER_DDOS_ATTACK)
    os.chdir(CLIENTS_FOLDER_DDOS_ATTACK)
    parent_directory = os.getcwd()
    for i in range(CLIENTS_AMOUNT):
        filename = "c" + str(i)
        os.mkdir(filename)
        os.chdir(filename)
        with open("srv.info", "w") as file:
            file.write("127.0.0.1:5555\n127.0.0.1:9999\n")
            os.chdir(parent_directory)


    for i in range(CLIENTS_AMOUNT):
        filename = "c" + str(i)
        os.chdir(filename)
        input_data = "C" + str(i) + "\nc" + str(i) + "\n"
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)
        output, error = process.communicate(input=input_data)



if __name__ == '__main__':
    main()