import base64
import socket
import sys
import time
import threading
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def decrypt_message(message):
    return Fernet(decryption_key).decrypt(message)


if len(sys.argv) < 3:
    print("Wrong amount of arguments. should be two.")
    exit(-1)

#create the decryption key
password = bytes(sys.argv[1].encode())
salt = bytes(sys.argv[2].encode())
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
)
decryption_key = base64.urlsafe_b64encode(kdf.derive(password))


print("please enter listening port: ")
port = int(input())
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("", port))
s.listen()
# messages_for_next_round = []

while True:
    client_socket, client_address = s.accept()
    data = client_socket.recv(8192)
    content = decrypt_message(data).decode()
    t= time.localtime()
    current_time = str(t[3])+":"+str(t[4])+":"+str(t[5])
    print(content+ " " +current_time)
    print( "yupi")
#

# t = f.decrypt(data)
#
# print(t + current_time)
