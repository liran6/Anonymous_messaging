from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from threading import Thread, Lock
import threading
import random
import socket
import sys


# def send_message(message, ip, port):
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.connect((ip, port))
#     s.send(message)
#     s.close()


def decryptor(cipher_text, private_key):
    return private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def encryp_check(message, private_key):
    message = decryptor(message, private_key)
    # print(message)
    port = []
    ip = ""
    msg = list(message)
    for i in range(4):
        ip = ip + str(msg.pop(0))
        if i != 3:
            ip += "."

    # -- convert the byte of the port value -- #
    for i in range(2):
        port.append(msg.pop(0))
    port = int.from_bytes(port, byteorder='big', signed=False)

    msg = bytes(msg)  # this is the "real" message
    print(msg)
    print(ip)
    print(port)
    print("------------------------------------------------------------------------\n")
    message = msg
    return ip, port, message

def send_message(message, ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.send(message)
    s.close()


#     get the decrypted message with the address & port and forward it to send.
def analyze_data():
    #     create the next circle of analyzing
    t = threading.Timer(60.0, analyze_data)
    t.start()
    size = len(messages)
    mutex.acquire()
    while len(messages) > 0:
        i = random.choice(range(len(messages)))
        m = messages.pop(i)
        a = addresses.pop(i)
        p = ports.pop(i)
        send_message(m, a, p)
    mutex.release()


def decrypt_data(sock):
    data = sock.recv(8192)
    dest_ip, dest_port, message_to_forward = encryp_check(data, private_key)

    mutex.acquire()
    messages.append(message_to_forward)
    addresses.append(dest_ip)
    ports.append(dest_port)
    mutex.release()

    # send_message(message_to_forward, dest_ip, dest_port)


# checking the arguments.
if len(sys.argv) < 2:
    print("Wrong amount of arguments. should be one number")
    exit(-1)

# get private key for the server
x = sys.argv[1]
file_name = "sk" + x + ".pem"
sk = open(file_name, 'r')
key = sk.read()
private_key = serialization.load_pem_private_key(key.encode(), password=None)
sk.close()

# get the ip+port for the server
ips = open("ips.txt", 'r')
data = ips.readlines()
ipNport = data[int(x) - 1].split(" ")
ips.close()
print("ip & port: " + ipNport[0] + " : " + ipNport[1] + "\n")
print("private key:")
print(private_key)
print("---------------------------------------------------\n")

# open socket and wait for inputs from the clients.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("", int(ipNport[1])))
s.listen()
mutex = threading.Lock()
messages = []
addresses = []
ports = []
t = threading.Timer(60.0, analyze_data)
t.start()


while True:
    client_socket, client_address = s.accept()
    thread = threading.Thread(target=decrypt_data, args=(client_socket,))
    thread.start()
    # data = client_socket.recv(8192)
    # dest_ip, dest_port, message_to_forward = encryp_check (data, private_key)
    # print("--------------------------------------\n")
    # print("dest ip:\n")
    # print(dest_ip)
    # print("dest port:\n")
    # print(dest_port)
    # print("message to send:\n")
    # print(message_to_forward)
    # print("--------------------------------------\n")
    # send_message(message_to_forward,dest_ip,dest_port)
    #

    # message_include_ip_port = private_key_object.decrypt(
    #     data,
    #     padding.OAEP(
    #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #         algorithm=hashes.SHA256(),
    #         label=None
    #     )
    # )
    # messages_for_next_round.append(message_include_ip_port)
    # client_socket.close()
    #
    # # הוא ממתין שיגמר הסיבוב, ואז שולח את c לכתובת הIP והפורט שהופיעו ב msg
    # temp_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # for m in messages_for_next_round:
    #     ip = str(int(m[0:4])) + "." + str(int(m[4:8])) + "." + str(int(m[8:12])) + "." + str(int(m[12:16]))
    #     port = int(m[16:24])
    #     temp_s.connect((ip, port))
    #     temp_s.send(m[24:])
    #     temp_s.close()
