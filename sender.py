import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
import socket



def encrypt_with_public_key(message, public_key):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def public_encryption(enc_sequence,message,addresses, ports):

    # int_sequence = list(map(int, enc_sequence))
    # sequence = enc_sequence.reverse()
    enc_sequence.reverse()
    pks = []
    path = 0
    flag = True
    for x in enc_sequence:
        pk = "".encode()
        enc_file = "pk"+str(x)+".pem"
        f = open(enc_file,'br')
        for l in f:
         pk+= l
        pk = load_pem_public_key(pk)
        if(flag):
            encryped_message = encrypt_with_public_key(message, pk)
        else:
            message_with_address = addresses[path]+ports[path]+encryped_message
            print(message_with_address)
            print("\n")
            encryped_message = encrypt_with_public_key(message_with_address, pk)
        print(encryped_message)
        print("------------------------------------------------------------------------\n")
        path = x
        flag = False
        #pks.append(pk)
        f.close()
    return encryped_message


def decryptor(cipher_text, private_key):
    return private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encryp_check(message):
    way = [3,2,1]
    for x in way:
        sk = ""
        dec_file = "sk"+str(x)+".pem"
        f = open(dec_file,'r')
        sk = f.read()
        # for l in f:
        #     sk+=l
        p_sk = serialization.load_pem_private_key(sk.encode(), password = None)
        message = decryptor(message, p_sk)
        print(message)
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

        msg = bytes(msg) # this is the "real" message
        print(msg)
        print(ip)
        print(port)
        print("------------------------------------------------------------------------\n")
        message = msg

def send_message(message, ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    s.send(message)
    s.close()

# checking the arguments.
if len(sys.argv) < 2:
    print("Wrong amount of arguments. should be one number")
    exit(-1)
# creating the message file name to input for the reading.
x = sys.argv[1]
message_file = "messages" + x + ".txt"

# open the messages file and divide it b lines.
f = open(message_file, "r")
messages = []
for l in f:
    messages.append(l)
# print(messages)

ips = open("ips.txt")
addresses = {}
str_addresses = {}
ports = {}
i = 1
for l in ips:
    routes = l.split()
    str_addresses[i] = routes[0]
    addresses[i]= bytes(map(int, routes[0].split('.')))
    ports[i]= int(routes[1]).to_bytes(2,'big')
    i+=1
# print(addresses)
# print(ports)

for line in messages:
    content = line.split()
    message = bytes(content[0].encode())
    server_path = content[1].split(",")
    round = content[2]
    password = bytes(content[3].encode())
    salt = bytes(content[4].encode())
    dest_ip = bytes(map(int,content[5].split('.')))
    dest_port = int(content[6]).to_bytes(2,'big')
    int_server_path = list(map(int, server_path))
    server_num = int_server_path[0]
    server_ip= str_addresses[server_num]
    server_port= int.from_bytes(ports[server_num],'big')

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    token = f.encrypt(message)
    routing_massage = dest_ip+dest_port+token
    # print(routing_massage)
    message_to_send = public_encryption(int_server_path, routing_massage, addresses, ports)
    print("------------------------------------------------------------------------\n")
    send_message(message_to_send, server_ip, server_port)
    # encryp_check(message_to_send)
    print(token)
    # print(routing_massage)
    # print('hi')
