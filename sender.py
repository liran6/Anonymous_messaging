import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
import socket


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
print(messages)

ips = open("ips.txt")
addresses = []
ports = []
for l in ips:
    routes = l.split()
    addresses.append(routes[0])
    ports.append(routes[1])
print(addresses)
print(ports)



def public_encryption(enc_sequence,message):

    int_sequence = list(map(int, enc_sequence))
    # sequence = enc_sequence.reverse()
    pks = []
    for x in int_sequence:
        pk = ""
        enc_file = "pk"+str(x)+".pem"
        f = open(enc_file,"r")
        for l in f:
            pk+= l

        # pks.append(pk)
        f.close()
    return pks



for line in messages:
    content = line.split()
    message = bytes(content[0].encode())
    server_path = content[1].split(",")
    round = content[2]
    password = bytes(content[3].encode())
    salt = bytes(content[4].encode())
    dest_ip = bytes(map(int,content[5].split('.')))
    dest_port = int(content[6]).to_bytes(2,'big')
    print(content)

    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    token = f.encrypt(message)
    routing_massage

    public_encryption(server_path, token)
