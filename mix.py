# import socket
# import sys
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding


import sys
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
import socket

if len(sys.argv) < 2:
    print("Not enough arguments")
    exit(-1)

x = sys.argv[1]
file_name = "messages" + x + ".txt"

# the file contains the messages that the sender wants to sent
with open(file_name) as f:
    lines = f.readlines()

# the file contains the public key of mix
with open("pk2.pem") as f:
    lines2 = f.readlines()

public_key = ""
for line in lines2:
    public_key += line

public_key_object = serialization.load_pem_public_key(public_key.encode())

for line in lines:
    l_split = line.split()
    message = bytes(l_split[0].encode())
    path = l_split[1]
    round = l_split[2]
    password = bytes(l_split[3].encode())
    salt = bytes(l_split[4].encode())
    dest_ip = l_split[5]
    dest_port = l_split[6]

    dest_ip_split = dest_ip.split(".")
    dest_ip_with_int_values = [int(numeric_string) for numeric_string in dest_ip_split]
    dest_ip_in_bytes = bytes(dest_ip_with_int_values)

    dest_port_in_bytes = (int(dest_port)).to_bytes(2, 'big')

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    k = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(k)
    c = f.encrypt(message)

    message_include_ip_port = dest_ip_in_bytes + dest_port_in_bytes + c
    # TODO: check at server if it is decrypt well
    l = public_key_object.encrypt(
        message_include_ip_port,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

