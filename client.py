import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 12345))

server_public_key_bytes = client_socket.recv(4096)
server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

public_key_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
client_socket.send(public_key_bytes)

while True:
    message = input("Digite uma mensagem para o servidor: ")
    if message.lower() == 'exit':
        break

    ciphertext = server_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    client_socket.send(ciphertext)

client_socket.close()
