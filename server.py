import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 12345))
server_socket.listen(1)
print("Aguardando conexão...")

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

(client_socket, client_address) = server_socket.accept()
print(f"Conexão estabelecida com {client_address}")

client_socket.send(public_key_bytes)

client_public_key_bytes = client_socket.recv(4096)
client_public_key = serialization.load_pem_public_key(client_public_key_bytes)

while True:
    data = client_socket.recv(4096)
    if not data:
        break

    decrypted_data = private_key.decrypt(data, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

    print(f"Cliente: {decrypted_data.decode()}")

client_socket.close()
server_socket.close()
