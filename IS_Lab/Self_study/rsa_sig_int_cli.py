# client.py
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils

# Generate RSA key pair for client
client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public_key = client_private_key.public_key()

# Simulate receiving the server's public key (in practice, you might load this from a file or a secure source)
server_public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

# Take user input, convert to integer, and prepare for encryption
message = input("Enter a message: ")
message_as_int = int.from_bytes(message.encode(), "big")

# Encrypt the integer message with the server's public key
encrypted_message = server_public_key.encrypt(
    message_as_int.to_bytes((message_as_int.bit_length() + 7) // 8, byteorder="big"),
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

# Sign the encrypted message with the client's private key
signature = client_private_key.sign(
    encrypted_message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# Send the encrypted message and signature to the server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect(('localhost', 65432))
    client_socket.sendall(encrypted_message)
    client_socket.sendall(signature)

print("Encrypted message and signature sent to the server.")
