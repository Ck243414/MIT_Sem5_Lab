# server.py
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature

# Generate RSA key pair for server
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()

# Assume we have the client's public key (in practice, this would come from a trusted source)
client_public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind(('localhost', 65432))
    server_socket.listen()

    print("Server listening for connections...")

    conn, addr = server_socket.accept()
    with conn:
        print(f"Connected by {addr}")

        # Receive the encrypted message and signature from the client
        encrypted_message = conn.recv(256)  # Adjust size as per your encryption output size
        signature = conn.recv(256)

        # Verify the digital signature
        try:
            client_public_key.verify(
                signature,
                encrypted_message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            print("Signature verified successfully.")
            
            # Decrypt the message with the server's private key
            decrypted_message_bytes = server_private_key.decrypt(
                encrypted_message,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            # Convert decrypted message from bytes to integer, then to string
            decrypted_message = decrypted_message_bytes.decode("big")
            print("Decrypted message:", decrypted_message)

        except InvalidSignature:
            print("Signature verification failed!")
