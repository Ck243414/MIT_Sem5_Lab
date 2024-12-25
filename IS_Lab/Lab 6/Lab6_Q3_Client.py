import socket
import random
from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

# Diffie-Hellman Key Exchange
def generate_dh_keys(prime, base):
    private_key = random.randint(1, prime - 1)
    public_key = pow(base, private_key, prime)
    return private_key, public_key

def compute_shared_secret(their_public_key, my_private_key, prime):
    return pow(their_public_key, my_private_key, prime)

# Sign a document
def sign_document(private_key, document):
    key = DSA.generate(2048)
    h = SHA256.new(document.encode())
    signature = DSS.new(key, 'fips-186-3').sign(h)
    return key.publickey().export_key(), signature

def main():
    # Step 1: Diffie-Hellman parameters
    prime = 23
    base = 5

    # Generate client keys
    client_private_key, client_public_key = generate_dh_keys(prime, base)
    print(f"Client's Public Key: {client_public_key}")

    # Set up the client
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    # Step 2: Send public key to the server
    client_socket.send(str(client_public_key).encode())
    server_public_key = int(client_socket.recv(1024).decode())

    # Step 3: Compute shared secret
    shared_secret = compute_shared_secret(server_public_key, client_private_key, prime)
    print(f"Shared Secret: {shared_secret}")

    # Step 4: Sign a document
    document = "This is a legal document signed by the client."
    client_public_key, client_signature = sign_document(client_private_key, document)

    # Send document and signature to the server
    client_socket.send(document.encode())
    client_socket.send(client_signature.hex().encode())

    client_socket.close()

if __name__ == "__main__":
    main()
