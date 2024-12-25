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

# Verify a signature
def verify_signature(public_key, document, signature):
    key = DSA.import_key(public_key)
    h = SHA256.new(document.encode())
    try:
        DSS.new(key, 'fips-186-3').verify(h, signature)
        return True
    except ValueError:
        return False

def main():
    # Step 1: Diffie-Hellman parameters
    prime = 23
    base = 5

    # Generate server keys
    server_private_key, server_public_key = generate_dh_keys(prime, base)
    print(f"Server's Public Key: {server_public_key}")

    # Set up the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(1)

    print("Server is listening for connections...")
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # Step 2: Exchange public keys with the client
    client_public_key = int(conn.recv(1024).decode())
    conn.send(str(server_public_key).encode())

    # Step 3: Compute shared secret
    shared_secret = compute_shared_secret(client_public_key, server_private_key, prime)
    print(f"Shared Secret: {shared_secret}")

    # Step 4: Receive signed document from client
    document = conn.recv(1024).decode()
    client_signature = bytes.fromhex(conn.recv(2048).decode())
    
    # Verify the client's signature
    if verify_signature(client_public_key, document, client_signature):
        print("Client's signature verified.")
    else:
        print("Client's signature verification failed.")

    conn.close()

if __name__ == "__main__":
    main()
