# server.py
import socket
from phe import paillier

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind(('localhost', 65432))
    server_socket.listen()
    print("Server listening for connections...")

    conn, addr = server_socket.accept()
    with conn:
        print(f"Connected by {addr}")

        # Receive the public key's 'n' value and recreate the public key
        public_key_n = int(conn.recv(1024).decode().strip())
        public_key = paillier.PaillierPublicKey(n=public_key_n)

        # Receive encrypted values, add them homomorphically
        encrypted_values = []
        while True:
            data = conn.recv(1024).decode().strip()
            if not data:
                break
            encrypted_values.append(paillier.EncryptedNumber(public_key, int(data)))

        # Homomorphic addition of the encrypted values
        encrypted_sum = encrypted_values[0]
        for enc_val in encrypted_values[1:]:
            encrypted_sum += enc_val

        # Send the result back to the client
        conn.sendall(str(encrypted_sum.ciphertext()).encode())
