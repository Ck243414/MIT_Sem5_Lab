# client.py
import socket
from phe import paillier

#pip install phe
# Generate Paillier key pair
public_key, private_key = paillier.generate_paillier_keypair()

# Example integers to send
messages = [5, 10, 15]

# Encrypt each message
encrypted_messages = [public_key.encrypt(m) for m in messages]

# Serialize the encrypted values (ciphertexts) for transmission
encrypted_values = [str(enc.ciphertext()) for enc in encrypted_messages]

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
    client_socket.connect(('localhost', 65432))
    
    # Send the public key's n value (necessary for the server to work with the encrypted messages)
    client_socket.sendall(str(public_key.n).encode() + b'\n')
    
    # Send each encrypted value
    for enc_val in encrypted_values:
        client_socket.sendall(enc_val.encode() + b'\n')
    
    # Receive the server's response (encrypted result of homomorphic addition)
    encrypted_sum_result = int(client_socket.recv(1024).decode())

# Decrypt the result from the server
result = private_key.decrypt(paillier.EncryptedNumber(public_key, encrypted_sum_result))
print("Decrypted sum result from the server:", result)
