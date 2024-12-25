import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

# Server configuration
HOST = 'localhost'
PORT = 65432

# AES configuration
key = get_random_bytes(16)  # AES-128 key
iv = get_random_bytes(16)   # Initialization Vector for CBC mode

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server listening on {HOST}:{PORT}")
        
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")
        
        with conn:
            conn.send(iv)  # Send IV to the client for decryption
            conn.send(key)  # Send AES key securely (e.g., assuming secure channel for this example)

            while True:
                # Receive encrypted message length
                data_length = conn.recv(4)
                if not data_length:
                    break
                
                # Convert byte length to integer
                message_length = int.from_bytes(data_length, 'big')
                
                # Receive encrypted message
                encrypted_message = conn.recv(message_length)
                if not encrypted_message:
                    break
                
                # Decrypt message
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
                
                print(f"Decrypted Message from client: {decrypted_message.decode()}")

if __name__ == "__main__":
    start_server()
