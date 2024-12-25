import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Client configuration
HOST = 'localhost'
PORT = 65432

def encrypt_and_send_message(conn, message, key, iv):
    # Initialize cipher with AES-CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad and encrypt the message
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))
    
    # Send the length of the encrypted message followed by the encrypted message
    conn.send(len(encrypted_message).to_bytes(4, 'big'))
    conn.send(encrypted_message)

def start_client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))
        
        # Receive IV and AES key from server
        iv = client_socket.recv(16)
        key = client_socket.recv(16)
        
        # Messages to send
        messages = [
            "Hello, this is the first message.",
            "Sending another secret message.",
            "Final message from client to server."
        ]
        
        for message in messages:
            encrypt_and_send_message(client_socket, message, key, iv)
            print(f"Encrypted and sent: {message}")

if __name__ == "__main__":
    start_client()
