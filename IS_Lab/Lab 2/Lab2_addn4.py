from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Define the key and IV (initialization vector)
key = b"A1B2C3D4"           # 8 bytes key for DES
iv = b"12345678"            # 8 bytes IV for DES

# Message to encrypt
message = "Secure Communication"

# Encrypting the message
des_cipher = DES.new(key, DES.MODE_CBC, iv)
padded_message = pad(message.encode(), DES.block_size)
ciphertext = des_cipher.encrypt(padded_message)
print("Ciphertext (in hex):", ciphertext.hex())

# Decrypting the message
des_decipher = DES.new(key, DES.MODE_CBC, iv)
decrypted_padded_message = des_decipher.decrypt(ciphertext)
decrypted_message = unpad(decrypted_padded_message, DES.block_size)
print("Decrypted message:", decrypted_message.decode())
