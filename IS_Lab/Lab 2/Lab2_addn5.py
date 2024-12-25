from Crypto.Cipher import AES
from Crypto.Util import Counter

# Define the key and nonce
key = b"0123456789ABCDEF0123456789ABCDEF"  # 32-byte key for AES-256
nonce = b"0000000000000000"                # 8-byte nonce for AES CTR mode

# Create a counter object for CTR mode
ctr = Counter.new(64, prefix=nonce, initial_value=0)

# Message to encrypt
message = "Cryptography Lab Exercise"

# Encrypt the message
aes_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
ciphertext = aes_cipher.encrypt(message.encode())
print("Ciphertext (in hex):", ciphertext.hex())

# Decrypt the message
# Create a new counter object with the same nonce and initial value for decryption
ctr = Counter.new(64, prefix=nonce, initial_value=0)
aes_decipher = AES.new(key, AES.MODE_CTR, counter=ctr)
decrypted_message = aes_decipher.decrypt(ciphertext).decode()
print("Decrypted message:", decrypted_message)
