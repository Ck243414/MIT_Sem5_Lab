import time
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

# Function for measuring time taken for each operation
def measure_time(func, *args, **kwargs):
    start = time.time()
    result = func(*args, **kwargs)
    end = time.time()
    return result, end - start

# Generate RSA keys (2048-bit)
def generate_rsa_keys():
    return RSA.generate(2048)

# RSA Encryption
def rsa_encrypt(public_key, message):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(message)

# RSA Decryption
def rsa_decrypt(private_key, ciphertext):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(ciphertext)

# Generate ECC keys (secp256r1 curve)
def generate_ecc_keys():
    return ECC.generate(curve='P-256')

# ECC Encryption (using symmetric key derived from ECC shared secret)
def ecc_encrypt(public_key, message):
    # Derive a shared key using ECDSA (for simplicity here)
    symmetric_key = SHA256.new(public_key.public_point.x.to_bytes()).digest()
    cipher_aes = AES.new(symmetric_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)
    return ciphertext, cipher_aes.nonce, tag

# ECC Decryption
def ecc_decrypt(private_key, ciphertext, nonce, tag):
    symmetric_key = SHA256.new(private_key.pointQ.x.to_bytes()).digest()
    cipher_aes = AES.new(symmetric_key, AES.MODE_GCM, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)

# Run performance tests
def performance_test():
    # Generate messages of varying sizes (1 KB, 10 KB)
    message_sizes = [1024, 10240]  # 1 KB and 10 KB
    for size in message_sizes:
        message = get_random_bytes(size)
        print(f"Testing with message size: {size} bytes")

        # RSA Performance
        rsa_key, rsa_keygen_time = measure_time(generate_rsa_keys)
        rsa_public_key = rsa_key.publickey()
        rsa_ciphertext, rsa_encryption_time = measure_time(rsa_encrypt, rsa_public_key, message)
        _, rsa_decryption_time = measure_time(rsa_decrypt, rsa_key, rsa_ciphertext)
        
        print(f"RSA 2048-bit Key Generation Time: {rsa_keygen_time:.6f} seconds")
        print(f"RSA Encryption Time: {rsa_encryption_time:.6f} seconds")
        print(f"RSA Decryption Time: {rsa_decryption_time:.6f} seconds")

        # ECC Performance
        ecc_key, ecc_keygen_time = measure_time(generate_ecc_keys)
        ecc_public_key = ecc_key.public_key()
        ecc_ciphertext, ecc_encryption_time = measure_time(ecc_encrypt, ecc_public_key, message)
        _, ecc_decryption_time = measure_time(ecc_decrypt, ecc_key, *ecc_ciphertext)

        print(f"ECC secp256r1 Key Generation Time: {ecc_keygen_time:.6f} seconds")
        print(f"ECC Encryption Time: {ecc_encryption_time:.6f} seconds")
        print(f"ECC Decryption Time: {ecc_decryption_time:.6f} seconds")

        print("\n" + "-"*50 + "\n")

if __name__ == "__main__":
    performance_test()
