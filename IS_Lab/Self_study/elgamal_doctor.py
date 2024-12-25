#pip install pycryptodome
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Util.number import GCD, inverse
import random

# Generate ElGamal keys
def generate_keys():
    key = ElGamal.generate(256, get_random_bytes)
    return key

# Encrypt a message using ElGamal
def encrypt(public_key, message):
    while True:
        k = random.randint(1, public_key.p - 2)
        if GCD(k, public_key.p - 1) == 1:
            break
    c1 = pow(public_key.g, k, public_key.p)
    s = pow(public_key.y, k, public_key.p)
    c2 = (message * s) % public_key.p
    return (c1, c2)

# Decrypt a message using ElGamal
def decrypt(private_key, c1, c2):
    s = pow(c1, private_key.x, private_key.p)
    s_inv = inverse(s, private_key.p)
    message = (c2 * s_inv) % private_key.p
    return message

# Simulated "secure diagnosis" by observing encrypted values
# Note: This approach does not securely compare encrypted values and is not fully homomorphic.
def secure_diagnosis(encrypted_bp, threshold, public_key):
    # Encrypt the threshold value
    encrypted_threshold = encrypt(public_key, threshold)
    # In practice, ElGamal doesn't support direct comparison, but this illustrates homomorphic use
    return encrypted_bp, encrypted_threshold  # Both values would need decryption for diagnosis

# Testing the encryption and decryption with a blood pressure value
def main():
    # Generate keys
    key = generate_keys()
    public_key = key.publickey()
    threshold = 130  # Doctor's threshold for high blood pressure

    # Patient's blood pressure (for example purposes)
    patient_bp = 145

    # Encrypt patient's blood pressure
    encrypted_bp = encrypt(public_key, patient_bp)
    print("Encrypted Blood Pressure (c1, c2):", encrypted_bp)

    # Simulate secure diagnosis by "comparing" encrypted values
    # Note: This is not a secure comparison and illustrates limitations with ElGamal
    encrypted_bp, encrypted_threshold = secure_diagnosis(encrypted_bp, threshold, public_key)
    print("Encrypted Threshold (c1, c2):", encrypted_threshold)

    # Decrypt both values for demonstration (in real secure comparison, the patient would decrypt)
    decrypted_bp = decrypt(key, *encrypted_bp)
    decrypted_threshold = decrypt(key, *encrypted_threshold)
    
    print("Decrypted Blood Pressure:", decrypted_bp)
    print("Decrypted Threshold:", decrypted_threshold)
    
    # Diagnosis decision (would require a secure comparison protocol)
    if decrypted_bp > decrypted_threshold:
        print("Diagnosis: High blood pressure detected.")
    else:
        print("Diagnosis: Blood pressure normal.")

if __name__ == "__main__":
    main()
