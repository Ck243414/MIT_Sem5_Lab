#pip install pycryptodome

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

# Verify a signature
def verify_signature(public_key, document, signature):
    key = DSA.import_key(public_key)
    h = SHA256.new(document.encode())
    try:
        DSS.new(key, 'fips-186-3').verify(h, signature)
        return True
    except ValueError:
        return False

# Example usage
if __name__ == "__main__":
    # Step 1: Diffie-Hellman parameters
    prime = 23  # A small prime number for demonstration
    base = 5    # A small base for demonstration

    # Step 2: Alice generates her keys
    alice_private_key, alice_public_key = generate_dh_keys(prime, base)
    print(f"Alice's Public Key: {alice_public_key}")

    # Step 3: Bob generates his keys
    bob_private_key, bob_public_key = generate_dh_keys(prime, base)
    print(f"Bob's Public Key: {bob_public_key}")

    # Step 4: Compute shared secrets
    alice_shared_secret = compute_shared_secret(bob_public_key, alice_private_key, prime)
    bob_shared_secret = compute_shared_secret(alice_public_key, bob_private_key, prime)

    print(f"Alice's Shared Secret: {alice_shared_secret}")
    print(f"Bob's Shared Secret: {bob_shared_secret}")

    # Step 5: Sign a document (Alice)
    alice_document = "This is a legal document signed by Alice."
    alice_public_key, alice_signature = sign_document(alice_private_key, alice_document)

    print("Alice's Signature:", alice_signature.hex())

    # Step 6: Verify Alice's signature (Bob)
    if verify_signature(alice_public_key, alice_document, alice_signature):
        print("Alice's signature verified by Bob.")
    else:
        print("Alice's signature verification failed.")

    # Step 7: Sign a document (Bob)
    bob_document = "This is a legal document signed by BOB."
    bob_public_key, bob_signature = sign_document(bob_private_key, bob_document)

    print("Bob's Signature:", bob_signature.hex())

    # Step 8: Verify Bob's signature (Alice)
    if verify_signature(bob_public_key, bob_document, bob_signature):
        print("Bob's signature verified by Alice.")
    else:
        print("Bob's signature verification failed.")
