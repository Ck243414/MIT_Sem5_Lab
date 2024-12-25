#pip install pycryptodome

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Generate RSA keys for Alice and Bob
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Sign a document
def sign_document(private_key, document):
    key = RSA.import_key(private_key)
    h = SHA256.new(document.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

# Verify a signature
def verify_signature(public_key, document, signature):
    key = RSA.import_key(public_key)
    h = SHA256.new(document.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Example usage
if __name__ == "__main__":
    # Step 1: Alice generates keys and signs a document
    alice_private_key, alice_public_key = generate_keys()
    alice_document = "This is a legal document signed by Alice."
    alice_signature = sign_document(alice_private_key, alice_document)
    
    print("Alice's Signature:", alice_signature.hex())

    # Step 2: Bob verifies Alice's signature
    if verify_signature(alice_public_key, alice_document, alice_signature):
        print("Alice's signature verified by Bob.")
    else:
        print("Alice's signature verification failed.")

    # Step 3: Bob generates keys and signs a document
    bob_private_key, bob_public_key = generate_keys()
    bob_document = "This is a legal document signed by BOB."
    bob_signature = sign_document(bob_private_key, bob_document)

    print("Bob's Signature:", bob_signature.hex())

    # Step 4: Alice verifies Bob's signature
    if verify_signature(bob_public_key, bob_document, bob_signature):
        print("Bob's signature verified by Alice.")
    else:
        print("Bob's signature verification failed.")
