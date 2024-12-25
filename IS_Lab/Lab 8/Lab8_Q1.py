import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# AES encryption and decryption functions
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv, ciphertext

def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# Create a dataset of documents
def create_dataset():
    return {
        "doc1": "the quick brown fox jumps over the lazy dog",
        "doc2": "jumps high and fast",
        "doc3": "hello world",
        "doc4": "the quick blue hare",
        "doc5": "lorem ipsum dolor sit amet",
        "doc6": "the quick brown dog",
        "doc7": "quick foxes are fast",
        "doc8": "the brown dog barks",
        "doc9": "the lazy dog sleeps",
        "doc10": "the fast hare jumps high"
    }

# Create an inverted index and encrypt it
def create_index(documents, key):
    index = {}
    
    for doc_id, doc in documents.items():
        for word in doc.split():
            word_hash = hashlib.sha256(word.encode()).digest()
            if word_hash not in index:
                index[word_hash] = []
            index[word_hash].append(doc_id)
    
    # Encrypt the index
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        encrypted_index[encrypt_data(key, word_hash)[1]] = [encrypt_data(key, str(doc_id))[1] for doc_id in doc_ids]
    
    return encrypted_index

# Search function
def search(encrypted_index, query, key):
    query_hash = hashlib.sha256(query.encode()).digest()
    encrypted_query_hash = encrypt_data(key, query_hash)[1]
    
    if encrypted_query_hash in encrypted_index:
        return [decrypt_data(key, *encrypt_data(key, doc_id)) for doc_id in encrypted_index[encrypted_query_hash]]
    else:
        return []

# Example usage
def main():
    # Generate a key for AES encryption
    key = get_random_bytes(16)

    # Create a dataset of documents
    documents = create_dataset()

    # Create and encrypt the inverted index
    encrypted_index = create_index(documents, key)

    # Take a search query as input
    query = "quick"  # Example query
    print(f"Searching for: {query}")

    # Perform the search
    results = search(encrypted_index, query, key)

    # Display results
    if results:
        print("Matching document IDs:")
        for doc_id in results:
            print(f"Document ID: {doc_id}, Content: {documents[doc_id]}")
    else:
        print("No matching documents found.")

if __name__ == "__main__":
    main()
