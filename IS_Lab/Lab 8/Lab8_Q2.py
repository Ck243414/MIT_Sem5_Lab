#pip install numpy pycryptodome

import numpy as np
from Crypto.Util import number
from Crypto.Hash import SHA256

# Paillier Cryptosystem
class Paillier:
    def __init__(self, bit_length=512):
        self.p = self._generate_large_prime(bit_length)
        self.q = self._generate_large_prime(bit_length)
        self.n = self.p * self.q
        self.n_squared = self.n * self.n
        self.g = self.n + 1
        self.lambda_ = (self.p - 1) * (self.q - 1) // np.gcd(self.p - 1, self.q - 1)
        self.mu = number.inverse(self.lambda_, self.n)

    def _generate_large_prime(self, bit_length):
        while True:
            num = number.getPrime(bit_length)
            return num

    def encrypt(self, plaintext):
        r = number.getRandomRange(1, self.n)
        ciphertext = (pow(self.g, plaintext, self.n_squared) * pow(r, self.n, self.n_squared)) % self.n_squared
        return ciphertext

    def decrypt(self, ciphertext):
        u = (pow(ciphertext, self.lambda_, self.n_squared) - 1) // self.n
        plaintext = (u * self.mu) % self.n
        return plaintext

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

# Create an encrypted index
def create_index(documents, paillier):
    index = {}
    
    for doc_id, doc in documents.items():
        for word in doc.split():
            word_hash = SHA256.new(word.encode()).digest()
            if word_hash not in index:
                index[word_hash] = []
            index[word_hash].append(doc_id)
    
    # Encrypt the index
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        encrypted_word = paillier.encrypt(int.from_bytes(word_hash, byteorder='big'))
        encrypted_doc_ids = [paillier.encrypt(int(doc_id)) for doc_id in doc_ids]
        encrypted_index[encrypted_word] = encrypted_doc_ids
    
    return encrypted_index

# Search function
def search(encrypted_index, query, paillier):
    query_hash = SHA256.new(query.encode()).digest()
    encrypted_query_hash = paillier.encrypt(int.from_bytes(query_hash, byteorder='big'))
    
    if encrypted_query_hash in encrypted_index:
        encrypted_doc_ids = encrypted_index[encrypted_query_hash]
        doc_ids = [paillier.decrypt(doc_id) for doc_id in encrypted_doc_ids]
        return [str(doc_id) for doc_id in doc_ids]
    else:
        return []

# Example usage
def main():
    # Initialize the Paillier cryptosystem
    paillier = Paillier()

    # Create a dataset of documents
    documents = create_dataset()

    # Create and encrypt the inverted index
    encrypted_index = create_index(documents, paillier)

    # Take a search query as input
    query = "quick"  # Example query
    print(f"Searching for: {query}")

    # Perform the search
    results = search(encrypted_index, query, paillier)

    # Display results
    if results:
        print("Matching document IDs:")
        for doc_id in results:
            print(f"Document ID: {doc_id}, Content: {documents[doc_id]}")
    else:
        print("No matching documents found.")

if __name__ == "__main__":
    main()
