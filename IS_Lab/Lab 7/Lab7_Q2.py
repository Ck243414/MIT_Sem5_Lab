import random
import math
from sympy import isprime, mod_inverse

class RSA:
    def __init__(self, bit_length=16):
        self.p, self.q = self._generate_prime_pairs(bit_length)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        self.e = self._choose_e(self.phi_n)
        self.d = mod_inverse(self.e, self.phi_n)

    def _generate_prime_pairs(self, bit_length):
        primes = []
        while len(primes) < 2:
            num = random.getrandbits(bit_length)
            if isprime(num):
                primes.append(num)
        return primes[0], primes[1]

    def _choose_e(self, phi_n):
        e = 3
        while e < phi_n:
            if math.gcd(e, phi_n) == 1:
                return e
            e += 2
        raise ValueError("Failed to choose e")

    def encrypt(self, plaintext):
        return pow(plaintext, self.e, self.n)

    def multiply_encrypted(self, ciphertext1, ciphertext2):
        return (ciphertext1 * ciphertext2) % self.n

    def decrypt(self, ciphertext):
        return pow(ciphertext, self.d, self.n)

# Example usage
rsa = RSA()

# Encrypt two integers
a = 7
b = 3
ciphertext_a = rsa.encrypt(a)
ciphertext_b = rsa.encrypt(b)

print(f"Ciphertext of {a}: {ciphertext_a}")
print(f"Ciphertext of {b}: {ciphertext_b}")

# Perform multiplication on encrypted integers
ciphertext_product = rsa.multiply_encrypted(ciphertext_a, ciphertext_b)
print(f"Ciphertext of product: {ciphertext_product}")

# Decrypt the result
decrypted_product = rsa.decrypt(ciphertext_product)
print(f"Decrypted product: {decrypted_product}")

# Verify that the decrypted product matches the actual product
print(f"Actual product: {a * b}")
