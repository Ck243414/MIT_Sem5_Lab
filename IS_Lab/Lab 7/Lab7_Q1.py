import random
import math
from sympy import mod_inverse

class Paillier:
    def __init__(self, bit_length=512):
        self.p, self.q = self._generate_prime_pairs(bit_length)
        self.n = self.p * self.q
        self.n_squared = self.n * self.n
        self.g = self.n + 1
        self.lambda_ = (self.p - 1) * (self.q - 1) // math.gcd(self.p - 1, self.q - 1)
        self.mu = mod_inverse(self.lambda_, self.n)

    def _generate_prime_pairs(self, bit_length):
        while True:
            p = self._generate_large_prime(bit_length)
            q = self._generate_large_prime(bit_length)
            if p != q:
                return p, q

    def _generate_large_prime(self, bit_length):
        while True:
            num = random.getrandbits(bit_length)
            if num % 2 == 0:  # Ensure it's odd
                num += 1
            if self._is_prime(num):
                return num

    def _is_prime(self, n, k=5):  # Miller-Rabin primality test
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            s //= 2
            r += 1

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def encrypt(self, plaintext):
        r = random.randint(1, self.n - 1)
        while math.gcd(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        ciphertext = (pow(self.g, plaintext, self.n_squared) * pow(r, self.n, self.n_squared)) % self.n_squared
        return ciphertext

    def add_encrypted(self, ciphertext1, ciphertext2):
        return (ciphertext1 * ciphertext2) % self.n_squared

    def decrypt(self, ciphertext):
        u = (pow(ciphertext, self.lambda_, self.n_squared) - 1) // self.n
        plaintext = (u * self.mu) % self.n
        return plaintext

# Example usage
paillier = Paillier()

# Encrypt two integers
a = 15
b = 25
ciphertext_a = paillier.encrypt(a)
ciphertext_b = paillier.encrypt(b)

print(f"Ciphertext of {a}: {ciphertext_a}")
print(f"Ciphertext of {b}: {ciphertext_b}")

# Perform addition on encrypted integers
ciphertext_sum = paillier.add_encrypted(ciphertext_a, ciphertext_b)
print(f"Ciphertext of sum: {ciphertext_sum}")

# Decrypt the result
decrypted_sum = paillier.decrypt(ciphertext_sum)
print(f"Decrypted sum: {decrypted_sum}")

# Verify that the decrypted sum matches the actual sum
print(f"Actual sum: {a + b}")
