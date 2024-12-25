import os
import time
import sqlite3
from datetime import datetime, timedelta
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256

class DRMService:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.conn = sqlite3.connect(':memory:')  # Use in-memory DB for demo; replace with persistent DB in production
        self.create_tables()
        self.master_private_key, self.master_public_key = self.generate_master_key()
        self.key_renewal_period = timedelta(days=730)  # 24 months
        self.last_key_renewal = datetime.now()
        self.audit_log("Master key generated and stored securely.")

    def create_tables(self):
        """Sets up tables for content, access control, and logging."""
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE content (id INTEGER PRIMARY KEY, creator TEXT, encrypted_data BLOB)''')
        cursor.execute('''CREATE TABLE access (user TEXT, content_id INTEGER, expires_at TIMESTAMP)''')
        cursor.execute('''CREATE TABLE logs (timestamp TEXT, action TEXT, details TEXT)''')
        self.conn.commit()

    def audit_log(self, action, details=""):
        """Logs all actions for auditing."""
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO logs (timestamp, action, details) VALUES (?, ?, ?)",
                       (datetime.now().isoformat(), action, details))
        self.conn.commit()

    def generate_master_key(self):
        """Generates a master ElGamal key pair."""
        key = ElGamal.generate(self.key_size, os.urandom)
        return key, key.publickey()

    def encrypt_content(self, creator, data):
        """Encrypts content using the master public key and stores it."""
        symmetric_key = SHA256.new(self.master_public_key.y.to_bytes()).digest()  # Derive symmetric key
        cipher_aes = AES.new(symmetric_key, AES.MODE_CBC)
        encrypted_data = cipher_aes.encrypt(pad(data, AES.block_size))
        iv = cipher_aes.iv

        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO content (creator, encrypted_data) VALUES (?, ?)",
                       (creator, iv + encrypted_data))
        self.conn.commit()

        content_id = cursor.lastrowid
        self.audit_log("Content encrypted and stored.", f"Content ID: {content_id}")
        return content_id

    def distribute_key(self, user, content_id, duration_days=30):
        """Grants access to user for specific content with expiration."""
        expires_at = datetime.now() + timedelta(days=duration_days)
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO access (user, content_id, expires_at) VALUES (?, ?, ?)",
                       (user, content_id, expires_at))
        self.conn.commit()
        self.audit_log("Access granted to user.", f"User: {user}, Content ID: {content_id}, Expires At: {expires_at}")

    def check_access(self, user, content_id):
        """Checks if a user has access to specific content."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT expires_at FROM access WHERE user = ? AND content_id = ?", (user, content_id))
        row = cursor.fetchone()
        if row:
            expires_at = datetime.fromisoformat(row[0])
            if expires_at > datetime.now():
                return True
        return False

    def decrypt_content(self, user, content_id):
        """Decrypts content if user has access."""
        if not self.check_access(user, content_id):
            self.audit_log("Access denied", f"User: {user}, Content ID: {content_id}")
            raise PermissionError("Access denied or expired")

        cursor = self.conn.cursor()
        cursor.execute("SELECT encrypted_data FROM content WHERE id = ?", (content_id,))
        row = cursor.fetchone()
        if not row:
            raise ValueError("Content not found")

        encrypted_data = row[0]
        iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
        symmetric_key = SHA256.new(self.master_private_key.y.to_bytes()).digest()
        cipher_aes = AES.new(symmetric_key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

        self.audit_log("Content decrypted", f"User: {user}, Content ID: {content_id}")
        return plaintext

    def revoke_access(self, user, content_id):
        """Revokes access to specific content for a user."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM access WHERE user = ? AND content_id = ?", (user, content_id))
        self.conn.commit()
        self.audit_log("Access revoked", f"User: {user}, Content ID: {content_id}")

    def revoke_master_key(self):
        """Revokes the current master key in case of a security breach."""
        self.master_private_key, self.master_public_key = self.generate_master_key()
        self.audit_log("Master key revoked and regenerated.")

    def renew_master_key(self):
        """Renews the master key pair periodically (every 24 months)."""
        if datetime.now() - self.last_key_renewal >= self.key_renewal_period:
            self.revoke_master_key()
            self.last_key_renewal = datetime.now()
            self.audit_log("Master key renewed as per policy.")

    def view_logs(self):
        """Displays the logs for auditing."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM logs")
        logs = cursor.fetchall()
        for log in logs:
            print(log)

# Test the DRM service
if __name__ == "__main__":
    drm = DRMService()
    # Encrypt content
    content_id = drm.encrypt_content("AuthorA", b"Confidential E-book Content")
    
    # Grant access to a user
    drm.distribute_key("User1", content_id, duration_days=15)
    
    # Decrypt content
    try:
        content = drm.decrypt_content("User1", content_id)
        print("Decrypted Content:", content)
    except PermissionError as e:
        print(str(e))

    # Revoke access and try decryption again
    drm.revoke_access("User1", content_id)
    try:
        drm.decrypt_content("User1", content_id)
    except PermissionError as e:
        print(str(e))
    
    # Show logs
    drm.view_logs()
