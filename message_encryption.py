from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class MessageEncryption:
    """Handles AES-256-GCM encryption and decryption of messages."""

    def __init__(self, shared_key):
        self.shared_key = shared_key

    def encrypt(self, plaintext):
        """Encrypts a message using AES-256-GCM."""
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(self.shared_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv, encryptor.tag, ciphertext

    def decrypt(self, iv, tag, ciphertext):
        """Decrypts a message using AES-256-GCM."""
        cipher = Cipher(algorithms.AES(self.shared_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
