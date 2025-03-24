from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

class DigitalSignature:
    """Handles digital signature generation and verification using ECDSA."""

    def sign_message(self, message, private_key):
        """Signs a message using the provided ECDSA private key."""
        return private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify_signature(self, message, signature, public_key):
        """Verifies an ECDSA signature using the provided public key."""
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except:
            return False

    @staticmethod
    def load_private_key(filename):
        """Loads a private key from a PEM file."""
        with open(filename, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None  # Assuming no password encryption
            )

    @staticmethod
    def load_public_key(filename):
        """Loads a public key from a PEM file."""
        with open(filename, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())
