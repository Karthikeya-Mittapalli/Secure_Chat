from kyber_py.kyber.kyber import Kyber
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os

class KeyExchange:
    def __init__(self):
        # Define the Kyber parameter set
        parameter_set = {
            "k": 2,      # Security level parameter (Kyber-768)
            "eta_1": 3,  # Noise parameter for key generation
            "eta_2": 2,  # Noise parameter for encapsulation
            "du": 10,    # Compression parameter for public key
            "dv": 4      # Compression parameter for ciphertext
        }
        self.kyber = Kyber(parameter_set)
        self.ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.ec_public_key = self.ec_private_key.public_key()
    
    def generate_ecc_key_pair(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key
    
    def serialize_public_key(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def deserialize_public_key(self, pem_data):
        return serialization.load_pem_public_key(pem_data, backend=default_backend())
    
    def get_ecdh_public_bytes(self):
        return self.serialize_public_key(self.ec_public_key)
    
    def derive_ecdh_shared_secret(self, peer_ecc_public_key):
        return self.ec_private_key.exchange(ec.ECDH(), peer_ecc_public_key)
    
    def encapsulate_kyber_secret(self,kyber_public_key):
        # kyber_public_key, kyber_secret_key = self.kyber.keygen()
        kyber_shared_secret, ciphertext = self.kyber.encaps(kyber_public_key)
        print(f"[DEBUG] Kyber Ciphertext Length (Before Sending): {len(ciphertext)} bytes")
        print(f"[inner 2 DEBUG] Kyber Public Key Length: {len(kyber_public_key)} bytes")
        print(f"[inner 2 DEBUG] Kyber Ciphertext Length: {len(ciphertext)} bytes")
        print(f"[inner 2 DEBUG] Kyber Shared Secret Length: {len(kyber_shared_secret)} bytes")
        return ciphertext, kyber_shared_secret
    
    def hybrid_key_exchange(self, peer_ecc_public_bytes,server_kyber_pub):
        peer_ecc_public_key = self.deserialize_public_key(peer_ecc_public_bytes)
        
        # ECC key agreement
        ecdh_shared_secret = self.derive_ecdh_shared_secret(peer_ecc_public_key)
        print(f"[DEBUG] ECDH Shared Secret: {ecdh_shared_secret.hex()}")

        
        # Kyber key encapsulation
        ciphertext, kyber_shared_secret = self.encapsulate_kyber_secret(server_kyber_pub)
        print(f"[DEBUG] Kyber Shared Secret: {kyber_shared_secret.hex()}")

        print(f"[inner DEBUG] Expected Kyber Ciphertext Length: 1088 bytes, Got: {len(ciphertext)} bytes")
        print(f"[inner DEBUG] Kyber Shared Secret Length: {len(kyber_shared_secret)} bytes")

        print(f"[Inner DEBUG] Kyber Ciphertext Length: {len(ciphertext)} bytes")  

        print(f"[DEBUG] HKDF Input: {ecdh_shared_secret.hex()} + {kyber_shared_secret.hex()}")
        
        # Combine secrets using HKDF
        hybrid_shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"AES-GCM Secure Key",
            backend=default_backend()
        ).derive(kyber_shared_secret + ecdh_shared_secret)
        
        return hybrid_shared_secret, ciphertext
    
    '''
    def hybrid_key_decapsulation(self, ciphertext, kyber_secret_key, ecdh_pub):
        """
        Hybrid Decapsulation of Kyber + ECDH Shared Secrets.
        Fix: Handles 32-byte Kyber Ciphertext by expanding it before Kyber decryption.

        :param bytes ciphertext: 32-byte Kyber ciphertext (instead of 800 bytes)
        :param bytes kyber_secret_key: Kyber secret key
        :param bytes ecdh_pub: ECDH public key from the other party
        :return: Combined shared key
        :rtype: bytes
        """
        if len(ciphertext) == 32:
            # Fix: Expand ciphertext to expected length using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=800,  # Expected Kyber ciphertext length
                salt=b"kyber_padding",
                info=b"expand_kyber_ct"
            )
            ciphertext = hkdf.derive(ciphertext)  # Expand 32 bytes to 800 bytes

        # Now pass the correctly-sized ciphertext to Kyber
        kyber_shared_secret = self.kyber.decaps(ciphertext, kyber_secret_key)

        # ECDH key agreement
        ecdh_shared_secret = self.ecdh.compute_shared_secret(ecdh_pub)

        # Derive final hybrid key
        combined_secret = kyber_shared_secret + ecdh_shared_secret
        hkdf_final = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"final_hybrid_secret",
            info=b"kyber_ecdh_shared"
        )
        final_shared_key = hkdf_final.derive(combined_secret)

        return final_shared_key
    '''
    
    def hybrid_key_decapsulation(self, ciphertext, kyber_secret_key, ecdh_pub):
        """
        Hybrid Decapsulation of Kyber + ECDH Shared Secrets.

        :param bytes ciphertext: Kyber ciphertext
        :param bytes kyber_secret_key: Kyber secret key
        :param bytes ecdh_pub: ECDH public key from the other party
        :return: Combined shared key
        :rtype: bytes
        """

        expected_kyber_ct_len = 768  # Kyber-512: 768 bytes, Kyber-768: 1088 bytes, Kyber-1024: 1568 bytes
        if len(ciphertext) != expected_kyber_ct_len:
            raise ValueError(f"[ERROR] Invalid Kyber ciphertext length: Expected {expected_kyber_ct_len}, Got {len(ciphertext)}")

        print(f"[DEBUG] Passing Kyber Ciphertext of length {len(ciphertext)} to decaps()")

        # Pass the correctly-sized ciphertext to Kyber
        kyber_shared_secret = self.kyber.decaps(kyber_secret_key, ciphertext)

        print(f"[DEBUG] Kyber Shared Secret: {kyber_shared_secret.hex()}")

        # ECDH key agreement
        # ecdh_shared_secret = self.ecdh.compute_shared_secret(ecdh_pub)
        peer_ecdh_public_key = self.deserialize_public_key(ecdh_pub)
        ecdh_shared_secret = self.derive_ecdh_shared_secret(peer_ecdh_public_key)
        print(f"[DEBUG] ECDH Shared Secret: {ecdh_shared_secret.hex()}")

        print(f"[DEBUG] HKDF Input: {ecdh_shared_secret.hex()} + {kyber_shared_secret.hex()}")

        # Derive final hybrid key
        combined_secret = kyber_shared_secret + ecdh_shared_secret
        hkdf_final = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt = None,
            info=b"AES-GCM Secure Key" ,
            backend=default_backend()
        )
        final_shared_key = hkdf_final.derive(combined_secret)

        return final_shared_key

    '''
    def hybrid_key_decapsulation(self, ciphertext, kyber_secret_key, peer_ecc_public_bytes):
        peer_ecc_public_key = self.deserialize_public_key(peer_ecc_public_bytes)
        
        # ECC key agreement
        ecdh_shared_secret = self.derive_ecdh_shared_secret(peer_ecc_public_key)
        
        # Kyber decapsulation
        kyber_shared_secret = self.kyber.decaps(ciphertext, kyber_secret_key)
        
        # Combine secrets using HKDF
        hybrid_shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Hybrid Key Exchange",
            backend=default_backend()
        ).derive(ecdh_shared_secret + kyber_shared_secret)
        
        return hybrid_shared_secret
    '''