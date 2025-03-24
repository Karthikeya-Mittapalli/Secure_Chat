from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

# Directories for storing keys
PRIVATE_KEY_DIR = "private_keys/"
PUBLIC_KEY_DIR = "verified_public_keys/"

# Ensure directories exist
os.makedirs(PRIVATE_KEY_DIR, exist_ok=True)
os.makedirs(PUBLIC_KEY_DIR, exist_ok=True)

def generate_ecc_keypair(client_id):
    """Generates an ECC key pair and saves them using the client ID."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # Save private key
    private_key_path = os.path.join(PRIVATE_KEY_DIR, f"{client_id}_private.pem")
    with open(private_key_path, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    public_key_path = os.path.join(PUBLIC_KEY_DIR, f"{client_id}_public.pem")
    with open(public_key_path, "wb") as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print(f"Keys generated and saved for {client_id}.")

def load_private_key(client_id):
    """Loads the private key for a given client ID."""
    private_key_path = os.path.join(PRIVATE_KEY_DIR, f"{client_id}_private.pem")
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"No private key found for {client_id}")
    
    with open(private_key_path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

def load_public_key(client_id):
    """Loads the public key for a given client ID."""
    public_key_path = os.path.join(PUBLIC_KEY_DIR, f"{client_id}_public.pem")
    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f"No public key found for {client_id}")
    
    with open(public_key_path, "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read()
        )
    