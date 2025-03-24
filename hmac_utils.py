import hmac
import hashlib

def generate_hmac(hmac_key, message):
    """Generate HMAC-SHA256 for a given message."""
    return hmac.new(hmac_key, message, hashlib.sha256).digest()

def verify_hmac(hmac_key, message, received_hmac):
    """Verify the received HMAC against the computed HMAC."""
    computed_hmac = generate_hmac(hmac_key, message)
    return hmac.compare_digest(computed_hmac, received_hmac)
