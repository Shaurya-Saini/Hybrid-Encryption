"""
hkdf.py — HKDF (HMAC-based Key Derivation Function) implementation.

HKDF is the recommended baseline KDF for this project.
It's fast and standardized (RFC 5869), ideal for deriving keys from
high-entropy input like the combined RSA + Kyber secrets.
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # HKDF implementation
from cryptography.hazmat.primitives import hashes            # SHA-256 hash algorithm


def derive_key(input_bytes: bytes) -> tuple:
    """Derive a 256-bit session key from combined secrets using HKDF-SHA256.

    Args:
        input_bytes: Combined key material (rsa_secret + pq_secret).

    Returns:
        tuple: (session_key, salt)
               - session_key: 32-byte derived key for AES-256-GCM.
               - salt: None (HKDF doesn't require a separate salt for high-entropy input).
    """
    # Create HKDF instance:
    #   - SHA256 as the underlying hash
    #   - 32 bytes = 256-bit output key length
    #   - salt=None is acceptable when input already has high entropy
    #   - info provides domain separation for this specific use case
    hkdf = HKDF(
        algorithm=hashes.SHA256(),       # Hash function for HMAC
        length=32,                       # Output key length: 256 bits
        salt=None,                       # No salt needed for high-entropy input
        info=b"hybrid-encryption",       # Context/domain separation string
    )

    # Derive the session key from the combined input material
    session_key = hkdf.derive(input_bytes)

    # Return key and None for salt (HKDF doesn't use a random salt here)
    return session_key, None
