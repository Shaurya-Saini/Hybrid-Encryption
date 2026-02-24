"""
pbkdf2.py — PBKDF2 (Password-Based Key Derivation Function 2) implementation.

PBKDF2 is a deliberately slow KDF using many iterations of HMAC.
While designed for password-based scenarios, it's included here for
comparison with HKDF and Scrypt in the hybrid encryption analysis.
"""

import os  # For generating random salt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # PBKDF2 implementation
from cryptography.hazmat.primitives import hashes                   # SHA-256 hash algorithm


def derive_key(input_bytes: bytes, salt: bytes = None) -> tuple:
    """Derive a 256-bit session key using PBKDF2-HMAC-SHA256.

    Args:
        input_bytes: Combined key material (rsa_secret + pq_secret).
        salt: Optional salt bytes. If None, a random 16-byte salt is generated.

    Returns:
        tuple: (session_key, salt)
               - session_key: 32-byte derived key for AES-256-GCM.
               - salt: 16-byte salt used (must be sent to receiver for re-derivation).
    """
    # Generate a random 16-byte salt if not provided (sender generates, receiver reuses)
    if salt is None:
        salt = os.urandom(16)

    # Create PBKDF2 instance:
    #   - SHA256 as the pseudorandom function
    #   - 32 bytes = 256-bit output key
    #   - 100,000 iterations — slows brute-force attacks
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # PRF hash function
        length=32,                  # Output key length: 256 bits
        salt=salt,                  # Random or provided salt
        iterations=100_000,         # High iteration count for added security
    )

    # Derive the session key from the combined input material
    session_key = kdf.derive(input_bytes)

    # Return both the key and salt (the receiver needs the salt to re-derive)
    return session_key, salt
