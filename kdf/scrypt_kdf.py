"""
scrypt_kdf.py — Scrypt key derivation function implementation.

Scrypt is a memory-hard KDF that resists GPU/ASIC brute-force attacks
by requiring significant memory alongside CPU time. Included here for
security comparison against HKDF and PBKDF2.
"""

import os  # For generating random salt
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # Scrypt implementation


def derive_key(input_bytes: bytes, salt: bytes = None) -> tuple:
    """Derive a 256-bit session key using Scrypt.

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

    # Create Scrypt instance:
    #   - salt: random bytes to prevent precomputation attacks
    #   - length: 32 bytes = 256-bit output key
    #   - n=2^14 (16384): CPU/memory cost parameter (higher = slower + more memory)
    #   - r=8: block size parameter (affects memory usage)
    #   - p=1: parallelization parameter
    kdf = Scrypt(
        salt=salt,    # Random or provided salt
        length=32,    # Output key length: 256 bits
        n=2**14,      # CPU/memory cost: 16384
        r=8,          # Block size factor
        p=1,          # Parallelism factor
    )

    # Derive the session key from the combined input material
    session_key = kdf.derive(input_bytes)

    # Return both the key and salt (the receiver needs the salt to re-derive)
    return session_key, salt
