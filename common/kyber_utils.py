"""
kyber_utils.py — Post-quantum Kyber KEM (Key Encapsulation Mechanism).

Uses the kyber-py library's Kyber512 implementation for:
  - Key pair generation (public key + secret key)
  - Encapsulation: sender creates (shared_secret, ciphertext) from public key
  - Decapsulation: receiver recovers shared_secret from ciphertext + secret key
"""

from kyber_py.kyber import Kyber512  # Pure-Python Kyber-512 KEM implementation


def generate_kyber_keypair():
    """Generate a Kyber-512 key pair.

    Returns:
        tuple: (public_key, secret_key) — both as raw bytes.
    """
    # Kyber512.keygen() returns (pk, sk) where both are byte strings
    public_key, secret_key = Kyber512.keygen()
    return public_key, secret_key


def kyber_encapsulate(public_key: bytes):
    """Encapsulate: generate a shared secret and its corresponding ciphertext.

    The sender calls this with the receiver's Kyber public key.

    Args:
        public_key: Receiver's Kyber public key (bytes).

    Returns:
        tuple: (shared_secret, ciphertext) — both as bytes.
               shared_secret is 32 bytes (256-bit).
               ciphertext is sent to the receiver for decapsulation.
    """
    # encaps(pk) → (shared_key, ciphertext) — the core KEM encapsulation
    shared_secret, ciphertext = Kyber512.encaps(public_key)
    return shared_secret, ciphertext


def kyber_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate: recover the shared secret from ciphertext using the secret key.

    The receiver calls this with their Kyber secret key and the received ciphertext.

    Args:
        secret_key: Receiver's Kyber secret key (bytes).
        ciphertext: Ciphertext received from the sender (bytes).

    Returns:
        bytes: Recovered shared secret (32 bytes), identical to sender's.
    """
    # decaps(sk, ct) → shared_key — recovers the same secret the sender derived
    shared_secret = Kyber512.decaps(secret_key, ciphertext)
    return shared_secret
