"""
aes_gcm.py — AES-256-GCM authenticated encryption and decryption.

AES-GCM provides both confidentiality (encryption) and integrity (authentication tag).
Uses a 256-bit key derived from the hybrid KDF and a random 96-bit nonce.
"""

import os  # For generating cryptographically secure random bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # AES-GCM implementation


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple:
    """Encrypt plaintext using AES-256-GCM.

    Args:
        key: 32-byte (256-bit) symmetric key from KDF.
        plaintext: Message bytes to encrypt.

    Returns:
        tuple: (ciphertext_with_tag, nonce)
               - ciphertext_with_tag: encrypted data with appended 16-byte auth tag
               - nonce: 12-byte random nonce used for this encryption
    """
    # Create AES-GCM cipher instance with the 256-bit session key
    aesgcm = AESGCM(key)

    # Generate a random 12-byte (96-bit) nonce — must be unique per encryption
    nonce = os.urandom(12)

    # Encrypt and authenticate; GCM appends a 16-byte tag to the ciphertext
    # associated_data=None means no additional authenticated data (AAD)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    return ciphertext_with_tag, nonce


def aes_gcm_decrypt(key: bytes, ciphertext_with_tag: bytes, nonce: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext and verify its authentication tag.

    Args:
        key: 32-byte (256-bit) symmetric key (must match encryption key).
        ciphertext_with_tag: Ciphertext with appended authentication tag.
        nonce: 12-byte nonce that was used during encryption.

    Returns:
        bytes: Decrypted plaintext.

    Raises:
        cryptography.exceptions.InvalidTag: If ciphertext was tampered with.
    """
    # Create AES-GCM cipher instance with the same session key
    aesgcm = AESGCM(key)

    # Decrypt and verify authentication tag; raises InvalidTag if tampered
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

    return plaintext
