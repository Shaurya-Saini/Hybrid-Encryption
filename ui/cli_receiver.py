"""
cli_receiver.py — Receiver-side decryption and display logic.

Called by the receiver server when an encrypted message arrives.
Performs:
  1. RSA decryption to recover the classical secret
  2. Kyber decapsulation to recover the PQ secret
  3. KDF re-derivation to reconstruct the session key
  4. AES-GCM decryption to recover the original plaintext
"""

import sys  # For manipulating the Python module search path
import os   # For resolving the project root directory

# Add the project root directory to sys.path so we can import from sibling packages
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import base64  # For decoding base64-encoded message fields

from common.rsa_utils import rsa_decrypt       # RSA-OAEP decryption
from common.kyber_utils import kyber_decapsulate  # Kyber KEM decapsulation
from common.aes_gcm import aes_gcm_decrypt      # AES-GCM authenticated decryption
from kdf import hkdf, pbkdf2, scrypt_kdf        # All three KDF implementations


# Map KDF names to their module implementations for dynamic selection
KDF_MAP = {
    "HKDF": hkdf,          # Fast, standard KDF (RFC 5869)
    "PBKDF2": pbkdf2,      # Password-based KDF with high iteration count
    "Scrypt": scrypt_kdf,  # Memory-hard KDF resistant to GPU attacks
}


def decrypt_and_display(message_data: dict, rsa_private_key, kyber_secret_key: bytes) -> str:
    """Decrypt an incoming encrypted message and display the plaintext.

    Args:
        message_data: Dictionary with base64-encoded encryption fields:
                      ciphertext, nonce, rsa_encrypted_secret, pq_ciphertext, kdf_used, salt.
        rsa_private_key: Receiver's RSA private key object.
        kyber_secret_key: Receiver's Kyber secret key (raw bytes).

    Returns:
        str: The decrypted plaintext message.
    """
    # --- Step 1: Decode all base64 fields back to raw bytes ---
    ciphertext = base64.b64decode(message_data["ciphertext"])          # AES-GCM encrypted data + tag
    nonce = base64.b64decode(message_data["nonce"])                    # AES-GCM nonce (12 bytes)
    rsa_encrypted_secret = base64.b64decode(message_data["rsa_encrypted_secret"])  # RSA-encrypted classical secret
    pq_ciphertext = base64.b64decode(message_data["pq_ciphertext"])   # Kyber ciphertext for decapsulation
    kdf_used = message_data["kdf_used"]                                # KDF identifier string (e.g., "HKDF")

    # Decode salt if present (PBKDF2 and Scrypt use salts; HKDF does not)
    salt = None
    if message_data.get("salt") is not None:
        salt = base64.b64decode(message_data["salt"])

    # --- Step 2: Recover the classical RSA secret ---
    # Decrypt the RSA-encrypted random bytes using the receiver's RSA private key
    rsa_secret = rsa_decrypt(rsa_private_key, rsa_encrypted_secret)
    print(f"[Receiver] RSA secret recovered ({len(rsa_secret)} bytes)")

    # --- Step 3: Recover the post-quantum Kyber shared secret ---
    # Decapsulate using the Kyber secret key and the received ciphertext
    pq_secret = kyber_decapsulate(kyber_secret_key, pq_ciphertext)
    print(f"[Receiver] Kyber PQ secret recovered ({len(pq_secret)} bytes)")

    # --- Step 4: Combine both secrets (same order as sender) ---
    combined_secret = rsa_secret + pq_secret
    print(f"[Receiver] Combined secret: {len(combined_secret)} bytes")

    # --- Step 5: Re-derive the session key using the same KDF ---
    # Look up the KDF module by name
    kdf_module = KDF_MAP[kdf_used]

    # Call derive_key with the salt (for PBKDF2/Scrypt) or without (HKDF)
    if salt is not None:
        # PBKDF2 and Scrypt need the same salt that was used during encryption
        session_key, _ = kdf_module.derive_key(combined_secret, salt=salt)
    else:
        # HKDF doesn't use a random salt
        session_key, _ = kdf_module.derive_key(combined_secret)

    print(f"[Receiver] Session key derived using {kdf_used}")

    # --- Step 6: Decrypt the ciphertext using AES-GCM ---
    # AES-GCM decrypt also verifies the authentication tag (integrity check)
    plaintext_bytes = aes_gcm_decrypt(session_key, ciphertext, nonce)

    # Decode bytes to UTF-8 string for display
    plaintext = plaintext_bytes.decode("utf-8")

    # Display the decrypted message prominently
    print(f"\n{'='*50}")
    print(f"  Decrypted Message: {plaintext}")
    print(f"{'='*50}\n")

    return plaintext
