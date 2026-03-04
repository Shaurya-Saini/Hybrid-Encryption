"""
cli_rsa_only_receiver.py — Receiver-side decryption logic for RSA-only mode.

Called by the receiver server when an RSA-only encrypted message arrives.
Performs:
  1. RSA decryption to recover the AES session key
  2. AES-GCM decryption to recover the original plaintext

NOTE: Uses small RSA keys — deliberately vulnerable for Shor's algorithm demo.
"""

import sys  # For manipulating the Python module search path
import os   # For resolving the project root directory

# Add the project root directory to sys.path so we can import from sibling packages
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import base64  # For decoding base64-encoded message fields

from common.rsa_utils import small_rsa_decrypt  # Raw RSA decryption (small keys)
from common.aes_gcm import aes_gcm_decrypt      # AES-GCM authenticated decryption


def decrypt_rsa_only_and_display(message_data: dict, rsa_key_dict: dict) -> str:
    """Decrypt an RSA-only encrypted message and display the plaintext.

    Args:
        message_data: Dictionary with encrypted message fields:
                      ciphertext (base64), nonce (base64), rsa_encrypted_key (str int),
                      encryption_mode, session_key_length.
        rsa_key_dict: Dictionary with RSA key parameters (n, e, d, p, q).

    Returns:
        str: The decrypted plaintext message.
    """
    # --- Step 1: Decode base64 fields back to raw bytes ---
    ciphertext = base64.b64decode(message_data["ciphertext"])   # AES-GCM encrypted data + tag
    nonce = base64.b64decode(message_data["nonce"])             # AES-GCM nonce (12 bytes)
    rsa_encrypted_key = int(message_data["rsa_encrypted_key"])  # RSA ciphertext as integer
    session_key_length = int(message_data["session_key_length"])  # Original key byte length

    # --- Step 2: Decrypt the RSA-encrypted AES session key ---
    # Use the private exponent d to recover the session key
    n = rsa_key_dict["n"]
    d = rsa_key_dict["d"]
    session_key = small_rsa_decrypt(n, d, rsa_encrypted_key, key_length=session_key_length)
    print(f"[Receiver] AES session key recovered ({len(session_key)} bytes)")

    # --- Step 3: Pad session key to 32 bytes for AES-256-GCM ---
    if len(session_key) < 32:
        padded_key = session_key.rjust(32, b'\x00')
    else:
        padded_key = session_key

    # --- Step 4: Decrypt the ciphertext using AES-GCM ---
    # AES-GCM decrypt also verifies the authentication tag (integrity check)
    plaintext_bytes = aes_gcm_decrypt(padded_key, ciphertext, nonce)

    # Decode bytes to UTF-8 string for display
    plaintext = plaintext_bytes.decode("utf-8")

    # Display the decrypted message prominently
    print(f"\n{'='*50}")
    print(f"  Decrypted Message: {plaintext}")
    print(f"{'='*50}\n")

    return plaintext
