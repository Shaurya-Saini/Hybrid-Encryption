"""
cli_sender.py — Sender-side CLI for encrypting and sending messages.

Orchestrates the complete sender workflow:
  1. Prompt user for plaintext message and KDF choice
  2. Fetch receiver's public keys via HTTP
  3. Generate classical (RSA) and post-quantum (Kyber) secrets
  4. Combine secrets and derive session key using selected KDF
  5. Encrypt plaintext with AES-GCM
  6. Send encrypted payload to receiver via HTTP
"""

import sys  # For manipulating the Python module search path
import os   # For generating random bytes and resolving paths

# Add the project root directory to sys.path so we can import from sibling packages
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import base64  # For encoding binary data to base64 strings for JSON

from common.rsa_utils import rsa_encrypt, load_public_key  # RSA encryption + key loading
from common.kyber_utils import kyber_encapsulate            # Kyber KEM encapsulation
from common.aes_gcm import aes_gcm_encrypt                 # AES-GCM encryption
from kdf import hkdf, pbkdf2, scrypt_kdf                   # All three KDF modules
from network.sender_server import fetch_public_keys, send_message  # HTTP client functions
from storage.message_handler import create_message          # Save message.txt locally


# Map menu choices to (KDF name, KDF module) for dynamic selection
KDF_OPTIONS = {
    "1": ("HKDF", hkdf),           # Option 1: Fast standard KDF
    "2": ("PBKDF2", pbkdf2),       # Option 2: Slow password-based KDF
    "3": ("Scrypt", scrypt_kdf),   # Option 3: Memory-hard KDF
}


def run_sender():
    """Run the interactive sender CLI flow.

    Guides the user through message encryption and transmission.
    """
    print("=" * 50)
    print("  HYBRID ENCRYPTION — SENDER")
    print("=" * 50)

    # --- Step 1: Get plaintext input from the user ---
    plaintext = input("\nEnter your message: ").strip()
    if not plaintext:
        print("[Error] Empty message. Aborting.")
        return

    # --- Step 2: Let user choose which KDF to use ---
    print("\nSelect Key Derivation Function (KDF):")
    print("  1. HKDF   (fast, recommended)")
    print("  2. PBKDF2 (slow, high iterations)")
    print("  3. Scrypt (memory-hard)")
    choice = input("\nEnter choice (1/2/3): ").strip()

    # Validate the user's KDF choice
    if choice not in KDF_OPTIONS:
        print("[Error] Invalid choice. Aborting.")
        return

    # Unpack the selected KDF name and module
    kdf_name, kdf_module = KDF_OPTIONS[choice]
    print(f"\n[Sender] Using KDF: {kdf_name}")

    # --- Step 3: Fetch receiver's public keys via HTTP ---
    print("[Sender] Fetching receiver's public keys...")
    try:
        keys = fetch_public_keys()  # GET /get_public_keys from receiver server
    except Exception as e:
        print(f"[Error] Could not reach receiver: {e}")
        return

    # Parse the received RSA public key from PEM bytes
    rsa_public_key = load_public_key(keys["rsa_public_key"])
    # Kyber public key is already raw bytes
    kyber_public_key = keys["kyber_public_key"]
    print("[Sender] Public keys received successfully")

    # --- Step 4: Generate classical (RSA) secret ---
    # Create 32 random bytes as the classical shared secret
    rsa_secret = os.urandom(32)
    # Encrypt the secret with the receiver's RSA public key
    rsa_encrypted_secret = rsa_encrypt(rsa_public_key, rsa_secret)
    print(f"[Sender] RSA secret generated and encrypted ({len(rsa_secret)} bytes)")

    # --- Step 5: Generate post-quantum (Kyber) secret ---
    # Encapsulate: produces a shared secret + ciphertext using Kyber KEM
    pq_secret, pq_ciphertext = kyber_encapsulate(kyber_public_key)
    print(f"[Sender] Kyber PQ secret encapsulated ({len(pq_secret)} bytes)")

    # --- Step 6: Combine both secrets ---
    # Concatenate RSA secret and Kyber secret as input for the KDF
    combined_secret = rsa_secret + pq_secret
    print(f"[Sender] Combined secret: {len(combined_secret)} bytes")

    # --- Step 7: Derive session key using selected KDF ---
    # derive_key returns (session_key, salt) — salt is None for HKDF
    session_key, salt = kdf_module.derive_key(combined_secret)
    print(f"[Sender] Session key derived using {kdf_name}")

    # --- Step 8: Encrypt the plaintext with AES-GCM ---
    # Encode the plaintext string to bytes for encryption
    plaintext_bytes = plaintext.encode("utf-8")
    # AES-GCM returns (ciphertext_with_tag, nonce)
    ciphertext, nonce = aes_gcm_encrypt(session_key, plaintext_bytes)
    print("[Sender] Message encrypted with AES-256-GCM")

    # --- Step 9: Build the message payload ---
    # All binary fields are base64-encoded for JSON/HTTP transport
    message_payload = {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "rsa_encrypted_secret": base64.b64encode(rsa_encrypted_secret).decode("utf-8"),
        "pq_ciphertext": base64.b64encode(pq_ciphertext).decode("utf-8"),
        "kdf_used": kdf_name,
        "salt": base64.b64encode(salt).decode("utf-8") if salt is not None else None,
    }

    # --- Step 10: Save message.txt locally (for reference/debugging) ---
    create_message({
        "ciphertext": ciphertext,
        "nonce": nonce,
        "rsa_encrypted_secret": rsa_encrypted_secret,
        "pq_ciphertext": pq_ciphertext,
        "kdf_used": kdf_name,
        "salt": salt,
    })
    print("[Sender] message.txt saved locally")

    # --- Step 11: Send the encrypted message to the receiver via HTTP ---
    print("[Sender] Sending encrypted message to receiver...")
    try:
        response = send_message(message_payload)  # POST /receive_message
        print(f"\n[Sender] ✅ Message encrypted and sent successfully!")
        print(f"[Sender] Receiver confirmed: {response.get('status', 'unknown')}")
    except Exception as e:
        print(f"[Error] Failed to send message: {e}")
