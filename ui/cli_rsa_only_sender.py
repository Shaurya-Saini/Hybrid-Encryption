"""
cli_rsa_only_sender.py — Sender-side CLI for RSA-only encryption mode.

Orchestrates the RSA-only sender workflow:
  1. Prompt user for plaintext message
  2. Fetch receiver's RSA public key via HTTP
  3. Generate a random AES-256 session key
  4. Encrypt the AES key with the receiver's RSA public key (raw RSA, small key)
  5. Encrypt plaintext with AES-GCM using the session key
  6. Save message.txt and send encrypted payload to receiver via HTTP

NOTE: This uses deliberately small RSA keys to demonstrate vulnerability to Shor's algorithm.
"""

import sys  # For manipulating the Python module search path
import os   # For generating random bytes and resolving paths

# Add the project root directory to sys.path so we can import from sibling packages
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import base64  # For encoding binary data to base64 strings for JSON

from common.rsa_utils import small_rsa_encrypt      # Raw RSA encryption (small keys)
from common.aes_gcm import aes_gcm_encrypt           # AES-GCM encryption
from network.sender_server import fetch_rsa_public_key, send_rsa_only_message  # HTTP client
from storage.message_handler import create_message    # Save message.txt locally


def run_rsa_only_sender():
    """Run the interactive RSA-only sender CLI flow.

    Guides the user through message encryption using only RSA for key exchange
    and AES-GCM for plaintext encryption. Uses small RSA keys for Shor's demo.
    """
    print("=" * 50)
    print("  RSA-ONLY ENCRYPTION — SENDER")
    print("  ⚠️  Vulnerable to quantum attacks!")
    print("=" * 50)

    # --- Step 1: Get plaintext input from the user ---
    plaintext = input("\nEnter your message: ").strip()
    if not plaintext:
        print("[Error] Empty message. Aborting.")
        return

    # --- Step 2: Fetch receiver's RSA public key via HTTP ---
    print("\n[Sender] Fetching receiver's RSA public key...")
    try:
        key_data = fetch_rsa_public_key()  # GET /get_rsa_public_key from receiver
    except Exception as e:
        print(f"[Error] Could not reach receiver: {e}")
        return

    # Extract modulus (n) and public exponent (e) from the response
    n = key_data["n"]
    e = key_data["e"]
    print(f"[Sender] RSA public key received (n = {n}, e = {e})")

    # --- Step 3: Generate random AES-256 session key ---
    # Only use key bytes that fit within the RSA modulus
    # For small RSA keys, the session key must be smaller than n
    n_byte_length = (n.bit_length() + 7) // 8  # Number of bytes in modulus
    session_key_length = min(n_byte_length - 1, 32)  # Leave room, max 32 bytes
    session_key = os.urandom(session_key_length)

    # Ensure session key as integer is less than n (required for textbook RSA)
    while int.from_bytes(session_key, "big") >= n:
        session_key = os.urandom(session_key_length)

    print(f"[Sender] AES session key generated ({len(session_key)} bytes)")

    # --- Step 4: Encrypt AES key with RSA (raw/textbook RSA) ---
    rsa_encrypted_key = small_rsa_encrypt(n, e, session_key)
    print(f"[Sender] AES key encrypted with RSA (ciphertext integer: {rsa_encrypted_key})")

    # --- Step 5: Pad session key to 32 bytes for AES-256-GCM ---
    # If session key is shorter than 32 bytes, left-pad with zeros
    if len(session_key) < 32:
        padded_key = session_key.rjust(32, b'\x00')
    else:
        padded_key = session_key

    # --- Step 6: Encrypt the plaintext with AES-GCM ---
    plaintext_bytes = plaintext.encode("utf-8")  # Convert string to bytes
    ciphertext, nonce = aes_gcm_encrypt(padded_key, plaintext_bytes)
    print("[Sender] Message encrypted with AES-256-GCM")

    # --- Step 7: Build the message payload ---
    # rsa_encrypted_key is an integer — store it as a string
    message_payload = {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "rsa_encrypted_key": str(rsa_encrypted_key),  # Integer as string
        "encryption_mode": "RSA_ONLY",
        "session_key_length": session_key_length,  # Needed for decryption byte conversion
    }

    # --- Step 8: Save message.txt locally (for reference/Shor's attack demo) ---
    create_message({
        "ciphertext": ciphertext,
        "nonce": nonce,
        "rsa_encrypted_key": str(rsa_encrypted_key),
        "encryption_mode": "RSA_ONLY",
        "session_key_length": session_key_length,
    })
    print("[Sender] message.txt saved locally")

    # --- Step 9: Send the encrypted message to the receiver via HTTP ---
    print("[Sender] Sending encrypted message to receiver...")
    try:
        response = send_rsa_only_message(message_payload)  # POST /receive_rsa_only_message
        print(f"\n[Sender] ✅ Message encrypted and sent successfully!")
        print(f"[Sender] Receiver confirmed: {response.get('status', 'unknown')}")
    except Exception as e:
        print(f"[Error] Failed to send message: {e}")
