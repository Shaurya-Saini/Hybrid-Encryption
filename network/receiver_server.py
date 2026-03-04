"""
receiver_server.py — FastAPI server for the receiver side.

Exposes HTTP endpoints for both hybrid and RSA-only encryption modes:
  Hybrid mode:
    GET  /get_public_keys   — Returns RSA + Kyber public keys (base64-encoded)
    POST /receive_message   — Receives hybrid encrypted message, decrypts, displays
  RSA-only mode:
    GET  /get_rsa_public_key      — Returns small RSA public key (n, e)
    POST /receive_rsa_only_message — Receives RSA-only encrypted message, decrypts

The receiver must generate keys before starting the server.
Keys and decryption logic are injected via the app's state.
"""

import sys  # For manipulating the Python module search path
import os   # For resolving the project root directory

# Add the project root directory to sys.path so we can import from sibling packages
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import base64  # For encoding/decoding binary key data to/from JSON-safe strings
from fastapi import FastAPI, Request  # FastAPI framework and request handling
from ui.cli_receiver import decrypt_and_display  # Hybrid decryption + display logic

# Create the FastAPI application instance
app = FastAPI(title="Hybrid Encryption Receiver")

# Module-level storage for keys — set by main_receiver.py before server starts
receiver_keys = {
    "rsa_private_key": None,   # RSA private key object (for hybrid decryption)
    "rsa_public_key": None,    # RSA public key object (shared with sender)
    "kyber_public_key": None,  # Kyber public key bytes (shared with sender)
    "kyber_secret_key": None,  # Kyber secret key bytes (for decapsulation)
}

# Module-level storage for small RSA keys (RSA-only mode) — set by main_receiver.py
small_rsa_keys = {
    "key_dict": None,  # Dict with n, e, d, p, q (small RSA key params)
}

# Current encryption mode — set by main_receiver.py before server starts
encryption_mode = {"mode": "HYBRID"}  # "HYBRID" or "RSA_ONLY"


@app.get("/get_public_keys")
def get_public_keys():
    """Return the receiver's public keys so the sender can encrypt (hybrid mode).

    Returns:
        JSON with base64-encoded RSA public key (PEM) and Kyber public key (raw bytes).
    """
    from common.rsa_utils import serialize_public_key  # Serialize RSA key to PEM bytes

    # Serialize RSA public key to PEM format, then base64-encode for JSON transport
    rsa_pub_pem = serialize_public_key(receiver_keys["rsa_public_key"])
    rsa_pub_b64 = base64.b64encode(rsa_pub_pem).decode("utf-8")

    # Base64-encode the raw Kyber public key bytes for JSON transport
    kyber_pub_b64 = base64.b64encode(receiver_keys["kyber_public_key"]).decode("utf-8")

    # Return both public keys as a JSON response
    return {
        "rsa_public_key": rsa_pub_b64,      # Base64(PEM) of RSA public key
        "kyber_public_key": kyber_pub_b64,   # Base64 of raw Kyber public key bytes
    }


@app.post("/receive_message")
async def receive_message(request: Request):
    """Receive an encrypted message from the sender, decrypt it, and display (hybrid mode).

    Expects JSON body matching the message.txt format:
        ciphertext, nonce, rsa_encrypted_secret, pq_ciphertext, kdf_used, salt

    Returns:
        JSON with status and the decrypted plaintext message.
    """
    # Parse the incoming JSON request body
    message_data = await request.json()

    # Decrypt the message using receiver's private keys and display result
    plaintext = decrypt_and_display(
        message_data=message_data,
        rsa_private_key=receiver_keys["rsa_private_key"],
        kyber_secret_key=receiver_keys["kyber_secret_key"],
    )

    # Return success response with the decrypted message
    return {
        "status": "success",
        "decrypted_message": plaintext,
    }


# =============================================================================
# RSA-Only Mode Endpoints
# =============================================================================


@app.get("/get_rsa_public_key")
def get_rsa_public_key():
    """Return the receiver's small RSA public key for RSA-only mode.

    Returns:
        JSON with n (modulus) and e (public exponent) as strings.
    """
    key_dict = small_rsa_keys["key_dict"]

    # Return modulus and exponent as strings (they may be large integers)
    return {
        "n": str(key_dict["n"]),  # RSA modulus
        "e": str(key_dict["e"]),  # RSA public exponent
    }


@app.post("/receive_rsa_only_message")
async def receive_rsa_only_message(request: Request):
    """Receive an RSA-only encrypted message, decrypt it, and display.

    Expects JSON body with:
        ciphertext (base64), nonce (base64), rsa_encrypted_key (str int),
        encryption_mode, session_key_length

    Returns:
        JSON with status and the decrypted plaintext message.
    """
    from ui.cli_rsa_only_receiver import decrypt_rsa_only_and_display  # RSA-only decryption

    # Parse the incoming JSON request body
    message_data = await request.json()

    # Decrypt using the small RSA private key
    plaintext = decrypt_rsa_only_and_display(
        message_data=message_data,
        rsa_key_dict=small_rsa_keys["key_dict"],
    )

    # Return success response with the decrypted message
    return {
        "status": "success",
        "decrypted_message": plaintext,
    }

