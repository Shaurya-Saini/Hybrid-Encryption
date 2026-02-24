"""
main_receiver.py — Entry point for the receiver side.

Workflow:
  1. Generate RSA and Kyber key pairs
  2. Save keys to disk (optional persistence)
  3. Inject keys into the FastAPI server
  4. Start the FastAPI server via uvicorn on port 5001

Run this FIRST before starting the sender:
    python main_receiver.py
"""

import sys  # For manipulating the Python module search path
import os   # For resolving the project root directory

# Add the project root directory to sys.path so Python can find all packages
# (common, kdf, storage, network, ui) regardless of where this script is run from
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import uvicorn  # ASGI server to run FastAPI

from common.rsa_utils import generate_rsa_keypair     # Generate RSA-2048 key pair
from common.kyber_utils import generate_kyber_keypair  # Generate Kyber-512 key pair
from storage.key_store import save_rsa_keys, save_kyber_keys  # Persist keys to disk
from network.receiver_server import app, receiver_keys  # FastAPI app + key storage dict


def main():
    """Initialize keys and start the receiver server."""

    print("=" * 50)
    print("  HYBRID ENCRYPTION — RECEIVER")
    print("=" * 50)

    # --- Step 1: Generate RSA-2048 key pair ---
    print("\n[Receiver] Generating RSA-2048 key pair...")
    rsa_private_key, rsa_public_key = generate_rsa_keypair()
    print("[Receiver] RSA keys generated ✅")

    # --- Step 2: Generate Kyber-512 key pair ---
    print("[Receiver] Generating Kyber-512 key pair...")
    kyber_public_key, kyber_secret_key = generate_kyber_keypair()
    print("[Receiver] Kyber keys generated ✅")

    # --- Step 3: Save keys to disk for persistence ---
    save_rsa_keys(rsa_private_key, rsa_public_key)
    save_kyber_keys(kyber_public_key, kyber_secret_key)
    print("[Receiver] Keys saved to disk (keys/ directory)")

    # --- Step 4: Inject keys into the FastAPI server's shared state ---
    # The receiver_server module reads these when handling requests
    receiver_keys["rsa_private_key"] = rsa_private_key
    receiver_keys["rsa_public_key"] = rsa_public_key
    receiver_keys["kyber_public_key"] = kyber_public_key
    receiver_keys["kyber_secret_key"] = kyber_secret_key

    # --- Step 5: Start the FastAPI server ---
    print("\n[Receiver] Starting server on http://127.0.0.1:5001")
    print("[Receiver] Waiting for messages...\n")

    # Run uvicorn ASGI server hosting the FastAPI app
    # host="0.0.0.0" allows connections from any network interface
    # log_level="info" provides useful request logging
    uvicorn.run(app, host="0.0.0.0", port=5001, log_level="info")


# Standard Python entry point guard
if __name__ == "__main__":
    main()
