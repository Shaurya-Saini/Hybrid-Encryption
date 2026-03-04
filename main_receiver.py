"""
main_receiver.py — Entry point for the receiver side.

Presents a terminal menu to choose between two encryption modes:
  1. RSA-Only (Classical) — generates only small RSA keys, no Kyber
  2. Hybrid RSA + Kyber (Quantum-Safe) — generates both RSA and Kyber keys

Workflow:
  1. Display mode selection menu
  2. Generate appropriate key pairs based on mode
  3. Save keys to disk (optional persistence)
  4. Inject keys into the FastAPI server
  5. Start the FastAPI server via uvicorn on port 5001

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

from common.rsa_utils import generate_rsa_keypair               # Generate RSA-2048 key pair
from common.rsa_utils import generate_small_rsa_keypair          # Generate small RSA key pair
from common.rsa_utils import serialize_small_rsa_keys            # Serialize small RSA keys
from common.kyber_utils import generate_kyber_keypair            # Generate Kyber-512 key pair
from storage.key_store import save_rsa_keys, save_kyber_keys     # Persist keys to disk
from network.receiver_server import app, receiver_keys, small_rsa_keys, encryption_mode  # Server state


def run_hybrid_mode():
    """Initialize keys and start the receiver server in Hybrid mode."""

    print("\n[Mode] Hybrid RSA + Kyber (Quantum-Safe) selected\n")

    # --- Step 1: Generate RSA-2048 key pair ---
    print("[Receiver] Generating RSA-2048 key pair...")
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
    receiver_keys["rsa_private_key"] = rsa_private_key
    receiver_keys["rsa_public_key"] = rsa_public_key
    receiver_keys["kyber_public_key"] = kyber_public_key
    receiver_keys["kyber_secret_key"] = kyber_secret_key

    # Set encryption mode
    encryption_mode["mode"] = "HYBRID"


def run_rsa_only_mode():
    """Initialize small RSA keys and start the receiver server in RSA-only mode."""

    print("\n[Mode] RSA-Only (Classical) selected")
    print("[Mode] ⚠️  Using small RSA keys (vulnerable to Shor's algorithm)\n")

    # --- Step 1: Generate small RSA key pair (≈32-bit modulus) ---
    # Using 16-bit primes so Shor's classical simulation can factor n quickly
    print("[Receiver] Generating small RSA key pair (16-bit primes)...")
    key_dict = generate_small_rsa_keypair(bits=16)
    print(f"[Receiver] RSA modulus n = {key_dict['n']}")
    print(f"[Receiver] RSA public exponent e = {key_dict['e']}")
    print("[Receiver] Small RSA keys generated ✅")

    # --- Step 2: Save small RSA keys to disk for persistence ---
    keys_dir = os.path.join(PROJECT_ROOT, "keys")
    os.makedirs(keys_dir, exist_ok=True)

    # Save as JSON file
    with open(os.path.join(keys_dir, "small_rsa_keys.json"), "w") as f:
        f.write(serialize_small_rsa_keys(key_dict))
    print("[Receiver] Small RSA keys saved to keys/small_rsa_keys.json")

    # --- Step 3: Inject keys into the FastAPI server's shared state ---
    small_rsa_keys["key_dict"] = key_dict

    # Set encryption mode
    encryption_mode["mode"] = "RSA_ONLY"


def main():
    """Display encryption mode selection menu and start the receiver server."""

    print("=" * 60)
    print("       ENCRYPTION SYSTEM — RECEIVER")
    print("=" * 60)
    print()
    print("  Choose Encryption Technique:")
    print()
    print("  1. RSA-Only (Classical)")
    print("     └─ Uses RSA for key exchange + AES for encryption")
    print("     └─ ⚠️  VULNERABLE to quantum attacks (Shor's Algorithm)")
    print()
    print("  2. Hybrid RSA + Kyber (Quantum-Safe)")
    print("     └─ Combines RSA + Kyber via KDF for key exchange")
    print("     └─ ✅  RESISTANT to quantum decryption attacks")
    print()
    print("=" * 60)

    # Get user's choice
    choice = input("\n  Enter choice (1 or 2): ").strip()

    if choice == "1":
        run_rsa_only_mode()
    elif choice == "2":
        run_hybrid_mode()
    else:
        print("\n[Error] Invalid choice. Please enter 1 or 2.")
        return

    # --- Start the FastAPI server ---
    print(f"\n[Receiver] Starting server on http://127.0.0.1:5001")
    print(f"[Receiver] Mode: {encryption_mode['mode']}")
    print("[Receiver] Waiting for messages...\n")

    # Run uvicorn ASGI server hosting the FastAPI app
    # host="0.0.0.0" allows connections from any network interface
    # log_level="info" provides useful request logging
    uvicorn.run(app, host="0.0.0.0", port=5001, log_level="info")


# Standard Python entry point guard
if __name__ == "__main__":
    main()
