"""
key_store.py — Save and load cryptographic keys to/from disk.

Handles persistence for both RSA keys (PEM format) and Kyber keys (raw bytes).
Avoids pickle for security — uses PEM for RSA and raw binary files for Kyber.
"""

import sys  # For manipulating the Python module search path
import os   # For path operations and directory creation

# Add the project root directory to sys.path so we can import from sibling packages
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from common.rsa_utils import (
    serialize_public_key,   # Convert RSA public key → PEM bytes
    serialize_private_key,  # Convert RSA private key → PEM bytes
    load_public_key,        # Load RSA public key from PEM bytes
    load_private_key,       # Load RSA private key from PEM bytes
)

# Default directory where keys are stored
KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "keys")


def _ensure_keys_dir():
    """Create the keys directory if it doesn't already exist."""
    os.makedirs(KEYS_DIR, exist_ok=True)  # exist_ok prevents error if dir exists


def save_rsa_keys(private_key, public_key):
    """Save RSA key pair to PEM files on disk.

    Args:
        private_key: RSA private key object.
        public_key: RSA public key object.
    """
    _ensure_keys_dir()  # Make sure keys/ directory exists

    # Write RSA private key in PEM format
    with open(os.path.join(KEYS_DIR, "rsa_private.pem"), "wb") as f:
        f.write(serialize_private_key(private_key))

    # Write RSA public key in PEM format
    with open(os.path.join(KEYS_DIR, "rsa_public.pem"), "wb") as f:
        f.write(serialize_public_key(public_key))


def load_rsa_keys():
    """Load RSA key pair from PEM files on disk.

    Returns:
        tuple: (private_key, public_key) — RSA key objects.
    """
    # Read and parse RSA private key from PEM file
    with open(os.path.join(KEYS_DIR, "rsa_private.pem"), "rb") as f:
        private_key = load_private_key(f.read())

    # Read and parse RSA public key from PEM file
    with open(os.path.join(KEYS_DIR, "rsa_public.pem"), "rb") as f:
        public_key = load_public_key(f.read())

    return private_key, public_key


def save_kyber_keys(public_key: bytes, secret_key: bytes):
    """Save Kyber key pair as raw binary files on disk.

    Args:
        public_key: Kyber public key (raw bytes).
        secret_key: Kyber secret key (raw bytes).
    """
    _ensure_keys_dir()  # Make sure keys/ directory exists

    # Write Kyber public key as raw bytes
    with open(os.path.join(KEYS_DIR, "kyber_public.bin"), "wb") as f:
        f.write(public_key)

    # Write Kyber secret key as raw bytes
    with open(os.path.join(KEYS_DIR, "kyber_secret.bin"), "wb") as f:
        f.write(secret_key)


def load_kyber_keys():
    """Load Kyber key pair from binary files on disk.

    Returns:
        tuple: (public_key, secret_key) — both as raw bytes.
    """
    # Read Kyber public key bytes
    with open(os.path.join(KEYS_DIR, "kyber_public.bin"), "rb") as f:
        public_key = f.read()

    # Read Kyber secret key bytes
    with open(os.path.join(KEYS_DIR, "kyber_secret.bin"), "rb") as f:
        secret_key = f.read()

    return public_key, secret_key
