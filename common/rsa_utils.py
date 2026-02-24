"""
rsa_utils.py — RSA key generation, encryption, and decryption.

Uses RSA-2048 with OAEP padding (SHA-256) for secure key transport.
The sender encrypts a random classical secret with the receiver's RSA public key.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding  # RSA operations
from cryptography.hazmat.primitives import hashes, serialization     # Hashing & key serialization


def generate_rsa_keypair():
    """Generate a 2048-bit RSA key pair.

    Returns:
        tuple: (private_key, public_key) — cryptography RSA key objects.
    """
    # Generate RSA private key with public exponent 65537 and 2048-bit modulus
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Derive the corresponding public key from the private key
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(public_key, plaintext_bytes: bytes) -> bytes:
    """Encrypt plaintext bytes using RSA-OAEP with SHA-256.

    Args:
        public_key: RSA public key object.
        plaintext_bytes: Raw bytes to encrypt (must be small, e.g. 32 bytes).

    Returns:
        bytes: RSA ciphertext.
    """
    # Encrypt using OAEP padding with SHA-256 for both main hash and MGF
    ciphertext = public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask generation function
            algorithm=hashes.SHA256(),                     # Main hash algorithm
            label=None                                     # No label needed
        )
    )
    return ciphertext


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Decrypt RSA-OAEP ciphertext using the private key.

    Args:
        private_key: RSA private key object.
        ciphertext: RSA ciphertext bytes.

    Returns:
        bytes: Recovered plaintext bytes.
    """
    # Decrypt using the same OAEP parameters that were used for encryption
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Must match encryption MGF
            algorithm=hashes.SHA256(),                     # Must match encryption hash
            label=None
        )
    )
    return plaintext


def serialize_public_key(public_key) -> bytes:
    """Serialize an RSA public key to PEM format bytes.

    Args:
        public_key: RSA public key object.

    Returns:
        bytes: PEM-encoded public key.
    """
    # Convert public key to PEM format (human-readable, base64-encoded)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,               # PEM text format
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Standard format
    )
    return pem


def load_public_key(pem_data: bytes):
    """Load an RSA public key from PEM-encoded bytes.

    Args:
        pem_data: PEM-encoded public key bytes.

    Returns:
        RSA public key object.
    """
    # Parse PEM bytes back into a usable public key object
    public_key = serialization.load_pem_public_key(pem_data)
    return public_key


def serialize_private_key(private_key) -> bytes:
    """Serialize an RSA private key to PEM format bytes (no password).

    Args:
        private_key: RSA private key object.

    Returns:
        bytes: PEM-encoded private key.
    """
    # Convert private key to PEM format without encryption (for demo purposes)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,               # PEM text format
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # OpenSSL-compatible
        encryption_algorithm=serialization.NoEncryption()  # No passphrase protection
    )
    return pem


def load_private_key(pem_data: bytes):
    """Load an RSA private key from PEM-encoded bytes.

    Args:
        pem_data: PEM-encoded private key bytes.

    Returns:
        RSA private key object.
    """
    # Parse PEM bytes back into a usable private key object
    private_key = serialization.load_pem_private_key(pem_data, password=None)
    return private_key
