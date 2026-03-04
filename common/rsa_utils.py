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


# =============================================================================
# Small RSA utilities — deliberately weak keys for Shor's algorithm demo
# =============================================================================

import random  # For Miller-Rabin primality testing
import math    # For GCD computation
import json    # For JSON-based small key serialization


def _is_prime_miller_rabin(n, k=20):
    """Miller-Rabin primality test with k rounds.

    Args:
        n: Integer to test for primality.
        k: Number of testing rounds (more = higher confidence).

    Returns:
        bool: True if n is probably prime, False if definitely composite.
    """
    # Handle small edge cases directly
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d where d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Perform k rounds of Miller-Rabin testing
    for _ in range(k):
        a = random.randrange(2, n - 1)  # Random witness
        x = pow(a, d, n)                # a^d mod n (modular exponentiation)

        if x == 1 or x == n - 1:
            continue  # Passes this round

        for _ in range(r - 1):
            x = pow(x, 2, n)  # Square and reduce mod n
            if x == n - 1:
                break  # Passes this round
        else:
            return False  # Definitely composite

    return True  # Probably prime


def _generate_prime(bits):
    """Generate a random prime number of the specified bit length.

    Args:
        bits: Desired bit length of the prime.

    Returns:
        int: A prime number with the specified number of bits.
    """
    while True:
        # Generate random odd number in the correct bit range
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime_miller_rabin(p):
            return p


def _mod_inverse(e, phi):
    """Compute modular multiplicative inverse using Extended Euclidean Algorithm.

    Finds d such that (e * d) mod phi = 1.

    Args:
        e: The public exponent.
        phi: Euler's totient φ(n) = (p-1)(q-1).

    Returns:
        int: The modular inverse d (private exponent).
    """
    # Extended Euclidean Algorithm
    g, x, _ = _extended_gcd(e, phi)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi  # Ensure positive result


def _extended_gcd(a, b):
    """Extended Euclidean Algorithm — returns (gcd, x, y) where a*x + b*y = gcd.

    Args:
        a, b: Input integers.

    Returns:
        tuple: (gcd, x, y) satisfying a*x + b*y = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1  # Back-substitute to find x
    y = x1                   # Back-substitute to find y
    return gcd, x, y


def generate_small_rsa_keypair(bits=32):
    """Generate a deliberately small RSA key pair for Shor's algorithm demo.

    Uses raw math instead of the cryptography library (which enforces min 512-bit).
    The small key size makes classical factoring feasible for demonstration.

    Args:
        bits: Bit length for each prime (total modulus ≈ 2*bits). Default 32.

    Returns:
        dict: {
            "n": int (modulus),
            "e": int (public exponent),
            "d": int (private exponent),
            "p": int (first prime factor),
            "q": int (second prime factor)
        }
    """
    while True:
        # Generate two distinct primes of the specified bit length
        p = _generate_prime(bits)
        q = _generate_prime(bits)
        if p == q:
            continue  # Primes must be distinct

        n = p * q                     # RSA modulus
        phi = (p - 1) * (q - 1)      # Euler's totient
        e = 65537                     # Standard public exponent

        # Ensure e and φ(n) are coprime (required for RSA)
        if math.gcd(e, phi) != 1:
            continue

        # Compute private exponent d = e⁻¹ mod φ(n)
        d = _mod_inverse(e, phi)
        return {"n": n, "e": e, "d": d, "p": p, "q": q}


def small_rsa_encrypt(n, e, plaintext_bytes: bytes) -> int:
    """Encrypt plaintext bytes using raw RSA (textbook RSA, no padding).

    Converts bytes to integer, then computes c = m^e mod n.
    No padding is used — this is intentionally insecure for demo purposes.

    Args:
        n: RSA modulus (int).
        e: RSA public exponent (int).
        plaintext_bytes: Raw bytes to encrypt (must be < n when interpreted as int).

    Returns:
        int: RSA ciphertext as an integer.
    """
    # Convert bytes to integer (big-endian)
    m = int.from_bytes(plaintext_bytes, byteorder="big")
    # Textbook RSA encryption: c = m^e mod n
    c = pow(m, e, n)
    return c


def small_rsa_decrypt(n, d, ciphertext_int: int, key_length: int = 32) -> bytes:
    """Decrypt RSA ciphertext integer using the private exponent.

    Computes m = c^d mod n, then converts back to bytes.

    Args:
        n: RSA modulus (int).
        d: RSA private exponent (int).
        ciphertext_int: RSA ciphertext as an integer.
        key_length: Expected length of decrypted bytes (default 32 for AES-256 key).

    Returns:
        bytes: Recovered plaintext bytes.
    """
    # Textbook RSA decryption: m = c^d mod n
    m = pow(ciphertext_int, d, n)
    # Convert integer back to bytes, preserving leading zeros
    return m.to_bytes(key_length, byteorder="big")


def serialize_small_rsa_keys(key_dict: dict) -> str:
    """Serialize small RSA key dict to JSON string for storage.

    Args:
        key_dict: Dictionary with n, e, d, p, q as integers.

    Returns:
        str: JSON string representation.
    """
    return json.dumps(key_dict, indent=2)


def load_small_rsa_keys(json_str: str) -> dict:
    """Load small RSA key dict from JSON string.

    Args:
        json_str: JSON string with n, e, d, p, q fields.

    Returns:
        dict: Key dictionary with integer values.
    """
    return json.loads(json_str)
