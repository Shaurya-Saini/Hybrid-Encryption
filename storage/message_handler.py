"""
message_handler.py — Create and read the encrypted message file (message.txt).

All binary data (ciphertext, nonce, keys) is base64-encoded before storage
so the JSON file remains text-safe and human-readable.
"""

import sys  # For manipulating the Python module search path
import os   # For file path operations

# Add the project root directory to sys.path for consistency
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import json    # For JSON serialization/deserialization
import base64  # For encoding binary data as text-safe strings


def create_message(data: dict, filepath: str = None) -> str:
    """Create a message.txt file containing the encrypted message payload.

    The data dict should contain raw bytes values which will be
    automatically base64-encoded for JSON storage.

    Args:
        data: Dictionary with encryption artifacts (ciphertext, nonce, etc.).
        filepath: Optional output file path. Defaults to 'message.txt' in project root.

    Returns:
        str: Path to the created message file.
    """
    # Default filepath is message.txt in the project root directory
    if filepath is None:
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),  # Go up from storage/
            "message.txt"
        )

    # Base64-encode any bytes values so they can be stored as JSON strings
    encoded_data = {}
    for key, value in data.items():
        if isinstance(value, bytes):
            # Convert raw bytes → base64 string for JSON compatibility
            encoded_data[key] = base64.b64encode(value).decode("utf-8")
        else:
            # Keep non-bytes values (e.g., kdf_used string) as-is
            encoded_data[key] = value

    # Write the JSON payload to file with readable indentation
    with open(filepath, "w") as f:
        json.dump(encoded_data, f, indent=2)

    return filepath


def read_message(filepath: str = None) -> dict:
    """Read and parse a message.txt file, decoding base64 fields back to bytes.

    Args:
        filepath: Path to message file. Defaults to 'message.txt' in project root.

    Returns:
        dict: Parsed message with binary fields decoded back to bytes.
    """
    # Default filepath is message.txt in the project root directory
    if filepath is None:
        filepath = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "message.txt"
        )

    # Read and parse the JSON file
    with open(filepath, "r") as f:
        data = json.load(f)

    # Decode base64 strings back to raw bytes for all fields except 'kdf_used'
    decoded_data = {}
    for key, value in data.items():
        if key == "kdf_used":
            # KDF identifier is a plain string, not base64-encoded
            decoded_data[key] = value
        elif key == "salt" and value is None:
            # HKDF doesn't use a salt, so it may be None
            decoded_data[key] = None
        else:
            # Decode base64 string back to raw bytes
            decoded_data[key] = base64.b64decode(value)

    return decoded_data
