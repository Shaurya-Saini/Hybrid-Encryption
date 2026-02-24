"""
sender_server.py — HTTP client functions for the sender side.

Provides helper functions to:
  1. Fetch the receiver's public keys via GET request
  2. Send the encrypted message payload via POST request

Uses the 'requests' library for simple synchronous HTTP calls.
"""

import sys  # For manipulating the Python module search path
import os   # For resolving the project root directory

# Add the project root directory to sys.path for consistency
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import base64    # For decoding base64-encoded keys from the receiver's response
import requests  # HTTP client library for making API calls


def fetch_public_keys(receiver_url: str = "http://127.0.0.1:5001") -> dict:
    """Fetch the receiver's RSA and Kyber public keys via HTTP GET.

    Args:
        receiver_url: Base URL of the receiver server (default: localhost:5001).

    Returns:
        dict: {
            "rsa_public_key": bytes (PEM),
            "kyber_public_key": bytes (raw)
        }

    Raises:
        requests.exceptions.ConnectionError: If receiver server is not running.
    """
    # Send GET request to the receiver's public key endpoint
    response = requests.get(f"{receiver_url}/get_public_keys")

    # Raise an exception if the HTTP status code indicates an error
    response.raise_for_status()

    # Parse the JSON response body
    data = response.json()

    # Decode base64 strings back to raw bytes:
    #   RSA key: base64 → PEM bytes
    #   Kyber key: base64 → raw key bytes
    return {
        "rsa_public_key": base64.b64decode(data["rsa_public_key"]),
        "kyber_public_key": base64.b64decode(data["kyber_public_key"]),
    }


def send_message(message_data: dict, receiver_url: str = "http://127.0.0.1:5001") -> dict:
    """Send the encrypted message payload to the receiver via HTTP POST.

    Args:
        message_data: Dictionary containing the encrypted message fields
                      (ciphertext, nonce, rsa_encrypted_secret, etc.).
                      All bytes values must already be base64-encoded strings.
        receiver_url: Base URL of the receiver server (default: localhost:5001).

    Returns:
        dict: Response from the receiver (status + decrypted message confirmation).

    Raises:
        requests.exceptions.ConnectionError: If receiver server is not running.
    """
    # Send POST request with the encrypted message as JSON body
    response = requests.post(
        f"{receiver_url}/receive_message",
        json=message_data,  # Automatically serializes dict to JSON
    )

    # Raise an exception if the HTTP status code indicates an error
    response.raise_for_status()

    # Return the receiver's JSON response (contains decryption confirmation)
    return response.json()
