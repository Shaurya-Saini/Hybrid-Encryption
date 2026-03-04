"""
main_attack.py — Entry point for Shor's Algorithm Attack Demonstration.

Demonstrates breaking RSA-only encryption by:
  1. Reading the encrypted message from message.txt
  2. Factoring the RSA public key modulus using Shor's algorithm (simulated)
  3. Reconstructing the RSA private key from the factors
  4. Decrypting the AES session key and then the plaintext

PREREQUISITES:
  - Run RSA-only encryption first:
      Terminal 1: python main_receiver.py → choose option 1
      Terminal 2: python main_sender.py → choose option 1 → enter a message
  - This creates message.txt and keys/small_rsa_keys.json

Then run this script:
    python main_attack.py
"""

import sys  # For manipulating the Python module search path
import os   # For resolving the project root directory

# Add the project root directory to sys.path so Python can find all packages
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from attack.shor_attack import run_attack  # Import the attack execution function


def main():
    """Launch the Shor's algorithm attack demonstration."""
    run_attack()


# Standard Python entry point guard
if __name__ == "__main__":
    main()
