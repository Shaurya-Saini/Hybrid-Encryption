"""
main_sender.py — Entry point for the sender side.

Presents a terminal menu to choose between two encryption techniques:
  1. RSA-Only (Classical) — uses RSA for key exchange, AES for data encryption
     ⚠️  Vulnerable to quantum attacks (Shor's algorithm)
  2. Hybrid RSA + Kyber (Quantum-Safe) — uses KDF to combine RSA and Kyber secrets
     ✅  Resistant to quantum decryption attacks

Run this AFTER the receiver is already running:
    python main_sender.py
"""

import sys  # For manipulating the Python module search path
import os   # For resolving the project root directory

# Add the project root directory to sys.path so Python can find all packages
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ui.cli_sender import run_sender                      # Hybrid encryption sender
from ui.cli_rsa_only_sender import run_rsa_only_sender    # RSA-only encryption sender


def main():
    """Display encryption method selection menu and launch the chosen sender."""

    print("=" * 60)
    print("       ENCRYPTION SYSTEM — SENDER")
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
        # Launch RSA-only sender (uses small RSA keys for Shor's demo)
        print("\n[Mode] RSA-Only (Classical) selected\n")
        run_rsa_only_sender()

    elif choice == "2":
        # Launch hybrid sender (RSA + Kyber + KDF)
        print("\n[Mode] Hybrid RSA + Kyber (Quantum-Safe) selected\n")
        run_sender()

    else:
        print("\n[Error] Invalid choice. Please enter 1 or 2.")


# Standard Python entry point guard
if __name__ == "__main__":
    main()
