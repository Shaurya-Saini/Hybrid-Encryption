"""
main_sender.py — Entry point for the sender side.

Simply launches the interactive sender CLI.
The CLI handles all encryption and transmission logic.

Run this AFTER the receiver is already running:
    python main_sender.py
"""

import sys  # For manipulating the Python module search path
import os   # For resolving the project root directory

# Add the project root directory to sys.path so Python can find all packages
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ui.cli_sender import run_sender  # Import the sender CLI workflow


def main():
    """Launch the sender CLI flow."""
    # Run the interactive sender: prompts for message, KDF choice, then encrypts & sends
    run_sender()


# Standard Python entry point guard
if __name__ == "__main__":
    main()
