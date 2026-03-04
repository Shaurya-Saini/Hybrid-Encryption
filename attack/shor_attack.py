"""
shor_attack.py — Shor's Algorithm Attack Demonstration.

Demonstrates breaking RSA-only encryption by:
  1. Reading the encrypted message from message.txt
  2. Loading the RSA public key (n, e) from keys/small_rsa_keys.json
  3. Factoring n using a classical simulation of Shor's algorithm
  4. Reconstructing the RSA private key (d) from the factors
  5. Decrypting the RSA-encrypted AES session key
  6. Decrypting the AES-GCM ciphertext to recover the original plaintext

NOTE: This is a CLASSICAL SIMULATION of Shor's algorithm.
Real Shor's algorithm requires a quantum computer and can factor
arbitrarily large numbers efficiently. This demo uses small RSA keys
so factoring completes in seconds on classical hardware.

WHY NOT QISKIT?
  Qiskit simulates quantum circuits on classical hardware using exponentially
  large state vectors (2^n entries for n qubits). For even a 32-bit RSA modulus,
  Shor's circuit would need ~64+ qubits → 2^64 state vector entries → infeasible.
  Qiskit can only demo Shor's on tiny numbers like 15 or 21 (~8 qubits).
  The real speedup only exists on actual quantum hardware.
"""

import sys  # For manipulating the Python module search path
import os   # For resolving the project root directory
import math  # For GCD and mathematical operations
import random  # For random number generation in period-finding
import time  # For timing the attack steps

# Add the project root directory to sys.path so we can import from sibling packages
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import json    # For parsing key files and message files
import base64  # For decoding base64-encoded ciphertext

from common.rsa_utils import small_rsa_decrypt, load_small_rsa_keys, _mod_inverse
from common.aes_gcm import aes_gcm_decrypt


def shors_algorithm_simulation(n):
    """Classical simulation of Shor's algorithm for integer factorization.

    Shor's algorithm (1994) efficiently factors integers on a quantum computer
    using quantum period-finding. This function simulates the algorithm classically:

    1. Check trivial cases (even numbers, perfect powers)
    2. Pick a random base 'a' coprime to n
    3. Find the period 'r' of f(x) = a^x mod n (classically simulated)
    4. Use the period to extract factors: gcd(a^(r/2) ± 1, n)
    5. Repeat if needed with different random bases

    On a real quantum computer, step 3 would use Quantum Fourier Transform (QFT)
    to find the period exponentially faster than any classical method.

    Args:
        n: The integer to factor (RSA modulus = p * q).

    Returns:
        tuple: (p, q) — the two prime factors of n.
    """
    print(f"\n  [Shor] Starting factorization of n = {n}")
    print(f"  [Shor] n has {n.bit_length()} bits")

    # --- Step 1: Trivial checks ---
    # Check if n is even (trivial factor of 2)
    if n % 2 == 0:
        print(f"  [Shor] n is even — trivial factor found: 2")
        return 2, n // 2

    # Check for small prime factors (optimization)
    for small_prime in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        if n % small_prime == 0:
            print(f"  [Shor] Small prime factor found: {small_prime}")
            return small_prime, n // small_prime

    # --- Step 2: Shor's algorithm main loop ---
    max_attempts = 50  # Limit attempts to prevent infinite loops
    attempt = 0
    while attempt < max_attempts:
        attempt += 1

        # Pick a random base 'a' in range [2, n-1]
        a = random.randint(2, n - 1)
        print(f"\n  [Shor] Attempt {attempt}: random base a = {a}")

        # Check if a shares a factor with n (lucky case)
        g = math.gcd(a, n)
        if g > 1:
            print(f"  [Shor] Lucky! gcd(a, n) = {g} — factor found directly")
            return g, n // g

        # --- Step 3: Find the period r of a^x mod n ---
        # On a quantum computer, this uses QFT for exponential speedup
        # Here we simulate it classically by brute-force iteration
        print(f"  [Shor] Finding period of {a}^x mod {n}...")
        r = _find_period_classical(a, n)

        if r is None:
            print(f"  [Shor] Period not found for a={a}, trying another base...")
            continue

        print(f"  [Shor] Period found: r = {r}")

        # --- Step 4: Check if period is useful ---
        # Period must be even for the algorithm to work
        if r % 2 != 0:
            print(f"  [Shor] Period r={r} is odd — cannot use, trying another base...")
            continue

        # --- Step 5: Extract factors using gcd(a^(r/2) ± 1, n) ---
        # Compute a^(r/2) mod n
        x = pow(a, r // 2, n)

        # Check for trivial result: a^(r/2) ≡ -1 (mod n)
        if x == n - 1:
            print(f"  [Shor] a^(r/2) ≡ -1 (mod n) — trivial, trying another base...")
            continue

        # Compute the two candidate factors
        factor1 = math.gcd(x + 1, n)
        factor2 = math.gcd(x - 1, n)

        print(f"  [Shor] gcd({x}+1, {n}) = {factor1}")
        print(f"  [Shor] gcd({x}-1, {n}) = {factor2}")

        # Check if we found non-trivial factors
        if 1 < factor1 < n:
            print(f"  [Shor] ✅ Non-trivial factor found: {factor1}")
            return factor1, n // factor1
        if 1 < factor2 < n:
            print(f"  [Shor] ✅ Non-trivial factor found: {factor2}")
            return factor2, n // factor2

        print(f"  [Shor] No useful factor this round, trying another base...")

    # --- Fallback: Pollard's rho algorithm ---
    # If Shor's simulation didn't find factors quickly, use Pollard's rho
    # as a faster classical fallback (runs in O(n^1/4) expected time)
    print(f"\n  [Shor] Period-finding attempts exhausted.")
    print(f"  [Shor] Falling back to Pollard's rho (fast classical factoring)...")
    print(f"  [Shor] NOTE: On a real quantum computer, Shor's would always succeed.\n")
    return _pollards_rho(n)


def _find_period_classical(a, n):
    """Find the multiplicative order (period) of a modulo n by brute force.

    The period r is the smallest positive integer such that a^r ≡ 1 (mod n).

    On a quantum computer, this would be done via Quantum Fourier Transform
    in O(log(n)^3) time. Classically, this is O(n) in the worst case.

    Args:
        a: The base (random integer coprime to n).
        n: The modulus (RSA modulus to factor).

    Returns:
        int or None: The period r, or None if not found within the search limit.
    """
    # Limit search to prevent long runtimes on classical hardware
    # For small keys (~32-bit modulus), periods are usually < 100,000
    max_period = min(n, 500_000)

    result = 1  # Start with a^1 mod n
    for r in range(1, max_period):
        result = (result * a) % n  # Compute a^r mod n incrementally
        if result == 1:
            return r  # Found: a^r ≡ 1 (mod n)

    return None  # Period not found within limit


def _pollards_rho(n):
    """Pollard's rho algorithm — a fast probabilistic classical factoring method.

    Runs in expected O(n^(1/4)) time, much faster than trial division.
    Used as a fallback when Shor's simulation fails due to classical limitations.

    On a real quantum computer, Shor's algorithm would make this unnecessary
    since it factors in O(log(n)^3) time — exponentially faster.

    Args:
        n: The integer to factor.

    Returns:
        tuple: (p, q) — the two factors of n.
    """
    if n % 2 == 0:
        return 2, n // 2

    # Pseudorandom function: f(x) = (x^2 + c) mod n
    # Floyd's cycle detection to find a collision
    x = random.randint(2, n - 1)  # Starting value
    y = x                          # Tortoise and hare start at same point
    c = random.randint(1, n - 1)  # Random constant for pseudorandom function
    d = 1                          # Will store gcd result

    while d == 1:
        x = (x * x + c) % n       # Tortoise moves one step
        y = (y * y + c) % n       # Hare moves two steps
        y = (y * y + c) % n
        d = math.gcd(abs(x - y), n)  # Check for non-trivial factor

    if d != n:
        print(f"  [Pollard's rho] Factor found: {d}")
        return d, n // d

    # Retry with different random values if this attempt failed
    return _pollards_rho(n)


def reconstruct_private_key(p, q, e):
    """Reconstruct the RSA private exponent from the prime factors.

    Given p, q (factors of n) and e (public exponent), compute:
      d = e^(-1) mod φ(n)  where φ(n) = (p-1)(q-1)

    Args:
        p: First prime factor.
        q: Second prime factor.
        e: RSA public exponent.

    Returns:
        int: The private exponent d.
    """
    # Compute Euler's totient φ(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)

    # Compute private exponent d = e⁻¹ mod φ(n)
    d = _mod_inverse(e, phi)

    return d


def run_attack():
    """Execute the complete Shor's algorithm attack on an RSA-only encrypted message.

    Reads message.txt and small_rsa_keys.json, then demonstrates:
      Step 1: Load encrypted data
      Step 2: Extract RSA public key
      Step 3: Factor n using Shor's algorithm
      Step 4: Reconstruct private key
      Step 5: Decrypt RSA-encrypted AES session key
      Step 6: Decrypt AES-GCM ciphertext
    """
    print()
    print("=" * 60)
    print("    SHOR'S ALGORITHM ATTACK DEMONSTRATION")
    print("    Breaking RSA-Only Encryption")
    print("=" * 60)

    # ===== STEP 1: Load the encrypted message =====
    print("\n" + "─" * 60)
    print("  STEP 1: Loading encrypted message from message.txt")
    print("─" * 60)

    message_path = os.path.join(PROJECT_ROOT, "message.txt")
    if not os.path.exists(message_path):
        print(f"\n  [Error] message.txt not found at {message_path}")
        print("  [Error] Run RSA-only encryption first (python main_sender.py → option 1)")
        return

    with open(message_path, "r") as f:
        message_data = json.load(f)

    # Verify this is an RSA-only encrypted message
    if message_data.get("encryption_mode") != "RSA_ONLY":
        print(f"\n  [Error] message.txt is not RSA-only encrypted")
        print(f"  [Error] Found mode: {message_data.get('encryption_mode', 'unknown')}")
        print("  [Error] Run RSA-only encryption first (python main_sender.py → option 1)")
        return

    rsa_encrypted_key = int(message_data["rsa_encrypted_key"])
    ciphertext = base64.b64decode(message_data["ciphertext"])
    nonce = base64.b64decode(message_data["nonce"])
    session_key_length = int(message_data["session_key_length"])

    print(f"  ✅ Encrypted message loaded")
    print(f"     RSA-encrypted AES key (as integer): {rsa_encrypted_key}")
    print(f"     AES ciphertext length: {len(ciphertext)} bytes")
    print(f"     AES nonce: {nonce.hex()}")

    # ===== STEP 2: Load RSA public key =====
    print("\n" + "─" * 60)
    print("  STEP 2: Loading RSA public key")
    print("─" * 60)

    keys_path = os.path.join(PROJECT_ROOT, "keys", "small_rsa_keys.json")
    if not os.path.exists(keys_path):
        print(f"\n  [Error] small_rsa_keys.json not found at {keys_path}")
        return

    with open(keys_path, "r") as f:
        key_data = json.load(f)

    n = key_data["n"]
    e = key_data["e"]

    print(f"  ✅ RSA public key loaded")
    print(f"     Modulus n = {n}")
    print(f"     n has {n.bit_length()} bits")
    print(f"     Public exponent e = {e}")
    print(f"\n  🔑 An attacker only needs (n, e) — both are PUBLIC!")

    # ===== STEP 3: Factor n using Shor's Algorithm =====
    print("\n" + "─" * 60)
    print("  STEP 3: Factoring n using Shor's Algorithm")
    print("─" * 60)
    print(f"\n  On a quantum computer, Shor's algorithm can factor")
    print(f"  any RSA modulus in polynomial time using QFT.")
    print(f"  This is a classical simulation for demonstration.")
    print(f"\n  NOTE: Qiskit (quantum simulator) would be even SLOWER here")
    print(f"  because it simulates 2^n quantum states in memory.")
    print(f"  Real speedup only exists on actual quantum hardware.\n")

    start_time = time.time()
    p, q = shors_algorithm_simulation(n)
    elapsed = time.time() - start_time

    print(f"\n  ✅ FACTORIZATION COMPLETE!")
    print(f"     p = {p}")
    print(f"     q = {q}")
    print(f"     p × q = {p * q} {'✅ matches n' if p * q == n else '❌ ERROR'}")
    print(f"     Time: {elapsed:.4f} seconds")

    # ===== STEP 4: Reconstruct private key =====
    print("\n" + "─" * 60)
    print("  STEP 4: Reconstructing RSA private key from factors")
    print("─" * 60)

    d = reconstruct_private_key(p, q, e)
    print(f"  ✅ Private exponent recovered!")
    print(f"     d = {d}")
    print(f"     φ(n) = (p-1)(q-1) = {(p-1)*(q-1)}")
    print(f"     Verification: (e × d) mod φ(n) = {(e * d) % ((p-1)*(q-1))}")

    # ===== STEP 5: Decrypt RSA-encrypted AES session key =====
    print("\n" + "─" * 60)
    print("  STEP 5: Decrypting RSA-encrypted AES session key")
    print("─" * 60)

    session_key = small_rsa_decrypt(n, d, rsa_encrypted_key, key_length=session_key_length)
    print(f"  ✅ AES session key recovered!")
    print(f"     Session key (hex): {session_key.hex()}")
    print(f"     Session key length: {len(session_key)} bytes")

    # Pad session key to 32 bytes for AES-256 (same as sender)
    if len(session_key) < 32:
        padded_key = session_key.rjust(32, b'\x00')
    else:
        padded_key = session_key

    # ===== STEP 6: Decrypt AES-GCM ciphertext =====
    print("\n" + "─" * 60)
    print("  STEP 6: Decrypting AES-GCM ciphertext")
    print("─" * 60)

    try:
        plaintext_bytes = aes_gcm_decrypt(padded_key, ciphertext, nonce)
        plaintext = plaintext_bytes.decode("utf-8")

        print(f"  ✅ AES-GCM decryption successful!")
        print(f"\n  {'='*50}")
        print(f"   🔓 RECOVERED PLAINTEXT: {plaintext}")
        print(f"  {'='*50}")

    except Exception as ex:
        print(f"  ❌ AES-GCM decryption failed: {ex}")
        return

    # ===== SUMMARY =====
    print(f"\n{'='*60}")
    print(f"    ATTACK SUMMARY")
    print(f"{'='*60}")
    print(f"  ✅ RSA modulus factored using Shor's algorithm")
    print(f"  ✅ RSA private key reconstructed from factors")
    print(f"  ✅ AES session key decrypted using recovered RSA key")
    print(f"  ✅ Original plaintext recovered from AES ciphertext")
    print(f"\n  ⚠️  This demonstrates why RSA-only key exchange is")
    print(f"     INSECURE against quantum computing attacks.")
    print(f"     Shor's algorithm can break RSA of ANY key size")
    print(f"     given a sufficiently powerful quantum computer.")
    print(f"\n  ✅ The Hybrid approach (RSA + Kyber) is SAFE because")
    print(f"     even if RSA is broken, the Kyber post-quantum layer")
    print(f"     keeps the combined key secure against quantum attacks.")
    print(f"{'='*60}\n")
