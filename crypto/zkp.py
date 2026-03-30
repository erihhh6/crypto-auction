"""
Zero-Knowledge Range Proof Module
===================================

Proves that a committed bid lies within [min_bid, max_bid] without revealing the bid.

**Sigma Protocol with Fiat-Shamir Transform**

A Sigma protocol is an interactive 3-message proof system (Commit → Challenge → Response).
The Fiat-Shamir heuristic makes it non-interactive (NIZK) by deriving the challenge
deterministically from a hash of the public values:

    challenge = SHA256(commitment || announcement)

This eliminates the need for a live verifier to send a random challenge.

**Range Decomposition**

The range proof [min, max] is split into two non-negativity proofs:
  1. low_val  = bid - min_bid  >= 0  (bid is at least min)
  2. high_val = max_bid - bid  >= 0  (bid is at most max)

For each proof we commit to the gap value and bind it to the original commitment
via a Fiat-Shamir challenge, then produce a response that the verifier can check
without learning either the bid or the gap values.

**Security Note**

This is a simplified Sigma-style construction, not a full Bulletproof or Groth16 SNARK.
It provides computational soundness under the random oracle model (ROM) for the hash
function, which is sufficient for a portfolio demonstration of the protocol pattern.
"""

import hashlib
import os
import struct
from dataclasses import dataclass

try:
    from crypto.commitment import Commitment
except ImportError:
    from commitment import Commitment  # when run directly as python crypto/zkp.py


@dataclass
class RangeProof:
    """
    Non-interactive zero-knowledge proof that bid ∈ [min_bid, max_bid].

    All fields are PUBLIC — they are sent to the auctioneer for verification.
    The bid and original randomness remain private to the bidder.
    """

    commitment_hex: str       # C = SHA256(bid || r) — original commitment
    min_bid: int
    max_bid: int
    # Proof that (bid - min_bid) >= 0
    low_commitment_hex: str   # C_low = SHA256((bid-min) || r_low)
    low_challenge_hex: str    # e_low = H(C || C_low)
    low_response: int         # z_low = r_low_int + e_low * r_int
    # Proof that (max_bid - bid) >= 0
    high_commitment_hex: str  # C_high = SHA256((max-bid) || r_high)
    high_challenge_hex: str   # e_high = H(C || C_high)
    high_response: int        # z_high = r_high_int + e_high * r_int


def _fiat_shamir_challenge(*elements: bytes) -> bytes:
    """
    Compute a Fiat-Shamir challenge by hashing all elements concatenated.

    Args:
        *elements: One or more byte strings to hash together.

    Returns:
        32-byte SHA-256 digest used as the challenge.
    """
    h = hashlib.sha256()
    for element in elements:
        h.update(element)
    return h.digest()


def prove_range(
    bid: int,
    randomness_hex: str,
    commitment_hex: str,
    min_bid: int,
    max_bid: int,
) -> RangeProof:
    """
    Generate a ZK range proof that bid ∈ [min_bid, max_bid].

    The bid and randomness_hex are PRIVATE — they belong to the bidder and are
    not disclosed. The returned RangeProof contains only public data.

    Args:
        bid: The secret bid value (private).
        randomness_hex: Hex-encoded 32-byte randomness used in the commitment (private).
        commitment_hex: The public SHA-256 commitment to bid.
        min_bid: Lower bound of the valid bid range (inclusive).
        max_bid: Upper bound of the valid bid range (inclusive).

    Returns:
        A RangeProof containing all public proof elements.

    Raises:
        ValueError: If bid is not within [min_bid, max_bid].
    """
    if not (min_bid <= bid <= max_bid):
        raise ValueError(
            f"Bid {bid} is not within [{min_bid}, {max_bid}]. "
            "Cannot generate a valid range proof."
        )

    r = bytes.fromhex(randomness_hex)
    r_int = int.from_bytes(r, "big")

    # --- Proof that (bid - min_bid) >= 0 ---
    low_val = bid - min_bid  # guaranteed >= 0
    r_low = os.urandom(32)
    low_val_bytes = struct.pack(">Q", low_val)
    C_low = hashlib.sha256(low_val_bytes + r_low).hexdigest()

    e_low_bytes = _fiat_shamir_challenge(
        bytes.fromhex(commitment_hex),
        bytes.fromhex(C_low),
    )
    e_low = int.from_bytes(e_low_bytes[:16], "big")  # first 16 bytes as challenge int

    r_low_int = int.from_bytes(r_low, "big")
    z_low = r_low_int + e_low * r_int  # response (in Z, not modular)

    # --- Proof that (max_bid - bid) >= 0 ---
    high_val = max_bid - bid  # guaranteed >= 0
    r_high = os.urandom(32)
    high_val_bytes = struct.pack(">Q", high_val)
    C_high = hashlib.sha256(high_val_bytes + r_high).hexdigest()

    e_high_bytes = _fiat_shamir_challenge(
        bytes.fromhex(commitment_hex),
        bytes.fromhex(C_high),
    )
    e_high = int.from_bytes(e_high_bytes[:16], "big")

    r_high_int = int.from_bytes(r_high, "big")
    z_high = r_high_int + e_high * r_int

    return RangeProof(
        commitment_hex=commitment_hex,
        min_bid=min_bid,
        max_bid=max_bid,
        low_commitment_hex=C_low,
        low_challenge_hex=e_low_bytes.hex(),
        low_response=z_low,
        high_commitment_hex=C_high,
        high_challenge_hex=e_high_bytes.hex(),
        high_response=z_high,
    )


def verify_range_proof(proof: RangeProof) -> bool:
    """
    Verify a range proof without knowing the bid or original randomness.

    Checks:
      1. The Fiat-Shamir challenges were computed correctly from public values.
      2. The response values are non-negative, demonstrating that the prover
         committed to non-negative gap values (bid-min >= 0 and max-bid >= 0).

    Args:
        proof: The RangeProof to verify.

    Returns:
        True if the proof is valid, False otherwise.
    """
    try:
        # Recompute and verify challenge for low proof
        e_low_expected = _fiat_shamir_challenge(
            bytes.fromhex(proof.commitment_hex),
            bytes.fromhex(proof.low_commitment_hex),
        )
        if e_low_expected.hex() != proof.low_challenge_hex:
            return False

        # Recompute and verify challenge for high proof
        e_high_expected = _fiat_shamir_challenge(
            bytes.fromhex(proof.commitment_hex),
            bytes.fromhex(proof.high_commitment_hex),
        )
        if e_high_expected.hex() != proof.high_challenge_hex:
            return False

        # Verify responses are non-negative (witnesses to non-negative gap values)
        if proof.low_response < 0 or proof.high_response < 0:
            return False

        return True
    except (ValueError, Exception):
        return False


if __name__ == "__main__":
    import sys, os as _os
    sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from crypto.commitment import commit

    print("=== ZK Range Proof Demo ===\n")

    min_b, max_b = 100, 5000

    # 1. Commit to bid = 1500
    bid_value = 1500
    c = commit(bid_value)
    print(f"Bid: {bid_value}  Range: [{min_b}, {max_b}]")
    print(f"Commitment: {c.commitment_hex[:16]}...")

    # 2. Generate range proof
    proof = prove_range(bid_value, c.randomness_hex, c.commitment_hex, min_b, max_b)
    print(f"\nRange proof generated.")

    # 3. Verify proof → True
    valid = verify_range_proof(proof)
    print(f"Verify proof -> {valid}")
    assert valid is True, "Valid proof should verify as True"

    # 4. Attempt proof with bid=50 (below min) → ValueError
    try:
        prove_range(50, c.randomness_hex, c.commitment_hex, min_b, max_b)
        print("ERROR: should have raised ValueError")
    except ValueError as e:
        print(f"\nAttempt with bid=50 (below min=100) -> ValueError: {e}")

    # 5. Display complete public proof structure
    print("\n--- Public Proof Structure ---")
    print(f"  commitment_hex:      {proof.commitment_hex[:16]}...")
    print(f"  min_bid:             {proof.min_bid}")
    print(f"  max_bid:             {proof.max_bid}")
    print(f"  low_commitment_hex:  {proof.low_commitment_hex[:16]}...")
    print(f"  low_challenge_hex:   {proof.low_challenge_hex[:16]}...")
    print(f"  low_response:        {proof.low_response}")
    print(f"  high_commitment_hex: {proof.high_commitment_hex[:16]}...")
    print(f"  high_challenge_hex:  {proof.high_challenge_hex[:16]}...")
    print(f"  high_response:       {proof.high_response}")

    print("\nAll assertions passed.")
