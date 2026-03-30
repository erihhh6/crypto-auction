"""
Commitment Scheme Module
========================

A cryptographic commitment scheme based on SHA-256 with the following properties:

- **Hiding**: The commitment C = SHA256(bid_bytes || randomness) reveals nothing about
  the bid. SHA-256 is a one-way function; given C, an adversary cannot recover bid
  without exhaustive search over the entire bid space.

- **Binding**: The bidder cannot find an alternative (bid', r') such that
  SHA256(bid'_bytes || r') == C. This follows from SHA-256's collision resistance:
  finding two distinct inputs that produce the same hash is computationally infeasible.

Schema: C = SHA256(bid_bytes || randomness)
  - bid_bytes: 8-byte big-endian unsigned 64-bit integer representation of the bid
  - randomness: 32 cryptographically random bytes (256 bits of entropy)

The randomness ensures that two commitments for the same bid value produce different
commitment hashes (semantic security / hiding under repeated use).
"""

import hashlib
import os
import struct
from dataclasses import dataclass


@dataclass
class Commitment:
    """
    Holds the result of a commit operation.

    commitment_hex: SHA-256 hex digest (64 hex chars) — PUBLIC, sent to auctioneer.
    randomness_hex: 32-byte random nonce (64 hex chars) — PRIVATE, kept by bidder only.
    """

    commitment_hex: str
    randomness_hex: str


def commit(bid: int) -> Commitment:
    """
    Generate a cryptographic commitment for a bid value.

    Args:
        bid: A non-negative integer representing the bid price.

    Returns:
        A Commitment containing the public commitment_hex and the private randomness_hex.

    Raises:
        ValueError: If bid is negative or exceeds uint64 max (2^64 - 1).
    """
    if bid < 0:
        raise ValueError(f"Bid must be non-negative, got {bid}")
    if bid > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"Bid exceeds uint64 maximum, got {bid}")

    randomness = os.urandom(32)
    bid_bytes = struct.pack(">Q", bid)  # big-endian uint64
    preimage = bid_bytes + randomness
    commitment = hashlib.sha256(preimage).hexdigest()
    return Commitment(
        commitment_hex=commitment,
        randomness_hex=randomness.hex(),
    )


def verify(bid: int, randomness_hex: str, commitment_hex: str) -> bool:
    """
    Verify that a (bid, randomness) pair opens to a given commitment.

    Used in Phase 3 (Reveal): the auctioneer recomputes SHA256(bid_bytes || randomness)
    and checks it matches the commitment stored from Phase 1.

    Args:
        bid: The claimed bid value (integer).
        randomness_hex: Hex-encoded 32-byte randomness revealed by the bidder.
        commitment_hex: The commitment hash stored by the auctioneer.

    Returns:
        True if the commitment is valid, False otherwise.
    """
    try:
        if bid < 0 or bid > 0xFFFFFFFFFFFFFFFF:
            return False
        randomness = bytes.fromhex(randomness_hex)
        bid_bytes = struct.pack(">Q", bid)
        preimage = bid_bytes + randomness
        expected = hashlib.sha256(preimage).hexdigest()
        return expected == commitment_hex
    except (ValueError, struct.error):
        return False


def commitment_to_bytes(commitment_hex: str) -> bytes:
    """
    Convert a commitment hex string to raw bytes.

    Used when embedding commitments into ZK proof hash computations.

    Args:
        commitment_hex: A 64-character hex string representing a SHA-256 digest.

    Returns:
        32 bytes decoded from the hex string.
    """
    return bytes.fromhex(commitment_hex)


if __name__ == "__main__":
    print("=== Commitment Scheme Demo ===\n")

    # 1. Commit to bid = 1500
    bid_value = 1500
    c = commit(bid_value)
    print(f"Bid: {bid_value}")
    print(f"Commitment (public): {c.commitment_hex}")
    print(f"Randomness (private): {c.randomness_hex[:16]}...  ({len(c.randomness_hex)//2} bytes)")

    # 2. Verify with correct values → True
    result_correct = verify(bid_value, c.randomness_hex, c.commitment_hex)
    print(f"\nVerify(bid=1500, correct randomness) -> {result_correct}")
    assert result_correct is True, "Correct verification should return True"

    # 3. Verify with wrong bid -> False
    result_wrong_bid = verify(9999, c.randomness_hex, c.commitment_hex)
    print(f"Verify(bid=9999, correct randomness) -> {result_wrong_bid}")
    assert result_wrong_bid is False, "Wrong bid should return False"

    # 4. Two commits to the same bid produce different commitments (hiding / IND-CPA)
    c2 = commit(bid_value)
    print(f"\nTwo commitments to bid={bid_value}:")
    print(f"  C1 = {c.commitment_hex}")
    print(f"  C2 = {c2.commitment_hex}")
    print(f"  Are different: {c.commitment_hex != c2.commitment_hex}")
    assert c.commitment_hex != c2.commitment_hex, "Two commits should differ (hiding)"

    print("\nAll assertions passed.")
