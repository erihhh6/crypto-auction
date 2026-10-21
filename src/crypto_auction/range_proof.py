"""
Zero-Knowledge Range Proof for a Pedersen Commitment
=====================================================

Statement: C = v·G + r·H with min ≤ v ≤ max.

Let d = max - min and k = bitlen(d) (at least 1). The proof shows that both

    x = v - min,  committed by C_low  = C - min·G          = x·G + r·H
    y = max - v,  committed by C_high = max·G - C          = y·G + (n - r)·H

lie in [0, 2^k). Each is decomposed into bits: a commitment C_i to every bit,
a bit proof (bit_proof.py) that C_i hides 0 or 1, and the check that
Σ 2^i·C_i equals C_low (resp. C_high), which holds exactly when the bits sum
to x (resp. y) and their blindings to the original blinding.

Why this proves the range: x + y ≡ d (mod n), and x + y < 2^(k+1) and d are
both far below the group order n, so x + y = d as integers. Hence
x ∈ [0, d], i.e. v ∈ [min, max].

That argument needs the verifier to fix k from its own range and to reject
proofs with any other number of bits. A proof free to choose its length could
encode y = n - 500 in 256 bits: then x + y wraps around n and an out-of-range
value passes. The statement (C, min, max) likewise comes from the verifier,
never from the proof, and is hashed into every bit proof's context.
"""

import secrets
from dataclasses import dataclass
from typing import Any, Self

from ecdsa.ellipticcurve import INFINITY

from crypto_auction.bit_proof import BitProof, prove_bit, verify_bit
from crypto_auction.pedersen import (
    G,
    N,
    Point,
    commit_with,
    decode_point,
    decode_scalar,
    encode_point,
    encode_scalar,
)
from crypto_auction.transcript import encode_int, encode_parts

# Bounds are limited to 64 bits, so k ≤ 64 and x + y < 2^65 is far below n.
MAX_VALUE = 2**64 - 1

_DOMAIN = b"crypto-auction/range-proof/v1"


@dataclass(frozen=True)
class NonNegativeProof:
    """Proof that a commitment hides a value in [0, 2^k): one commitment and bit proof per bit."""

    bit_commitments: tuple[Point, ...]
    bit_proofs: tuple[BitProof, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "bit_commitments": [encode_point(c) for c in self.bit_commitments],
            "bit_proofs": [
                {
                    "e0": encode_scalar(p.e0),
                    "s0": encode_scalar(p.s0),
                    "e1": encode_scalar(p.e1),
                    "s1": encode_scalar(p.s1),
                }
                for p in self.bit_proofs
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        commitments, proofs = data["bit_commitments"], data["bit_proofs"]
        if not isinstance(commitments, list) or not isinstance(proofs, list):
            raise TypeError("bit_commitments and bit_proofs must be lists.")
        return cls(
            bit_commitments=tuple(decode_point(c) for c in commitments),
            bit_proofs=tuple(
                BitProof(
                    e0=decode_scalar(p["e0"]),
                    s0=decode_scalar(p["s0"]),
                    e1=decode_scalar(p["e1"]),
                    s1=decode_scalar(p["s1"]),
                )
                for p in proofs
            ),
        )


@dataclass(frozen=True)
class RangeProof:
    """Proof that a commitment hides a value in [min, max]; the range itself is not included."""

    low: NonNegativeProof  # v - min ∈ [0, 2^k)
    high: NonNegativeProof  # max - v ∈ [0, 2^k)

    def to_dict(self) -> dict[str, Any]:
        return {"low": self.low.to_dict(), "high": self.high.to_dict()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Self:
        """
        Parse a proof serialised by to_dict().

        Raises:
            KeyError, TypeError, ValueError: If data is not a well-formed proof
                (missing fields, wrong types, or non-canonical encodings).
        """
        return cls(
            low=NonNegativeProof.from_dict(data["low"]),
            high=NonNegativeProof.from_dict(data["high"]),
        )


def _bits_for(min_value: int, max_value: int) -> int:
    for name, bound in (("min_value", min_value), ("max_value", max_value)):
        if isinstance(bound, bool) or not isinstance(bound, int) or not 0 <= bound <= MAX_VALUE:
            raise ValueError(f"{name} must be an integer in [0, {MAX_VALUE}], got {bound!r}.")
    if min_value > max_value:
        raise ValueError(f"min_value {min_value} is greater than max_value {max_value}.")
    # At least one bit: with zero bits the empty sum could never equal C_low.
    return max(1, (max_value - min_value).bit_length())


def _halves(commitment: Point, min_value: int, max_value: int) -> tuple[Point, Point]:
    """C_low = C - min·G and C_high = max·G - C (using n - 1, as points cannot be negated)."""
    return commitment + G * ((N - min_value) % N), G * max_value + commitment * (N - 1)


def _context(
    commitment: Point, min_value: int, max_value: int, side: bytes, context: bytes
) -> bytes:
    """Everything a bit proof must be bound to, besides its own position."""
    return encode_parts(
        _DOMAIN,
        encode_point(commitment).encode(),
        encode_int(min_value),
        encode_int(max_value),
        side,
        context,
    )


def _bit_context(side_context: bytes, index: int) -> bytes:
    return encode_parts(side_context, encode_int(index))


def _prove_non_negative(value: int, blinding: int, bits: int, context: bytes) -> NonNegativeProof:
    """Prove that value·G + blinding·H hides a value in [0, 2^bits)."""
    # Random blindings for all bits but the last, which is chosen so that
    # Σ 2^i·blinding_i ≡ blinding (mod n) and the bit commitments sum to the input.
    blindings = [secrets.randbelow(N) for _ in range(bits - 1)]
    partial = sum(b << i for i, b in enumerate(blindings)) % N
    blindings.append((blinding - partial) * pow(1 << (bits - 1), -1, N) % N)

    commitments, proofs = [], []
    for i, bit_blinding in enumerate(blindings):
        bit = (value >> i) & 1
        bit_commitment = commit_with(bit, bit_blinding)
        commitments.append(bit_commitment)
        proofs.append(prove_bit(bit_commitment, bit, bit_blinding, _bit_context(context, i)))
    return NonNegativeProof(bit_commitments=tuple(commitments), bit_proofs=tuple(proofs))


def _verify_non_negative(target: Point, proof: NonNegativeProof, bits: int, context: bytes) -> bool:
    # The number of bits comes from the verifier's range, never from the proof
    # (see the module docstring: a longer proof could wrap around n).
    if len(proof.bit_commitments) != bits or len(proof.bit_proofs) != bits:
        return False
    total = INFINITY
    for i, (bit_commitment, bit_proof) in enumerate(
        zip(proof.bit_commitments, proof.bit_proofs, strict=True)
    ):
        if not verify_bit(bit_commitment, bit_proof, _bit_context(context, i)):
            return False
        total = total + bit_commitment * (1 << i)
    return bool(total == target)


def prove_range(
    commitment: Point,
    value: int,
    blinding: int,
    min_value: int,
    max_value: int,
    context: bytes,
) -> RangeProof:
    """
    Prove that commitment hides a value in [min_value, max_value], revealing nothing else.

    Args:
        commitment: C = value·G + blinding·H.
        value, blinding: The opening of C (private).
        min_value, max_value: The range, inclusive; both in [0, MAX_VALUE].
        context: Bytes identifying where the proof is used (e.g. the auction
            and bidder); verification needs the same.

    Raises:
        ValueError: If the range is invalid, (value, blinding) does not open
            commitment, or value lies outside the range. The prover refuses to
            prove a false statement.
    """
    bits = _bits_for(min_value, max_value)
    if commitment != commit_with(value, blinding):
        raise ValueError("(value, blinding) does not open the given commitment.")
    if not min_value <= value <= max_value:
        raise ValueError(f"Value {value} is not within [{min_value}, {max_value}].")

    return RangeProof(
        low=_prove_non_negative(
            value - min_value,
            blinding,
            bits,
            _context(commitment, min_value, max_value, b"low", context),
        ),
        high=_prove_non_negative(
            max_value - value,
            (N - blinding) % N,
            bits,
            _context(commitment, min_value, max_value, b"high", context),
        ),
    )


def verify_range(
    commitment: Point,
    proof: RangeProof,
    min_value: int,
    max_value: int,
    context: bytes,
) -> bool:
    """Whether proof shows that commitment hides a value in [min_value, max_value]."""
    try:
        bits = _bits_for(min_value, max_value)
        c_low, c_high = _halves(commitment, min_value, max_value)
        low_context = _context(commitment, min_value, max_value, b"low", context)
        high_context = _context(commitment, min_value, max_value, b"high", context)
    except ValueError:  # invalid range, or C is the point at infinity
        return False
    return _verify_non_negative(c_low, proof.low, bits, low_context) and _verify_non_negative(
        c_high, proof.high, bits, high_context
    )
