"""
Pedersen Commitments on secp256k1
==================================

    C = v·G + r·H

- G is the standard secp256k1 generator. H is a second generator derived by
  hashing a fixed tag to a curve point (see _hash_to_curve), so that nobody
  knows log_G(H).

- **Hiding** (perfect): r is uniform in [0, n), so r·H is a uniformly random
  group element and C reveals nothing about v, even to an unbounded adversary.

- **Binding** (computational): two openings (v, r) ≠ (v', r') of the same C give
  v·G + r·H = v'·G + r'·H, hence log_G(H) = (v - v') / (r' - r) mod n. Breaking
  binding therefore means solving a discrete logarithm on secp256k1, which is
  exactly why H must have no known discrete log relative to G.

- **Additively homomorphic**: C(v1, r1) + C(v2, r2) = C(v1 + v2, r1 + r2), the
  property range proofs are built on (unlike hash commitments).

Curve arithmetic comes from the pure-Python `ecdsa` package. It is not
constant-time, so it should not handle secrets where timing can be observed;
the plan is for bidders to commit and prove in the browser, leaving the server
only public data to verify.
"""

import hashlib
import re
import secrets
from dataclasses import dataclass
from typing import Any, TypeAlias

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import INFINITY, PointJacobi
from ecdsa.errors import MalformedPointError

# An ecdsa.ellipticcurve.PointJacobi. ecdsa ships without type hints, so the
# alias can only be Any.
Point: TypeAlias = Any

_CURVE = SECP256k1.curve
P: int = _CURVE.p()  # field prime; p ≡ 3 (mod 4)
N: int = SECP256k1.order  # group order; secp256k1's cofactor is 1
G: Point = SECP256k1.generator

# Compressed SEC1 encoding: 02/03 (parity of y) followed by the 32-byte x.
_COMPRESSED_HEX = re.compile(r"0[23][0-9a-f]{64}")
_SCALAR_HEX = re.compile(r"[0-9a-f]{64}")


def _hash_to_curve(tag: bytes) -> Point:
    """
    Map a tag to a curve point with no known discrete log ("nothing up my sleeve").

    Try-and-increment: hash the tag and a counter to an x-coordinate until
    x³ + 7 is a square mod p, then take the point with even y. Since the point
    comes out of a hash, nobody can have chosen it with a known log_G, and the
    loop's timing depends only on the public tag. Every curve point lies in the
    prime-order group because secp256k1's cofactor is 1.
    """
    for counter in range(256):
        x = int.from_bytes(hashlib.sha256(tag + bytes([counter])).digest(), "big")
        if x >= P:
            continue
        y_squared = (pow(x, 3, P) + 7) % P
        y = pow(y_squared, (P + 1) // 4, P)  # a square root, because p ≡ 3 (mod 4)
        if y * y % P != y_squared:
            continue  # no point with this x
        if y % 2:
            y = P - y
        return PointJacobi(_CURVE, x, y, 1, N)
    # Each attempt succeeds with probability ~1/2, so 256 failures never happen.
    raise RuntimeError(f"Could not hash {tag!r} to a curve point.")  # pragma: no cover


# Part of the protocol: changing the tag changes H, which silently invalidates
# every existing commitment and must be mirrored by any other implementation.
H: Point = _hash_to_curve(b"crypto-auction/pedersen/H/v1")


@dataclass(frozen=True)
class Commitment:
    """A commitment and its opening. Only `point` is public."""

    point: Point
    value: int
    blinding: int


def _check_scalar(name: str, scalar: int) -> None:
    if isinstance(scalar, bool) or not isinstance(scalar, int) or not 0 <= scalar < N:
        raise ValueError(f"{name} must be an integer in [0, n), got {scalar!r}.")


def commit_with(value: int, blinding: int) -> Point:
    """Return value·G + blinding·H."""
    _check_scalar("value", value)
    _check_scalar("blinding", blinding)
    return G * value + H * blinding


def commit(value: int) -> Commitment:
    """Commit to value with a fresh uniformly random blinding factor."""
    blinding = secrets.randbelow(N)
    return Commitment(point=commit_with(value, blinding), value=value, blinding=blinding)


def verify(point: Point, value: int, blinding: int) -> bool:
    """Whether (value, blinding) opens point."""
    try:
        return bool(commit_with(value, blinding) == point)
    except ValueError:
        return False


def encode_point(point: Point) -> str:
    """Compressed SEC1 encoding as lowercase hex (66 characters)."""
    if point == INFINITY:
        raise ValueError("The point at infinity has no compressed encoding.")
    return str(point.to_bytes("compressed").hex())


def decode_point(encoded: str) -> Point:
    """
    Parse a compressed point produced by encode_point().

    Raises:
        ValueError: If encoded is not 66 lowercase hex characters starting with
            02 or 03, or does not describe a point on secp256k1.
    """
    if not isinstance(encoded, str) or not _COMPRESSED_HEX.fullmatch(encoded):
        raise ValueError(f"Expected a compressed point as 66 lowercase hex chars, got {encoded!r}.")
    # ecdsa accepts x >= p without reducing it, which gives one point a second
    # encoding. Anything that compares or hashes encodings (duplicate checks,
    # Fiat-Shamir transcripts) needs exactly one, so only x < p is accepted.
    if int(encoded[2:], 16) >= P:
        raise ValueError(f"Non-canonical point encoding (x >= p): {encoded!r}.")
    try:
        return PointJacobi.from_bytes(
            _CURVE, bytes.fromhex(encoded), valid_encodings=["compressed"], order=N
        )
    except MalformedPointError as exc:
        raise ValueError(f"Not a point on secp256k1: {encoded!r}.") from exc


def encode_scalar(scalar: int) -> str:
    """A scalar in [0, n) as 64 lowercase hex characters (fixed width)."""
    _check_scalar("scalar", scalar)
    return f"{scalar:064x}"


def decode_scalar(encoded: str) -> int:
    """
    Parse a scalar produced by encode_scalar().

    Raises:
        ValueError: Unless encoded is 64 lowercase hex characters for a value
            below n. Fixed width and range give every scalar one encoding.
    """
    if not isinstance(encoded, str) or not _SCALAR_HEX.fullmatch(encoded):
        raise ValueError(f"Expected a scalar as 64 lowercase hex chars, got {encoded!r}.")
    scalar = int(encoded, 16)
    if scalar >= N:
        raise ValueError(f"Scalar out of range (>= n): {encoded!r}.")
    return scalar
