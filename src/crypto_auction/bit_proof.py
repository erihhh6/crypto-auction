"""
Zero-Knowledge Proof that a Pedersen Commitment Hides a Bit
============================================================

Statement: C = b·G + r·H with b ∈ {0, 1}, i.e.

    C = r·H          (b = 0)    or    C - G = r·H    (b = 1)

The proof is an OR-composition of two Schnorr proofs of knowledge of a discrete
logarithm base H (Cramer, Damgård & Schoenmakers, CRYPTO '94). The prover runs
the real Schnorr protocol for the true branch and simulates the other branch by
picking its challenge and response first. The verifier only checks that the two
challenges add up to the Fiat-Shamir challenge, so it cannot tell which branch
was real.

- Completeness: an honest proof for b ∈ {0, 1} always verifies.
- Special soundness: two accepting transcripts with different challenges reveal
  r for one branch, so a successful prover must know an opening of C to 0 or 1.
- Zero knowledge: a real and a simulated branch are identically distributed.

Fiat-Shamir: the challenge hashes a domain tag, both generators, the statement
C, the caller's context and both announcements. Leaving any of these out lets a
proof be reused for a different statement ("weak Fiat-Shamir"; Bernhard,
Pereira & Warinschi, ASIACRYPT 2012). The old zkp module had exactly this flaw:
its challenge omitted the range.
"""

import hashlib
import secrets
from dataclasses import dataclass

from crypto_auction.pedersen import G, H, N, Point, commit_with, encode_point
from crypto_auction.transcript import encode_parts

_DOMAIN = b"crypto-auction/bit-proof/v1"


@dataclass(frozen=True)
class BitProof:
    """
    Proof that a commitment hides 0 or 1, in compact form: per branch i, the
    challenge e_i and response s_i. The announcements A_i = s_i·H - e_i·Y_i are
    recomputed by the verifier rather than sent.
    """

    e0: int
    s0: int
    e1: int
    s1: int


def _neg(scalar: int) -> int:
    # ecdsa points have no subtraction (and cannot negate the point at
    # infinity), so P - e·Q is written as P + (n - e)·Q throughout.
    return (N - scalar) % N


def _branch_points(commitment: Point) -> tuple[Point, Point]:
    """Y_0 = C and Y_1 = C - G: the points that must equal r·H for b = 0 and b = 1."""
    return commitment, commitment + G * _neg(1)


def _challenge(commitment: Point, context: bytes, a0: Point, a1: Point) -> int:
    """
    Fiat-Shamir challenge over the whole statement and both announcements.

    Every part is length-prefixed, so different inputs can never produce the
    same byte string. SHA-512 reduced mod n keeps the bias from the reduction
    negligible (about 2**-256).
    """
    transcript = encode_parts(
        _DOMAIN,
        encode_point(G).encode(),
        encode_point(H).encode(),
        encode_point(commitment).encode(),
        context,
        encode_point(a0).encode(),
        encode_point(a1).encode(),
    )
    return int.from_bytes(hashlib.sha512(transcript).digest(), "big") % N


def prove_bit(commitment: Point, bit: int, blinding: int, context: bytes) -> BitProof:
    """
    Prove that commitment hides a bit, without revealing which.

    Args:
        commitment: C = bit·G + blinding·H.
        bit: The committed value, 0 or 1 (private).
        blinding: The commitment's blinding factor (private).
        context: Bytes identifying where the proof is used (for example the
            auction, bidder and bit position); verification needs the same.

    Raises:
        ValueError: If bit is not 0 or 1, or (bit, blinding) does not open
            commitment. The prover refuses to prove a false statement.
    """
    if bit not in (0, 1) or commitment != commit_with(bit, blinding):
        raise ValueError("The commitment does not open to a bit with this blinding.")

    ys = _branch_points(commitment)
    fake = 1 - bit
    k = secrets.randbelow(N)
    e_fake, s_fake = secrets.randbelow(N), secrets.randbelow(N)

    announcements = [G, G]  # placeholders, both overwritten below
    announcements[bit] = H * k  # real Schnorr announcement
    # Simulated branch: choose (e, s) first, then the A that makes them verify.
    announcements[fake] = H * s_fake + ys[fake] * _neg(e_fake)

    e = _challenge(commitment, context, announcements[0], announcements[1])
    e_real = (e - e_fake) % N
    s_real = (k + e_real * blinding) % N

    if bit == 0:
        return BitProof(e0=e_real, s0=s_real, e1=e_fake, s1=s_fake)
    return BitProof(e0=e_fake, s0=s_fake, e1=e_real, s1=s_real)


def verify_bit(commitment: Point, proof: BitProof, context: bytes) -> bool:
    """Whether proof shows that commitment hides 0 or 1, for this context."""
    scalars = (proof.e0, proof.s0, proof.e1, proof.s1)
    # Scalars must be canonical: s and s + n act alike on points, so accepting
    # both would let anyone alter a valid proof's bytes without the secret.
    if not all(isinstance(x, int) and not isinstance(x, bool) and 0 <= x < N for x in scalars):
        return False
    y0, y1 = _branch_points(commitment)
    try:
        a0 = H * proof.s0 + y0 * _neg(proof.e0)
        a1 = H * proof.s1 + y1 * _neg(proof.e1)
        expected = _challenge(commitment, context, a0, a1)
    except ValueError:  # an announcement or C is the point at infinity
        return False
    return (proof.e0 + proof.e1) % N == expected
