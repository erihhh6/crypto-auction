"""
Auction State Machine Module
==============================

Implements a sealed-bid auction with a 3-phase cryptographic protocol:

  OPEN → COMMITTED → PROVED → FINISHED

State transitions:
  OPEN      → COMMITTED : all bidders have submitted Pedersen commitments
  COMMITTED → PROVED    : all bidders have submitted a range proof (valid or not)
  PROVED    → FINISHED  : all bidders have revealed (bid, blinding); the winner
                          is determined from the verified reveals

Security model: honest-but-curious auctioneer.
The auctioneer sees only commitments and ZK proofs in phases 1-2 (bidders
compute both themselves), and learns actual bid values only in phase 3.
"""

import secrets
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from crypto_auction.pedersen import N, decode_point, encode_scalar
from crypto_auction.pedersen import verify as verify_opening
from crypto_auction.range_proof import RangeProof, verify_range
from crypto_auction.transcript import encode_parts

_PROOF_DOMAIN = b"crypto-auction/bid-range-proof/v1"


def bid_proof_context(auction_id: str, bidder_id: str) -> bytes:
    """
    What a bidder's range proof is bound to: one auction and one bidder.

    Bidders compute their proofs themselves (in the browser), so this exact
    encoding is part of the protocol; static/auction-crypto.js mirrors it.
    """
    return encode_parts(_PROOF_DOMAIN, auction_id.encode(), bidder_id.encode())


class AuctionState(Enum):
    OPEN = "open"
    COMMITTED = "committed"
    PROVED = "proved"
    FINISHED = "finished"


@dataclass
class BidderState:
    """Tracks the per-bidder protocol state across all three phases."""

    bidder_id: str
    name: str
    # Phase 1 — public after commit
    commitment_hex: str | None = None  # canonical encoding of C = bid·G + blinding·H
    commit_order: int | None = None  # 0 for the first commitment received, 1 next, ...
    # Phase 2 — public after prove
    range_proof: dict[str, Any] | None = None  # RangeProof serialised as dict
    proof_valid: bool | None = None
    # Phase 3 — public after reveal
    revealed_bid: int | None = None
    revealed_blinding: int | None = None  # becomes public at reveal
    commitment_verified: bool | None = None


@dataclass(frozen=True)
class AuctionConfig:
    """Immutable configuration set when the auction is created."""

    min_bid: int
    max_bid: int
    item_name: str
    bidder_names: tuple[str, ...]


@dataclass(frozen=True)
class Winner:
    bidder_id: str
    name: str
    bid: int
    commitment_hex: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CommitResult:
    phase: AuctionState
    message: str


@dataclass(frozen=True)
class ProofResult:
    proof_valid: bool
    phase: AuctionState
    message: str


@dataclass(frozen=True)
class RevealResult:
    verified: bool
    phase: AuctionState
    message: str
    winner: Winner | None  # set by the reveal that finishes the auction


class Auction:
    """
    Manages the full lifecycle of a sealed-bid cryptographic auction.

    Attributes:
        config: Immutable auction configuration.
        state: Current phase of the auction (AuctionState).
        bidders: Ordered dict mapping bidder_id → BidderState.
    """

    def __init__(self, config: AuctionConfig) -> None:
        self.config = config
        self.state = AuctionState.OPEN
        self.bidders: dict[str, BidderState] = {}
        for idx, name in enumerate(config.bidder_names):
            bidder_id = f"bidder_{idx}"
            self.bidders[bidder_id] = BidderState(bidder_id=bidder_id, name=name)
        # Ties go to the earliest commitment. A counter orders commitments
        # deterministically, where timestamps could collide or be skewed.
        self._commits_received = 0
        # Bound into every range proof's context, so a proof made for one
        # auction cannot be replayed in another.
        self.auction_id = secrets.token_hex(16)

    def proof_context(self, bidder_id: str) -> bytes:
        """What a bidder's range proof is bound to: this auction and this bidder."""
        return bid_proof_context(self.auction_id, bidder_id)

    # ------------------------------------------------------------------
    # Phase 1 — Commit
    # ------------------------------------------------------------------

    def submit_commitment(self, bidder_id: str, commitment_hex: str) -> CommitResult:
        """
        Record a bidder's Pedersen commitment.

        Allowed in states OPEN and COMMITTED (so bidders can commit asynchronously).
        Advances to COMMITTED once all bidders have committed.

        Args:
            bidder_id: Identifier of the bidder submitting the commitment.
            commitment_hex: C = bid·G + blinding·H as a compressed point
                (pedersen.encode_point).

        Returns:
            The phase after this commitment, and a message for the protocol log.

        Raises:
            ValueError: On invalid state, unknown bidder_id, duplicate commit, or
                a commitment that is not a canonically encoded curve point.
        """
        if self.state not in (AuctionState.OPEN, AuctionState.COMMITTED):
            raise ValueError(
                f"Cannot commit in state '{self.state.value}'. Expected OPEN or COMMITTED."
            )
        if bidder_id not in self.bidders:
            raise ValueError(f"Unknown bidder_id '{bidder_id}'.")

        bidder = self.bidders[bidder_id]
        if bidder.commitment_hex is not None:
            raise ValueError(
                f"Bidder '{bidder.name}' has already committed. Double-commit is not allowed."
            )
        decode_point(commitment_hex)  # raises ValueError unless canonical and on the curve

        bidder.commitment_hex = commitment_hex
        bidder.commit_order = self._commits_received
        self._commits_received += 1

        if all(b.commitment_hex is not None for b in self.bidders.values()):
            self.state = AuctionState.COMMITTED

        return CommitResult(phase=self.state, message=f"{bidder.name} committed successfully.")

    # ------------------------------------------------------------------
    # Phase 2 — ZK Range Proof
    # ------------------------------------------------------------------

    def submit_proof(self, bidder_id: str, proof_data: dict[str, Any]) -> ProofResult:
        """
        Receive and verify a ZK range proof from a bidder.

        The proof must show that this bidder's commitment hides a bid in this
        auction's [min_bid, max_bid], for this auction and bidder
        (proof_context); a proof of any other statement is recorded as invalid.

        Allowed in states COMMITTED and PROVED.
        Advances to PROVED once every bidder has submitted a proof, valid or not.

        Args:
            bidder_id: Identifier of the bidder submitting the proof.
            proof_data: A RangeProof serialised with RangeProof.to_dict().

        Returns:
            Whether the proof is valid, the phase after it, and a log message.

        Raises:
            ValueError: On invalid state, unknown bidder_id, or missing commitment.
        """
        if self.state not in (AuctionState.COMMITTED, AuctionState.PROVED):
            raise ValueError(
                f"Cannot submit proof in state '{self.state.value}'. Expected COMMITTED or PROVED."
            )
        if bidder_id not in self.bidders:
            raise ValueError(f"Unknown bidder_id '{bidder_id}'.")

        bidder = self.bidders[bidder_id]
        if bidder.commitment_hex is None:
            raise ValueError(
                f"Bidder '{bidder.name}' has not committed yet. Submit commitment first."
            )
        if bidder.proof_valid is not None:
            raise ValueError(f"Bidder '{bidder.name}' has already submitted a proof.")

        # Deserialise and verify. The statement (commitment, range and context)
        # comes from the auction; the proof carries none of it, so a valid
        # proof of a different statement cannot pass for this one.
        try:
            proof = RangeProof.from_dict(proof_data)
            is_valid = verify_range(
                decode_point(bidder.commitment_hex),
                proof,
                self.config.min_bid,
                self.config.max_bid,
                self.proof_context(bidder_id),
            )
        except (KeyError, TypeError, ValueError):
            is_valid = False

        bidder.range_proof = proof_data
        bidder.proof_valid = is_valid

        if all(b.proof_valid is not None for b in self.bidders.values()):
            self.state = AuctionState.PROVED

        return ProofResult(
            proof_valid=is_valid,
            phase=self.state,
            message=f"{bidder.name}'s proof is {'valid' if is_valid else 'INVALID'}.",
        )

    # ------------------------------------------------------------------
    # Phase 3 — Reveal
    # ------------------------------------------------------------------

    def submit_reveal(self, bidder_id: str, bid: int, blinding: int) -> RevealResult:
        """
        Accept a bidder's reveal of (bid, blinding) and verify against commitment.

        Bidders with a failed commitment verification are marked as cheaters and
        excluded from the winner determination. Bidders whose range proof was
        invalid, or whose revealed bid lies outside [min_bid, max_bid], may still
        reveal, so the auction can finish, but cannot win.

        Advances to FINISHED once all bidders have revealed.

        Args:
            bidder_id: Identifier of the bidder revealing.
            bid: The actual bid value being revealed.
            blinding: The commitment's blinding factor, a scalar in [0, n).

        Returns:
            Whether the opening matches the commitment, the phase after this
            reveal, a log message, and the winner once the auction is finished.

        Raises:
            ValueError: On invalid state, unknown bidder, missing proof, duplicate
                reveal, or a blinding that is not a scalar in [0, n). Malformed
                input is rejected rather than counted as a failed opening.
        """
        if isinstance(blinding, bool) or not isinstance(blinding, int) or not 0 <= blinding < N:
            raise ValueError("The blinding factor must be an integer in [0, n).")
        if self.state != AuctionState.PROVED:
            raise ValueError(f"Cannot reveal in state '{self.state.value}'. Expected PROVED.")
        if bidder_id not in self.bidders:
            raise ValueError(f"Unknown bidder_id '{bidder_id}'.")

        bidder = self.bidders[bidder_id]
        # A proof implies a commitment; checking both lets the type checker
        # see that commitment_hex is set below.
        if bidder.commitment_hex is None or bidder.proof_valid is None:
            raise ValueError(f"Bidder '{bidder.name}' has not submitted a ZK proof yet.")
        if bidder.revealed_bid is not None:
            raise ValueError(
                f"Bidder '{bidder.name}' has already revealed. Duplicate reveal is not allowed."
            )

        is_verified = verify_opening(decode_point(bidder.commitment_hex), bid, blinding)

        bidder.revealed_bid = bid
        bidder.revealed_blinding = blinding
        bidder.commitment_verified = is_verified

        if all(b.revealed_bid is not None for b in self.bidders.values()):
            self.state = AuctionState.FINISHED

        winner = self.get_winner() if self.state == AuctionState.FINISHED else None

        if not is_verified:
            outcome = "INVALID — marked as cheater"
        elif not self._in_range(bid):
            outcome = "verified, but outside the allowed range — disqualified"
        else:
            outcome = "verified"

        return RevealResult(
            verified=is_verified,
            phase=self.state,
            message=f"{bidder.name}'s reveal is {outcome}.",
            winner=winner,
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_public_state(self) -> dict[str, Any]:
        """
        Return the complete public state visible to all participants.

        Bids and blinding factors are included only once the auction is FINISHED.
        """
        bidders_public = []
        for b in self.bidders.values():
            entry = {
                "bidder_id": b.bidder_id,
                "name": b.name,
                "commitment_hex": b.commitment_hex,
                "commit_order": b.commit_order,
                "proof_valid": b.proof_valid,
                "commitment_verified": b.commitment_verified,
            }
            # Publishing reveals as they arrive would let bidders who have not
            # revealed yet see the others' bids and withhold their own if they
            # are losing (selective abort), so openings stay hidden until all
            # bidders have revealed.
            if self.state == AuctionState.FINISHED:
                entry["revealed_bid"] = b.revealed_bid
                entry["randomness_hex"] = (
                    None if b.revealed_blinding is None else encode_scalar(b.revealed_blinding)
                )
            bidders_public.append(entry)

        winner = self.get_winner()
        return {
            "auction_id": self.auction_id,
            "state": self.state.value,
            "item_name": self.config.item_name,
            "min_bid": self.config.min_bid,
            "max_bid": self.config.max_bid,
            "bidders": bidders_public,
            "winner": winner.to_dict() if winner else None,
        }

    def get_winner(self) -> Winner | None:
        """
        Determine and return the auction winner.

        The winner is the bidder with the highest bid among eligible bidders:
        those whose range proof was valid, whose reveal opened their commitment,
        and whose revealed bid lies within [min_bid, max_bid]. In case of a tie,
        the bidder who committed first wins.

        Returns:
            The winner, or None if the auction is not yet finished or no bidder
            is eligible.
        """
        if self.state != AuctionState.FINISHED:
            return None

        # A bid only counts if every check passed: the range proof vouches that
        # the committed bid lies in [min, max], and the opening shows the
        # revealed bid is the committed one. The range is checked again on the
        # revealed bid as defence in depth: it costs nothing once a bid is
        # revealed, and keeps the auction safe should the proof system break.
        # A verified bidder always has a commitment and a commit order; the
        # explicit checks let the type checker see that too.
        candidates = [
            (b.commit_order, Winner(b.bidder_id, b.name, b.revealed_bid, b.commitment_hex))
            for b in self.bidders.values()
            if b.proof_valid is True
            and b.commitment_verified is True
            and b.revealed_bid is not None
            and b.commitment_hex is not None
            and b.commit_order is not None
            and self._in_range(b.revealed_bid)
        ]

        if not candidates:
            return None

        # Highest bid first; among equal bids, the earliest commitment.
        _, winner = min(candidates, key=lambda c: (-c[1].bid, c[0]))
        return winner

    def _in_range(self, bid: int) -> bool:
        return self.config.min_bid <= bid <= self.config.max_bid
