"""
Auction State Machine Module
==============================

Implements a sealed-bid auction with a 3-phase cryptographic protocol:

  OPEN → COMMITTED → PROVED → FINISHED

State transitions:
  OPEN      → COMMITTED : all bidders have submitted their hash commitments
  COMMITTED → PROVED    : all bidders have submitted a range proof (valid or not)
  PROVED    → FINISHED  : all bidders have revealed (bid, randomness); the winner
                          is determined from the verified reveals

Security model: honest-but-curious auctioneer.
The auctioneer should see only commitments and ZK proofs in phases 1-2, and
learn actual bid values only in phase 3. Not met yet: the server currently
receives bids in plaintext (see README).
"""

from dataclasses import dataclass
from enum import Enum

from crypto_auction.commitment import verify as verify_commitment
from crypto_auction.zkp import RangeProof, verify_range_proof


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
    commitment_hex: str | None = None
    commit_order: int | None = None  # 0 for the first commitment received, 1 next, ...
    # Phase 2 — public after prove
    range_proof: dict | None = None  # RangeProof serialised as dict
    proof_valid: bool | None = None
    # Phase 3 — public after reveal
    revealed_bid: int | None = None
    randomness_hex: str | None = None  # becomes public at reveal
    commitment_verified: bool | None = None


@dataclass
class AuctionConfig:
    """Immutable configuration set when the auction is created."""

    min_bid: int
    max_bid: int
    item_name: str
    bidder_names: list


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
        self.bidders: dict = {}
        for idx, name in enumerate(config.bidder_names):
            bidder_id = f"bidder_{idx}"
            self.bidders[bidder_id] = BidderState(bidder_id=bidder_id, name=name)
        # Ties go to the earliest commitment. A counter orders commitments
        # deterministically, where timestamps could collide or be skewed.
        self._commits_received = 0

    # ------------------------------------------------------------------
    # Phase 1 — Commit
    # ------------------------------------------------------------------

    def submit_commitment(self, bidder_id: str, commitment_hex: str) -> dict:
        """
        Record a bidder's hash commitment.

        Allowed in states OPEN and COMMITTED (so bidders can commit asynchronously).
        Advances to COMMITTED once all bidders have committed.

        Args:
            bidder_id: Identifier of the bidder submitting the commitment.
            commitment_hex: SHA-256 hex digest of (bid_bytes || randomness).

        Returns:
            dict with keys: success, phase, bidder_id, message.

        Raises:
            ValueError: On invalid state, unknown bidder_id, or duplicate commit.
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

        bidder.commitment_hex = commitment_hex
        bidder.commit_order = self._commits_received
        self._commits_received += 1

        if all(b.commitment_hex is not None for b in self.bidders.values()):
            self.state = AuctionState.COMMITTED

        return {
            "success": True,
            "phase": self.state.value,
            "bidder_id": bidder_id,
            "message": f"{bidder.name} committed successfully.",
        }

    # ------------------------------------------------------------------
    # Phase 2 — ZK Range Proof
    # ------------------------------------------------------------------

    def submit_proof(self, bidder_id: str, proof_data: dict) -> dict:
        """
        Receive and verify a ZK range proof from a bidder.

        The proof must be about this bidder's commitment and this auction's
        [min_bid, max_bid]; a proof of any other statement is recorded as invalid.

        Allowed in states COMMITTED and PROVED.
        Advances to PROVED once all proofs are received and valid.

        Args:
            bidder_id: Identifier of the bidder submitting the proof.
            proof_data: Serialised RangeProof as a plain dict.

        Returns:
            dict with keys: success, proof_valid, phase, bidder_id, message.

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

        # Deserialise and verify. The statement (commitment and range) must come
        # from the auction, not from the proof: an otherwise valid proof of a
        # different statement says nothing about this bidder's bid.
        try:
            proof = RangeProof(
                commitment_hex=proof_data["commitment_hex"],
                min_bid=proof_data["min_bid"],
                max_bid=proof_data["max_bid"],
                low_commitment_hex=proof_data["low_commitment_hex"],
                low_challenge_hex=proof_data["low_challenge_hex"],
                low_response=proof_data["low_response"],
                high_commitment_hex=proof_data["high_commitment_hex"],
                high_challenge_hex=proof_data["high_challenge_hex"],
                high_response=proof_data["high_response"],
            )
            is_valid = (
                proof.commitment_hex == bidder.commitment_hex
                and proof.min_bid == self.config.min_bid
                and proof.max_bid == self.config.max_bid
                and verify_range_proof(proof)
            )
        except (KeyError, TypeError, ValueError):
            is_valid = False

        bidder.range_proof = proof_data
        bidder.proof_valid = is_valid

        if all(b.proof_valid is not None for b in self.bidders.values()):
            self.state = AuctionState.PROVED

        return {
            "success": True,
            "proof_valid": is_valid,
            "phase": self.state.value,
            "bidder_id": bidder_id,
            "message": f"{bidder.name}'s proof is {'valid' if is_valid else 'INVALID'}.",
        }

    # ------------------------------------------------------------------
    # Phase 3 — Reveal
    # ------------------------------------------------------------------

    def submit_reveal(self, bidder_id: str, bid: int, randomness_hex: str) -> dict:
        """
        Accept a bidder's reveal of (bid, randomness) and verify against commitment.

        Bidders with a failed commitment verification are marked as cheaters and
        excluded from the winner determination. Bidders whose range proof was
        invalid, or whose revealed bid lies outside [min_bid, max_bid], may still
        reveal, so the auction can finish, but cannot win.

        Advances to FINISHED once all bidders have revealed.

        Args:
            bidder_id: Identifier of the bidder revealing.
            bid: The actual bid value being revealed.
            randomness_hex: The secret randomness used in Phase 1.

        Returns:
            dict with keys: success, verified, phase, bidder_id, winner (may be None).

        Raises:
            ValueError: On invalid state, unknown bidder, missing proof, or duplicate reveal.
        """
        if self.state != AuctionState.PROVED:
            raise ValueError(f"Cannot reveal in state '{self.state.value}'. Expected PROVED.")
        if bidder_id not in self.bidders:
            raise ValueError(f"Unknown bidder_id '{bidder_id}'.")

        bidder = self.bidders[bidder_id]
        if bidder.proof_valid is None:
            raise ValueError(f"Bidder '{bidder.name}' has not submitted a ZK proof yet.")
        if bidder.revealed_bid is not None:
            raise ValueError(
                f"Bidder '{bidder.name}' has already revealed. Duplicate reveal is not allowed."
            )

        # Verify commitment opening
        is_verified = verify_commitment(bid, randomness_hex, bidder.commitment_hex)

        bidder.revealed_bid = bid
        bidder.randomness_hex = randomness_hex
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

        return {
            "success": True,
            "verified": is_verified,
            "phase": self.state.value,
            "bidder_id": bidder_id,
            "message": f"{bidder.name}'s reveal is {outcome}.",
            "winner": winner,
        }

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_public_state(self) -> dict:
        """
        Return the complete public state visible to all participants.

        Bid values and randomness are included only once the auction is FINISHED.
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
                entry["randomness_hex"] = b.randomness_hex
            bidders_public.append(entry)

        return {
            "state": self.state.value,
            "item_name": self.config.item_name,
            "min_bid": self.config.min_bid,
            "max_bid": self.config.max_bid,
            "bidders": bidders_public,
            "winner": self.get_winner(),
        }

    def get_winner(self) -> dict | None:
        """
        Determine and return the auction winner.

        The winner is the bidder with the highest bid among eligible bidders:
        those whose range proof was valid, whose reveal opened their commitment,
        and whose revealed bid lies within [min_bid, max_bid]. In case of a tie,
        the bidder who committed first wins.

        Returns:
            dict with winner info, or None if the auction is not yet finished or
            no bidder is eligible.
        """
        if self.state != AuctionState.FINISHED:
            return None

        # A bid only counts if every check passed: the range proof vouches that
        # the committed bid lies in [min, max], and the opening shows the
        # revealed bid is the committed one. The range is checked again on the
        # revealed bid as defence in depth: the current range proof can be
        # forged, and once a bid is revealed the check costs nothing.
        eligible = [
            b
            for b in self.bidders.values()
            if b.proof_valid is True
            and b.commitment_verified is True
            and b.revealed_bid is not None
            and self._in_range(b.revealed_bid)
        ]

        if not eligible:
            return None

        # Highest bid first; among equal bids, the earliest commitment.
        winner = min(eligible, key=lambda b: (-b.revealed_bid, b.commit_order))
        return {
            "bidder_id": winner.bidder_id,
            "name": winner.name,
            "bid": winner.revealed_bid,
            "commitment_hex": winner.commitment_hex,
        }

    def _in_range(self, bid: int) -> bool:
        return self.config.min_bid <= bid <= self.config.max_bid
