"""
Auction State Machine Module
==============================

Implements a sealed-bid auction with a 3-phase cryptographic protocol:

  OPEN → COMMITTED → PROVED → REVEALED → FINISHED

State transitions:
  OPEN      → COMMITTED : all bidders have submitted their hash commitments
  COMMITTED → PROVED    : all bidders have submitted valid ZK range proofs
  PROVED    → REVEALED  : all bidders have revealed (bid, randomness) pairs
  REVEALED  → FINISHED  : winner is determined after all reveals are verified

Security model: honest-but-curious auctioneer.
The auctioneer sees only commitments and ZK proofs in phases 1-2,
and learns actual bid values only in phase 3.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

try:
    from crypto.commitment import verify as verify_commitment
    from crypto.zkp import RangeProof, prove_range, verify_range_proof
except ImportError:
    from commitment import verify as verify_commitment   # when run directly
    from zkp import RangeProof, prove_range, verify_range_proof


class AuctionState(Enum):
    OPEN = "open"
    COMMITTED = "committed"
    PROVED = "proved"
    REVEALED = "revealed"
    FINISHED = "finished"


@dataclass
class BidderState:
    """Tracks the per-bidder protocol state across all three phases."""

    bidder_id: str
    name: str
    # Phase 1 — public after commit
    commitment_hex: Optional[str] = None
    # Phase 2 — public after prove
    range_proof: Optional[dict] = None   # RangeProof serialised as dict
    proof_valid: Optional[bool] = None
    # Phase 3 — public after reveal
    revealed_bid: Optional[int] = None
    randomness_hex: Optional[str] = None  # becomes public at reveal
    commitment_verified: Optional[bool] = None


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
        # Preserve insertion order for tie-breaking (first committed wins ties)
        self.bidders: dict = {}
        for idx, name in enumerate(config.bidder_names):
            bidder_id = f"bidder_{idx}"
            self.bidders[bidder_id] = BidderState(bidder_id=bidder_id, name=name)

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
            raise ValueError(
                f"Bidder '{bidder.name}' has already submitted a proof."
            )

        # Deserialise and verify
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
            is_valid = verify_range_proof(proof)
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
            "message": (
                f"{bidder.name}'s proof is {'valid' if is_valid else 'INVALID'}."
            ),
        }

    # ------------------------------------------------------------------
    # Phase 3 — Reveal
    # ------------------------------------------------------------------

    def submit_reveal(
        self, bidder_id: str, bid: int, randomness_hex: str
    ) -> dict:
        """
        Accept a bidder's reveal of (bid, randomness) and verify against commitment.

        Bidders with a failed commitment verification are marked as cheaters and
        excluded from the winner determination.

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
        if self.state not in (AuctionState.PROVED, AuctionState.REVEALED):
            raise ValueError(
                f"Cannot reveal in state '{self.state.value}'. Expected PROVED or REVEALED."
            )
        if bidder_id not in self.bidders:
            raise ValueError(f"Unknown bidder_id '{bidder_id}'.")

        bidder = self.bidders[bidder_id]
        if bidder.proof_valid is None:
            raise ValueError(
                f"Bidder '{bidder.name}' has not submitted a ZK proof yet."
            )
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

        return {
            "success": True,
            "verified": is_verified,
            "phase": self.state.value,
            "bidder_id": bidder_id,
            "message": (
                f"{bidder.name}'s reveal is "
                f"{'verified' if is_verified else 'INVALID — marked as cheater'}."
            ),
            "winner": winner,
        }

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_public_state(self) -> dict:
        """
        Return the complete public state visible to all participants.

        Bid values are included only in REVEALED / FINISHED states.
        """
        bidders_public = []
        for b in self.bidders.values():
            entry = {
                "bidder_id": b.bidder_id,
                "name": b.name,
                "commitment_hex": b.commitment_hex,
                "proof_valid": b.proof_valid,
                "commitment_verified": b.commitment_verified,
            }
            # Reveal bid and randomness only in phase 3+
            if self.state in (AuctionState.REVEALED, AuctionState.FINISHED):
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

    def get_winner(self) -> Optional[dict]:
        """
        Determine and return the auction winner.

        Only valid after REVEALED state. The winner is the bidder with the highest
        verified bid among those with commitment_verified=True. In case of a tie,
        the bidder who appears earlier in the original bidder list wins
        (implicit tie-breaking by commit order).

        Returns:
            dict with winner info, or None if the auction is not yet finished.
        """
        if self.state not in (AuctionState.REVEALED, AuctionState.FINISHED):
            return None

        # Only consider bidders with verified commitments
        verified = [
            b for b in self.bidders.values()
            if b.commitment_verified is True and b.revealed_bid is not None
        ]

        if not verified:
            return None

        winner = max(verified, key=lambda b: b.revealed_bid)
        return {
            "bidder_id": winner.bidder_id,
            "name": winner.name,
            "bid": winner.revealed_bid,
            "commitment_hex": winner.commitment_hex,
        }

    def can_advance_phase(self) -> bool:
        """
        Check whether all bidders have completed the current phase.

        Returns True if every bidder satisfies the completion condition for the
        current state, indicating it is time to transition to the next phase.
        """
        if self.state == AuctionState.OPEN:
            return all(b.commitment_hex is not None for b in self.bidders.values())

        if self.state == AuctionState.COMMITTED:
            return all(b.proof_valid is not None for b in self.bidders.values())

        if self.state in (AuctionState.PROVED, AuctionState.REVEALED):
            return all(b.revealed_bid is not None for b in self.bidders.values())

        return False


if __name__ == "__main__":
    import sys, os as _os
    sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from crypto.commitment import commit
    from crypto.zkp import prove_range

    print("=== Full Auction Simulation: Alice, Bob, Carol ===\n")

    config = AuctionConfig(
        min_bid=100,
        max_bid=5000,
        item_name="Rare NFT #42",
        bidder_names=["Alice", "Bob", "Carol"],
    )
    auction = Auction(config)

    bids = {
        "bidder_0": ("Alice", 1200),
        "bidder_1": ("Bob", 1800),
        "bidder_2": ("Carol", 1500),
    }

    # Store secrets keyed by bidder_id (simulating what each bidder holds locally)
    secrets: dict = {}

    print("--- PHASE 1: COMMIT ---")
    for bidder_id, (name, bid) in bids.items():
        c = commit(bid)
        secrets[bidder_id] = {"bid": bid, "randomness_hex": c.randomness_hex}
        result = auction.submit_commitment(bidder_id, c.commitment_hex)
        print(f"  {name}: commitment={c.commitment_hex[:16]}...  -> phase={result['phase']}")

    print(f"\nAuction state: {auction.state.value}")

    print("\n--- PHASE 2: ZK PROVE ---")
    for bidder_id, (name, bid) in bids.items():
        s = secrets[bidder_id]
        # The bidder retrieves their own commitment from public state
        commitment_hex = auction.bidders[bidder_id].commitment_hex
        proof = prove_range(bid, s["randomness_hex"], commitment_hex, config.min_bid, config.max_bid)
        proof_dict = {
            "commitment_hex": proof.commitment_hex,
            "min_bid": proof.min_bid,
            "max_bid": proof.max_bid,
            "low_commitment_hex": proof.low_commitment_hex,
            "low_challenge_hex": proof.low_challenge_hex,
            "low_response": proof.low_response,
            "high_commitment_hex": proof.high_commitment_hex,
            "high_challenge_hex": proof.high_challenge_hex,
            "high_response": proof.high_response,
        }
        result = auction.submit_proof(bidder_id, proof_dict)
        print(f"  {name}: proof_valid={result['proof_valid']}  -> phase={result['phase']}")

    print(f"\nAuction state: {auction.state.value}")

    print("\n--- PHASE 3: REVEAL ---")
    for bidder_id, (name, bid) in bids.items():
        s = secrets[bidder_id]
        result = auction.submit_reveal(bidder_id, s["bid"], s["randomness_hex"])
        print(
            f"  {name}: bid={s['bid']}, verified={result['verified']}  -> phase={result['phase']}"
        )

    print(f"\nAuction state: {auction.state.value}")

    winner = auction.get_winner()
    print(f"\n=== WINNER: {winner['name']} with bid {winner['bid']} ===")

    public = auction.get_public_state()
    print("\nPublic state summary:")
    for b in public["bidders"]:
        print(
            f"  {b['name']}: commitment={str(b['commitment_hex'])[:16]}...  "
            f"proof_valid={b['proof_valid']}  "
            f"bid={b.get('revealed_bid')}  "
            f"verified={b['commitment_verified']}"
        )
