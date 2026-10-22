"""
Application service: runs one auction on the server.

Bidders compute their commitments and range proofs themselves (in the browser),
so the service only records and verifies what they send; it never sees a bid
before the reveal. It knows nothing about HTTP: the web layer maps
NoAuctionError to 404 and AuctionRuleError to 400.
"""

import threading
from typing import Any

from crypto_auction.auction import (
    Auction,
    AuctionConfig,
    CommitResult,
    ProofResult,
    RevealResult,
)


class NoAuctionError(LookupError):
    """No auction has been created yet, or it was reset."""


class AuctionRuleError(Exception):
    """The request breaks the auction's rules, e.g. a commitment in the wrong phase."""


class AuctionService:
    def __init__(self) -> None:
        self._auction: Auction | None = None
        # Flask serves requests on several threads, and every operation reads
        # and updates the auction (phase changes, commit order), so they run
        # one at a time.
        self._lock = threading.Lock()

    def _current(self) -> Auction:
        if self._auction is None:
            raise NoAuctionError("No auction created yet.")
        return self._auction

    def require_auction(self) -> None:
        """Raise NoAuctionError unless an auction exists."""
        with self._lock:
            self._current()

    def create(self, config: AuctionConfig) -> Auction:
        """Start a new auction, replacing the current one."""
        with self._lock:
            self._auction = Auction(config)
            return self._auction

    def public_state(self) -> dict[str, Any]:
        with self._lock:
            return self._current().get_public_state()

    def commit(self, bidder_id: str, commitment_hex: str) -> CommitResult:
        """Record a bidder's Pedersen commitment (a compressed point)."""
        with self._lock:
            try:
                return self._current().submit_commitment(bidder_id, commitment_hex)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def prove(self, bidder_id: str, proof_data: dict[str, Any]) -> ProofResult:
        """Verify and record a bidder's range proof (RangeProof.to_dict() format)."""
        with self._lock:
            try:
                return self._current().submit_proof(bidder_id, proof_data)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def reveal(self, bidder_id: str, bid: int, blinding: int) -> RevealResult:
        """Open a bidder's commitment; the last reveal determines the winner."""
        with self._lock:
            try:
                return self._current().submit_reveal(bidder_id, bid, blinding)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def reset(self) -> None:
        with self._lock:
            self._auction = None
