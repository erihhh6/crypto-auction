"""
Application service: runs one auction and the server's part of the protocol.

The service owns the auction a server instance runs and performs the steps the
server currently does on the bidder's behalf (computing the commitment and the
range proof). It knows nothing about HTTP: the web layer maps NoAuctionError to
404 and AuctionRuleError to 400.
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
from crypto_auction.pedersen import Commitment, commit, decode_point, encode_point
from crypto_auction.range_proof import RangeProof, prove_range


class NoAuctionError(LookupError):
    """No auction has been created yet, or it was reset."""


class AuctionRuleError(Exception):
    """The request breaks the auction's rules, e.g. a bid outside the range."""


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

    def commit(self, bidder_id: str, bid: int) -> tuple[Commitment, CommitResult]:
        """Commit to a bid for a bidder; the opening is returned, not stored."""
        with self._lock:
            auction = self._current()
            config = auction.config
            if not config.min_bid <= bid <= config.max_bid:
                raise AuctionRuleError(
                    f"Bid {bid} is outside the allowed range [{config.min_bid}, {config.max_bid}]."
                )
            try:
                commitment = commit(bid)
                result = auction.submit_commitment(bidder_id, encode_point(commitment.point))
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc
            return commitment, result

    def prove(self, bidder_id: str, bid: int, blinding: int) -> tuple[RangeProof, ProofResult]:
        """Prove a bidder's committed bid lies in the auction's range, and record it."""
        with self._lock:
            auction = self._current()
            bidder = auction.bidders.get(bidder_id)
            if bidder is None:
                raise AuctionRuleError(f"Unknown bidder_id '{bidder_id}'.")
            if bidder.commitment_hex is None:
                raise AuctionRuleError("Bidder has not committed yet.")
            try:
                proof = prove_range(
                    decode_point(bidder.commitment_hex),
                    bid,
                    blinding,
                    auction.config.min_bid,
                    auction.config.max_bid,
                    auction.proof_context(bidder_id),
                )
                result = auction.submit_proof(bidder_id, proof.to_dict())
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc
            return proof, result

    def reveal(self, bidder_id: str, bid: int, blinding: int) -> RevealResult:
        """Open a bidder's commitment; the last reveal determines the winner."""
        with self._lock:
            auction = self._current()
            try:
                return auction.submit_reveal(bidder_id, bid, blinding)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def reset(self) -> None:
        with self._lock:
            self._auction = None
