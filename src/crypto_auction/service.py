"""
Application service: runs one auction on the server.

Bidders compute their commitments and range proofs themselves (in the browser),
so the service only records and verifies what they send; it never sees a bid
before the reveal. A bidder is identified by the join token they present,
never by an id they name.

The service knows nothing about HTTP: the web layer maps NoAuctionError to 404,
AuthenticationError to 401 and AuctionRuleError to 400.
"""

import threading
import time
from typing import Any

from crypto_auction.auction import (
    Auction,
    AuctionConfig,
    Clock,
    CommitResult,
    ProofResult,
    RevealResult,
)


class NoAuctionError(LookupError):
    """No auction has been created yet, or it was reset."""


class AuthenticationError(Exception):
    """The request carries no valid join token for the current auction."""


class AuctionRuleError(Exception):
    """The request breaks the auction's rules, e.g. a commitment in the wrong phase."""


class AuctionService:
    def __init__(self, clock: Clock = time.time) -> None:
        """clock: what the auction's deadlines are measured against (tests pass a fake)."""
        self._clock = clock
        self._auction: Auction | None = None
        # Flask serves requests on several threads, and every operation reads
        # and updates the auction (phase changes, commit order), so they run
        # one at a time.
        self._lock = threading.Lock()

    def _current(self) -> Auction:
        if self._auction is None:
            raise NoAuctionError("No auction created yet.")
        return self._auction

    def _authenticate(self, token: str) -> tuple[Auction, str]:
        """
        The current auction and the bidder_id that token belongs to.

        Operations call this while holding the lock until they are done, so a
        token is checked against the very auction it then acts on; otherwise a
        token from a replaced auction could act in the new one, whose bidders
        reuse the same ids.
        """
        auction = self._current()
        bidder_id = auction.authenticate(token)
        if bidder_id is None:
            raise AuthenticationError("Missing or invalid join token.")
        return auction, bidder_id

    def require_bidder(self, token: str) -> None:
        """Raise NoAuctionError or AuthenticationError unless token is a bidder's."""
        with self._lock:
            self._authenticate(token)

    def create(self, config: AuctionConfig) -> tuple[Auction, dict[str, str]]:
        """
        Start a new auction, replacing the current one.

        Returns the auction and every bidder's join token (bidder_id → token).
        The tokens cannot be retrieved later: the auction keeps only digests.
        """
        with self._lock:
            self._auction = Auction(config, clock=self._clock)
            return self._auction, self._auction.issue_join_tokens()

    def public_state(self) -> dict[str, Any]:
        with self._lock:
            return self._current().get_public_state()

    def commit(self, token: str, commitment_hex: str) -> CommitResult:
        """Record the token holder's Pedersen commitment (a compressed point)."""
        with self._lock:
            auction, bidder_id = self._authenticate(token)
            try:
                return auction.submit_commitment(bidder_id, commitment_hex)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def prove(self, token: str, proof_data: dict[str, Any]) -> ProofResult:
        """Verify and record the token holder's range proof (RangeProof.to_dict() format)."""
        with self._lock:
            auction, bidder_id = self._authenticate(token)
            try:
                return auction.submit_proof(bidder_id, proof_data)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def reveal(self, token: str, bid: int, blinding: int) -> RevealResult:
        """Open the token holder's commitment; the last reveal determines the winner."""
        with self._lock:
            auction, bidder_id = self._authenticate(token)
            try:
                return auction.submit_reveal(bidder_id, bid, blinding)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def reset(self) -> None:
        with self._lock:
            self._auction = None
