"""
Application service: runs the server's auctions, each under its own id.

Bidders compute their commitments and range proofs themselves (in the browser),
so the service only records and verifies what they send; it never sees a bid
before the reveal. A bidder is identified by the join token they present,
never by an id they name; the organizer, by the organizer token.

The service knows nothing about HTTP: the web layer maps NoAuctionError to 404,
AuthenticationError to 401, AuctionRuleError to 400 and CapacityError to 503.
"""

import threading
import time
from dataclasses import dataclass
from typing import Any

from crypto_auction.auction import (
    Auction,
    AuctionConfig,
    Clock,
    CommitResult,
    ProofResult,
    RevealResult,
)

# Anyone may create an auction, so the number held at once is capped: memory
# stays bounded however many are created.
DEFAULT_MAX_AUCTIONS = 1000


class NoAuctionError(LookupError):
    """There is no auction with this id (it never existed, or was deleted)."""


class AuthenticationError(Exception):
    """The request carries no valid token for what it asks to do in this auction."""


class AuctionRuleError(Exception):
    """The request breaks the auction's rules, e.g. a commitment in the wrong phase."""


class CapacityError(Exception):
    """The server holds as many auctions as it may; none can be created now."""


@dataclass(frozen=True)
class NewAuction:
    """A created auction, with secrets that are handed out only this once."""

    auction: Auction
    organizer_token: str
    join_tokens: dict[str, str]  # bidder_id → join token


class AuctionService:
    def __init__(self, clock: Clock = time.time, max_auctions: int = DEFAULT_MAX_AUCTIONS) -> None:
        """
        clock: what the auctions' deadlines are measured against (tests pass a fake).
        max_auctions: how many auctions may exist at once.
        """
        self._clock = clock
        self._max_auctions = max_auctions
        self._auctions: dict[str, Auction] = {}
        # Flask serves requests on several threads, and operations read and
        # update auctions (phase changes, commit order), so they run one at a
        # time, each holding the lock until it is done. One lock for all
        # auctions keeps that simple; the slowest operation, verifying a range
        # proof, takes about 0.1 s.
        self._lock = threading.Lock()

    def _get(self, auction_id: str) -> Auction:
        try:
            return self._auctions[auction_id]
        except KeyError:
            raise NoAuctionError(f"No auction with id '{auction_id}'.") from None

    def _authenticate(self, auction_id: str, token: str) -> tuple[Auction, str]:
        """The auction and the bidder_id that token belongs to in it."""
        auction = self._get(auction_id)
        bidder_id = auction.authenticate(token)
        if bidder_id is None:
            raise AuthenticationError("Missing or invalid join token for this auction.")
        return auction, bidder_id

    def require_bidder(self, auction_id: str, token: str) -> None:
        """Raise NoAuctionError or AuthenticationError unless token is a bidder's."""
        with self._lock:
            self._authenticate(auction_id, token)

    def create(self, config: AuctionConfig) -> NewAuction:
        """
        Start a new auction alongside the others.

        Returns it with the organizer token and every bidder's join token. The
        tokens cannot be retrieved later: the auction keeps only digests.

        Raises:
            CapacityError: if max_auctions already exist.
        """
        with self._lock:
            if len(self._auctions) >= self._max_auctions:
                raise CapacityError("Too many auctions at once; try again later.")
            auction = Auction(config, clock=self._clock)
            self._auctions[auction.auction_id] = auction
            return NewAuction(
                auction=auction,
                organizer_token=auction.issue_organizer_token(),
                join_tokens=auction.issue_join_tokens(),
            )

    def public_state(self, auction_id: str) -> dict[str, Any]:
        with self._lock:
            return self._get(auction_id).get_public_state()

    def commit(self, auction_id: str, token: str, commitment_hex: str) -> CommitResult:
        """Record the token holder's Pedersen commitment (a compressed point)."""
        with self._lock:
            auction, bidder_id = self._authenticate(auction_id, token)
            try:
                return auction.submit_commitment(bidder_id, commitment_hex)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def prove(self, auction_id: str, token: str, proof_data: dict[str, Any]) -> ProofResult:
        """Verify and record the token holder's range proof (RangeProof.to_dict() format)."""
        with self._lock:
            auction, bidder_id = self._authenticate(auction_id, token)
            try:
                return auction.submit_proof(bidder_id, proof_data)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def reveal(self, auction_id: str, token: str, bid: int, blinding: int) -> RevealResult:
        """Open the token holder's commitment; the last reveal determines the winner."""
        with self._lock:
            auction, bidder_id = self._authenticate(auction_id, token)
            try:
                return auction.submit_reveal(bidder_id, bid, blinding)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def delete(self, auction_id: str, organizer_token: str) -> None:
        """Discard an auction; only its organizer may."""
        with self._lock:
            if not self._get(auction_id).is_organizer(organizer_token):
                raise AuthenticationError("Missing or invalid organizer token for this auction.")
            del self._auctions[auction_id]
