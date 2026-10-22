"""
Application service: runs the server's auctions, each under its own id.

Bidders compute their commitments and range proofs themselves (in the browser),
so the service only records and verifies what they send; it never sees a bid
before the reveal. A bidder is identified by the join token they present,
never by an id they name; the organizer, by the organizer token.

Auctions live in an SQLite database (store.py). Each operation loads the
auction, acts on it and stores it again, all in one transaction, so concurrent
requests (threads, or processes sharing the database) never interleave.

The service knows nothing about HTTP: the web layer maps NoAuctionError to 404,
AuthenticationError to 401, AuctionRuleError to 400 and CapacityError to 503.
"""

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import Any

from crypto_auction.auction import (
    Auction,
    AuctionConfig,
    Clock,
    CommitResult,
    ProofResult,
    RevealResult,
)
from crypto_auction.store import AuctionStore

# Anyone may create an auction, so the number running at once is capped.
DEFAULT_MAX_AUCTIONS = 1000


class NoAuctionError(LookupError):
    """There is no auction with this id (it never existed, or was deleted)."""


class AuthenticationError(Exception):
    """The request carries no valid token for what it asks to do in this auction."""


class AuctionRuleError(Exception):
    """The request breaks the auction's rules, e.g. a commitment in the wrong phase."""


class CapacityError(Exception):
    """As many auctions are running as may; none can be created now."""


@dataclass(frozen=True)
class NewAuction:
    """A created auction, with secrets that are handed out only this once."""

    auction: Auction
    organizer_token: str
    join_tokens: dict[str, str]  # bidder_id → join token


class AuctionService:
    def __init__(
        self,
        database: str | PathLike[str],
        clock: Clock = time.time,
        max_auctions: int = DEFAULT_MAX_AUCTIONS,
    ) -> None:
        """
        database: the SQLite file holding the auctions (created on first use).
        clock: what the auctions' deadlines are measured against (tests pass a fake).
        max_auctions: how many auctions may be running at once; finished ones,
            and ones past their reveal deadline, do not count.
        """
        self._store = AuctionStore(database)
        self._clock = clock
        self._max_auctions = max_auctions

    @property
    def database(self) -> Path:
        """The SQLite file the auctions are stored in."""
        return self._store.database

    @contextmanager
    def _auction(self, auction_id: str) -> Iterator[Auction]:
        """
        The auction, loaded for one operation and stored again afterwards if
        the operation changed it; nothing is stored if the operation raises.
        """
        with self._store.transaction() as tx:
            record = tx.load(auction_id)
            if record is None:
                raise NoAuctionError(f"No auction with id '{auction_id}'.")
            auction = Auction.from_record(record, clock=self._clock)
            yield auction
            # Queries change an auction too when they pass a deadline, which
            # moves it on to the next phase.
            changed = auction.to_record()
            if changed != record:
                tx.save(changed)

    @staticmethod
    def _bidder(auction: Auction, token: str) -> str:
        """The bidder_id that token belongs to in this auction."""
        bidder_id = auction.authenticate(token)
        if bidder_id is None:
            raise AuthenticationError("Missing or invalid join token for this auction.")
        return bidder_id

    def require_bidder(self, auction_id: str, token: str) -> None:
        """Raise NoAuctionError or AuthenticationError unless token is a bidder's."""
        with self._auction(auction_id) as auction:
            self._bidder(auction, token)

    def identify(self, auction_id: str, token: str) -> tuple[str, str]:
        """The bidder_id and name of the bidder whose join token this is."""
        with self._auction(auction_id) as auction:
            bidder_id = self._bidder(auction, token)
            return bidder_id, auction.bidders[bidder_id].name

    def create(self, config: AuctionConfig) -> NewAuction:
        """
        Start a new auction alongside the others.

        Returns it with the organizer token and every bidder's join token. The
        tokens cannot be retrieved later: only their digests are stored.

        Raises:
            CapacityError: if max_auctions are already running.
        """
        with self._store.transaction() as tx:
            if tx.count_running(self._clock()) >= self._max_auctions:
                raise CapacityError("Too many auctions at once; try again later.")
            auction = Auction(config, clock=self._clock)
            created = NewAuction(
                auction=auction,
                organizer_token=auction.issue_organizer_token(),
                join_tokens=auction.issue_join_tokens(),
            )
            tx.save(auction.to_record())
            return created

    def public_state(self, auction_id: str) -> dict[str, Any]:
        with self._auction(auction_id) as auction:
            return auction.get_public_state()

    def commit(self, auction_id: str, token: str, commitment_hex: str) -> CommitResult:
        """Record the token holder's Pedersen commitment (a compressed point)."""
        with self._auction(auction_id) as auction:
            bidder_id = self._bidder(auction, token)
            try:
                return auction.submit_commitment(bidder_id, commitment_hex)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def prove(self, auction_id: str, token: str, proof_data: dict[str, Any]) -> ProofResult:
        """Verify and record the token holder's range proof (RangeProof.to_dict() format)."""
        with self._auction(auction_id) as auction:
            bidder_id = self._bidder(auction, token)
            try:
                return auction.submit_proof(bidder_id, proof_data)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def reveal(self, auction_id: str, token: str, bid: int, blinding: int) -> RevealResult:
        """Open the token holder's commitment; the last reveal determines the winner."""
        with self._auction(auction_id) as auction:
            bidder_id = self._bidder(auction, token)
            try:
                return auction.submit_reveal(bidder_id, bid, blinding)
            except ValueError as exc:
                raise AuctionRuleError(str(exc)) from exc

    def delete(self, auction_id: str, organizer_token: str) -> None:
        """Discard an auction; only its organizer may."""
        with self._store.transaction() as tx:
            record = tx.load(auction_id)
            if record is None:
                raise NoAuctionError(f"No auction with id '{auction_id}'.")
            if not Auction.from_record(record, clock=self._clock).is_organizer(organizer_token):
                raise AuthenticationError("Missing or invalid organizer token for this auction.")
            tx.delete(auction_id)
