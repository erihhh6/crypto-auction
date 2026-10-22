"""
SQLite storage for auctions.

An auction is stored as one row in `auctions` and one per bidder in `bidders`.
Every operation opens its own connection and runs in a single transaction
begun with BEGIN IMMEDIATE, which takes the database's write lock up front:
operations on one database file run one at a time, across threads and
processes alike, so none can act on an auction another is changing.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from os import PathLike
from pathlib import Path
from typing import Any

from crypto_auction.auction import AuctionConfig, AuctionRecord, AuctionState, BidderState
from crypto_auction.pedersen import decode_scalar, encode_scalar

# Stored in the database file as PRAGMA user_version; bumped (with a
# migration) whenever the schema changes.
SCHEMA_VERSION = 1

_SCHEMA = (
    """
    CREATE TABLE auctions (
        auction_id       TEXT PRIMARY KEY,
        item_name        TEXT NOT NULL,
        min_bid          INTEGER NOT NULL,
        max_bid          INTEGER NOT NULL,
        commit_seconds   INTEGER NOT NULL,
        prove_seconds    INTEGER NOT NULL,
        reveal_seconds   INTEGER NOT NULL,
        state            TEXT NOT NULL
                         CHECK (state IN ('open', 'committed', 'proved', 'finished')),
        commit_deadline  REAL NOT NULL,
        prove_deadline   REAL NOT NULL,
        reveal_deadline  REAL NOT NULL,
        organizer_digest BLOB
    ) STRICT
    """,
    """
    CREATE TABLE bidders (
        auction_id          TEXT NOT NULL REFERENCES auctions ON DELETE CASCADE,
        position            INTEGER NOT NULL,
        bidder_id           TEXT NOT NULL,
        name                TEXT NOT NULL,
        token_digest        BLOB,
        missed_deadline     TEXT CHECK (missed_deadline IN ('commit', 'prove', 'reveal')),
        commitment_hex      TEXT,
        commit_order        INTEGER,
        range_proof         TEXT,     -- JSON, as the bidder sent it
        proof_valid         INTEGER,  -- 0 or 1
        revealed_bid        INTEGER,
        revealed_blinding   TEXT,     -- hex: a scalar can exceed SQLite's 64-bit integers
        commitment_verified INTEGER,  -- 0 or 1
        PRIMARY KEY (auction_id, bidder_id),
        UNIQUE (auction_id, position),
        -- The auction rejects copied commitments too; NULLs never clash.
        UNIQUE (auction_id, commitment_hex)
    ) STRICT
    """,
    # Counting the auctions still running looks them up by deadline.
    "CREATE INDEX auctions_by_reveal_deadline ON auctions (reveal_deadline)",
)

_UPSERT_AUCTION = """
    INSERT INTO auctions (
        auction_id, item_name, min_bid, max_bid, commit_seconds, prove_seconds,
        reveal_seconds, state, commit_deadline, prove_deadline, reveal_deadline,
        organizer_digest
    ) VALUES (
        :auction_id, :item_name, :min_bid, :max_bid, :commit_seconds, :prove_seconds,
        :reveal_seconds, :state, :commit_deadline, :prove_deadline, :reveal_deadline,
        :organizer_digest
    )
    ON CONFLICT (auction_id) DO UPDATE SET
        state = excluded.state,
        organizer_digest = excluded.organizer_digest
"""

_UPSERT_BIDDER = """
    INSERT INTO bidders (
        auction_id, position, bidder_id, name, token_digest, missed_deadline,
        commitment_hex, commit_order, range_proof, proof_valid, revealed_bid,
        revealed_blinding, commitment_verified
    ) VALUES (
        :auction_id, :position, :bidder_id, :name, :token_digest, :missed_deadline,
        :commitment_hex, :commit_order, :range_proof, :proof_valid, :revealed_bid,
        :revealed_blinding, :commitment_verified
    )
    ON CONFLICT (auction_id, bidder_id) DO UPDATE SET
        token_digest = excluded.token_digest,
        missed_deadline = excluded.missed_deadline,
        commitment_hex = excluded.commitment_hex,
        commit_order = excluded.commit_order,
        range_proof = excluded.range_proof,
        proof_valid = excluded.proof_valid,
        revealed_bid = excluded.revealed_bid,
        revealed_blinding = excluded.revealed_blinding,
        commitment_verified = excluded.commitment_verified
"""


def _flag(value: bool | None) -> int | None:
    return None if value is None else int(value)


def _unflag(value: int | None) -> bool | None:
    return None if value is None else bool(value)


def _bidder_row(auction_id: str, position: int, b: BidderState) -> dict[str, Any]:
    return {
        "auction_id": auction_id,
        "position": position,
        "bidder_id": b.bidder_id,
        "name": b.name,
        "token_digest": b.token_digest,
        "missed_deadline": b.missed_deadline,
        "commitment_hex": b.commitment_hex,
        "commit_order": b.commit_order,
        "range_proof": None if b.range_proof is None else json.dumps(b.range_proof),
        "proof_valid": _flag(b.proof_valid),
        "revealed_bid": b.revealed_bid,
        "revealed_blinding": (
            None if b.revealed_blinding is None else encode_scalar(b.revealed_blinding)
        ),
        "commitment_verified": _flag(b.commitment_verified),
    }


def _bidder_state(row: sqlite3.Row) -> BidderState:
    return BidderState(
        bidder_id=row["bidder_id"],
        name=row["name"],
        token_digest=row["token_digest"],
        missed_deadline=row["missed_deadline"],
        commitment_hex=row["commitment_hex"],
        commit_order=row["commit_order"],
        range_proof=None if row["range_proof"] is None else json.loads(row["range_proof"]),
        proof_valid=_unflag(row["proof_valid"]),
        revealed_bid=row["revealed_bid"],
        revealed_blinding=(
            None if row["revealed_blinding"] is None else decode_scalar(row["revealed_blinding"])
        ),
        commitment_verified=_unflag(row["commitment_verified"]),
    )


class Transaction:
    """The operations available inside AuctionStore.transaction()."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db

    def load(self, auction_id: str) -> AuctionRecord | None:
        """The stored auction, or None if there is none with this id."""
        row = self._db.execute(
            "SELECT * FROM auctions WHERE auction_id = ?", (auction_id,)
        ).fetchone()
        if row is None:
            return None
        bidder_rows = self._db.execute(
            "SELECT * FROM bidders WHERE auction_id = ? ORDER BY position", (auction_id,)
        ).fetchall()
        config = AuctionConfig(
            min_bid=row["min_bid"],
            max_bid=row["max_bid"],
            item_name=row["item_name"],
            bidder_names=tuple(b["name"] for b in bidder_rows),
            commit_seconds=row["commit_seconds"],
            prove_seconds=row["prove_seconds"],
            reveal_seconds=row["reveal_seconds"],
        )
        return AuctionRecord(
            auction_id=row["auction_id"],
            config=config,
            state=AuctionState(row["state"]),
            deadlines={
                "commit": row["commit_deadline"],
                "prove": row["prove_deadline"],
                "reveal": row["reveal_deadline"],
            },
            organizer_digest=row["organizer_digest"],
            bidders=[_bidder_state(b) for b in bidder_rows],
        )

    def save(self, record: AuctionRecord) -> None:
        """Store a new auction, or bring a stored one up to date with the record."""
        config = record.config
        self._db.execute(
            _UPSERT_AUCTION,
            {
                "auction_id": record.auction_id,
                "item_name": config.item_name,
                "min_bid": config.min_bid,
                "max_bid": config.max_bid,
                "commit_seconds": config.commit_seconds,
                "prove_seconds": config.prove_seconds,
                "reveal_seconds": config.reveal_seconds,
                "state": record.state.value,
                "commit_deadline": record.deadlines["commit"],
                "prove_deadline": record.deadlines["prove"],
                "reveal_deadline": record.deadlines["reveal"],
                "organizer_digest": record.organizer_digest,
            },
        )
        self._db.executemany(
            _UPSERT_BIDDER,
            [_bidder_row(record.auction_id, i, b) for i, b in enumerate(record.bidders)],
        )

    def delete(self, auction_id: str) -> None:
        self._db.execute("DELETE FROM auctions WHERE auction_id = ?", (auction_id,))

    def count_running(self, now: float) -> int:
        """How many auctions have neither finished nor passed their reveal deadline."""
        (count,) = self._db.execute(
            "SELECT COUNT(*) FROM auctions WHERE state != 'finished' AND reveal_deadline > ?",
            (now,),
        ).fetchone()
        return int(count)


class AuctionStore:
    """Auctions in an SQLite database file, created on first use."""

    def __init__(self, database: str | PathLike[str]) -> None:
        if str(database) == ":memory:":
            # Every operation opens its own connection, and each connection
            # to ":memory:" would see a new, empty database.
            raise ValueError("The auction store needs a database file, not ':memory:'.")
        self.database = Path(database)
        self._schema_ready = False

    @contextmanager
    def transaction(self) -> Iterator[Transaction]:
        """
        One transaction, holding the database's write lock throughout:
        committed if the block completes, rolled back if it raises.
        """
        self.database.parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None turns off the sqlite3 module's implicit
        # transactions, so the transaction is exactly BEGIN ... COMMIT below.
        with closing(sqlite3.connect(self.database, isolation_level=None)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")  # off by default, per connection
            db.execute("BEGIN IMMEDIATE")
            try:
                if not self._schema_ready:
                    self._create_schema(db)
                yield Transaction(db)
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")
            self._schema_ready = True  # only once the schema is surely committed

    def _create_schema(self, db: sqlite3.Connection) -> None:
        """Create the tables in a new database; refuse one of an unknown schema version."""
        (version,) = db.execute("PRAGMA user_version").fetchone()
        if version == SCHEMA_VERSION:
            return
        if version != 0:
            raise RuntimeError(
                f"{self.database} has schema version {version}; "
                f"this version of the app supports only {SCHEMA_VERSION}."
            )
        for statement in _SCHEMA:
            db.execute(statement)
        db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
