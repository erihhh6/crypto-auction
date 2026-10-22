"""Tests for crypto_auction.store (SQLite storage) and for the service running on it."""

import sqlite3
import threading
import unittest
from contextlib import closing

from crypto_auction.auction import Auction, AuctionConfig, AuctionState
from crypto_auction.pedersen import N, commit, encode_point
from crypto_auction.range_proof import prove_range
from crypto_auction.service import AuctionService
from crypto_auction.store import SCHEMA_VERSION, AuctionStore
from tests.support import FakeClock, temporary_database


def config(names=("Alice", "Bob", "Carol")):
    return AuctionConfig(
        min_bid=100,
        max_bid=5000,
        item_name="Test Item",
        bidder_names=tuple(names),
        commit_seconds=60,
        prove_seconds=60,
        reveal_seconds=60,
    )


def query(database, sql):
    with closing(sqlite3.connect(database)) as db:
        return db.execute(sql).fetchall()


class TestRoundTrip(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.store = AuctionStore(temporary_database(self))

    def reload(self, auction):
        """Store the auction and load it back, as the next request would."""
        with self.store.transaction() as tx:
            tx.save(auction.to_record())
        with self.store.transaction() as tx:
            record = tx.load(auction.auction_id)
        self.assertEqual(record, auction.to_record())
        return Auction.from_record(record, clock=self.clock)

    def test_an_auction_survives_every_phase_unchanged(self):
        # Every kind of value along the way: token digests, a missed
        # deadline, proofs (JSON), booleans, and a revealed blinding factor
        # (a scalar far beyond SQLite's 64-bit integers).
        auction = Auction(config(), clock=self.clock)
        auction.issue_organizer_token()
        auction.issue_join_tokens()
        auction = self.reload(auction)

        openings = {"bidder_0": commit(1200), "bidder_1": commit(1800)}
        for bidder_id, c in openings.items():
            auction.submit_commitment(bidder_id, encode_point(c.point))
            auction = self.reload(auction)
        self.clock.advance(60)  # Carol misses the commit deadline
        auction.get_public_state()
        auction = self.reload(auction)
        self.assertEqual(auction.state, AuctionState.COMMITTED)

        for bidder_id, c in openings.items():
            context = auction.proof_context(bidder_id)
            proof = prove_range(c.point, c.value, c.blinding, 100, 5000, context).to_dict()
            auction.submit_proof(bidder_id, proof)
            auction = self.reload(auction)

        big = openings["bidder_1"]
        self.assertGreater(big.blinding, 2**63)  # all but certain for a random scalar < n
        for bidder_id, c in openings.items():
            auction.submit_reveal(bidder_id, c.value, c.blinding)
            auction = self.reload(auction)

        self.assertEqual(auction.state, AuctionState.FINISHED)
        self.assertEqual(auction.get_winner().name, "Bob")
        self.assertEqual(auction.bidders["bidder_1"].revealed_blinding, big.blinding)
        self.assertLess(big.blinding, N)

    def test_a_failed_transaction_stores_nothing(self):
        auction = Auction(config(), clock=self.clock)
        with self.assertRaises(RuntimeError), self.store.transaction() as tx:
            tx.save(auction.to_record())
            raise RuntimeError("the operation failed")
        with self.store.transaction() as tx:
            self.assertIsNone(tx.load(auction.auction_id))

    def test_deleting_an_auction_deletes_its_bidders(self):
        auction = Auction(config(), clock=self.clock)
        with self.store.transaction() as tx:
            tx.save(auction.to_record())
        with self.store.transaction() as tx:
            tx.delete(auction.auction_id)
        self.assertEqual(query(self.store.database, "SELECT COUNT(*) FROM bidders"), [(0,)])


class TestSchema(unittest.TestCase):
    def test_a_new_database_gets_the_current_schema(self):
        database = temporary_database(self)
        with AuctionStore(database).transaction() as tx:
            self.assertIsNone(tx.load("none"))
        self.assertEqual(query(database, "PRAGMA user_version"), [(SCHEMA_VERSION,)])

    def test_a_database_of_a_newer_schema_is_refused(self):
        database = temporary_database(self)
        with closing(sqlite3.connect(database)) as db:
            db.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
        with (
            self.assertRaisesRegex(RuntimeError, "schema version"),
            AuctionStore(database).transaction(),
        ):
            pass

    def test_an_in_memory_database_is_refused(self):
        # Each operation opens its own connection, which would see an empty one.
        with self.assertRaises(ValueError):
            AuctionStore(":memory:")


class TestServiceOnTheDatabase(unittest.TestCase):
    def test_auctions_and_tokens_survive_a_restart(self):
        database, clock = temporary_database(self), FakeClock()
        created = AuctionService(database, clock=clock).create(config())
        alice = created.join_tokens["bidder_0"]
        auction_id = created.auction.auction_id

        restarted = AuctionService(database, clock=clock)
        restarted.commit(auction_id, alice, encode_point(commit(1200).point))
        state = restarted.public_state(auction_id)
        self.assertIsNotNone(state["bidders"][0]["commitment_hex"])
        restarted.delete(auction_id, created.organizer_token)

    def test_concurrent_requests_lose_no_update(self):
        # Every bidder commits at the same moment, each through a service of
        # its own, as separate server processes would. Each request reads the
        # auction and writes it back; without the write lock taken up front,
        # requests would overwrite each other's commitments or fail.
        database, clock = temporary_database(self), FakeClock()
        names = [f"Bidder {i}" for i in range(10)]
        created = AuctionService(database, clock=clock).create(config(names))
        auction_id = created.auction.auction_id
        start = threading.Barrier(len(names))
        errors = []

        def commit_as(token):
            service = AuctionService(database, clock=clock)
            start.wait()
            try:
                service.commit(auction_id, token, encode_point(commit(1000).point))
            except Exception as exc:  # reported below, with every other failure
                errors.append(exc)

        threads = [
            threading.Thread(target=commit_as, args=(token,))
            for token in created.join_tokens.values()
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        state = AuctionService(database, clock=clock).public_state(auction_id)
        self.assertEqual(state["state"], "committed")
        orders = sorted(b["commit_order"] for b in state["bidders"])
        self.assertEqual(orders, list(range(len(names))))


if __name__ == "__main__":
    unittest.main()
