"""Tests for crypto_auction.auction — state machine and auction logic."""

import unittest

from crypto_auction.auction import Auction, AuctionConfig, AuctionState
from crypto_auction.commitment import commit
from crypto_auction.zkp import prove_range
from tests.support import forged_range_proof


def make_auction(bidder_names=None, min_bid=100, max_bid=5000):
    if bidder_names is None:
        bidder_names = ["Alice", "Bob", "Carol"]
    config = AuctionConfig(
        min_bid=min_bid, max_bid=max_bid, item_name="Test Item", bidder_names=bidder_names
    )
    return Auction(config)


def _proof_dict(bid, randomness_hex, commitment_hex, min_bid, max_bid):
    return prove_range(bid, randomness_hex, commitment_hex, min_bid, max_bid).to_dict()


def run_full_auction(bids_map, min_bid=100, max_bid=5000):
    """Helper: run a complete 3-phase auction. bids_map = {name: bid}."""
    names = list(bids_map.keys())
    auction = make_auction(names, min_bid, max_bid)
    secrets = {}

    for bidder_id, b in auction.bidders.items():
        bid = bids_map[b.name]
        c = commit(bid)
        secrets[bidder_id] = {
            "bid": bid,
            "randomness_hex": c.randomness_hex,
            "commitment_hex": c.commitment_hex,
        }
        auction.submit_commitment(bidder_id, c.commitment_hex)

    for bidder_id, s in secrets.items():
        pd = _proof_dict(s["bid"], s["randomness_hex"], s["commitment_hex"], min_bid, max_bid)
        auction.submit_proof(bidder_id, pd)

    for bidder_id, s in secrets.items():
        auction.submit_reveal(bidder_id, s["bid"], s["randomness_hex"])

    return auction


class TestAuctionInit(unittest.TestCase):
    def test_initial_state_is_open(self):
        auction = make_auction()
        self.assertEqual(auction.state, AuctionState.OPEN)

    def test_bidder_ids_generated(self):
        auction = make_auction(["Alice", "Bob"])
        self.assertIn("bidder_0", auction.bidders)
        self.assertIn("bidder_1", auction.bidders)

    def test_bidder_names_stored(self):
        auction = make_auction(["Alice", "Bob"])
        self.assertEqual(auction.bidders["bidder_0"].name, "Alice")
        self.assertEqual(auction.bidders["bidder_1"].name, "Bob")


class TestPhase1Commit(unittest.TestCase):
    def test_commit_advances_to_committed_when_all_done(self):
        auction = make_auction(["Alice", "Bob"])
        c0 = commit(1000)
        c1 = commit(2000)
        auction.submit_commitment("bidder_0", c0.commitment_hex)
        self.assertEqual(auction.state, AuctionState.OPEN)
        auction.submit_commitment("bidder_1", c1.commitment_hex)
        self.assertEqual(auction.state, AuctionState.COMMITTED)

    def test_double_commit_raises(self):
        auction = make_auction(["Alice", "Bob"])
        c = commit(1000)
        auction.submit_commitment("bidder_0", c.commitment_hex)
        with self.assertRaises(ValueError):
            auction.submit_commitment("bidder_0", c.commitment_hex)

    def test_unknown_bidder_raises(self):
        auction = make_auction(["Alice"])
        with self.assertRaises(ValueError):
            auction.submit_commitment("bidder_99", "a" * 64)

    def test_commit_in_wrong_state_raises(self):
        auction = run_full_auction({"Alice": 500, "Bob": 1000})
        with self.assertRaises(ValueError):
            auction.submit_commitment("bidder_0", "a" * 64)


class TestPhase2Prove(unittest.TestCase):
    def _committed_auction(self):
        auction = make_auction(["Alice", "Bob"])
        secrets = {}
        for bidder_id, b in auction.bidders.items():
            bid = 1000 if b.name == "Alice" else 2000
            c = commit(bid)
            secrets[bidder_id] = {
                "bid": bid,
                "randomness_hex": c.randomness_hex,
                "commitment_hex": c.commitment_hex,
            }
            auction.submit_commitment(bidder_id, c.commitment_hex)
        return auction, secrets

    def test_prove_advances_to_proved_when_all_done(self):
        auction, secrets = self._committed_auction()
        for bidder_id, s in secrets.items():
            pd = _proof_dict(s["bid"], s["randomness_hex"], s["commitment_hex"], 100, 5000)
            auction.submit_proof(bidder_id, pd)
        self.assertEqual(auction.state, AuctionState.PROVED)

    def test_prove_before_commit_raises(self):
        auction = make_auction(["Alice", "Bob"])
        with self.assertRaises(ValueError):
            auction.submit_proof("bidder_0", {})

    def test_double_prove_raises(self):
        auction, secrets = self._committed_auction()
        s = secrets["bidder_0"]
        pd = _proof_dict(s["bid"], s["randomness_hex"], s["commitment_hex"], 100, 5000)
        auction.submit_proof("bidder_0", pd)
        with self.assertRaises(ValueError):
            auction.submit_proof("bidder_0", pd)

    def test_invalid_proof_dict_marks_invalid(self):
        auction, _ = self._committed_auction()
        result = auction.submit_proof("bidder_0", {"bad": "data"})
        self.assertFalse(result["proof_valid"])

    def test_proof_for_another_commitment_is_invalid(self):
        auction, _ = self._committed_auction()
        other = commit(2000)
        pd = _proof_dict(2000, other.randomness_hex, other.commitment_hex, 100, 5000)
        self.assertFalse(auction.submit_proof("bidder_0", pd)["proof_valid"])

    def test_proof_for_another_range_is_invalid(self):
        auction, secrets = self._committed_auction()
        # One bound differs per case, each on its own bidder, so a missing check
        # on either bound is caught on its own.
        for bidder_id, bounds in (("bidder_0", (0, 5000)), ("bidder_1", (100, 10**9))):
            s = secrets[bidder_id]
            pd = _proof_dict(s["bid"], s["randomness_hex"], s["commitment_hex"], *bounds)
            self.assertFalse(auction.submit_proof(bidder_id, pd)["proof_valid"], bounds)


class TestPhase3Reveal(unittest.TestCase):
    def test_highest_bid_wins(self):
        auction = run_full_auction({"Alice": 1200, "Bob": 1800, "Carol": 1500})
        winner = auction.get_winner()
        self.assertEqual(winner["name"], "Bob")
        self.assertEqual(winner["bid"], 1800)

    def test_state_is_finished_after_all_reveal(self):
        auction = run_full_auction({"Alice": 1000, "Bob": 2000})
        self.assertEqual(auction.state, AuctionState.FINISHED)

    def test_cheater_excluded_from_winner(self):
        auction = make_auction(["Alice", "Bob"], 100, 5000)
        secrets = {}
        for bidder_id, b in auction.bidders.items():
            bid = 1000 if b.name == "Alice" else 500
            c = commit(bid)
            secrets[bidder_id] = {
                "bid": bid,
                "randomness_hex": c.randomness_hex,
                "commitment_hex": c.commitment_hex,
            }
            auction.submit_commitment(bidder_id, c.commitment_hex)

        for bidder_id, s in secrets.items():
            pd = _proof_dict(s["bid"], s["randomness_hex"], s["commitment_hex"], 100, 5000)
            auction.submit_proof(bidder_id, pd)

        # Alice reveals correctly
        s_alice = secrets["bidder_0"]
        auction.submit_reveal("bidder_0", s_alice["bid"], s_alice["randomness_hex"])

        # Bob cheats — reveals a different (higher) bid
        s_bob = secrets["bidder_1"]
        auction.submit_reveal("bidder_1", 9999, s_bob["randomness_hex"])

        winner = auction.get_winner()
        self.assertEqual(winner["name"], "Alice")  # Bob disqualified

    def test_double_reveal_raises(self):
        auction = make_auction(["Alice", "Bob"], 100, 5000)
        secrets = {}
        for bidder_id in auction.bidders:
            bid = 1000
            c = commit(bid)
            secrets[bidder_id] = {
                "bid": bid,
                "randomness_hex": c.randomness_hex,
                "commitment_hex": c.commitment_hex,
            }
            auction.submit_commitment(bidder_id, c.commitment_hex)
        for bidder_id, s in secrets.items():
            pd = _proof_dict(s["bid"], s["randomness_hex"], s["commitment_hex"], 100, 5000)
            auction.submit_proof(bidder_id, pd)
        s = secrets["bidder_0"]
        auction.submit_reveal("bidder_0", s["bid"], s["randomness_hex"])
        with self.assertRaises(ValueError):
            auction.submit_reveal("bidder_0", s["bid"], s["randomness_hex"])

    def test_reveal_before_prove_raises(self):
        auction = make_auction(["Alice", "Bob"], 100, 5000)
        c = commit(1000)
        auction.submit_commitment("bidder_0", c.commitment_hex)
        with self.assertRaises(ValueError):
            auction.submit_reveal("bidder_0", 1000, c.randomness_hex)

    def test_tie_won_by_earliest_commitment(self):
        auction = make_auction(["Alice", "Bob"])
        alice, bob = commit(1000), commit(1000)
        auction.submit_commitment("bidder_1", bob.commitment_hex)  # Bob commits first
        auction.submit_commitment("bidder_0", alice.commitment_hex)
        for bidder_id, c in (("bidder_0", alice), ("bidder_1", bob)):
            pd = _proof_dict(1000, c.randomness_hex, c.commitment_hex, 100, 5000)
            auction.submit_proof(bidder_id, pd)
        for bidder_id, c in (("bidder_0", alice), ("bidder_1", bob)):
            auction.submit_reveal(bidder_id, 1000, c.randomness_hex)
        self.assertEqual(auction.get_winner()["name"], "Bob")

    def test_bidder_with_invalid_proof_cannot_win(self):
        auction = make_auction(["Alice", "Bob"])
        alice, bob = commit(1000), commit(3000)
        auction.submit_commitment("bidder_0", alice.commitment_hex)
        auction.submit_commitment("bidder_1", bob.commitment_hex)
        pd = _proof_dict(1000, alice.randomness_hex, alice.commitment_hex, 100, 5000)
        auction.submit_proof("bidder_0", pd)
        auction.submit_proof("bidder_1", {"bad": "data"})  # recorded as proof_valid=False
        auction.submit_reveal("bidder_0", 1000, alice.randomness_hex)
        auction.submit_reveal("bidder_1", 3000, bob.randomness_hex)
        self.assertEqual(auction.get_winner()["name"], "Alice")

    def test_no_winner_when_no_bidder_is_eligible(self):
        auction = make_auction(["Alice", "Bob"])
        openings = {"bidder_0": commit(1000), "bidder_1": commit(3000)}
        for bidder_id, c in openings.items():
            auction.submit_commitment(bidder_id, c.commitment_hex)
        for bidder_id in openings:
            auction.submit_proof(bidder_id, {"bad": "data"})
        for bidder_id, bid in (("bidder_0", 1000), ("bidder_1", 3000)):
            result = auction.submit_reveal(bidder_id, bid, openings[bidder_id].randomness_hex)
        self.assertEqual(auction.state, AuctionState.FINISHED)
        self.assertIsNone(result["winner"])
        self.assertIsNone(auction.get_public_state()["winner"])

    def test_out_of_range_bid_cannot_win(self):
        auction = make_auction(["Alice", "Mallory"])
        alice, mallory = commit(4000), commit(999_999)
        auction.submit_commitment("bidder_0", alice.commitment_hex)
        auction.submit_commitment("bidder_1", mallory.commitment_hex)
        pd = _proof_dict(4000, alice.randomness_hex, alice.commitment_hex, 100, 5000)
        auction.submit_proof("bidder_0", pd)
        forged = forged_range_proof(mallory.commitment_hex, 100, 5000)
        auction.submit_proof("bidder_1", forged.to_dict())
        auction.submit_reveal("bidder_0", 4000, alice.randomness_hex)
        auction.submit_reveal("bidder_1", 999_999, mallory.randomness_hex)
        self.assertEqual(auction.get_winner()["name"], "Alice")


class TestPublicState(unittest.TestCase):
    def test_bids_hidden_before_reveal(self):
        auction = make_auction(["Alice", "Bob"], 100, 5000)
        for bidder_id in auction.bidders:
            c = commit(1000)
            auction.submit_commitment(bidder_id, c.commitment_hex)
        state = auction.get_public_state()
        for b in state["bidders"]:
            self.assertNotIn("revealed_bid", b)

    def test_bids_hidden_until_every_bidder_revealed(self):
        # Otherwise a bidder who has not revealed yet could see the others'
        # bids and withhold their own if losing (selective abort).
        auction = make_auction(["Alice", "Bob"])
        openings = {"bidder_0": (1200, commit(1200)), "bidder_1": (800, commit(800))}
        for bidder_id, (_, c) in openings.items():
            auction.submit_commitment(bidder_id, c.commitment_hex)
        for bidder_id, (bid, c) in openings.items():
            auction.submit_proof(
                bidder_id, _proof_dict(bid, c.randomness_hex, c.commitment_hex, 100, 5000)
            )
        auction.submit_reveal("bidder_0", 1200, openings["bidder_0"][1].randomness_hex)
        for b in auction.get_public_state()["bidders"]:
            self.assertNotIn("revealed_bid", b)
            self.assertNotIn("randomness_hex", b)

    def test_commit_order_is_public(self):
        auction = make_auction(["Alice", "Bob"])
        auction.submit_commitment("bidder_1", commit(1000).commitment_hex)  # Bob first
        auction.submit_commitment("bidder_0", commit(1000).commitment_hex)
        orders = {b["name"]: b["commit_order"] for b in auction.get_public_state()["bidders"]}
        self.assertEqual(orders, {"Alice": 1, "Bob": 0})

    def test_bids_visible_after_reveal(self):
        auction = run_full_auction({"Alice": 1200, "Bob": 800})
        state = auction.get_public_state()
        for b in state["bidders"]:
            self.assertIn("revealed_bid", b)

    def test_winner_in_public_state(self):
        auction = run_full_auction({"Alice": 1200, "Bob": 800})
        state = auction.get_public_state()
        self.assertIsNotNone(state["winner"])
        self.assertEqual(state["winner"]["name"], "Alice")


if __name__ == "__main__":
    unittest.main()
