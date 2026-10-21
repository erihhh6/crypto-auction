"""Tests for crypto/auction.py — state machine and auction logic."""

import unittest
from dataclasses import asdict

from crypto.auction import Auction, AuctionConfig, AuctionState
from crypto.commitment import commit
from crypto.zkp import prove_range
from tests.support import forged_range_proof, known_bug


def make_auction(bidder_names=None, min_bid=100, max_bid=5000):
    if bidder_names is None:
        bidder_names = ["Alice", "Bob", "Carol"]
    config = AuctionConfig(
        min_bid=min_bid, max_bid=max_bid, item_name="Test Item", bidder_names=bidder_names
    )
    return Auction(config)


def _proof_dict(bid, randomness_hex, commitment_hex, min_bid, max_bid):
    proof = prove_range(bid, randomness_hex, commitment_hex, min_bid, max_bid)
    return {
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

    @known_bug("submit_proof never checks that the proof is about this bidder's commitment")
    def test_proof_for_another_commitment_is_invalid(self):
        auction, _ = self._committed_auction()
        other = commit(2000)
        pd = _proof_dict(2000, other.randomness_hex, other.commitment_hex, 100, 5000)
        self.assertFalse(auction.submit_proof("bidder_0", pd)["proof_valid"])

    @known_bug("submit_proof never checks that the proof's range is the auction's range")
    def test_proof_for_another_range_is_invalid(self):
        auction, secrets = self._committed_auction()
        s = secrets["bidder_0"]
        pd = _proof_dict(s["bid"], s["randomness_hex"], s["commitment_hex"], 0, 10**9)
        self.assertFalse(auction.submit_proof("bidder_0", pd)["proof_valid"])


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

    def test_tie_won_by_first_in_list(self):
        auction = run_full_auction({"Alice": 1000, "Bob": 1000})
        winner = auction.get_winner()
        self.assertEqual(winner["name"], "Alice")

    @known_bug("ties go to the earlier name in the bidder list, not the earliest commitment")
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

    @known_bug("a bid outside [min, max] can win: proofs are forgeable and reveal never rechecks")
    def test_out_of_range_bid_cannot_win(self):
        auction = make_auction(["Alice", "Mallory"])
        alice, mallory = commit(4000), commit(999_999)
        auction.submit_commitment("bidder_0", alice.commitment_hex)
        auction.submit_commitment("bidder_1", mallory.commitment_hex)
        pd = _proof_dict(4000, alice.randomness_hex, alice.commitment_hex, 100, 5000)
        auction.submit_proof("bidder_0", pd)
        forged = forged_range_proof(mallory.commitment_hex, 100, 5000)
        auction.submit_proof("bidder_1", asdict(forged))
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
