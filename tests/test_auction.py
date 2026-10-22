"""Tests for crypto_auction.auction — state machine and auction logic."""

import unittest
from datetime import datetime
from unittest import mock

from crypto_auction.auction import Auction, AuctionConfig, AuctionState
from crypto_auction.pedersen import N, commit, decode_point, decode_scalar, encode_point, verify
from crypto_auction.range_proof import prove_range
from tests.support import FakeClock


def make_auction(bidder_names=None, min_bid=100, max_bid=5000, **kwargs):
    """An auction; kwargs go to Auction (clock) or AuctionConfig (window lengths)."""
    if bidder_names is None:
        bidder_names = ["Alice", "Bob", "Carol"]
    clock = kwargs.pop("clock", None)
    config = AuctionConfig(
        min_bid=min_bid,
        max_bid=max_bid,
        item_name="Test Item",
        bidder_names=tuple(bidder_names),
        **kwargs,
    )
    return Auction(config) if clock is None else Auction(config, clock=clock)


def submit_commit(auction, bidder_id, c):
    return auction.submit_commitment(bidder_id, encode_point(c.point))


def proof_for(auction, bidder_id, c, *, bounds=None, context=None):
    """An honest range proof of commitment c, by default for this auction and bidder."""
    min_bid, max_bid = bounds or (auction.config.min_bid, auction.config.max_bid)
    if context is None:
        context = auction.proof_context(bidder_id)
    return prove_range(c.point, c.value, c.blinding, min_bid, max_bid, context).to_dict()


def committed_auction(bids, **kwargs):
    """An auction where every bidder committed; bids = {name: bid}."""
    auction = make_auction(list(bids), **kwargs)
    openings = {}
    for bidder_id, b in auction.bidders.items():
        openings[bidder_id] = commit(bids[b.name])
        submit_commit(auction, bidder_id, openings[bidder_id])
    return auction, openings


def proved_auction(bids, **kwargs):
    auction, openings = committed_auction(bids, **kwargs)
    for bidder_id, c in openings.items():
        auction.submit_proof(bidder_id, proof_for(auction, bidder_id, c))
    return auction, openings


def run_full_auction(bids):
    auction, openings = proved_auction(bids)
    for bidder_id, c in openings.items():
        auction.submit_reveal(bidder_id, c.value, c.blinding)
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

    def test_each_auction_gets_its_own_random_id(self):
        first, second = make_auction(), make_auction()
        self.assertRegex(first.auction_id, r"^[0-9a-f]{32}$")
        self.assertNotEqual(first.auction_id, second.auction_id)


class TestBidderIdentity(unittest.TestCase):
    def test_each_token_authenticates_its_own_bidder(self):
        auction = make_auction()
        tokens = auction.issue_join_tokens()
        self.assertEqual(set(tokens), set(auction.bidders))
        for bidder_id, token in tokens.items():
            self.assertEqual(auction.authenticate(token), bidder_id)

    def test_anything_else_authenticates_nobody(self):
        auction = make_auction()
        token = auction.issue_join_tokens()["bidder_0"]
        guesses = {
            "empty": "",
            "a bidder id": "bidder_0",
            "a prefix of a token": token[:-1],
            "another auction's token": make_auction().issue_join_tokens()["bidder_0"],
        }
        for label, guess in guesses.items():
            with self.subTest(label):
                self.assertIsNone(auction.authenticate(guess))
        # Before tokens are issued, not even a real one from elsewhere works.
        self.assertIsNone(make_auction().authenticate(token))

    def test_auction_keeps_only_token_digests(self):
        auction = make_auction()
        tokens = auction.issue_join_tokens()
        # Everything the auction holds, including each BidderState.
        held = repr(vars(auction)) + repr(auction.get_public_state())
        for token in tokens.values():
            self.assertNotIn(token, held)


WINDOW = 60  # seconds per step in the deadline tests
BIDS = {"Alice": 1200, "Bob": 1800, "Carol": 1500}  # Bob bids highest, then Carol


def timed(**kwargs):
    """Arguments for an auction on a fake clock, with WINDOW-second steps."""
    clock = FakeClock()
    windows = {f"{s}_seconds": WINDOW for s in ("commit", "prove", "reveal")}
    return clock, {"clock": clock, **windows, **kwargs}


class TestDeadlines(unittest.TestCase):
    def test_windows_follow_one_another_from_creation(self):
        _, kwargs = timed(commit_seconds=60, prove_seconds=120, reveal_seconds=30)
        auction = make_auction(**kwargs)
        start = FakeClock.START
        self.assertEqual(
            auction.deadlines,
            {"commit": start + 60, "prove": start + 180, "reveal": start + 210},
        )

    def test_a_commitment_at_the_deadline_is_too_late(self):
        clock, kwargs = timed()
        auction = make_auction(**kwargs)
        clock.advance(WINDOW - 0.001)
        submit_commit(auction, "bidder_0", commit(1200))  # just in time
        clock.advance(0.001)
        with self.assertRaisesRegex(ValueError, "missed the commit deadline"):
            submit_commit(auction, "bidder_1", commit(1800))

    def test_bidders_who_miss_the_commit_deadline_take_no_further_part(self):
        clock, kwargs = timed()
        auction = make_auction(**kwargs)
        openings = {"bidder_0": commit(1200), "bidder_1": commit(1800)}
        for bidder_id, c in openings.items():
            submit_commit(auction, bidder_id, c)
        clock.advance(WINDOW)

        # The others move on to proving without Carol, who cannot catch up.
        self.assertEqual(auction.get_public_state()["state"], "committed")
        self.assertEqual(auction.bidders["bidder_2"].missed_deadline, "commit")
        with self.assertRaisesRegex(ValueError, "missed the commit deadline"):
            submit_commit(auction, "bidder_2", commit(1500))
        for bidder_id, c in openings.items():
            auction.submit_proof(bidder_id, proof_for(auction, bidder_id, c))
        for bidder_id, c in openings.items():
            auction.submit_reveal(bidder_id, c.value, c.blinding)

        self.assertEqual(auction.state, AuctionState.FINISHED)
        self.assertEqual(auction.get_winner().name, "Bob")

    def test_bidders_who_miss_the_prove_deadline_need_not_reveal(self):
        clock, kwargs = timed()
        auction, openings = committed_auction(BIDS, **kwargs)
        for bidder_id in ("bidder_0", "bidder_2"):  # Bob never proves
            auction.submit_proof(bidder_id, proof_for(auction, bidder_id, openings[bidder_id]))
        clock.advance(2 * WINDOW)

        bob = openings["bidder_1"]
        with self.assertRaisesRegex(ValueError, "missed the prove deadline"):
            auction.submit_reveal("bidder_1", bob.value, bob.blinding)
        # The auction finishes as soon as the others have revealed.
        for bidder_id in ("bidder_0", "bidder_2"):
            c = openings[bidder_id]
            auction.submit_reveal(bidder_id, c.value, c.blinding)
        self.assertEqual(auction.state, AuctionState.FINISHED)
        self.assertEqual(auction.get_winner().name, "Carol")

    def test_the_highest_bidder_forfeits_by_not_revealing(self):
        # Withholding a reveal no longer stalls the auction: once the reveal
        # deadline passes, the auction finishes without the silent bidder.
        clock, kwargs = timed()
        auction, openings = proved_auction(BIDS, **kwargs)
        for bidder_id in ("bidder_0", "bidder_2"):  # Bob stays silent
            c = openings[bidder_id]
            auction.submit_reveal(bidder_id, c.value, c.blinding)
        self.assertEqual(auction.state, AuctionState.PROVED)

        clock.advance(3 * WINDOW)
        state = auction.get_public_state()
        self.assertEqual(state["state"], "finished")
        self.assertEqual(state["winner"]["name"], "Carol")
        bob = state["bidders"][1]
        self.assertEqual(bob["missed_deadline"], "reveal")
        self.assertIsNone(bob["revealed_bid"])

    def test_nobody_committing_ends_the_auction_without_a_winner(self):
        clock, kwargs = timed()
        auction = make_auction(**kwargs)
        clock.advance(WINDOW)
        self.assertIsNone(auction.get_winner())
        self.assertEqual(auction.state, AuctionState.FINISHED)
        self.assertEqual({b.missed_deadline for b in auction.bidders.values()}, {"commit"})

    def test_one_query_passes_every_deadline_that_has_passed(self):
        clock, kwargs = timed()
        auction, _ = committed_auction(BIDS, **kwargs)  # then nobody proves
        clock.advance(10 * WINDOW)
        self.assertEqual(auction.get_public_state()["state"], "finished")
        self.assertEqual({b.missed_deadline for b in auction.bidders.values()}, {"prove"})

    def test_public_state_gives_deadlines_and_server_time_in_utc(self):
        clock, kwargs = timed()
        auction = make_auction(**kwargs)
        clock.advance(5)
        state = auction.get_public_state()

        def parse(text):
            self.assertTrue(text.endswith("+00:00"), text)  # UTC, with an explicit offset
            return datetime.fromisoformat(text).timestamp()

        self.assertEqual(parse(state["server_time"]), FakeClock.START + 5)
        deadlines = {step: parse(text) for step, text in state["deadlines"].items()}
        self.assertEqual(deadlines, auction.deadlines)
        self.assertEqual({b["missed_deadline"] for b in state["bidders"]}, {None})


class TestPhase1Commit(unittest.TestCase):
    def test_commit_advances_to_committed_when_all_done(self):
        auction = make_auction(["Alice", "Bob"])
        submit_commit(auction, "bidder_0", commit(1000))
        self.assertEqual(auction.state, AuctionState.OPEN)
        submit_commit(auction, "bidder_1", commit(2000))
        self.assertEqual(auction.state, AuctionState.COMMITTED)

    def test_double_commit_raises(self):
        auction = make_auction(["Alice", "Bob"])
        c = commit(1000)
        submit_commit(auction, "bidder_0", c)
        with self.assertRaises(ValueError):
            submit_commit(auction, "bidder_0", c)

    def test_copy_of_another_bidders_commitment_raises(self):
        auction = make_auction(["Alice", "Bob"])
        c = commit(1000)
        submit_commit(auction, "bidder_0", c)
        with self.assertRaises(ValueError):
            submit_commit(auction, "bidder_1", c)
        self.assertIsNone(auction.bidders["bidder_1"].commitment_hex)

    def test_unknown_bidder_raises(self):
        auction = make_auction(["Alice"])
        with self.assertRaises(ValueError):
            submit_commit(auction, "bidder_99", commit(1000))

    def test_commit_in_wrong_state_raises(self):
        auction = run_full_auction({"Alice": 500, "Bob": 1000})
        with self.assertRaises(ValueError):
            submit_commit(auction, "bidder_0", commit(1000))

    def test_rejects_malformed_or_non_canonical_commitments(self):
        auction = make_auction(["Alice", "Bob"])
        for bad in ("a" * 64, "02" + "05" * 32, "02" + "ff" * 32):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                auction.submit_commitment("bidder_0", bad)
        self.assertIsNone(auction.bidders["bidder_0"].commitment_hex)


PROVE_BIDS = {"Alice": 1000, "Bob": 2000}


class TestPhase2Prove(unittest.TestCase):
    def test_prove_advances_to_proved_when_all_done(self):
        auction, _ = proved_auction(PROVE_BIDS)
        self.assertEqual(auction.state, AuctionState.PROVED)

    def test_prove_before_commit_raises(self):
        auction = make_auction(["Alice", "Bob"])
        with self.assertRaises(ValueError):
            auction.submit_proof("bidder_0", {})

    def test_unknown_bidder_raises(self):
        auction, _ = committed_auction(PROVE_BIDS)
        with self.assertRaises(ValueError):
            auction.submit_proof("bidder_99", {})

    def test_double_prove_raises(self):
        auction, openings = committed_auction(PROVE_BIDS)
        proof = proof_for(auction, "bidder_0", openings["bidder_0"])
        auction.submit_proof("bidder_0", proof)
        with self.assertRaises(ValueError):
            auction.submit_proof("bidder_0", proof)

    def test_valid_proof_is_accepted(self):
        auction, openings = committed_auction(PROVE_BIDS)
        proof = proof_for(auction, "bidder_0", openings["bidder_0"])
        self.assertTrue(auction.submit_proof("bidder_0", proof).proof_valid)

    def test_invalid_proof_dict_marks_invalid(self):
        auction, _ = committed_auction(PROVE_BIDS)
        result = auction.submit_proof("bidder_0", {"bad": "data"})
        self.assertFalse(result.proof_valid)

    def test_proof_for_another_commitment_is_invalid(self):
        auction, _ = committed_auction(PROVE_BIDS)
        proof = proof_for(auction, "bidder_0", commit(2000))
        self.assertFalse(auction.submit_proof("bidder_0", proof).proof_valid)

    def test_proof_for_another_range_is_invalid(self):
        auction, openings = committed_auction(PROVE_BIDS)
        # One bound differs per case, each on its own bidder.
        for bidder_id, bounds in (("bidder_0", (0, 5000)), ("bidder_1", (100, 10**9))):
            proof = proof_for(auction, bidder_id, openings[bidder_id], bounds=bounds)
            self.assertFalse(auction.submit_proof(bidder_id, proof).proof_valid, bounds)

    def test_proof_made_for_another_bidder_is_invalid(self):
        auction, openings = committed_auction(PROVE_BIDS)
        context = auction.proof_context("bidder_1")
        proof = proof_for(auction, "bidder_0", openings["bidder_0"], context=context)
        self.assertFalse(auction.submit_proof("bidder_0", proof).proof_valid)

    def test_proof_replayed_from_another_auction_is_invalid(self):
        # Same commitment and range, but proven for a different auction.
        auction, openings = committed_auction(PROVE_BIDS)
        other_context = make_auction(["Alice", "Bob"]).proof_context("bidder_0")
        proof = proof_for(auction, "bidder_0", openings["bidder_0"], context=other_context)
        self.assertFalse(auction.submit_proof("bidder_0", proof).proof_valid)


class TestPhase3Reveal(unittest.TestCase):
    def test_highest_bid_wins(self):
        auction = run_full_auction({"Alice": 1200, "Bob": 1800, "Carol": 1500})
        winner = auction.get_winner()
        self.assertEqual(winner.name, "Bob")
        self.assertEqual(winner.bid, 1800)

    def test_state_is_finished_after_all_reveal(self):
        auction = run_full_auction({"Alice": 1000, "Bob": 2000})
        self.assertEqual(auction.state, AuctionState.FINISHED)

    def test_unknown_bidder_raises(self):
        auction, openings = proved_auction(PROVE_BIDS)
        c = openings["bidder_0"]
        with self.assertRaises(ValueError):
            auction.submit_reveal("bidder_99", c.value, c.blinding)

    def test_cheater_excluded_from_winner(self):
        auction, openings = proved_auction({"Alice": 1000, "Bob": 500})
        alice, bob = openings["bidder_0"], openings["bidder_1"]
        auction.submit_reveal("bidder_0", alice.value, alice.blinding)
        # Bob cheats: he opens his commitment to a higher bid than he committed to.
        result = auction.submit_reveal("bidder_1", 4999, bob.blinding)
        self.assertFalse(result.verified)
        self.assertEqual(auction.get_winner().name, "Alice")

    def test_double_reveal_raises(self):
        auction, openings = proved_auction({"Alice": 1000, "Bob": 1000})
        c = openings["bidder_0"]
        auction.submit_reveal("bidder_0", c.value, c.blinding)
        with self.assertRaises(ValueError):
            auction.submit_reveal("bidder_0", c.value, c.blinding)

    def test_reveal_before_prove_raises(self):
        auction = make_auction(["Alice", "Bob"])
        c = commit(1000)
        submit_commit(auction, "bidder_0", c)
        with self.assertRaises(ValueError):
            auction.submit_reveal("bidder_0", 1000, c.blinding)

    def test_malformed_blinding_is_rejected_not_counted_as_cheating(self):
        auction, openings = proved_auction({"Alice": 1000, "Bob": 2000})
        c = openings["bidder_0"]
        for bad in (-1, N, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                auction.submit_reveal("bidder_0", c.value, bad)
        self.assertTrue(auction.submit_reveal("bidder_0", c.value, c.blinding).verified)

    def test_tie_won_by_earliest_commitment(self):
        auction = make_auction(["Alice", "Bob"])
        alice, bob = commit(1000), commit(1000)
        submit_commit(auction, "bidder_1", bob)  # Bob commits first
        submit_commit(auction, "bidder_0", alice)
        for bidder_id, c in (("bidder_0", alice), ("bidder_1", bob)):
            auction.submit_proof(bidder_id, proof_for(auction, bidder_id, c))
        for bidder_id, c in (("bidder_0", alice), ("bidder_1", bob)):
            auction.submit_reveal(bidder_id, c.value, c.blinding)
        self.assertEqual(auction.get_winner().name, "Bob")

    def test_bidder_with_invalid_proof_cannot_win(self):
        auction, openings = committed_auction({"Alice": 1000, "Bob": 3000})
        auction.submit_proof("bidder_0", proof_for(auction, "bidder_0", openings["bidder_0"]))
        auction.submit_proof("bidder_1", {"bad": "data"})  # recorded as proof_valid=False
        for bidder_id, c in openings.items():
            auction.submit_reveal(bidder_id, c.value, c.blinding)
        self.assertEqual(auction.get_winner().name, "Alice")

    def test_no_winner_when_no_bidder_is_eligible(self):
        auction, openings = committed_auction({"Alice": 1000, "Bob": 3000})
        for bidder_id in openings:
            auction.submit_proof(bidder_id, {"bad": "data"})
        for bidder_id, c in openings.items():
            result = auction.submit_reveal(bidder_id, c.value, c.blinding)
        self.assertEqual(auction.state, AuctionState.FINISHED)
        self.assertIsNone(result.winner)
        self.assertIsNone(auction.get_public_state()["winner"])

    def test_out_of_range_bid_cannot_win_even_if_proofs_were_broken(self):
        # No valid range proof exists for an out-of-range bid any more, so
        # simulate a broken proof system that accepts anything: the range check
        # on the revealed bid must still disqualify Mallory (defence in depth).
        auction, openings = committed_auction({"Alice": 4000, "Mallory": 999_999})
        alice = openings["bidder_0"]
        with mock.patch("crypto_auction.auction.verify_range", return_value=True):
            for bidder_id in openings:
                auction.submit_proof(bidder_id, proof_for(auction, "bidder_0", alice))
        self.assertTrue(auction.bidders["bidder_1"].proof_valid)
        for bidder_id, c in openings.items():
            auction.submit_reveal(bidder_id, c.value, c.blinding)
        self.assertEqual(auction.get_winner().name, "Alice")


class TestPublicState(unittest.TestCase):
    def test_bids_hidden_before_reveal(self):
        auction, _ = committed_auction({"Alice": 1000, "Bob": 1000})
        for b in auction.get_public_state()["bidders"]:
            self.assertNotIn("revealed_bid", b)

    def test_bids_hidden_until_every_bidder_revealed(self):
        # Otherwise a bidder who has not revealed yet could see the others'
        # bids and withhold their own if losing (selective abort).
        auction, openings = proved_auction({"Alice": 1200, "Bob": 800})
        alice = openings["bidder_0"]
        auction.submit_reveal("bidder_0", alice.value, alice.blinding)
        for b in auction.get_public_state()["bidders"]:
            self.assertNotIn("revealed_bid", b)
            self.assertNotIn("randomness_hex", b)

    def test_commit_order_is_public(self):
        auction = make_auction(["Alice", "Bob"])
        submit_commit(auction, "bidder_1", commit(1000))  # Bob first
        submit_commit(auction, "bidder_0", commit(1000))
        orders = {b["name"]: b["commit_order"] for b in auction.get_public_state()["bidders"]}
        self.assertEqual(orders, {"Alice": 1, "Bob": 0})

    def test_published_openings_let_anyone_audit_the_result(self):
        auction = run_full_auction({"Alice": 1200, "Bob": 800})
        state = auction.get_public_state()
        self.assertEqual(state["auction_id"], auction.auction_id)
        for b in state["bidders"]:
            point = decode_point(b["commitment_hex"])
            blinding = decode_scalar(b["randomness_hex"])
            self.assertTrue(verify(point, b["revealed_bid"], blinding), b["name"])

    def test_winner_in_public_state(self):
        auction = run_full_auction({"Alice": 1200, "Bob": 800})
        state = auction.get_public_state()
        self.assertEqual(state["winner"]["name"], "Alice")


if __name__ == "__main__":
    unittest.main()
