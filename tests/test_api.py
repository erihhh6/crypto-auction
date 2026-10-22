"""Tests for the REST API (crypto_auction.web), exercised through Flask's test client."""

import json
import os
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from crypto_auction.auction import Auction, bid_proof_context
from crypto_auction.pedersen import (
    N,
    commit,
    decode_point,
    decode_scalar,
    encode_point,
    encode_scalar,
    verify,
)
from crypto_auction.range_proof import prove_range
from crypto_auction.service import AuctionService
from crypto_auction.web import create_app
from crypto_auction.web.api import (
    MAX_JSON_INT,
    MAX_NAME_LENGTH,
    MAX_PHASE_SECONDS,
    MAX_REQUEST_BYTES,
    MIN_PHASE_SECONDS,
    SERVICE_KEY,
)
from tests.support import FakeClock, temporary_database

# bidder_0..2 are Alice, Bob and Carol in the default auction; Bob bids highest.
BIDS = {"bidder_0": 1200, "bidder_1": 1800, "bidder_2": 1500}
STEPS = ("commit", "prove", "reveal")
UNKNOWN_ID = "0" * 32


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def opening(secret):
    """What a bidder sends at the reveal: the bid and the blinding factor."""
    return {"bid": secret["bid"], "randomness_hex": secret["randomness_hex"]}


class ApiTestCase(unittest.TestCase):
    """Gives every test its own app, with no auctions yet, on a fake clock."""

    def setUp(self):
        self.clock = FakeClock()
        self.database = temporary_database(self)
        service = AuctionService(self.database, clock=self.clock)
        # TESTING lets unhandled exceptions propagate instead of becoming 500s.
        self.client = create_app({"TESTING": True}, service=service).test_client()

    def url(self, suffix=""):
        """The URL of the auction created last, or of one of its actions."""
        return f"/api/auctions/{self.auction_id}{suffix}"

    def post(self, path, **body):
        return self.client.post(path, json=body)

    def post_as(self, bidder_id, step, /, **body):
        """POST a step as a bidder, authenticated by their join token as the browser does."""
        headers = bearer(self.tokens[bidder_id])
        return self.client.post(self.url(f"/{step}"), json=body, headers=headers)

    def create(self, **overrides):
        """Create an auction; on success it becomes the one url() and post_as() address."""
        body = {
            "item_name": "Rare NFT #42",
            "min_bid": 100,
            "max_bid": 5000,
            "bidders": ["Alice", "Bob", "Carol"],
        }
        body.update(overrides)
        resp = self.post("/api/auctions", **body)
        if resp.status_code == 201:
            data = resp.get_json()
            self.auction_id = data["auction_id"]
            self.organizer_token = data["organizer_token"]
            self.tokens = {b["bidder_id"]: b["join_token"] for b in data["bidders"]}
        return resp

    def state(self):
        return self.client.get(self.url()).get_json()

    def assert_ok(self, resp, status=200):
        self.assertEqual(resp.status_code, status, resp.get_json())
        self.assertTrue(resp.get_json()["success"])
        return resp.get_json()

    def assert_created(self, resp):
        data = self.assert_ok(resp, 201)
        self.assertEqual(resp.headers["Location"], f"/api/auctions/{data['auction_id']}")
        return data

    def assert_error(self, resp, status=400):
        """Errors use the JSON envelope {"success": false, "error": "<reason>"}."""
        self.assertTrue(resp.is_json, f"expected a JSON error, got {resp.content_type}")
        self.assertEqual(resp.status_code, status, resp.get_json())
        body = resp.get_json()
        self.assertIs(body["success"], False)
        self.assertTrue(body["error"])
        return body

    def commit_all(self, bids=BIDS):
        """
        Commit every bid the way the browser does: compute C = bid·G + r·H
        locally and send only C. Returns the openings the bidders keep.
        """
        secrets = {}
        for bidder_id, bid in bids.items():
            c = commit(bid)
            commitment_hex = encode_point(c.point)
            self.assert_ok(self.post_as(bidder_id, "commit", commitment_hex=commitment_hex))
            secrets[bidder_id] = {
                "bid": bid,
                "randomness_hex": encode_scalar(c.blinding),
                "commitment_hex": commitment_hex,
            }
        return secrets

    def make_proof(self, bidder_id, secret, *, bounds=None, auction_id=None):
        """The range proof the browser computes; for this auction unless told otherwise."""
        state = self.state()
        min_bid, max_bid = bounds or (state["min_bid"], state["max_bid"])
        context = bid_proof_context(auction_id or state["auction_id"], bidder_id)
        return prove_range(
            decode_point(secret["commitment_hex"]),
            secret["bid"],
            decode_scalar(secret["randomness_hex"]),
            min_bid,
            max_bid,
            context,
        ).to_dict()

    def prove(self, bidder_id, secret, **kwargs):
        proof = self.make_proof(bidder_id, secret, **kwargs)
        return self.post_as(bidder_id, "prove", proof=proof)

    def prove_all(self, secrets):
        for bidder_id, secret in secrets.items():
            self.assert_ok(self.prove(bidder_id, secret))


class TestIndex(ApiTestCase):
    def test_serves_html_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.content_type)


class TestUnknownAuction(ApiTestCase):
    def test_every_auction_endpoint_returns_404(self):
        self.auction_id = UNKNOWN_ID
        requests = [("GET", ""), ("DELETE", "")] + [("POST", f"/{step}") for step in STEPS]
        for method, suffix in requests:
            with self.subTest(method=method, path=self.url(suffix)):
                resp = self.client.open(self.url(suffix), method=method, json={})
                self.assert_error(resp, 404)


class TestCreate(ApiTestCase):
    def test_returns_bidders_with_generated_ids(self):
        data = self.assert_created(self.create())
        self.assertEqual(data["item_name"], "Rare NFT #42")
        self.assertEqual((data["min_bid"], data["max_bid"]), (100, 5000))
        self.assertEqual(
            [(b["bidder_id"], b["name"]) for b in data["bidders"]],
            [("bidder_0", "Alice"), ("bidder_1", "Bob"), ("bidder_2", "Carol")],
        )

    def test_strips_whitespace_from_names(self):
        data = self.assert_created(self.create(item_name="  Watch  ", bidders=[" Alice ", "Bob\t"]))
        self.assertEqual(data["item_name"], "Watch")
        self.assertEqual([b["name"] for b in data["bidders"]], ["Alice", "Bob"])

    def test_rejects_missing_fields(self):
        for field in ("item_name", "min_bid", "max_bid", "bidders"):
            with self.subTest(field=field):
                body = {"item_name": "x", "min_bid": 1, "max_bid": 2, "bidders": ["A", "B"]}
                del body[field]
                self.assert_error(self.post("/api/auctions", **body))

    def test_rejects_non_integer_bounds(self):
        self.assert_error(self.create(min_bid="cheap"))
        self.assert_error(self.create(max_bid=None))

    def test_rejects_blank_item_name(self):
        self.assert_error(self.create(item_name="   "))

    def test_rejects_min_bid_not_below_max_bid(self):
        for min_bid, max_bid in ((5000, 5000), (5000, 100)):
            with self.subTest(min_bid=min_bid, max_bid=max_bid):
                self.assert_error(self.create(min_bid=min_bid, max_bid=max_bid))

    def test_bidder_count_limits(self):
        cases = {1: 400, 2: 201, 10: 201, 11: 400}
        for count, status in cases.items():
            with self.subTest(count=count):
                resp = self.create(bidders=[f"Bidder {i}" for i in range(count)])
                self.assertEqual(resp.status_code, status)

    def test_rejects_integers_javascript_cannot_represent_exactly(self):
        self.assert_error(self.create(max_bid=2**53))
        self.assert_created(self.create(max_bid=2**53 - 1))

    def test_rejects_negative_min_bid(self):
        self.assert_error(self.create(min_bid=-50))

    def test_rejects_float_and_bool_bounds(self):
        self.assert_error(self.create(min_bid=100.5))
        self.assert_error(self.create(min_bid=True))

    def test_rejects_bidders_that_are_not_a_list(self):
        # A string is iterable, so "AB" used to create bidders "A" and "B".
        self.assert_error(self.create(bidders="AB"))

    def test_rejects_non_string_bidder_names(self):
        self.assert_error(self.create(bidders=["Alice", 1]))
        self.assert_error(self.create(bidders=["Alice", None]))

    def test_rejects_blank_bidder_names(self):
        self.assert_error(self.create(bidders=["Alice", "   "]))

    def test_rejects_duplicate_bidder_names_ignoring_case(self):
        self.assert_error(self.create(bidders=["Alice", "Alice"]))
        self.assert_error(self.create(bidders=["Alice", "ALICE"]))

    def test_name_length_limit(self):
        longest = "x" * MAX_NAME_LENGTH
        self.assert_created(self.create(item_name=longest, bidders=[longest, "Bob"]))
        self.assert_error(self.create(item_name=longest + "x"))
        self.assert_error(self.create(bidders=[longest + "x", "Bob"]))


class TestSeveralAuctions(ApiTestCase):
    def test_auctions_run_independently(self):
        self.create(item_name="First")
        first, first_tokens = self.auction_id, self.tokens
        self.commit_all({"bidder_0": 1200})
        self.create(item_name="Second")
        self.assertNotEqual(self.auction_id, first)

        second = self.state()
        self.assertEqual(second["item_name"], "Second")
        self.assertTrue(all(b["commitment_hex"] is None for b in second["bidders"]))
        self.auction_id, self.tokens = first, first_tokens
        self.assertIsNotNone(self.state()["bidders"][0]["commitment_hex"])

    def test_tokens_work_only_in_their_own_auction(self):
        # Bidder ids repeat across auctions (bidder_0, ...); tokens do not.
        self.create()
        first_tokens, first_organizer = self.tokens, self.organizer_token
        self.create()
        body = {"commitment_hex": encode_point(commit(1200).point)}
        resp = self.client.post(
            self.url("/commit"), json=body, headers=bearer(first_tokens["bidder_0"])
        )
        self.assert_error(resp, 401)
        resp = self.client.delete(self.url(), headers=bearer(first_organizer))
        self.assert_error(resp, 401)

    def test_the_number_of_running_auctions_is_capped(self):
        service = AuctionService(self.database, clock=self.clock, max_auctions=2)
        self.client = create_app({"TESTING": True}, service=service).test_client()
        self.assert_created(self.create())
        self.assert_created(self.create(reveal_seconds=60))
        self.assert_error(self.create(), 503)
        # Deleting one makes room again.
        self.assert_ok(self.client.delete(self.url(), headers=bearer(self.organizer_token)))
        self.assert_created(self.create(reveal_seconds=60))
        self.assert_error(self.create(), 503)
        # So does an auction ending: this one's reveal deadline passes.
        self.clock.advance(1200 + 60)
        self.assert_created(self.create())


class TestState(ApiTestCase):
    def test_initial_state(self):
        self.create()
        state = self.state()
        self.assertEqual(state["state"], "open")
        self.assertIsNone(state["winner"])
        self.assertEqual(len(state["bidders"]), 3)

    def test_hides_bids_and_randomness_before_reveal(self):
        self.create()
        self.prove_all(self.commit_all())
        for bidder in self.state()["bidders"]:
            self.assertNotIn("revealed_bid", bidder)
            self.assertNotIn("randomness_hex", bidder)


class TestCommit(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.create()

    def test_server_receives_only_the_commitment(self):
        c = commit(1200)
        commitment_hex = encode_point(c.point)
        data = self.assert_ok(self.post_as("bidder_0", "commit", commitment_hex=commitment_hex))
        self.assertEqual(set(data), {"success", "phase", "message"})  # no secrets either way
        self.assertEqual(self.state()["bidders"][0]["commitment_hex"], commitment_hex)

    def test_rejects_double_commit(self):
        self.commit_all({"bidder_0": 1200})
        commitment_hex = encode_point(commit(1300).point)
        resp = self.post_as("bidder_0", "commit", commitment_hex=commitment_hex)
        self.assert_error(resp)

    def test_rejects_a_copy_of_another_bidders_commitment(self):
        alices = self.commit_all({"bidder_0": 1200})["bidder_0"]["commitment_hex"]
        self.assert_error(self.post_as("bidder_2", "commit", commitment_hex=alices))
        self.assertIsNone(self.state()["bidders"][2]["commitment_hex"])
        # Carol can still commit to a bid of her own.
        self.commit_all({"bidder_2": 1500})

    def test_rejects_malformed_commitments(self):
        cases = {
            "missing": None,
            "not a string": 12345,
            "old SHA-256 digest": "ab" * 32,
            "not hex": "02" + "zz" * 32,
            "not on the curve": "02" + "05" * 32,
            "non-canonical x >= p": "02" + "ff" * 32,
            "uppercase": encode_point(commit(1200).point).upper(),
        }
        for label, value in cases.items():
            with self.subTest(label):
                body = {} if value is None else {"commitment_hex": value}
                self.assert_error(self.post_as("bidder_0", "commit", **body))
        self.assertIsNone(self.state()["bidders"][0]["commitment_hex"])

    def test_phase_advances_once_everyone_committed(self):
        self.commit_all({"bidder_0": 1200, "bidder_1": 1800})
        self.assertEqual(self.state()["state"], "open")
        self.commit_all({"bidder_2": 1500})
        self.assertEqual(self.state()["state"], "committed")


class TestProve(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.create()

    def test_valid_proof_is_accepted(self):
        secrets = self.commit_all()
        data = self.assert_ok(self.prove("bidder_0", secrets["bidder_0"]))
        self.assertTrue(data["proof_valid"])
        self.assertTrue(self.state()["bidders"][0]["proof_valid"])

    def test_bids_on_the_bounds_prove_valid(self):
        secrets = self.commit_all({"bidder_0": 100, "bidder_1": 5000, "bidder_2": 1500})
        for bidder_id in ("bidder_0", "bidder_1"):
            with self.subTest(bidder_id=bidder_id):
                data = self.assert_ok(self.prove(bidder_id, secrets[bidder_id]))
                self.assertTrue(data["proof_valid"])

    def test_rejects_proof_before_everyone_committed(self):
        secrets = self.commit_all({"bidder_0": 1200})
        self.assert_error(self.prove("bidder_0", secrets["bidder_0"]))

    def test_malformed_proof_is_rejected_without_disqualifying(self):
        secrets = self.commit_all()
        valid = self.make_proof("bidder_0", secrets["bidder_0"])
        cases = {
            "missing": None,
            "not an object": "proof",
            "missing a side": {"low": valid["low"]},
            "malformed point": {
                **valid,
                "low": {**valid["low"], "bit_commitments": ["02" + "zz" * 32]},
            },
        }
        for label, proof in cases.items():
            with self.subTest(label):
                body = {} if proof is None else {"proof": proof}
                self.assert_error(self.post_as("bidder_0", "prove", **body))
        # Rejected before reaching the auction, so the bidder can still prove.
        self.assertTrue(self.assert_ok(self.prove("bidder_0", secrets["bidder_0"]))["proof_valid"])

    def test_proof_for_another_statement_is_recorded_invalid(self):
        secrets = self.commit_all()
        cases = {
            "bidder_0": {"bounds": (0, 10**9)},  # another range
            "bidder_1": {"auction_id": UNKNOWN_ID},  # another auction
        }
        for bidder_id, kwargs in cases.items():
            with self.subTest(**kwargs):
                data = self.assert_ok(self.prove(bidder_id, secrets[bidder_id], **kwargs))
                self.assertFalse(data["proof_valid"])

    def test_copied_proof_is_recorded_invalid(self):
        # Carol submits Alice's valid proof: it is about Alice's commitment and
        # bound to Alice's bidder id, so it says nothing about Carol's bid.
        secrets = self.commit_all()
        alices_proof = self.make_proof("bidder_0", secrets["bidder_0"])
        data = self.assert_ok(self.post_as("bidder_2", "prove", proof=alices_proof))
        self.assertFalse(data["proof_valid"])
        self.assertIsNone(self.state()["bidders"][0]["proof_valid"])  # Alice is unaffected

    def test_out_of_range_bid_cannot_get_a_valid_proof(self):
        # The server cannot reject the commitment (it never sees the bid), but
        # the bidder can neither prove it honestly nor reuse another proof.
        secrets = self.commit_all({**BIDS, "bidder_0": 99_999})
        with self.assertRaises(ValueError):
            self.make_proof("bidder_0", secrets["bidder_0"])
        honest_bid = {**secrets["bidder_0"], "bid": 1200}
        other = commit(1200)
        honest_bid.update(
            commitment_hex=encode_point(other.point),
            randomness_hex=encode_scalar(other.blinding),
        )
        data = self.assert_ok(self.prove("bidder_0", honest_bid))
        self.assertFalse(data["proof_valid"])

    def test_rejects_double_proof(self):
        secrets = self.commit_all()
        self.assert_ok(self.prove("bidder_0", secrets["bidder_0"]))
        self.assert_error(self.prove("bidder_0", secrets["bidder_0"]))

    def test_phase_advances_once_everyone_proved(self):
        self.prove_all(self.commit_all())
        self.assertEqual(self.state()["state"], "proved")


class TestReveal(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.create()

    def reveal(self, bidder_id, secret):
        return self.post_as(bidder_id, "reveal", **opening(secret))

    def test_rejects_reveal_before_everyone_proved(self):
        secrets = self.commit_all()
        self.assert_error(self.reveal("bidder_0", secrets["bidder_0"]))

    def test_full_auction_highest_verified_bid_wins(self):
        secrets = self.commit_all()
        self.prove_all(secrets)
        for bidder_id, secret in secrets.items():
            data = self.assert_ok(self.reveal(bidder_id, secret))
            self.assertTrue(data["verified"])

        # The last reveal finishes the auction and announces the winner.
        self.assertEqual(data["phase"], "finished")
        self.assertEqual((data["winner"]["name"], data["winner"]["bid"]), ("Bob", 1800))

        state = self.state()
        self.assertEqual(state["winner"]["bidder_id"], "bidder_1")
        revealed = {b["bidder_id"]: b["revealed_bid"] for b in state["bidders"]}
        self.assertEqual(revealed, BIDS)
        # Anyone can now check every opening against its commitment.
        for b in state["bidders"]:
            point, blinding = decode_point(b["commitment_hex"]), decode_scalar(b["randomness_hex"])
            self.assertTrue(verify(point, b["revealed_bid"], blinding))

    def test_wrong_opening_marks_cheater_and_excludes_them(self):
        secrets = self.commit_all()
        self.prove_all(secrets)
        # Bob opens his commitment to a higher bid than he committed to.
        secrets["bidder_1"]["bid"] = 4999
        for bidder_id, secret in secrets.items():
            data = self.assert_ok(self.reveal(bidder_id, secret))
            self.assertEqual(data["verified"], bidder_id != "bidder_1")

        self.assertEqual(data["winner"]["name"], "Carol")
        self.assertFalse(self.state()["bidders"][1]["commitment_verified"])

    def test_rejects_malformed_payload(self):
        secrets = self.commit_all()
        self.prove_all(secrets)
        self.assert_error(self.post_as("bidder_0", "reveal", bid=1200))
        for bad_bid in ("lots", 1200.0, True):
            with self.subTest(bid=bad_bid):
                typo = {**opening(secrets["bidder_0"]), "bid": bad_bid}
                self.assert_error(self.post_as("bidder_0", "reveal", **typo))

    def test_rejects_double_reveal(self):
        secrets = self.commit_all()
        self.prove_all(secrets)
        self.assert_ok(self.reveal("bidder_0", secrets["bidder_0"]))
        self.assert_error(self.reveal("bidder_0", secrets["bidder_0"]))

    def test_malformed_randomness_is_rejected_without_disqualifying(self):
        secrets = self.commit_all()
        self.prove_all(secrets)
        malformed = (
            "not-hex",
            secrets["bidder_0"]["randomness_hex"].upper(),  # one encoding per scalar
            f"{N:064x}",  # not below the curve order
        )
        for bad in malformed:
            with self.subTest(bad=bad):
                typo = {**opening(secrets["bidder_0"]), "randomness_hex": bad}
                self.assert_error(self.post_as("bidder_0", "reveal", **typo))
        # Rejected before reaching the auction, so the bidder can still reveal.
        data = self.assert_ok(self.reveal("bidder_0", secrets["bidder_0"]))
        self.assertTrue(data["verified"])

    def test_numbers_are_exact_in_javascript(self):
        secrets = self.commit_all()
        self.prove_all(secrets)
        for bidder_id, secret in secrets.items():
            self.assert_ok(self.reveal(bidder_id, secret))

        def ints(value):
            """Every integer anywhere in a decoded JSON value."""
            if isinstance(value, dict):
                value = list(value.values())
            if isinstance(value, list):
                return [i for item in value for i in ints(item)]
            return [value] if isinstance(value, int) and not isinstance(value, bool) else []

        for number in ints(self.state()):
            self.assertLessEqual(abs(number), 2**53 - 1)


class TestDeadlines(ApiTestCase):
    def deadlines(self):
        """The public deadlines, as seconds after the auction was created."""
        state = self.state()
        return {
            step: datetime.fromisoformat(text).timestamp() - FakeClock.START
            for step, text in state["deadlines"].items()
        }

    def test_windows_default_to_ten_minutes_each(self):
        self.create()
        self.assertEqual(self.deadlines(), {"commit": 600, "prove": 1200, "reveal": 1800})
        server_time = datetime.fromisoformat(self.state()["server_time"]).timestamp()
        self.assertEqual(server_time, FakeClock.START)

    def test_each_window_can_be_set(self):
        self.assert_created(self.create(commit_seconds=60, prove_seconds=120, reveal_seconds=30))
        self.assertEqual(self.deadlines(), {"commit": 60, "prove": 180, "reveal": 210})

    def test_window_lengths_must_be_integers_within_bounds(self):
        bad = (MIN_PHASE_SECONDS - 1, MAX_PHASE_SECONDS + 1, "60", 60.5, True)
        for field in ("commit_seconds", "prove_seconds", "reveal_seconds"):
            for value in bad:
                with self.subTest(field=field, value=value):
                    self.assert_error(self.create(**{field: value}))
            for value in (MIN_PHASE_SECONDS, MAX_PHASE_SECONDS):
                with self.subTest(field=field, value=value):
                    self.assert_created(self.create(**{field: value}))

    def test_a_late_commitment_is_rejected_and_the_auction_moves_on(self):
        self.create(commit_seconds=60)
        self.commit_all({"bidder_0": 1200, "bidder_1": 1800})
        self.clock.advance(60)

        late = encode_point(commit(1500).point)
        body = self.assert_error(self.post_as("bidder_2", "commit", commitment_hex=late))
        self.assertIn("missed the commit deadline", body["error"])
        state = self.state()
        self.assertEqual(state["state"], "committed")
        self.assertEqual([b["missed_deadline"] for b in state["bidders"]], [None, None, "commit"])

    def test_a_bidder_who_does_not_reveal_forfeits(self):
        self.create()
        secrets = self.commit_all()
        self.prove_all(secrets)
        for bidder_id in ("bidder_0", "bidder_2"):  # Bob, the highest bidder, stays silent
            self.assert_ok(self.post_as(bidder_id, "reveal", **opening(secrets[bidder_id])))
        self.assertEqual(self.state()["state"], "proved")

        self.clock.advance(1800)
        state = self.state()
        self.assertEqual(state["state"], "finished")
        self.assertEqual(state["winner"]["name"], "Carol")
        self.assertEqual(state["bidders"][1]["missed_deadline"], "reveal")
        self.assert_error(self.post_as("bidder_1", "reveal", **opening(secrets["bidder_1"])))


class TestBidderAuthentication(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.create()

    def test_every_token_is_distinct_and_unguessable(self):
        tokens = [self.organizer_token, *self.tokens.values()]
        self.assertEqual(len(set(tokens)), 4)
        for token in tokens:
            # 32 random bytes, URL-safe so the token can go into a join link.
            self.assertRegex(token, r"^[A-Za-z0-9_-]{43}$")

    def test_tokens_never_appear_in_the_public_state(self):
        self.prove_all(self.commit_all())
        state = self.client.get(self.url()).get_data(as_text=True)
        for token in [self.organizer_token, *self.tokens.values()]:
            self.assertNotIn(token, state)

    def test_bidder_endpoints_require_a_valid_join_token(self):
        alices = self.tokens["bidder_0"]
        headers = {
            "no header": {},
            "empty token": {"Authorization": "Bearer "},
            "valid token, other scheme": {"Authorization": f"Token {alices}"},
            "unknown token": bearer("x" * 43),
            "truncated token": bearer(alices[:-1]),
            "the organizer token": bearer(self.organizer_token),
        }
        for step in STEPS:
            for label, header in headers.items():
                with self.subTest(step=step, header=label):
                    # The empty body would be a 400; the 401 comes first.
                    resp = self.client.post(self.url(f"/{step}"), json={}, headers=header)
                    self.assert_error(resp, 401)
                    self.assertEqual(resp.headers["WWW-Authenticate"], "Bearer")

    def test_a_join_token_tells_whose_it_is(self):
        for bidder_id, name in (("bidder_0", "Alice"), ("bidder_2", "Carol")):
            with self.subTest(bidder_id):
                resp = self.client.get(self.url("/me"), headers=bearer(self.tokens[bidder_id]))
                data = self.assert_ok(resp)
                self.assertEqual((data["bidder_id"], data["name"]), (bidder_id, name))

    def test_only_a_join_token_tells_whose_it_is(self):
        headers = {
            "no header": {},
            "unknown token": bearer("x" * 43),
            "the organizer token": bearer(self.organizer_token),
        }
        for label, header in headers.items():
            with self.subTest(label):
                self.assert_error(self.client.get(self.url("/me"), headers=header), 401)
        self.auction_id = UNKNOWN_ID
        resp = self.client.get(self.url("/me"), headers=bearer(self.tokens["bidder_0"]))
        self.assert_error(resp, 404)

    def test_the_token_alone_decides_who_is_acting(self):
        # Bob names Alice in the body, as the API once allowed: the server acts
        # for Bob, whose token it is, and Alice's slot stays free.
        commitment_hex = encode_point(commit(1800).point)
        resp = self.post_as(
            "bidder_1", "commit", bidder_id="bidder_0", commitment_hex=commitment_hex
        )
        self.assert_ok(resp)
        bidders = self.state()["bidders"]
        self.assertIsNone(bidders[0]["commitment_hex"])
        self.assertEqual(bidders[1]["commitment_hex"], commitment_hex)


class TestDelete(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.create()

    def test_the_organizer_deletes_the_auction(self):
        # Sent the way the frontend sends it: JSON content type, no body.
        resp = self.client.delete(
            self.url(), headers=bearer(self.organizer_token), content_type="application/json"
        )
        self.assert_ok(resp)
        self.assert_error(self.client.get(self.url()), 404)

    def test_nobody_else_may_delete(self):
        headers = {
            "no header": {},
            "a bidder's join token": bearer(self.tokens["bidder_0"]),
            "unknown token": bearer("x" * 43),
        }
        for label, header in headers.items():
            with self.subTest(label):
                resp = self.client.delete(self.url(), headers=header)
                self.assert_error(resp, 401)
                self.assertEqual(resp.headers["WWW-Authenticate"], "Bearer")
        self.assert_ok(self.client.get(self.url()))


class TestRequestFormat(ApiTestCase):
    def test_null_body_gets_a_clear_error(self):
        resp = self.client.post("/api/auctions", data="null", content_type="application/json")
        self.assertNotIn("NoneType", self.assert_error(resp)["error"])

    def test_malformed_json_gets_a_json_error(self):
        resp = self.client.post("/api/auctions", data="{not json", content_type="application/json")
        self.assert_error(resp)

    def test_body_must_be_a_json_object(self):
        self.assert_error(self.client.post("/api/auctions", json=["Alice", "Bob"]))

    # Browsers send text/plain POSTs to any origin without a CORS preflight, so
    # accepting them lets any website drive this API from a visitor's browser.
    def test_create_and_commit_reject_non_json_content_type(self):
        create = '{"item_name": "x", "min_bid": 1, "max_bid": 2, "bidders": ["A", "B"]}'
        resp = self.client.post("/api/auctions", data=create, content_type="text/plain")
        self.assert_error(resp, 415)
        self.create()
        commitment = f'{{"commitment_hex": "{encode_point(commit(1200).point)}"}}'
        resp = self.client.post(self.url("/commit"), data=commitment, content_type="text/plain")
        self.assert_error(resp, 415)

    # Anyone may create an auction: without a cap, one request could make the
    # server read and parse any amount of JSON (a 94 MB body took 421 MB).
    def test_an_oversized_body_is_refused(self):
        names = ",".join(['"' + "a" * 90 + '"'] * 1000)
        body = f'{{"item_name": "x", "min_bid": 1, "max_bid": 2, "bidders": [{names}]}}'
        self.assertGreater(len(body), MAX_REQUEST_BYTES)
        resp = self.client.post("/api/auctions", data=body, content_type="application/json")
        self.assert_error(resp, 413)

    def test_the_largest_proof_the_api_can_ask_for_fits(self):
        # The widest range the API accepts needs 53 bits per side.
        self.create(min_bid=0, max_bid=MAX_JSON_INT)
        secrets = self.commit_all({"bidder_0": MAX_JSON_INT, "bidder_1": 0, "bidder_2": 1})
        proof = self.make_proof("bidder_0", secrets["bidder_0"])
        body = json.dumps({"proof": proof}, indent=2)  # even with generous whitespace
        self.assertLess(len(body), MAX_REQUEST_BYTES)
        resp = self.client.post(
            self.url("/prove"),
            data=body,
            content_type="application/json",
            headers=bearer(self.tokens["bidder_0"]),
        )
        self.assertTrue(self.assert_ok(resp)["proof_valid"])

    def test_unknown_route_gets_a_json_404(self):
        self.assert_error(self.client.get("/api/nope"), 404)

    def test_wrong_method_gets_a_json_405_with_allow_header(self):
        resp = self.client.get("/api/auctions")
        self.assert_error(resp, 405)
        self.assertIn("POST", resp.headers["Allow"])

    def test_unexpected_error_gets_a_json_500_without_internals(self):
        # Outside TESTING mode Flask turns an unhandled exception into a 500.
        self.client = create_app({"DATABASE": self.database}).test_client()
        self.create()
        with mock.patch.object(Auction, "get_public_state", side_effect=RuntimeError("secret")):
            resp = self.client.get(self.url())
        self.assertNotIn("secret", self.assert_error(resp, 500)["error"])


class TestAppFactory(ApiTestCase):
    def test_apps_on_different_databases_have_different_auctions(self):
        self.assert_created(self.create())
        other = create_app({"TESTING": True, "DATABASE": temporary_database(self)})
        self.assert_error(other.test_client().get(self.url()), 404)
        self.assert_ok(self.client.get(self.url()))

    def test_apps_on_one_database_share_its_auctions(self):
        # As after a restart, or with several server processes.
        self.assert_created(self.create())
        other = create_app({"TESTING": True, "DATABASE": self.database}).test_client()
        self.assertEqual(other.get(self.url()).get_json()["item_name"], "Rare NFT #42")

    def test_the_database_can_be_set_by_environment_variable(self):
        with mock.patch.dict(os.environ, {"CRYPTO_AUCTION_DATABASE": self.database}):
            app = create_app({"TESTING": True})
        self.assert_created(self.create())
        self.assert_ok(app.test_client().get(self.url()))

    def test_by_default_the_database_is_in_the_instance_folder(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("CRYPTO_AUCTION_DATABASE", None)
            app = create_app()
        expected = Path(app.instance_path) / "auctions.sqlite3"
        self.assertEqual(app.extensions[SERVICE_KEY].database, expected)


if __name__ == "__main__":
    unittest.main()
