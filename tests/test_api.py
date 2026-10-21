"""Tests for the REST API in app.py, exercised through Flask's test client."""

import unittest
from unittest import mock

import app as app_module
from crypto_auction.auction import Auction
from crypto_auction.commitment import verify

# bidder_0..2 are Alice, Bob and Carol in the default auction; Bob bids highest.
BIDS = {"bidder_0": 1200, "bidder_1": 1800, "bidder_2": 1500}


class ApiTestCase(unittest.TestCase):
    """Gives every test a test client and an empty auction slot."""

    def setUp(self):
        # app.py keeps the auction in a module-level global; patching it gives
        # each test a clean slate and restores the previous value afterwards.
        patches = [
            mock.patch.object(app_module, "auction", None),
            # Let unhandled exceptions propagate instead of becoming HTTP 500s.
            mock.patch.dict(app_module.app.config, {"TESTING": True}),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = app_module.app.test_client()

    def post(self, path, **body):
        return self.client.post(path, json=body)

    def create(self, **overrides):
        body = {
            "item_name": "Rare NFT #42",
            "min_bid": 100,
            "max_bid": 5000,
            "bidders": ["Alice", "Bob", "Carol"],
        }
        body.update(overrides)
        return self.post("/api/create", **body)

    def state(self):
        return self.client.get("/api/state").get_json()

    def assert_ok(self, resp):
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertTrue(resp.get_json()["success"])
        return resp.get_json()

    def assert_error(self, resp, status=400):
        """Errors use the JSON envelope {"success": false, "error": "<reason>"}."""
        self.assertTrue(resp.is_json, f"expected a JSON error, got {resp.content_type}")
        self.assertEqual(resp.status_code, status, resp.get_json())
        body = resp.get_json()
        self.assertIs(body["success"], False)
        self.assertTrue(body["error"])
        return body

    def commit_all(self, bids=BIDS):
        """Commit every bid and return each bidder's opening (bid, randomness)."""
        secrets = {}
        for bidder_id, bid in bids.items():
            data = self.assert_ok(self.post("/api/commit", bidder_id=bidder_id, bid=bid))
            secrets[bidder_id] = {"bid": bid, "randomness_hex": data["randomness_hex"]}
        return secrets

    def prove_all(self, secrets):
        for bidder_id, secret in secrets.items():
            self.assert_ok(self.post("/api/prove", bidder_id=bidder_id, **secret))


class TestIndex(ApiTestCase):
    def test_serves_html_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.content_type)


class TestNoAuction(ApiTestCase):
    def test_endpoints_return_404_before_create(self):
        requests = [
            ("GET", "/api/state"),
            ("POST", "/api/commit"),
            ("POST", "/api/prove"),
            ("POST", "/api/reveal"),
        ]
        for method, path in requests:
            with self.subTest(path=path):
                resp = self.client.open(path, method=method, json={})
                self.assert_error(resp, 404)


class TestCreate(ApiTestCase):
    def test_returns_bidders_with_generated_ids(self):
        data = self.assert_ok(self.create())
        self.assertEqual(data["item_name"], "Rare NFT #42")
        self.assertEqual((data["min_bid"], data["max_bid"]), (100, 5000))
        self.assertEqual(
            data["bidders"],
            [
                {"bidder_id": "bidder_0", "name": "Alice"},
                {"bidder_id": "bidder_1", "name": "Bob"},
                {"bidder_id": "bidder_2", "name": "Carol"},
            ],
        )

    def test_strips_whitespace_from_names(self):
        data = self.assert_ok(self.create(item_name="  Watch  ", bidders=[" Alice ", "Bob\t"]))
        self.assertEqual(data["item_name"], "Watch")
        self.assertEqual([b["name"] for b in data["bidders"]], ["Alice", "Bob"])

    def test_rejects_missing_fields(self):
        for field in ("item_name", "min_bid", "max_bid", "bidders"):
            with self.subTest(field=field):
                body = {"item_name": "x", "min_bid": 1, "max_bid": 2, "bidders": ["A", "B"]}
                del body[field]
                self.assert_error(self.post("/api/create", **body))

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
        cases = {1: 400, 2: 200, 10: 200, 11: 400}
        for count, status in cases.items():
            with self.subTest(count=count):
                resp = self.create(bidders=[f"Bidder {i}" for i in range(count)])
                self.assertEqual(resp.status_code, status)

    def test_create_replaces_existing_auction(self):
        self.create()
        self.commit_all({"bidder_0": 1200})
        self.assert_ok(self.create(item_name="Second item"))
        state = self.state()
        self.assertEqual(state["item_name"], "Second item")
        self.assertEqual(state["state"], "open")
        self.assertTrue(all(b["commitment_hex"] is None for b in state["bidders"]))

    def test_rejects_integers_javascript_cannot_represent_exactly(self):
        self.assert_error(self.create(max_bid=2**53))
        self.assert_ok(self.create(max_bid=2**53 - 1))

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
        longest = "x" * app_module.MAX_NAME_LENGTH
        self.assert_ok(self.create(item_name=longest, bidders=[longest, "Bob"]))
        self.assert_error(self.create(item_name=longest + "x"))
        self.assert_error(self.create(bidders=[longest + "x", "Bob"]))


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

    def test_returns_opening_for_the_commitment(self):
        data = self.assert_ok(self.post("/api/commit", bidder_id="bidder_0", bid=1200))
        self.assertEqual(len(data["commitment_hex"]), 64)
        self.assertTrue(verify(1200, data["randomness_hex"], data["commitment_hex"]))

    def test_commitment_is_published_in_state(self):
        data = self.assert_ok(self.post("/api/commit", bidder_id="bidder_0", bid=1200))
        published = self.state()["bidders"][0]["commitment_hex"]
        self.assertEqual(published, data["commitment_hex"])

    def test_accepts_bids_on_the_bounds(self):
        self.assert_ok(self.post("/api/commit", bidder_id="bidder_0", bid=100))
        self.assert_ok(self.post("/api/commit", bidder_id="bidder_1", bid=5000))

    def test_rejects_bids_outside_the_range(self):
        # Separate bidders, so a wrongly accepted first bid cannot make the
        # second case fail as a double commit instead.
        for bidder_id, bid in (("bidder_0", 99), ("bidder_1", 5001)):
            with self.subTest(bid=bid):
                self.assert_error(self.post("/api/commit", bidder_id=bidder_id, bid=bid))

    def test_rejects_unknown_bidder(self):
        self.assert_error(self.post("/api/commit", bidder_id="bidder_99", bid=1200))

    def test_rejects_double_commit(self):
        self.assert_ok(self.post("/api/commit", bidder_id="bidder_0", bid=1200))
        self.assert_error(self.post("/api/commit", bidder_id="bidder_0", bid=1300))

    def test_rejects_malformed_payload(self):
        self.assert_error(self.post("/api/commit", bidder_id="bidder_0"))
        self.assert_error(self.post("/api/commit", bidder_id="bidder_0", bid="lots"))

    def test_rejects_float_and_bool_bids(self):
        self.create(min_bid=0)  # so that true (== 1) would be inside the range
        self.assert_error(self.post("/api/commit", bidder_id="bidder_0", bid=1500.9))
        self.assert_error(self.post("/api/commit", bidder_id="bidder_1", bid=True))

    def test_phase_advances_once_everyone_committed(self):
        self.commit_all({"bidder_0": 1200, "bidder_1": 1800})
        self.assertEqual(self.state()["state"], "open")
        self.commit_all({"bidder_2": 1500})
        self.assertEqual(self.state()["state"], "committed")


class TestProve(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.create()

    def test_valid_proof_is_accepted_and_published(self):
        secrets = self.commit_all()
        data = self.assert_ok(self.post("/api/prove", bidder_id="bidder_0", **secrets["bidder_0"]))
        self.assertTrue(data["proof_valid"])
        commitment = self.state()["bidders"][0]["commitment_hex"]
        self.assertEqual(data["proof_public"]["commitment_hex"], commitment)
        self.assertTrue(self.state()["bidders"][0]["proof_valid"])

    def test_rejects_proof_before_everyone_committed(self):
        secrets = self.commit_all({"bidder_0": 1200})
        self.assert_error(self.post("/api/prove", bidder_id="bidder_0", **secrets["bidder_0"]))

    def test_rejects_unknown_bidder(self):
        self.commit_all()
        resp = self.post("/api/prove", bidder_id="bidder_99", bid=1200, randomness_hex="00" * 32)
        self.assert_error(resp)

    def test_rejects_bidder_without_commitment(self):
        self.commit_all({"bidder_0": 1200})
        resp = self.post("/api/prove", bidder_id="bidder_1", bid=1800, randomness_hex="00" * 32)
        self.assert_error(resp)

    def test_rejects_malformed_payload(self):
        secrets = self.commit_all()
        self.assert_error(self.post("/api/prove", bidder_id="bidder_0", bid=1200))
        opening = {**secrets["bidder_0"], "bid": "lots"}
        self.assert_error(self.post("/api/prove", bidder_id="bidder_0", **opening))
        opening = {**secrets["bidder_0"], "randomness_hex": 12345}
        self.assert_error(self.post("/api/prove", bidder_id="bidder_0", **opening))

    def test_rejects_opening_that_does_not_match_the_commitment(self):
        secrets = self.commit_all()
        wrong_randomness = {**secrets["bidder_0"], "randomness_hex": "ab" * 32}
        self.assert_error(self.post("/api/prove", bidder_id="bidder_0", **wrong_randomness))
        wrong_bid = {**secrets["bidder_1"], "bid": 4999}
        self.assert_error(self.post("/api/prove", bidder_id="bidder_1", **wrong_bid))

    def test_rejects_claimed_bid_outside_the_range(self):
        secrets = self.commit_all()
        opening = {**secrets["bidder_0"], "bid": 99_999}
        self.assert_error(self.post("/api/prove", bidder_id="bidder_0", **opening))

    def test_rejects_double_proof(self):
        secrets = self.commit_all()
        self.assert_ok(self.post("/api/prove", bidder_id="bidder_0", **secrets["bidder_0"]))
        self.assert_error(self.post("/api/prove", bidder_id="bidder_0", **secrets["bidder_0"]))

    def test_phase_advances_once_everyone_proved(self):
        self.prove_all(self.commit_all())
        self.assertEqual(self.state()["state"], "proved")

    def test_proof_numbers_are_exact_in_javascript(self):
        secrets = self.commit_all()
        data = self.assert_ok(self.post("/api/prove", bidder_id="bidder_0", **secrets["bidder_0"]))
        for field, value in data["proof_public"].items():
            if isinstance(value, int):
                self.assertLessEqual(abs(value), 2**53 - 1, field)


class TestReveal(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.create()

    def test_rejects_reveal_before_everyone_proved(self):
        secrets = self.commit_all()
        self.assert_error(self.post("/api/reveal", bidder_id="bidder_0", **secrets["bidder_0"]))

    def test_full_auction_highest_verified_bid_wins(self):
        secrets = self.commit_all()
        self.prove_all(secrets)
        for bidder_id, secret in secrets.items():
            data = self.assert_ok(self.post("/api/reveal", bidder_id=bidder_id, **secret))
            self.assertTrue(data["verified"])

        # The last reveal finishes the auction and announces the winner.
        self.assertEqual(data["phase"], "finished")
        self.assertEqual((data["winner"]["name"], data["winner"]["bid"]), ("Bob", 1800))

        state = self.state()
        self.assertEqual(state["winner"]["bidder_id"], "bidder_1")
        revealed = {b["bidder_id"]: b["revealed_bid"] for b in state["bidders"]}
        self.assertEqual(revealed, BIDS)

    def test_wrong_opening_marks_cheater_and_excludes_them(self):
        secrets = self.commit_all()
        self.prove_all(secrets)
        # Bob opens his commitment to a higher bid than he committed to.
        secrets["bidder_1"]["bid"] = 4999
        for bidder_id, secret in secrets.items():
            data = self.assert_ok(self.post("/api/reveal", bidder_id=bidder_id, **secret))
            self.assertEqual(data["verified"], bidder_id != "bidder_1")

        self.assertEqual(data["winner"]["name"], "Carol")
        self.assertFalse(self.state()["bidders"][1]["commitment_verified"])

    def test_rejects_malformed_payload(self):
        secrets = self.commit_all()
        self.prove_all(secrets)
        self.assert_error(self.post("/api/reveal", bidder_id="bidder_0", bid=1200))
        opening = {**secrets["bidder_0"], "bid": "lots"}
        self.assert_error(self.post("/api/reveal", bidder_id="bidder_0", **opening))

    def test_rejects_double_reveal(self):
        secrets = self.commit_all()
        self.prove_all(secrets)
        self.assert_ok(self.post("/api/reveal", bidder_id="bidder_0", **secrets["bidder_0"]))
        self.assert_error(self.post("/api/reveal", bidder_id="bidder_0", **secrets["bidder_0"]))

    def test_malformed_randomness_is_rejected_without_disqualifying(self):
        secrets = self.commit_all()
        self.prove_all(secrets)
        typo = {**secrets["bidder_0"], "randomness_hex": "not-hex"}
        self.assert_error(self.post("/api/reveal", bidder_id="bidder_0", **typo))
        # Rejected before reaching the auction, so the bidder can still reveal.
        data = self.assert_ok(self.post("/api/reveal", bidder_id="bidder_0", **secrets["bidder_0"]))
        self.assertTrue(data["verified"])


class TestRequestFormat(ApiTestCase):
    def test_null_body_gets_a_clear_error(self):
        resp = self.client.post("/api/create", data="null", content_type="application/json")
        self.assertNotIn("NoneType", self.assert_error(resp)["error"])

    def test_malformed_json_gets_a_json_error(self):
        resp = self.client.post("/api/create", data="{not json", content_type="application/json")
        self.assert_error(resp)

    def test_body_must_be_a_json_object(self):
        self.assert_error(self.client.post("/api/create", json=["Alice", "Bob"]))

    # Browsers send text/plain POSTs to any origin without a CORS preflight, so
    # accepting them lets any website drive this API from a visitor's browser.
    def test_commit_rejects_non_json_content_type(self):
        self.create()
        body = '{"bidder_id": "bidder_0", "bid": 1200}'
        resp = self.client.post("/api/commit", data=body, content_type="text/plain")
        self.assert_error(resp, 415)

    def test_reset_rejects_non_json_content_type(self):
        self.create()
        resp = self.client.post("/api/reset", data="", content_type="text/plain")
        self.assert_error(resp, 415)
        self.assert_ok(self.client.get("/api/state"))

    def test_unknown_route_gets_a_json_404(self):
        self.assert_error(self.client.get("/api/nope"), 404)

    def test_wrong_method_gets_a_json_405_with_allow_header(self):
        resp = self.client.get("/api/create")
        self.assert_error(resp, 405)
        self.assertIn("POST", resp.headers["Allow"])

    def test_unexpected_error_gets_a_json_500_without_internals(self):
        self.create()
        # Outside TESTING mode Flask turns an unhandled exception into a 500.
        with (
            mock.patch.dict(app_module.app.config, {"TESTING": False}),
            mock.patch.object(Auction, "get_public_state", side_effect=RuntimeError("secret")),
        ):
            resp = self.client.get("/api/state")
        self.assertNotIn("secret", self.assert_error(resp, 500)["error"])


class TestReset(ApiTestCase):
    def test_reset_discards_the_auction(self):
        self.create()
        # Sent the way the frontend sends it: JSON content type, no body.
        self.assert_ok(self.client.post("/api/reset", content_type="application/json"))
        self.assert_error(self.client.get("/api/state"), 404)


if __name__ == "__main__":
    unittest.main()
