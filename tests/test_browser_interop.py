"""
Cross-language tests: the server accepts exactly what the browser produces.

Bidders commit and prove in the browser (static/auction-crypto.js), so the
JavaScript and Python implementations must agree byte for byte on encodings
and Fiat-Shamir transcripts. These tests run the browser module under Node and
check its output with the server's own code.

Node is needed. Without it the tests are skipped, unless REQUIRE_NODE=1 (set
in CI), in which case they fail instead of being skipped silently.
"""

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

from crypto_auction.auction import bid_proof_context
from crypto_auction.pedersen import decode_point, decode_scalar, verify
from crypto_auction.range_proof import RangeProof, verify_range
from crypto_auction.transcript import encode_parts
from crypto_auction.web import create_app

NODE = shutil.which("node")
CLI = Path(__file__).resolve().parent / "js" / "bidder_cli.mjs"
AUCTION_ID = "0123456789abcdef0123456789abcdef"

if NODE is None and os.environ.get("REQUIRE_NODE") == "1":
    raise RuntimeError("REQUIRE_NODE=1 but node is not on PATH")


def browser(*requests):
    """Run requests through the browser's crypto module (see tests/js/bidder_cli.mjs)."""
    result = subprocess.run(  # noqa: S603 - fixed command, test input only
        [NODE, str(CLI)],
        input=json.dumps(list(requests)),
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    return json.loads(result.stdout)


def commit_and_prove(bid, *, min_bid=100, max_bid=5000, auction_id=AUCTION_ID, bidder="bidder_0"):
    [commitment] = browser({"action": "commit", "bid": bid})
    [proved] = browser(
        {
            "action": "prove",
            "bid": bid,
            **commitment,
            "min_bid": min_bid,
            "max_bid": max_bid,
            "auction_id": auction_id,
            "bidder_id": bidder,
        }
    )
    return commitment, proved


@unittest.skipIf(NODE is None, "node is not installed")
class TestBrowserInterop(unittest.TestCase):
    def test_transcript_encoding_matches(self):
        parts = [b"ab", b"c", b"", bytes(range(256))]
        [result] = browser({"action": "encode_parts", "parts_hex": [p.hex() for p in parts]})
        self.assertEqual(result["hex"], encode_parts(*parts).hex())

    def test_browser_commitment_opens_in_python(self):
        [c] = browser({"action": "commit", "bid": 1500})
        point = decode_point(c["commitment_hex"])  # canonical, on the curve
        self.assertTrue(verify(point, 1500, decode_scalar(c["randomness_hex"])))

    def test_browser_proof_verifies_in_python_for_its_statement_only(self):
        c, proved = commit_and_prove(1500)
        point = decode_point(c["commitment_hex"])
        proof = RangeProof.from_dict(proved["proof"])
        context = bid_proof_context(AUCTION_ID, "bidder_0")
        self.assertTrue(verify_range(point, proof, 100, 5000, context))
        self.assertFalse(verify_range(point, proof, 100, 4999, context))
        other_bidder = bid_proof_context(AUCTION_ID, "bidder_1")
        self.assertFalse(verify_range(point, proof, 100, 5000, other_bidder))

    def test_browser_refuses_to_prove_an_out_of_range_bid(self):
        _, proved = commit_and_prove(99_999)
        self.assertIn("not within", proved["error"])

    def test_full_auction_through_the_api_with_browser_cryptography(self):
        # Exactly what the page does: every commitment and proof is computed by
        # the browser module; the server only ever sees commitments and proofs
        # until the reveal.
        client = create_app({"TESTING": True}).test_client()
        created = client.post(
            "/api/create",
            json={"item_name": "x", "min_bid": 100, "max_bid": 5000, "bidders": ["A", "B"]},
        ).get_json()
        bids = {"bidder_0": 1200, "bidder_1": 1800}
        commitments = browser(*({"action": "commit", "bid": bid} for bid in bids.values()))
        openings = dict(zip(bids, commitments, strict=True))
        for bidder_id, c in openings.items():
            body = {"bidder_id": bidder_id, "commitment_hex": c["commitment_hex"]}
            self.assertEqual(client.post("/api/commit", json=body).status_code, 200)

        proofs = browser(
            *(
                {
                    "action": "prove",
                    "bid": bids[bidder_id],
                    **c,
                    "min_bid": 100,
                    "max_bid": 5000,
                    "auction_id": created["auction_id"],
                    "bidder_id": bidder_id,
                }
                for bidder_id, c in openings.items()
            )
        )
        for bidder_id, proved in zip(openings, proofs, strict=True):
            body = {"bidder_id": bidder_id, "proof": proved["proof"]}
            self.assertTrue(client.post("/api/prove", json=body).get_json()["proof_valid"])

        for bidder_id, c in openings.items():
            body = {
                "bidder_id": bidder_id,
                "bid": bids[bidder_id],
                "randomness_hex": c["randomness_hex"],
            }
            result = client.post("/api/reveal", json=body).get_json()
            self.assertTrue(result["verified"])
        self.assertEqual(result["winner"]["bidder_id"], "bidder_1")


if __name__ == "__main__":
    unittest.main()
