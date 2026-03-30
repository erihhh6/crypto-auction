"""Tests for crypto/zkp.py"""

import unittest
from crypto.commitment import commit
from crypto.zkp import RangeProof, prove_range, verify_range_proof, _fiat_shamir_challenge


class TestFiatShamirChallenge(unittest.TestCase):

    def test_returns_32_bytes(self):
        result = _fiat_shamir_challenge(b"hello", b"world")
        self.assertEqual(len(result), 32)

    def test_deterministic(self):
        a = _fiat_shamir_challenge(b"foo", b"bar")
        b = _fiat_shamir_challenge(b"foo", b"bar")
        self.assertEqual(a, b)

    def test_different_inputs_differ(self):
        a = _fiat_shamir_challenge(b"aaa")
        b = _fiat_shamir_challenge(b"bbb")
        self.assertNotEqual(a, b)


class TestProveRange(unittest.TestCase):

    def _make_proof(self, bid, min_bid=100, max_bid=5000):
        c = commit(bid)
        return prove_range(bid, c.randomness_hex, c.commitment_hex, min_bid, max_bid), c

    def test_proof_at_min(self):
        proof, _ = self._make_proof(100, 100, 5000)
        self.assertTrue(verify_range_proof(proof))

    def test_proof_at_max(self):
        proof, _ = self._make_proof(5000, 100, 5000)
        self.assertTrue(verify_range_proof(proof))

    def test_proof_in_middle(self):
        proof, _ = self._make_proof(1500, 100, 5000)
        self.assertTrue(verify_range_proof(proof))

    def test_proof_below_min_raises(self):
        c = commit(50)
        with self.assertRaises(ValueError):
            prove_range(50, c.randomness_hex, c.commitment_hex, 100, 5000)

    def test_proof_above_max_raises(self):
        c = commit(9999)
        with self.assertRaises(ValueError):
            prove_range(9999, c.randomness_hex, c.commitment_hex, 100, 5000)

    def test_proof_zero_below_min_raises(self):
        c = commit(0)
        with self.assertRaises(ValueError):
            prove_range(0, c.randomness_hex, c.commitment_hex, 1, 100)

    def test_proof_fields_are_hex_strings(self):
        proof, _ = self._make_proof(1000)
        self.assertIsInstance(proof.commitment_hex, str)
        self.assertIsInstance(proof.low_commitment_hex, str)
        self.assertIsInstance(proof.low_challenge_hex, str)
        self.assertIsInstance(proof.high_commitment_hex, str)
        self.assertIsInstance(proof.high_challenge_hex, str)

    def test_proof_responses_are_non_negative(self):
        proof, _ = self._make_proof(1000)
        self.assertGreaterEqual(proof.low_response, 0)
        self.assertGreaterEqual(proof.high_response, 0)

    def test_multiple_bids_all_verify(self):
        for bid in [100, 500, 1000, 2500, 5000]:
            proof, _ = self._make_proof(bid, 100, 5000)
            self.assertTrue(verify_range_proof(proof), f"Failed for bid={bid}")


class TestVerifyRangeProof(unittest.TestCase):

    def _valid_proof(self):
        c = commit(1500)
        return prove_range(1500, c.randomness_hex, c.commitment_hex, 100, 5000)

    def test_valid_proof_returns_true(self):
        proof = self._valid_proof()
        self.assertTrue(verify_range_proof(proof))

    def test_tampered_low_challenge_fails(self):
        proof = self._valid_proof()
        proof.low_challenge_hex = "aa" * 32
        self.assertFalse(verify_range_proof(proof))

    def test_tampered_high_challenge_fails(self):
        proof = self._valid_proof()
        proof.high_challenge_hex = "bb" * 32
        self.assertFalse(verify_range_proof(proof))

    def test_negative_low_response_fails(self):
        proof = self._valid_proof()
        proof.low_response = -1
        self.assertFalse(verify_range_proof(proof))

    def test_negative_high_response_fails(self):
        proof = self._valid_proof()
        proof.high_response = -1
        self.assertFalse(verify_range_proof(proof))

    def test_tampered_commitment_fails(self):
        proof = self._valid_proof()
        proof.commitment_hex = "cc" * 32
        self.assertFalse(verify_range_proof(proof))


if __name__ == "__main__":
    unittest.main()
