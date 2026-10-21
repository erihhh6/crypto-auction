"""Tests for crypto/zkp.py"""

import os
import unittest

from crypto_auction.commitment import commit
from crypto_auction.zkp import _fiat_shamir_challenge, prove_range, verify_range_proof
from tests.support import forged_range_proof, known_bug


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


class TestSoundness(unittest.TestCase):
    """A proof must only convince the verifier if the prover holds a valid opening."""

    @known_bug("the verifier never links C_low/C_high to the commitment, so proofs can be forged")
    def test_forged_proof_is_rejected(self):
        c = commit(999_999)  # far outside [100, 5000]; the forger never uses the opening
        self.assertFalse(verify_range_proof(forged_range_proof(c.commitment_hex, 100, 5000)))

    def test_prover_rejects_an_opening_that_does_not_match(self):
        c = commit(1000)
        with self.assertRaises(ValueError):
            prove_range(4000, os.urandom(32).hex(), c.commitment_hex, 100, 5000)

    @known_bug("the Fiat-Shamir challenge omits min_bid/max_bid, so the range can be swapped")
    def test_proof_is_bound_to_its_range(self):
        c = commit(1500)
        proof = prove_range(1500, c.randomness_hex, c.commitment_hex, 100, 5000)
        proof.min_bid, proof.max_bid = 0, 10  # 1500 lies outside the relabelled range
        self.assertFalse(verify_range_proof(proof))


if __name__ == "__main__":
    unittest.main()
