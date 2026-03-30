"""Tests for crypto/commitment.py"""

import unittest
from crypto.commitment import commit, verify, commitment_to_bytes


class TestCommit(unittest.TestCase):

    def test_commit_returns_64_char_hex(self):
        c = commit(1000)
        self.assertEqual(len(c.commitment_hex), 64)
        self.assertEqual(len(c.randomness_hex), 64)

    def test_two_commits_same_bid_differ(self):
        c1 = commit(500)
        c2 = commit(500)
        self.assertNotEqual(c1.commitment_hex, c2.commitment_hex)
        self.assertNotEqual(c1.randomness_hex, c2.randomness_hex)

    def test_commit_zero_bid(self):
        c = commit(0)
        self.assertEqual(len(c.commitment_hex), 64)

    def test_commit_large_bid(self):
        c = commit(2**63)
        self.assertEqual(len(c.commitment_hex), 64)

    def test_commit_negative_raises(self):
        with self.assertRaises(ValueError):
            commit(-1)

    def test_commit_overflow_raises(self):
        with self.assertRaises(ValueError):
            commit(2**64)


class TestVerify(unittest.TestCase):

    def test_verify_correct(self):
        c = commit(1500)
        self.assertTrue(verify(1500, c.randomness_hex, c.commitment_hex))

    def test_verify_wrong_bid(self):
        c = commit(1500)
        self.assertFalse(verify(9999, c.randomness_hex, c.commitment_hex))

    def test_verify_wrong_randomness(self):
        c1 = commit(1500)
        c2 = commit(1500)
        self.assertFalse(verify(1500, c2.randomness_hex, c1.commitment_hex))

    def test_verify_tampered_commitment(self):
        c = commit(1500)
        tampered = "00" * 32
        self.assertFalse(verify(1500, c.randomness_hex, tampered))

    def test_verify_invalid_hex_returns_false(self):
        self.assertFalse(verify(100, "not-hex", "a" * 64))

    def test_verify_negative_bid_returns_false(self):
        c = commit(100)
        self.assertFalse(verify(-1, c.randomness_hex, c.commitment_hex))

    def test_multiple_bids(self):
        for bid in [0, 1, 100, 9999, 2**32]:
            c = commit(bid)
            self.assertTrue(verify(bid, c.randomness_hex, c.commitment_hex))
            self.assertFalse(verify(bid + 1, c.randomness_hex, c.commitment_hex))


class TestCommitmentToBytes(unittest.TestCase):

    def test_returns_32_bytes(self):
        c = commit(42)
        b = commitment_to_bytes(c.commitment_hex)
        self.assertIsInstance(b, bytes)
        self.assertEqual(len(b), 32)

    def test_round_trips(self):
        c = commit(42)
        b = commitment_to_bytes(c.commitment_hex)
        self.assertEqual(b.hex(), c.commitment_hex)


if __name__ == "__main__":
    unittest.main()
