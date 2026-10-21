"""Tests for crypto_auction.pedersen"""

import hashlib
import unittest

from ecdsa.ellipticcurve import INFINITY

from crypto_auction.pedersen import (
    G,
    H,
    N,
    P,
    _hash_to_curve,
    commit,
    commit_with,
    decode_point,
    decode_scalar,
    encode_point,
    encode_scalar,
    verify,
)

# The standard secp256k1 generator, compressed (SEC 2, section 2.4.1).
G_COMPRESSED = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
# H for the tag b"crypto-auction/pedersen/H/v1". Pinned because H is part of the
# protocol: a change silently invalidates every existing commitment, and other
# implementations (the browser) must derive exactly this point.
H_COMPRESSED = "02dcff14ee3f07929f95960463a3d806af79655299b20bfea66261ed5cd270ec38"


class TestGenerators(unittest.TestCase):
    def test_g_is_the_standard_secp256k1_generator(self):
        self.assertEqual(encode_point(G), G_COMPRESSED)

    def test_h_is_pinned(self):
        self.assertEqual(encode_point(H), H_COMPRESSED)

    def test_h_matches_a_plain_integer_derivation(self):
        # Re-derive H without ecdsa: the first SHA-256(tag || counter) that is
        # a valid x-coordinate (x < p and x³ + 7 a square mod p), with even y.
        tag = b"crypto-auction/pedersen/H/v1"
        for counter in range(256):
            x = int.from_bytes(hashlib.sha256(tag + bytes([counter])).digest(), "big")
            y_squared = (x**3 + 7) % P
            y = pow(y_squared, (P + 1) // 4, P)
            if x < P and y * y % P == y_squared:
                break
        expected_y = y if y % 2 == 0 else P - y
        self.assertEqual((H.x(), H.y()), (x, expected_y))

    def test_hash_to_curve_always_picks_the_even_y_point(self):
        # Each x has two points, (x, y) and (x, p - y); always taking the even
        # y makes the result unique. Several tags, so both cases occur.
        for i in range(8):
            point = _hash_to_curve(f"test-tag-{i}".encode())
            self.assertEqual(point.y() % 2, 0)
            self.assertEqual(point * N, INFINITY)

    def test_h_is_a_group_element_distinct_from_g(self):
        self.assertEqual(H * N, INFINITY)  # in the prime-order group
        self.assertNotEqual(H, INFINITY)
        self.assertNotIn(H, (G, -G))


class TestCommit(unittest.TestCase):
    def test_opening_verifies(self):
        c = commit(1500)
        self.assertTrue(verify(c.point, 1500, c.blinding))

    def test_wrong_value_or_blinding_does_not_verify(self):
        c = commit(1500)
        self.assertFalse(verify(c.point, 1501, c.blinding))
        self.assertFalse(verify(c.point, 1500, (c.blinding + 1) % N))

    def test_same_value_gives_different_commitments(self):
        self.assertNotEqual(commit(1500).point, commit(1500).point)

    def test_is_value_times_g_plus_blinding_times_h(self):
        self.assertEqual(commit_with(1, 0), G)
        self.assertEqual(commit_with(0, 1), H)
        self.assertEqual(commit_with(3, 5), G * 3 + H * 5)

    def test_accepts_the_full_scalar_range(self):
        c = commit(N - 1)
        self.assertTrue(verify(c.point, N - 1, c.blinding))

    def test_rejects_scalars_outside_the_group_order(self):
        for bad in (-1, N, True, 1.0, "1"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    commit_with(bad, 1)
                with self.assertRaises(ValueError):
                    commit_with(1, bad)

    def test_verify_is_false_for_out_of_range_openings(self):
        c = commit(1500)
        self.assertFalse(verify(c.point, -1, c.blinding))
        self.assertFalse(verify(c.point, 1500, N))


class TestHomomorphism(unittest.TestCase):
    def test_sum_of_commitments_commits_to_the_sum(self):
        a, b = commit(1200), commit(300)
        expected = commit_with(1500, (a.blinding + b.blinding) % N)
        self.assertEqual(a.point + b.point, expected)

    def test_multiple_of_a_commitment_commits_to_the_multiple(self):
        c = commit(1500)
        self.assertEqual(c.point * 7, commit_with(1500 * 7, c.blinding * 7 % N))


class TestEncoding(unittest.TestCase):
    def test_round_trip(self):
        point = commit(1500).point
        encoded = encode_point(point)
        self.assertRegex(encoded, r"^0[23][0-9a-f]{64}$")
        self.assertEqual(decode_point(encoded), point)

    def test_rejects_malformed_encodings(self):
        valid = encode_point(commit(1500).point)
        cases = {
            "uppercase": valid.upper(),
            "too short": valid[:-2],
            "uncompressed prefix": "04" + valid[2:],
            "not hex": "02" + "zz" * 32,
            "x not on the curve": "02" + "05" * 32,
            # x >= p would decode to the same point as x - p: two encodings
            # of one point, which breaks comparisons and transcript hashes.
            "x >= p (non-canonical)": "02" + "ff" * 32,
            "not a string": 12345,
        }
        for label, encoded in cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                decode_point(encoded)

    def test_point_at_infinity_cannot_be_encoded(self):
        with self.assertRaises(ValueError):
            encode_point(commit_with(0, 0))

    def test_scalars_round_trip_at_fixed_width(self):
        for scalar in (0, 1, N - 1):
            with self.subTest(scalar=scalar):
                encoded = encode_scalar(scalar)
                self.assertEqual(len(encoded), 64)
                self.assertEqual(decode_scalar(encoded), scalar)

    def test_rejects_malformed_scalars(self):
        # One encoding per scalar: fixed width, lowercase, and below n.
        for bad in (f"{N:064x}", "ab", "ab" * 32 + "0", "AB" * 32, 12345):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                decode_scalar(bad)
        with self.assertRaises(ValueError):
            encode_scalar(N)


if __name__ == "__main__":
    unittest.main()
