"""Tests for crypto_auction.range_proof"""

import json
import secrets
import unittest
from dataclasses import replace

from crypto_auction.bit_proof import prove_bit
from crypto_auction.pedersen import N, commit, commit_with
from crypto_auction.range_proof import (
    MAX_VALUE,
    NonNegativeProof,
    RangeProof,
    _bit_context,
    _context,
    _prove_non_negative,
    prove_range,
    verify_range,
)

CONTEXT = b"auction-1/bidder-0"
LO, HI = 100, 5000  # d = 4900, so k = 13 bits per side


def proven(value, lo=LO, hi=HI, context=CONTEXT):
    c = commit(value)
    return c, prove_range(c.point, value, c.blinding, lo, hi, context)


def side_context(c, side, lo=LO, hi=HI):
    return _context(c.point, lo, hi, side, CONTEXT)


class TestCompleteness(unittest.TestCase):
    def test_values_across_ranges_verify(self):
        cases = [
            (LO, HI, LO),  # lower bound
            (LO, HI, HI),  # upper bound
            (LO, HI, 1500),
            (0, 15, 15),  # d = 2^4 - 1: largest value in 4 bits
            (0, 16, 16),  # d = 2^4: needs a fifth bit
            (7, 7, 7),  # empty range width still uses one bit
            (0, 1, 0),
        ]
        for lo, hi, value in cases:
            with self.subTest(lo=lo, hi=hi, value=value):
                c, proof = proven(value, lo, hi)
                self.assertTrue(verify_range(c.point, proof, lo, hi, CONTEXT))

    def test_largest_supported_range(self):
        c, proof = proven(MAX_VALUE, 0, MAX_VALUE)
        self.assertTrue(verify_range(c.point, proof, 0, MAX_VALUE, CONTEXT))


class TestProverRefusesFalseStatements(unittest.TestCase):
    def test_value_outside_the_range(self):
        for value in (LO - 1, HI + 1):
            c = commit(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                prove_range(c.point, value, c.blinding, LO, HI, CONTEXT)

    def test_wrong_opening(self):
        c = commit(1500)
        with self.assertRaises(ValueError):
            prove_range(c.point, 1501, c.blinding, LO, HI, CONTEXT)

    def test_invalid_range(self):
        c = commit(1500)
        for lo, hi in ((5000, 100), (-1, 100), (0, MAX_VALUE + 1), (True, 100)):
            with self.subTest(lo=lo, hi=hi), self.assertRaises(ValueError):
                prove_range(c.point, 1500, c.blinding, lo, hi, CONTEXT)


class TestStatementBinding(unittest.TestCase):
    def test_proof_is_bound_to_its_range(self):
        # The old zkp module's flaw: its proofs could be relabelled with
        # another range. Here the verifier supplies the range itself.
        c, proof = proven(1500)
        for lo, hi in ((0, 10), (LO, HI - 1), (LO + 1, HI), (0, 2**20)):
            with self.subTest(lo=lo, hi=hi):
                self.assertFalse(verify_range(c.point, proof, lo, hi, CONTEXT))

    def test_proof_is_bound_to_its_commitment(self):
        _, proof = proven(1500)
        self.assertFalse(verify_range(commit(1500).point, proof, LO, HI, CONTEXT))

    def test_proof_is_bound_to_its_context(self):
        c, proof = proven(1500)
        self.assertFalse(verify_range(c.point, proof, LO, HI, b"auction-2/bidder-0"))

    def test_invalid_range_or_commitment_is_rejected_not_raised(self):
        c, proof = proven(1500)
        self.assertFalse(verify_range(c.point, proof, HI, LO, CONTEXT))
        self.assertFalse(verify_range(commit_with(0, 0), proof, LO, HI, CONTEXT))


class TestSoundness(unittest.TestCase):
    def test_wrong_number_of_bits_is_rejected(self):
        c, proof = proven(1500)
        low = proof.low
        shorter = NonNegativeProof(low.bit_commitments[:-1], low.bit_proofs[:-1])
        self.assertFalse(verify_range(c.point, replace(proof, low=shorter), LO, HI, CONTEXT))

    def test_bits_must_sum_to_the_commitment(self):
        # Swap bit 0 for an independent commitment to the same bit with a
        # valid bit proof at that position: every bit proof still verifies,
        # so only the sum check catches it.
        c, proof = proven(1500)
        bit = (1500 - LO) & 1
        other = commit(bit)
        other_proof = prove_bit(
            other.point, bit, other.blinding, _bit_context(side_context(c, b"low"), 0)
        )
        low = NonNegativeProof(
            (other.point, *proof.low.bit_commitments[1:]),
            (other_proof, *proof.low.bit_proofs[1:]),
        )
        self.assertFalse(verify_range(c.point, replace(proof, low=low), LO, HI, CONTEXT))

    def test_out_of_range_value_hidden_in_a_non_bit_commitment_is_rejected(self):
        # Attack: for v = HI + 1000, put each side's whole value into bit 0
        # (blindings chosen so the sums still match) and zeros elsewhere.
        # Bit 0 then hides a large value, so only its bit proof can stop it.
        value = HI + 1000
        c = commit(value)
        bits = (HI - LO).bit_length()

        def cheat(side_value, side_blinding, side):
            ctx = side_context(c, side)
            blindings = [secrets.randbelow(N) for _ in range(bits)]
            rest = sum(b << i for i, b in enumerate(blindings) if i > 0) % N
            blindings[0] = (side_blinding - rest) % N
            commitments = [commit_with(side_value % N, blindings[0])]
            commitments += [commit_with(0, b) for b in blindings[1:]]
            # No valid proof exists for bit 0; borrow one made for a real bit.
            decoy = commit(0)
            proofs = [prove_bit(decoy.point, 0, decoy.blinding, _bit_context(ctx, 0))]
            proofs += [
                prove_bit(commitments[i], 0, blindings[i], _bit_context(ctx, i))
                for i in range(1, bits)
            ]
            return NonNegativeProof(tuple(commitments), tuple(proofs))

        forged = RangeProof(
            low=cheat(value - LO, c.blinding, b"low"),
            high=cheat(HI - value, (N - c.blinding) % N, b"high"),
        )
        self.assertFalse(verify_range(c.point, forged, LO, HI, CONTEXT))

    def test_wrap_around_with_extra_bits_is_rejected(self):
        # Attack: v = HI + 500 is out of range, so y = HI - v = -500 ≡ n - 500.
        # With 256 honest bits for y (and the usual 13 for x), every bit proof
        # and both sums verify; x + y wraps around n to equal d. Only the
        # verifier insisting on k = 13 bits per side stops this.
        value = HI + 500
        c = commit(value)
        bits = (HI - LO).bit_length()
        forged = RangeProof(
            low=_prove_non_negative(value - LO, c.blinding, bits, side_context(c, b"low")),
            high=_prove_non_negative(
                (HI - value) % N, (N - c.blinding) % N, 256, side_context(c, b"high")
            ),
        )
        self.assertFalse(verify_range(c.point, forged, LO, HI, CONTEXT))


class TestSerialisation(unittest.TestCase):
    def test_json_round_trip(self):
        c, proof = proven(1500)
        restored = RangeProof.from_dict(json.loads(json.dumps(proof.to_dict())))
        self.assertEqual(restored, proof)
        self.assertTrue(verify_range(c.point, restored, LO, HI, CONTEXT))

    def test_rejects_malformed_proofs(self):
        _, proof = proven(1500)
        valid = proof.to_dict()
        first_bit = valid["low"]["bit_proofs"][0]

        def with_low(**changes):
            return {**valid, "low": {**valid["low"], **changes}}

        cases = {
            "missing side": ({"low": valid["low"]}, KeyError),
            "commitments not a list": (with_low(bit_commitments="02ab"), TypeError),
            "malformed point": (with_low(bit_commitments=["02" + "zz" * 32]), ValueError),
            "scalar >= n": (
                with_low(bit_proofs=[{**first_bit, "s0": f"{N:064x}"}]),
                ValueError,
            ),
            "uppercase scalar": (
                with_low(bit_proofs=[{**first_bit, "e0": first_bit["e0"].upper()}]),
                ValueError,
            ),
        }
        for label, (data, error) in cases.items():
            with self.subTest(label), self.assertRaises(error):
                RangeProof.from_dict(data)


if __name__ == "__main__":
    unittest.main()
