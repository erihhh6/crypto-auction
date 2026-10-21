"""Tests for crypto_auction.bit_proof"""

import secrets
import unittest
from dataclasses import replace

from crypto_auction.bit_proof import BitProof, _challenge, prove_bit, verify_bit
from crypto_auction.pedersen import G, N, commit, commit_with

CONTEXT = b"auction-1/bidder-0/bit-0"


def honest_proof(bit, context=CONTEXT):
    c = commit(bit)
    return c, prove_bit(c.point, bit, c.blinding, context)


class TestCompleteness(unittest.TestCase):
    def test_honest_proofs_verify_for_both_bits(self):
        for bit in (0, 1):
            with self.subTest(bit=bit):
                c, proof = honest_proof(bit)
                self.assertTrue(verify_bit(c.point, proof, CONTEXT))

    def test_proofs_are_randomised(self):
        c = commit(1)
        first = prove_bit(c.point, 1, c.blinding, CONTEXT)
        second = prove_bit(c.point, 1, c.blinding, CONTEXT)
        self.assertNotEqual(first, second)
        self.assertTrue(verify_bit(c.point, second, CONTEXT))


class TestProverRefusesFalseStatements(unittest.TestCase):
    def test_value_that_is_not_a_bit(self):
        c = commit(2)
        for claimed in (0, 1, 2):
            with self.subTest(claimed=claimed), self.assertRaises(ValueError):
                prove_bit(c.point, claimed, c.blinding, CONTEXT)

    def test_wrong_blinding(self):
        c = commit(1)
        with self.assertRaises(ValueError):
            prove_bit(c.point, 1, (c.blinding + 1) % N, CONTEXT)


class TestSoundness(unittest.TestCase):
    def test_random_proof_for_a_commitment_to_two_is_rejected(self):
        c = commit(2)
        forged = BitProof(*(secrets.randbelow(N) for _ in range(4)))
        self.assertFalse(verify_bit(c.point, forged, CONTEXT))

    def test_simulating_both_branches_fails(self):
        # The forger's strategy against a challenge that does not hash the
        # announcements: fix the challenge first, then simulate both branches
        # (pick e0, s0, s1 freely; e1 = challenge - e0). Each branch then passes
        # its Schnorr check, so only hashing the announcements stops this.
        c = commit(2)
        challenge = _challenge(c.point, CONTEXT, G, G)  # announcements not yet known
        e0, s0, s1 = (secrets.randbelow(N) for _ in range(3))
        forged = BitProof(e0=e0, s0=s0, e1=(challenge - e0) % N, s1=s1)
        self.assertFalse(verify_bit(c.point, forged, CONTEXT))

    def test_proof_does_not_transfer_to_another_commitment(self):
        _, proof = honest_proof(1)
        for other in (commit(1).point, commit(0).point):
            with self.subTest(other=other):
                self.assertFalse(verify_bit(other, proof, CONTEXT))

    def test_proof_is_bound_to_its_context(self):
        # The context names where the proof is used; a proof made for one
        # auction or bidder must not be accepted for another.
        c, proof = honest_proof(0)
        self.assertFalse(verify_bit(c.point, proof, b"auction-2/bidder-0/bit-0"))

    def test_any_tampered_field_is_rejected(self):
        c, proof = honest_proof(1)
        for field in ("e0", "s0", "e1", "s1"):
            with self.subTest(field=field):
                tampered = replace(proof, **{field: (getattr(proof, field) + 1) % N})
                self.assertFalse(verify_bit(c.point, tampered, CONTEXT))

    def test_swapped_branches_are_rejected(self):
        c, proof = honest_proof(0)
        swapped = BitProof(e0=proof.e1, s0=proof.s1, e1=proof.e0, s1=proof.s0)
        self.assertFalse(verify_bit(c.point, swapped, CONTEXT))


class TestCanonicalScalars(unittest.TestCase):
    def test_non_canonical_scalars_are_rejected(self):
        # s and s + n act identically on curve points, so without this check a
        # third party could change a valid proof's bytes without the secret.
        c, proof = honest_proof(1)
        cases = {
            "s0 + n": replace(proof, s0=proof.s0 + N),
            "negative e1": replace(proof, e1=proof.e1 - N),
            "bool": replace(proof, e0=True),
            "float": replace(proof, s1=float(proof.s1)),
        }
        for label, bad in cases.items():
            with self.subTest(label):
                self.assertFalse(verify_bit(c.point, bad, CONTEXT))


class TestDegenerateInputs(unittest.TestCase):
    def test_announcement_at_infinity_is_rejected_not_raised(self):
        # For C = x·H, choosing e0 = 1 and s0 = x makes A0 = s0·H - e0·C the
        # point at infinity, which has no encoding to hash.
        x = secrets.randbelow(N)
        proof = BitProof(e0=1, s0=x, e1=5, s1=7)
        self.assertFalse(verify_bit(commit_with(0, x), proof, CONTEXT))

    def test_commitment_at_infinity(self):
        infinity = commit_with(0, 0)
        with self.assertRaises(ValueError):
            prove_bit(infinity, 0, 0, CONTEXT)
        self.assertFalse(verify_bit(infinity, BitProof(1, 2, 3, 4), CONTEXT))


if __name__ == "__main__":
    unittest.main()
