"""Shared helpers for the test suite."""

import os

import pytest

from crypto_auction.zkp import RangeProof, _fiat_shamir_challenge


def known_bug(reason, *, raises=AssertionError):
    """
    Mark a test that asserts the *correct* behaviour for a known, unfixed bug.

    The test is expected to fail, and only by raising `raises`, so a broken
    test cannot pass itself off as the known bug. Strict mode turns an
    unexpected pass into a failure: the commit that fixes the bug must also
    remove this marker.
    """
    return pytest.mark.xfail(reason=reason, raises=raises, strict=True)


def forged_range_proof(commitment_hex, min_bid, max_bid):
    """
    Build a range "proof" from random bytes, without the bid or randomness.

    It passes every check verify_range_proof makes: the challenges are
    recomputed honestly and zero is a non-negative response.
    """
    commitment = bytes.fromhex(commitment_hex)
    c_low, c_high = os.urandom(32), os.urandom(32)
    return RangeProof(
        commitment_hex=commitment_hex,
        min_bid=min_bid,
        max_bid=max_bid,
        low_commitment_hex=c_low.hex(),
        low_challenge_hex=_fiat_shamir_challenge(commitment, c_low).hex(),
        low_response=0,
        high_commitment_hex=c_high.hex(),
        high_challenge_hex=_fiat_shamir_challenge(commitment, c_high).hex(),
        high_response=0,
    )
