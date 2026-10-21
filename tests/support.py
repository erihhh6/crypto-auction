"""Shared helpers for the test suite."""

import pytest


def known_bug(reason, *, raises=AssertionError):
    """
    Mark a test that asserts the *correct* behaviour for a known, unfixed bug.

    The test is expected to fail, and only by raising `raises`, so a broken
    test cannot pass itself off as the known bug. Strict mode turns an
    unexpected pass into a failure: the commit that fixes the bug must also
    remove this marker.
    """
    return pytest.mark.xfail(reason=reason, raises=raises, strict=True)
