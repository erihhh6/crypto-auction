"""Shared helpers for the test suite."""

import os
import tempfile

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


def temporary_database(test):
    """
    A path for a new SQLite database file, deleted when `test` ends.

    Deleting fails on Windows while a connection is still open, so this also
    checks that every operation closes its connection.
    """
    directory = tempfile.TemporaryDirectory()
    test.addCleanup(directory.cleanup)
    return os.path.join(directory.name, "auctions.sqlite3")


class FakeClock:
    """A clock for deadline tests: it stands still until the test moves it."""

    START = 1_800_000_000.0  # 2027-01-15 08:00:00 UTC

    def __init__(self):
        self.now = self.START

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds
