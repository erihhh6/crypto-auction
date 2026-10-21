"""Tests for the development server entry point (python -m crypto_auction.web)."""

import os
import runpy
import unittest
from unittest import mock


def run_entry_point(**env):
    """
    Run `python -m crypto_auction.web` in-process with the server stubbed out.

    Returns the keyword arguments Flask passed to werkzeug's run_simple,
    which is where the debugger and reloader are switched on or off.
    """
    with (
        mock.patch.dict(os.environ, env),
        mock.patch("werkzeug.serving.run_simple") as run_simple,
    ):
        if "FLASK_DEBUG" not in env:
            os.environ.pop("FLASK_DEBUG", None)
        runpy.run_module("crypto_auction.web", run_name="__main__")
    return run_simple.call_args.kwargs


class TestEntryPoint(unittest.TestCase):
    def test_debugger_disabled_by_default(self):
        options = run_entry_point()
        self.assertFalse(options["use_debugger"])
        self.assertFalse(options["use_reloader"])

    def test_debug_mode_is_opt_in_via_env(self):
        options = run_entry_point(FLASK_DEBUG="1")
        self.assertTrue(options["use_debugger"])


if __name__ == "__main__":
    unittest.main()
