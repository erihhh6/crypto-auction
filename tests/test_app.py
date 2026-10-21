"""Tests for app.py — development server entry point."""

import os
import runpy
import unittest
from pathlib import Path
from unittest import mock

APP_PATH = Path(__file__).resolve().parent.parent / "app.py"


def run_entry_point(**env):
    """
    Execute app.py as __main__ with the server stubbed out.

    Returns the keyword arguments Flask passed to werkzeug's run_simple,
    which is where the debugger and reloader are switched on or off.
    """
    with (
        mock.patch.dict(os.environ, env),
        mock.patch("werkzeug.serving.run_simple") as run_simple,
    ):
        if "FLASK_DEBUG" not in env:
            os.environ.pop("FLASK_DEBUG", None)
        runpy.run_path(str(APP_PATH), run_name="__main__")
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
