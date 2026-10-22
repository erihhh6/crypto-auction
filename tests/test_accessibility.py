"""
Static accessibility checks on the page as served: labels, live regions and
references a screen reader relies on. (What the script builds and how focus
moves are covered by tests/js.)
"""

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

from crypto_auction.web import create_app
from tests.support import temporary_database

STYLE_CSS = Path(__file__).parents[1] / "src/crypto_auction/web/static/style.css"


def _luminance(hex_colour):
    channels = [int(hex_colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(a, b):
    """The WCAG contrast ratio of two #rrggbb colours."""
    lighter, darker = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


class _Elements(HTMLParser):
    """Every start tag of a page, with its attributes."""

    def __init__(self):
        super().__init__()
        self.elements = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class TestPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test = unittest.TestCase()
        client = create_app({"TESTING": True, "DATABASE": temporary_database(test)}).test_client()
        parser = _Elements()
        parser.feed(client.get("/").get_data(as_text=True))
        test.doCleanups()
        cls.elements = parser.elements
        cls.ids = {attrs["id"]: (tag, attrs) for tag, attrs in parser.elements if "id" in attrs}

    def test_each_view_is_the_main_landmark_while_it_shows(self):
        # Several <main> elements are allowed while all but one are hidden.
        for view in ("setup-panel", "auction-view"):
            self.assertEqual(self.ids[view][0], "main", view)
        self.assertIn("hidden", self.ids["auction-view"][1])

    def test_the_language_is_declared(self):
        [html] = [attrs for tag, attrs in self.elements if tag == "html"]
        self.assertEqual(html.get("lang"), "en")

    def test_every_input_has_a_label(self):
        labelled = {
            attrs["for"] for tag, attrs in self.elements if tag == "label" and "for" in attrs
        }
        for tag, attrs in self.elements:
            if tag == "input":
                with self.subTest(attrs.get("id") or attrs.get("class")):
                    named = "aria-label" in attrs or "aria-labelledby" in attrs
                    self.assertTrue(named or attrs.get("id") in labelled, attrs)

    def test_aria_references_point_at_elements_that_exist(self):
        for tag, attrs in self.elements:
            for name in ("aria-labelledby", "aria-describedby", "for"):
                for ref in attrs.get(name, "").split():
                    with self.subTest(f"{tag} {name}={ref}"):
                        self.assertIn(ref, self.ids)

    def test_the_logs_are_read_out_as_they_grow(self):
        for log in ("public-log", "private-log"):
            _, attrs = self.ids[log]
            self.assertEqual(attrs.get("role"), "log")
            self.assertTrue(attrs.get("aria-label"), log)
        self.assertEqual(self.ids["announcer"][1].get("role"), "status")
        self.assertEqual(self.ids["setup-error"][1].get("role"), "alert")

    def test_the_winner_is_shown_in_a_labelled_native_dialog(self):
        tag, attrs = self.ids["winner-modal"]
        self.assertEqual(tag, "dialog")  # focus trap, inert page and Escape, by the browser
        self.assertIn(attrs["aria-labelledby"], self.ids)

    def test_decorative_symbols_are_hidden_from_screen_readers(self):
        decorative = {"brand-icon", "phase-arrow", "winner-trophy"}
        for _tag, attrs in self.elements:
            if set(attrs.get("class", "").split()) & decorative:
                with self.subTest(attrs["class"]):
                    self.assertEqual(attrs.get("aria-hidden"), "true")


class TestColours(unittest.TestCase):
    def test_text_has_enough_contrast_on_every_background(self):
        # WCAG AA: 4.5:1 for normal text. Every colour the stylesheet gives
        # text (color: var(--…)) must reach it on every background colour.
        css = STYLE_CSS.read_text(encoding="utf-8")
        colours = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", css))
        backgrounds = {n: c for n, c in colours.items() if n.startswith("bg-")}
        text_colours = set(re.findall(r"(?<![\w-])color:\s*var\(--([\w-]+)\)", css))
        self.assertIn("text-dim", text_colours)
        for name in text_colours - {"tone-text"}:  # tone-text: one of the text-* below
            for background, value in backgrounds.items():
                with self.subTest(f"{name} on {background}"):
                    self.assertGreaterEqual(contrast(colours[name], value), 4.5)


if __name__ == "__main__":
    unittest.main()
