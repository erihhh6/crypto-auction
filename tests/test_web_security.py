"""
Tests for the web app's browser-side defences: the security headers it sends,
and that the page holds nothing its Content-Security-Policy would block.
"""

import re
import unittest
from unittest import mock

from crypto_auction.auction import Auction
from crypto_auction.web import CONTENT_SECURITY_POLICY, SECURITY_HEADERS, create_app
from tests.support import temporary_database

# What the policy forbids in markup: inline handlers (onclick="...") and
# style attributes. (Script that builds markup is checked by the JS tests.)
INLINE_CODE = re.compile(r"""<[^>]*\s(?:on[a-z]+|style)\s*=""", re.IGNORECASE)


class WebTestCase(unittest.TestCase):
    def setUp(self):
        self.database = temporary_database(self)
        self.client = create_app({"TESTING": True, "DATABASE": self.database}).test_client()

    def create(self):
        body = {"item_name": "x", "min_bid": 1, "max_bid": 2, "bidders": ["A", "B"]}
        return self.client.post("/api/auctions", json=body)


class TestSecurityHeaders(WebTestCase):
    def assert_secured(self, resp):
        for header, value in SECURITY_HEADERS.items():
            self.assertEqual(resp.headers.get(header), value, header)

    def test_every_response_carries_them(self):
        self.create()
        for path in ("/", "/static/app.js", "/api/nope", f"/api/auctions/{'0' * 32}"):
            with self.subTest(path):
                resp = self.client.get(path)
                resp.close()  # a static file stays open until then
                self.assert_secured(resp)

    def test_so_do_unexpected_errors(self):
        # Outside TESTING mode Flask turns an unhandled exception into a 500.
        self.client = create_app({"DATABASE": self.database}).test_client()
        auction_id = self.create().get_json()["auction_id"]
        with mock.patch.object(Auction, "get_public_state", side_effect=RuntimeError):
            resp = self.client.get(f"/api/auctions/{auction_id}")
        self.assertEqual(resp.status_code, 500)
        self.assert_secured(resp)

    def test_the_policy_allows_no_inline_code(self):
        directives = dict(d.split(" ", 1) for d in CONTENT_SECURITY_POLICY.split("; "))
        for directive in ("default-src", "script-src", "style-src", "connect-src"):
            self.assertEqual(directives[directive], "'self'", directive)
        self.assertEqual(directives["object-src"], "'none'")
        self.assertEqual(directives["frame-ancestors"], "'none'")
        self.assertNotIn("unsafe", CONTENT_SECURITY_POLICY)

    def test_api_answers_are_never_cached(self):
        # The answer to creating an auction carries every token.
        created = self.create()
        self.assertEqual(created.headers.get("Cache-Control"), "no-store")
        state = self.client.get(created.headers["Location"])
        self.assertEqual(state.headers.get("Cache-Control"), "no-store")
        self.assertNotEqual(self.client.get("/").headers.get("Cache-Control"), "no-store")


class TestNoInlineCode(WebTestCase):
    def test_the_page_has_no_inline_handlers_styles_or_scripts(self):
        html = self.client.get("/").get_data(as_text=True)
        markup = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)  # comments may mention them
        self.assertEqual(INLINE_CODE.findall(markup), [])
        self.assertNotIn("<style", markup)
        for script in re.findall(r"<script[^>]*>", markup):
            self.assertIn(" src=", script, "inline script")


if __name__ == "__main__":
    unittest.main()
