"""Flask web app for the auction: the page plus the /api blueprint."""

import os
from collections.abc import Mapping
from typing import Any

from flask import Flask, Response, render_template, request

from crypto_auction.service import AuctionService
from crypto_auction.web import api

# Only this origin's own scripts, styles and connections; no inline code, no
# plugins, no framing. The page is written for it (no inline handlers or
# styles), so markup injected into it could not run script.
CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ]
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",  # serve scripts and styles only as what they are
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",  # frame-ancestors, for browsers that predate it
    "Cross-Origin-Opener-Policy": "same-origin",
}


def _add_security_headers(response: Response) -> Response:
    response.headers.update(SECURITY_HEADERS)
    # API answers carry tokens (when an auction is created) and live state:
    # no browser or proxy may keep a copy.
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def create_app(
    config: Mapping[str, Any] | None = None, service: AuctionService | None = None
) -> Flask:
    """
    Build the web app (also found by `flask --app crypto_auction.web run`).

    The auctions are stored in the SQLite file named by the DATABASE setting:
    from `config`, else from the CRYPTO_AUCTION_DATABASE environment variable,
    else auctions.sqlite3 in the app's instance folder. Pass `service` to
    supply the AuctionService instead, e.g. one whose clock a test controls.
    """
    app = Flask(__name__)
    # Larger bodies are refused (413) before they are read; see the constant.
    app.config["MAX_CONTENT_LENGTH"] = api.MAX_REQUEST_BYTES
    app.config.from_prefixed_env("CRYPTO_AUCTION")
    if config is not None:
        app.config.update(config)
    if service is None:
        database = app.config.get("DATABASE") or os.path.join(app.instance_path, "auctions.sqlite3")
        service = AuctionService(database)
    app.extensions[api.SERVICE_KEY] = service
    app.after_request(_add_security_headers)
    api.register_error_handlers(app)
    app.register_blueprint(api.bp)
    app.add_url_rule("/", "index", _index)
    return app


def _index() -> str:
    return render_template("index.html")
