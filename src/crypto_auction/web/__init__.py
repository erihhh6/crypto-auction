"""Flask web app for the auction: the page plus the /api blueprint."""

from collections.abc import Mapping
from typing import Any

from flask import Flask, render_template

from crypto_auction.service import AuctionService
from crypto_auction.web import api


def create_app(
    config: Mapping[str, Any] | None = None, service: AuctionService | None = None
) -> Flask:
    """
    Build the web app (also found by `flask --app crypto_auction.web run`).

    Each app gets its own AuctionService, so separate apps (one per test, for
    instance) never share auction state: there is no module-level auction.
    Pass `service` to supply it, e.g. one whose clock a test controls.
    """
    app = Flask(__name__)
    if config is not None:
        app.config.update(config)
    app.extensions[api.SERVICE_KEY] = service if service is not None else AuctionService()
    api.register_error_handlers(app)
    app.register_blueprint(api.bp)
    app.add_url_rule("/", "index", _index)
    return app


def _index() -> str:
    return render_template("index.html")
