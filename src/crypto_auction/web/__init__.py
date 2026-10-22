"""Flask web app for the auction: the page plus the /api blueprint."""

import os
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

    The auctions are stored in the SQLite file named by the DATABASE setting:
    from `config`, else from the CRYPTO_AUCTION_DATABASE environment variable,
    else auctions.sqlite3 in the app's instance folder. Pass `service` to
    supply the AuctionService instead, e.g. one whose clock a test controls.
    """
    app = Flask(__name__)
    app.config.from_prefixed_env("CRYPTO_AUCTION")
    if config is not None:
        app.config.update(config)
    if service is None:
        database = app.config.get("DATABASE") or os.path.join(app.instance_path, "auctions.sqlite3")
        service = AuctionService(database)
    app.extensions[api.SERVICE_KEY] = service
    api.register_error_handlers(app)
    app.register_blueprint(api.bp)
    app.add_url_rule("/", "index", _index)
    return app


def _index() -> str:
    return render_template("index.html")
