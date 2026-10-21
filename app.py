"""
CryptoAuction Flask Application
=================================

REST API for the sealed-bid cryptographic auction demo.

Security note (for CV / README):
  In a production system, randomness_hex would NEVER pass through the server.
  The bidder would generate it locally in their browser, compute the commitment
  client-side, and only send the commitment hash. In this demo the server
  generates it for simplicity and returns it ONCE to the frontend, which then
  stores it in JS memory. It is never re-sent to the server except at the prove
  and reveal steps (where it is needed to compute the ZK proof and verify the
  commitment opening respectively). The server discards it after each use.

Endpoints:
  POST /api/create   — create a new auction session
  GET  /api/state    — fetch current public state
  POST /api/commit   — submit a bid commitment (server generates commitment)
  POST /api/prove    — generate and submit ZK range proof
  POST /api/reveal   — reveal bid + randomness, verify commitment
  POST /api/reset    — reset the auction session entirely

Request rules:
  Every POST must be sent as application/json (415 otherwise) with a JSON object
  body (400 otherwise). Integers must lie in [0, 2**53 - 1]. Every error,
  including unknown routes and unexpected server errors, is returned as
  {"success": false, "error": "<reason>"}.
"""

import json
import re

from flask import Flask, abort, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from crypto_auction.auction import Auction, AuctionConfig
from crypto_auction.commitment import commit
from crypto_auction.zkp import prove_range

app = Flask(__name__)

# Largest integer the API accepts. JSON numbers above 2**53 - 1 are not exact
# in JavaScript (RFC 7493, I-JSON), and the browser handles bids as numbers: a
# larger typed bid would silently become a different one. It is far below the
# commitment's own limit, MAX_BID = 2**64 - 1.
MAX_JSON_INT = 2**53 - 1
MAX_BIDDERS = 10
MAX_NAME_LENGTH = 100
# 32 random bytes, hex-encoded: the only randomness format commit() produces.
RANDOMNESS_HEX = re.compile(r"[0-9a-fA-F]{64}")

# Single in-memory auction session (one game per server process)
auction: Auction | None = None


# ---------------------------------------------------------------------------
# Errors and request validation
# ---------------------------------------------------------------------------


@app.errorhandler(HTTPException)
def json_error(exc: HTTPException):
    """
    Render every HTTP error as the API's JSON error envelope.

    This also covers unhandled exceptions, which Flask turns into a generic 500
    whose description reveals nothing about the cause. Werkzeug's response is
    reused so headers such as Allow (on 405) are kept.
    """
    response = exc.get_response()
    response.data = json.dumps({"success": False, "error": exc.description})
    response.content_type = "application/json"
    return response


@app.before_request
def require_json_posts():
    """
    Reject state-changing requests that are not application/json.

    Browsers send cross-site "simple" requests (HTML forms, text/plain bodies)
    without a CORS preflight, so accepting them would let any website drive this
    API from a visitor's browser (CSRF). A cross-origin application/json request
    needs a preflight, which this app never approves.
    """
    if request.method == "POST" and not request.is_json:
        abort(415, description="Request body must be JSON (Content-Type: application/json).")


def _require_auction() -> Auction:
    if auction is None:
        abort(404, description="No auction created yet.")
    return auction


def _json_object() -> dict:
    data = request.get_json(silent=True)  # None for malformed JSON and for `null`
    if not isinstance(data, dict):
        abort(400, description="Request body must be a JSON object.")
    return data


def _field(data: dict, name: str):
    if name not in data:
        abort(400, description=f"Missing field '{name}'.")
    return data[name]


def _int_field(data: dict, name: str) -> int:
    """A JSON integer in [0, MAX_JSON_INT]."""
    value = _field(data, name)
    # bool is a subclass of int and a float would be truncated silently, so
    # only genuine JSON integers are accepted.
    if isinstance(value, bool) or not isinstance(value, int):
        abort(400, description=f"'{name}' must be an integer.")
    if not 0 <= value <= MAX_JSON_INT:
        abort(400, description=f"'{name}' must be between 0 and {MAX_JSON_INT}.")
    return value


def _str_field(data: dict, name: str) -> str:
    value = _field(data, name)
    if not isinstance(value, str):
        abort(400, description=f"'{name}' must be a string.")
    return value


def _name(value, label: str) -> str:
    """A display name: a non-blank string of bounded length, trimmed."""
    if not isinstance(value, str) or not value.strip():
        abort(400, description=f"{label} must be a non-empty string.")
    name = value.strip()
    if len(name) > MAX_NAME_LENGTH:
        abort(400, description=f"{label} must be at most {MAX_NAME_LENGTH} characters.")
    return name


def _randomness_field(data: dict) -> str:
    value = _str_field(data, "randomness_hex")
    # Reject malformed input before it reaches the auction: a typo should be a
    # 400 the client can retry, not a failed reveal that disqualifies the bidder.
    if not RANDOMNESS_HEX.fullmatch(value):
        abort(400, description="'randomness_hex' must be 64 hexadecimal characters.")
    return value


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


@app.route("/api/create", methods=["POST"])
def create_auction():
    """
    Create a new auction session.

    Body JSON:
      {
        "item_name": str,
        "min_bid":   int,
        "max_bid":   int,
        "bidders":   [str, ...]   -- list of bidder display names
      }

    Response:
      {
        "success":    bool,
        "item_name":  str,
        "min_bid":    int,
        "max_bid":    int,
        "bidders":    [{"bidder_id": str, "name": str}, ...]
      }
    """
    global auction
    data = _json_object()

    item_name = _name(_field(data, "item_name"), "'item_name'")
    min_bid = _int_field(data, "min_bid")
    max_bid = _int_field(data, "max_bid")
    raw_names = _field(data, "bidders")
    if not isinstance(raw_names, list):
        abort(400, description="'bidders' must be a list of names.")
    bidder_names = [_name(n, "Each bidder name") for n in raw_names]

    if min_bid >= max_bid:
        abort(400, description="min_bid must be less than max_bid.")
    if not 2 <= len(bidder_names) <= MAX_BIDDERS:
        abort(400, description=f"Between 2 and {MAX_BIDDERS} bidders are required.")
    # Names are how results identify bidders, so they must be distinguishable.
    if len({n.casefold() for n in bidder_names}) != len(bidder_names):
        abort(400, description="Bidder names must be unique.")

    config = AuctionConfig(
        min_bid=min_bid,
        max_bid=max_bid,
        item_name=item_name,
        bidder_names=tuple(bidder_names),
    )
    auction = Auction(config)

    bidders_info = [{"bidder_id": bid_id, "name": b.name} for bid_id, b in auction.bidders.items()]

    return jsonify(
        {
            "success": True,
            "item_name": item_name,
            "min_bid": min_bid,
            "max_bid": max_bid,
            "bidders": bidders_info,
        }
    )


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


@app.route("/api/state", methods=["GET"])
def get_state():
    """
    Return the complete public state of the current auction.
    """
    current = _require_auction()
    return jsonify({"success": True, **current.get_public_state()})


# ---------------------------------------------------------------------------
# Commit (Phase 1)
# ---------------------------------------------------------------------------


@app.route("/api/commit", methods=["POST"])
def submit_commit():
    """
    Generate a commitment for a bidder's bid and register it.

    Body JSON:
      { "bidder_id": str, "bid": int }

    The server computes C = SHA256(bid_bytes || randomness), stores C,
    and returns randomness_hex to the client ONCE. The client must store it;
    the server does NOT retain randomness_hex.

    Response:
      {
        "success":        bool,
        "commitment_hex": str,   -- public
        "randomness_hex": str,   -- PRIVATE — store locally, never resend unnecessarily
        "phase":          str
      }
    """
    current = _require_auction()
    data = _json_object()
    bidder_id = _str_field(data, "bidder_id")
    bid = _int_field(data, "bid")

    if not current.config.min_bid <= bid <= current.config.max_bid:
        abort(
            400,
            description=(
                f"Bid {bid} is outside the allowed range "
                f"[{current.config.min_bid}, {current.config.max_bid}]."
            ),
        )

    try:
        c = commit(bid)
        result = current.submit_commitment(bidder_id, c.commitment_hex)
    except ValueError as exc:
        abort(400, description=str(exc))

    return jsonify(
        {
            "success": True,
            "commitment_hex": c.commitment_hex,
            "randomness_hex": c.randomness_hex,  # returned once; server does not store it
            "phase": result.phase.value,
            "message": result.message,
        }
    )


# ---------------------------------------------------------------------------
# Prove (Phase 2)
# ---------------------------------------------------------------------------


@app.route("/api/prove", methods=["POST"])
def submit_prove():
    """
    Generate and verify a ZK range proof for a bidder.

    Body JSON:
      { "bidder_id": str, "bid": int, "randomness_hex": str }

    The server generates the range proof using the private (bid, randomness)
    sent by the client, verifies it, and records the result.
    After this call the server discards the private values.

    Response:
      {
        "success":      bool,
        "proof_valid":  bool,
        "proof_public": { ... RangeProof fields ... },
        "phase":        str
      }
    """
    current = _require_auction()
    data = _json_object()
    bidder_id = _str_field(data, "bidder_id")
    bid = _int_field(data, "bid")
    randomness_hex = _randomness_field(data)

    if bidder_id not in current.bidders:
        abort(400, description=f"Unknown bidder_id '{bidder_id}'.")

    commitment_hex = current.bidders[bidder_id].commitment_hex
    if commitment_hex is None:
        abort(400, description="Bidder has not committed yet.")

    try:
        proof = prove_range(
            bid,
            randomness_hex,
            commitment_hex,
            current.config.min_bid,
            current.config.max_bid,
        )
    except ValueError as exc:
        abort(400, description=str(exc))

    proof_dict = proof.to_dict()

    try:
        result = current.submit_proof(bidder_id, proof_dict)
    except ValueError as exc:
        abort(400, description=str(exc))

    return jsonify(
        {
            "success": True,
            "proof_valid": result.proof_valid,
            "proof_public": proof_dict,
            "phase": result.phase.value,
            "message": result.message,
        }
    )


# ---------------------------------------------------------------------------
# Reveal (Phase 3)
# ---------------------------------------------------------------------------


@app.route("/api/reveal", methods=["POST"])
def submit_reveal():
    """
    Reveal a bidder's (bid, randomness) and verify against their commitment.

    Body JSON:
      { "bidder_id": str, "bid": int, "randomness_hex": str }

    Response:
      {
        "success":  bool,
        "verified": bool,
        "phase":    str,
        "winner":   { "bidder_id", "name", "bid", "commitment_hex" } | null
      }
    """
    current = _require_auction()
    data = _json_object()
    bidder_id = _str_field(data, "bidder_id")
    bid = _int_field(data, "bid")
    randomness_hex = _randomness_field(data)

    try:
        result = current.submit_reveal(bidder_id, bid, randomness_hex)
    except ValueError as exc:
        abort(400, description=str(exc))

    return jsonify(
        {
            "success": True,
            "verified": result.verified,
            "phase": result.phase.value,
            "message": result.message,
            "winner": result.winner.to_dict() if result.winner else None,
        }
    )


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


@app.route("/api/reset", methods=["POST"])
def reset():
    """
    Completely reset the auction session.

    The current auction state is discarded; a new /api/create call is required.
    """
    global auction
    auction = None
    return jsonify({"success": True, "message": "Auction reset. Ready for a new session."})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Debug mode is opt-in via FLASK_DEBUG=1 (read by app.run) or
    # `flask --app app run --debug`: the Werkzeug debugger serves an
    # interactive Python console, so it must never be on by default.
    app.run(port=5000)
