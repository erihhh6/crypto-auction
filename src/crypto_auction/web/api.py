"""
REST API for the sealed-bid cryptographic auction demo (blueprint at /api).

Security note (for CV / README):
  In a production system, randomness_hex (the commitment's blinding factor r)
  would NEVER pass through the server. The bidder would generate it locally in
  their browser, compute the commitment and the range proof client-side, and
  only send those. In this demo the server generates it for simplicity and
  returns it ONCE to the frontend, which then stores it in JS memory. It is
  never re-sent to the server except at the prove and reveal steps (where it is
  needed to compute the ZK proof and verify the commitment opening
  respectively). The server discards it after each use.

Endpoints:
  POST /api/create   — create a new auction session
  GET  /api/state    — fetch current public state
  POST /api/commit   — submit a bid commitment (server generates commitment)
  POST /api/prove    — generate and submit ZK range proof
  POST /api/reveal   — reveal bid + blinding factor, verify commitment
  POST /api/reset    — reset the auction session entirely

Request rules:
  Every POST must be sent as application/json (415 otherwise) with a JSON object
  body (400 otherwise). Integers must lie in [0, 2**53 - 1]. Every error,
  including unknown routes and unexpected server errors, is returned as
  {"success": false, "error": "<reason>"}.

Encodings: commitments are compressed secp256k1 points (66 lowercase hex chars),
the blinding factor a scalar below the group order (64 lowercase hex chars).
"""

import json
from typing import Any, NoReturn, cast

from flask import Blueprint, Flask, Response, abort, current_app, jsonify, request
from flask.typing import ResponseReturnValue
from werkzeug.exceptions import HTTPException

from crypto_auction.auction import AuctionConfig
from crypto_auction.pedersen import decode_scalar, encode_point, encode_scalar
from crypto_auction.service import AuctionRuleError, AuctionService, NoAuctionError

# Largest integer the API accepts. JSON numbers above 2**53 - 1 are not exact
# in JavaScript (RFC 7493, I-JSON), and the browser handles bids as numbers: a
# larger typed bid would silently become a different one. It is far below the
# range proof's own limit, range_proof.MAX_VALUE = 2**64 - 1.
MAX_JSON_INT = 2**53 - 1
MAX_BIDDERS = 10
MAX_NAME_LENGTH = 100

# Key under which create_app() stores each app's AuctionService.
SERVICE_KEY = "crypto_auction"

bp = Blueprint("api", __name__, url_prefix="/api")


def _service() -> AuctionService:
    return cast(AuctionService, current_app.extensions[SERVICE_KEY])


# ---------------------------------------------------------------------------
# Errors and request validation
# ---------------------------------------------------------------------------


def _error(status: int, message: str) -> Response:
    response = jsonify({"success": False, "error": message})
    response.status_code = status
    return response


def json_http_error(exc: HTTPException) -> ResponseReturnValue:
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


def _no_auction(exc: NoAuctionError) -> ResponseReturnValue:
    return _error(404, str(exc))


def _rule_violation(exc: AuctionRuleError) -> ResponseReturnValue:
    return _error(400, str(exc))


def register_error_handlers(app: Flask) -> None:
    # App-wide rather than on the blueprint, so that unknown routes (which
    # never reach a blueprint) also get the JSON envelope.
    app.register_error_handler(HTTPException, json_http_error)
    app.register_error_handler(NoAuctionError, _no_auction)
    app.register_error_handler(AuctionRuleError, _rule_violation)


@bp.before_request
def require_json_posts() -> None:
    """
    Reject state-changing requests that are not application/json.

    Browsers send cross-site "simple" requests (HTML forms, text/plain bodies)
    without a CORS preflight, so accepting them would let any website drive this
    API from a visitor's browser (CSRF). A cross-origin application/json request
    needs a preflight, which this app never approves.
    """
    if request.method == "POST" and not request.is_json:
        abort(415, description="Request body must be JSON (Content-Type: application/json).")


def _bad_request(message: str) -> NoReturn:
    abort(400, description=message)


def _json_object() -> dict[str, Any]:
    data = request.get_json(silent=True)  # None for malformed JSON and for `null`
    if not isinstance(data, dict):
        _bad_request("Request body must be a JSON object.")
    return data


def _field(data: dict[str, Any], name: str) -> Any:
    if name not in data:
        _bad_request(f"Missing field '{name}'.")
    return data[name]


def _int_field(data: dict[str, Any], name: str) -> int:
    """A JSON integer in [0, MAX_JSON_INT]."""
    value = _field(data, name)
    # bool is a subclass of int and a float would be truncated silently, so
    # only genuine JSON integers are accepted.
    if isinstance(value, bool) or not isinstance(value, int):
        _bad_request(f"'{name}' must be an integer.")
    if not 0 <= value <= MAX_JSON_INT:
        _bad_request(f"'{name}' must be between 0 and {MAX_JSON_INT}.")
    return value


def _str_field(data: dict[str, Any], name: str) -> str:
    value = _field(data, name)
    if not isinstance(value, str):
        _bad_request(f"'{name}' must be a string.")
    return value


def _name(value: object, label: str) -> str:
    """A display name: a non-blank string of bounded length, trimmed."""
    if not isinstance(value, str) or not value.strip():
        _bad_request(f"{label} must be a non-empty string.")
    name = value.strip()
    if len(name) > MAX_NAME_LENGTH:
        _bad_request(f"{label} must be at most {MAX_NAME_LENGTH} characters.")
    return name


def _blinding_field(data: dict[str, Any]) -> int:
    """The commitment's blinding factor, sent as 'randomness_hex'."""
    value = _str_field(data, "randomness_hex")
    # Reject malformed input before it reaches the auction: a typo should be a
    # 400 the client can retry, not a failed reveal that disqualifies the bidder.
    try:
        return decode_scalar(value)
    except ValueError:
        _bad_request(
            "'randomness_hex' must be 64 lowercase hexadecimal characters "
            "encoding a number below the curve order."
        )


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


@bp.post("/create")
def create_auction() -> ResponseReturnValue:
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
    data = _json_object()

    item_name = _name(_field(data, "item_name"), "'item_name'")
    min_bid = _int_field(data, "min_bid")
    max_bid = _int_field(data, "max_bid")
    raw_names = _field(data, "bidders")
    if not isinstance(raw_names, list):
        _bad_request("'bidders' must be a list of names.")
    bidder_names = [_name(n, "Each bidder name") for n in raw_names]

    if min_bid >= max_bid:
        _bad_request("min_bid must be less than max_bid.")
    if not 2 <= len(bidder_names) <= MAX_BIDDERS:
        _bad_request(f"Between 2 and {MAX_BIDDERS} bidders are required.")
    # Names are how results identify bidders, so they must be distinguishable.
    if len({n.casefold() for n in bidder_names}) != len(bidder_names):
        _bad_request("Bidder names must be unique.")

    config = AuctionConfig(
        min_bid=min_bid,
        max_bid=max_bid,
        item_name=item_name,
        bidder_names=tuple(bidder_names),
    )
    auction = _service().create(config)

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


@bp.get("/state")
def get_state() -> ResponseReturnValue:
    """
    Return the complete public state of the current auction.
    """
    return jsonify({"success": True, **_service().public_state()})


# ---------------------------------------------------------------------------
# Commit (Phase 1)
# ---------------------------------------------------------------------------


@bp.post("/commit")
def submit_commit() -> ResponseReturnValue:
    """
    Generate a commitment for a bidder's bid and register it.

    Body JSON:
      { "bidder_id": str, "bid": int }

    The server computes the Pedersen commitment C = bid·G + r·H with a random
    blinding factor r, stores C, and returns r (as randomness_hex) to the
    client ONCE. The client must store it; the server does NOT retain it.

    Response:
      {
        "success":        bool,
        "commitment_hex": str,   -- public; compressed point, 66 hex chars
        "randomness_hex": str,   -- PRIVATE blinding factor r, 64 hex chars
        "phase":          str
      }
    """
    service = _service()
    service.require_auction()  # 404 takes precedence over body validation
    data = _json_object()
    bidder_id = _str_field(data, "bidder_id")
    bid = _int_field(data, "bid")

    c, result = service.commit(bidder_id, bid)

    return jsonify(
        {
            "success": True,
            "commitment_hex": encode_point(c.point),
            "randomness_hex": encode_scalar(c.blinding),  # returned once; not stored
            "phase": result.phase.value,
            "message": result.message,
        }
    )


# ---------------------------------------------------------------------------
# Prove (Phase 2)
# ---------------------------------------------------------------------------


@bp.post("/prove")
def submit_prove() -> ResponseReturnValue:
    """
    Generate and verify a ZK range proof for a bidder.

    Body JSON:
      { "bidder_id": str, "bid": int, "randomness_hex": str }

    The server generates the range proof using the private (bid, blinding
    factor) sent by the client, verifies it, and records the result.
    After this call the server discards the private values.

    Response:
      {
        "success":      bool,
        "proof_valid":  bool,
        "proof_public": { "low": {...}, "high": {...} },  -- RangeProof.to_dict()
        "phase":        str
      }
    """
    service = _service()
    service.require_auction()  # 404 takes precedence over body validation
    data = _json_object()
    bidder_id = _str_field(data, "bidder_id")
    bid = _int_field(data, "bid")
    blinding = _blinding_field(data)

    proof, result = service.prove(bidder_id, bid, blinding)

    return jsonify(
        {
            "success": True,
            "proof_valid": result.proof_valid,
            "proof_public": proof.to_dict(),
            "phase": result.phase.value,
            "message": result.message,
        }
    )


# ---------------------------------------------------------------------------
# Reveal (Phase 3)
# ---------------------------------------------------------------------------


@bp.post("/reveal")
def submit_reveal() -> ResponseReturnValue:
    """
    Reveal a bidder's (bid, blinding factor) and verify against their commitment.

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
    service = _service()
    service.require_auction()  # 404 takes precedence over body validation
    data = _json_object()
    bidder_id = _str_field(data, "bidder_id")
    bid = _int_field(data, "bid")
    blinding = _blinding_field(data)

    result = service.reveal(bidder_id, bid, blinding)

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


@bp.post("/reset")
def reset() -> ResponseReturnValue:
    """
    Completely reset the auction session.

    The current auction state is discarded; a new /api/create call is required.
    """
    _service().reset()
    return jsonify({"success": True, "message": "Auction reset. Ready for a new session."})
