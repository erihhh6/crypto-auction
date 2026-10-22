"""
REST API for the sealed-bid cryptographic auction demo (blueprint at /api).

Bidders compute their commitment and range proof themselves (in the browser,
static/auction-crypto.js) and send only those. The bid and its blinding factor
reach the server for the first time at the reveal.

Endpoints:
  POST /api/create   — create a new auction session
  GET  /api/state    — fetch current public state
  POST /api/commit   — submit a bid commitment (computed by the bidder)
  POST /api/prove    — submit a ZK range proof for the commitment
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
from crypto_auction.pedersen import decode_scalar
from crypto_auction.range_proof import RangeProof
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


def _proof_field(data: dict[str, Any]) -> dict[str, Any]:
    """A range proof in RangeProof.to_dict() format, checked to be well-formed."""
    value = _field(data, "proof")
    # Like the blinding factor: a proof that does not even parse is a client
    # bug to retry (400), while a well-formed proof that fails verification is
    # recorded as invalid by the auction.
    try:
        if not isinstance(value, dict):
            raise TypeError("not an object")
        RangeProof.from_dict(value)
    except (KeyError, TypeError, ValueError):
        _bad_request("'proof' is not a well-formed range proof.")
    return value


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
        "auction_id": str,   -- part of every range proof's context
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
            "auction_id": auction.auction_id,
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
    Register a bidder's commitment, computed by the bidder.

    Body JSON:
      { "bidder_id": str, "commitment_hex": str }

    commitment_hex is the Pedersen commitment C = bid·G + r·H as a compressed
    point; the bid and the blinding factor r stay with the bidder.

    Response:
      { "success": bool, "phase": str, "message": str }
    """
    service = _service()
    service.require_auction()  # 404 takes precedence over body validation
    data = _json_object()
    bidder_id = _str_field(data, "bidder_id")
    commitment_hex = _str_field(data, "commitment_hex")

    result = service.commit(bidder_id, commitment_hex)

    return jsonify({"success": True, "phase": result.phase.value, "message": result.message})


# ---------------------------------------------------------------------------
# Prove (Phase 2)
# ---------------------------------------------------------------------------


@bp.post("/prove")
def submit_prove() -> ResponseReturnValue:
    """
    Verify and record a bidder's ZK range proof, computed by the bidder.

    Body JSON:
      { "bidder_id": str, "proof": { "low": {...}, "high": {...} } }

    The proof (RangeProof.to_dict() format) must show that the bidder's
    commitment hides a bid in [min_bid, max_bid], bound to this auction and
    bidder. A well-formed proof that fails verification is recorded as invalid.

    Response:
      { "success": bool, "proof_valid": bool, "phase": str, "message": str }
    """
    service = _service()
    service.require_auction()  # 404 takes precedence over body validation
    data = _json_object()
    bidder_id = _str_field(data, "bidder_id")
    proof = _proof_field(data)

    result = service.prove(bidder_id, proof)

    return jsonify(
        {
            "success": True,
            "proof_valid": result.proof_valid,
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
