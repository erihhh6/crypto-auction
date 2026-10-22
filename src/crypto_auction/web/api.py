"""
REST API for the sealed-bid cryptographic auction demo (blueprint at /api).

Bidders compute their commitment and range proof themselves (in the browser,
static/auction-crypto.js) and send only those. The bid and its blinding factor
reach the server for the first time at the reveal.

Endpoints (several auctions can run at once, each under its own id):
  POST   /api/auctions             — create an auction (201, Location header)
  GET    /api/auctions/<id>        — fetch its public state
  GET    /api/auctions/<id>/me     — which bidder a join token belongs to
  POST   /api/auctions/<id>/commit — submit a bid commitment (computed by the bidder)
  POST   /api/auctions/<id>/prove  — submit a ZK range proof for the commitment
  POST   /api/auctions/<id>/reveal — reveal bid + blinding factor, verify commitment
  DELETE /api/auctions/<id>        — discard the auction (organizer only)

Tokens:
  Creating an auction returns a secret organizer token and a join token per
  bidder, each sent as "Authorization: Bearer <token>". Commit, prove and
  reveal act for the bidder whose join token it is; only the organizer token
  deletes. A missing or wrong token gets a 401. An unknown auction id is a 404,
  and creation is refused with a 503 while the maximum number of auctions run.

Deadlines:
  Each step (commit, prove, reveal) has a window; they follow one another from
  creation, and the public state lists their deadlines. A bidder who misses one
  takes no further part: later requests from them get a 400.

Request rules:
  Every POST must be sent as application/json (415 otherwise) with a JSON object
  body (400 otherwise) of at most 64 KiB (413 otherwise). Integers must lie in
  [0, 2**53 - 1]. Every error,
  including unknown routes and unexpected server errors, is returned as
  {"success": false, "error": "<reason>"}.

Encodings: commitments are compressed secp256k1 points (66 lowercase hex chars),
the blinding factor a scalar below the group order (64 lowercase hex chars).
"""

import json
from typing import Any, NoReturn, cast

from flask import Blueprint, Flask, Response, abort, current_app, jsonify, request, url_for
from flask.typing import ResponseReturnValue
from werkzeug.exceptions import HTTPException

from crypto_auction.auction import DEFAULT_PHASE_SECONDS, AuctionConfig
from crypto_auction.pedersen import decode_scalar
from crypto_auction.range_proof import RangeProof
from crypto_auction.service import (
    AuctionRuleError,
    AuctionService,
    AuthenticationError,
    CapacityError,
    NoAuctionError,
)

# Largest integer the API accepts. JSON numbers above 2**53 - 1 are not exact
# in JavaScript (RFC 7493, I-JSON), and the browser handles bids as numbers: a
# larger typed bid would silently become a different one. It is far below the
# range proof's own limit, range_proof.MAX_VALUE = 2**64 - 1.
MAX_JSON_INT = 2**53 - 1
MAX_BIDDERS = 10
MAX_NAME_LENGTH = 100
# Bounds for each step's window: long enough to compute and send a proof, and
# short enough that an auction does not stay open indefinitely.
MIN_PHASE_SECONDS = 10
MAX_PHASE_SECONDS = 7 * 24 * 60 * 60
# Largest request body accepted (413 beyond; create_app sets it). Anyone may
# create an auction, so without a cap one request could make the server read
# and parse any amount of JSON. The largest legitimate body, a range proof for
# the widest range allowed (53 bits per side), is about 38 KB, 46 KB indented.
MAX_REQUEST_BYTES = 64 * 1024

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


def _unauthenticated(exc: AuthenticationError) -> ResponseReturnValue:
    response = _error(401, str(exc))
    # A 401 must name the authentication scheme to use (RFC 9110, RFC 6750).
    response.headers["WWW-Authenticate"] = "Bearer"
    return response


def _rule_violation(exc: AuctionRuleError) -> ResponseReturnValue:
    return _error(400, str(exc))


def _at_capacity(exc: CapacityError) -> ResponseReturnValue:
    return _error(503, str(exc))


def register_error_handlers(app: Flask) -> None:
    # App-wide rather than on the blueprint, so that unknown routes (which
    # never reach a blueprint) also get the JSON envelope.
    app.register_error_handler(HTTPException, json_http_error)
    app.register_error_handler(NoAuctionError, _no_auction)
    app.register_error_handler(AuthenticationError, _unauthenticated)
    app.register_error_handler(AuctionRuleError, _rule_violation)
    app.register_error_handler(CapacityError, _at_capacity)


@bp.before_request
def require_json_posts() -> None:
    """
    Reject state-changing requests that are not application/json.

    Browsers send cross-site "simple" requests (HTML forms, text/plain bodies)
    without a CORS preflight, so accepting them would let any website drive this
    API from a visitor's browser (CSRF). A cross-origin application/json request
    needs a preflight, which this app never approves; so does any DELETE.
    """
    if request.method == "POST" and not request.is_json:
        abort(415, description="Request body must be JSON (Content-Type: application/json).")


def _bearer_token() -> str:
    """
    The join or organizer token, sent as "Authorization: Bearer <token>".

    A header rather than a body field keeps the secret out of request bodies,
    and unlike a cookie the browser never attaches it on its own. Without a
    Bearer token this returns "", which authenticates nobody.
    """
    auth = request.authorization
    if auth is None or auth.type != "bearer" or not auth.token:
        return ""
    return auth.token


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


def _phase_seconds(data: dict[str, Any], name: str) -> int:
    """An optional window length in seconds, within the bounds above."""
    if name not in data:
        return DEFAULT_PHASE_SECONDS
    value = _int_field(data, name)
    if not MIN_PHASE_SECONDS <= value <= MAX_PHASE_SECONDS:
        _bad_request(f"'{name}' must be between {MIN_PHASE_SECONDS} and {MAX_PHASE_SECONDS}.")
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


@bp.post("/auctions")
def create_auction() -> ResponseReturnValue:
    """
    Create a new auction, alongside any others.

    Body JSON:
      {
        "item_name":      str,
        "min_bid":        int,
        "max_bid":        int,
        "bidders":        [str, ...],  -- list of bidder display names
        "commit_seconds": int,         -- optional, each window 600 s by default;
        "prove_seconds":  int,         -- the windows follow one another from
        "reveal_seconds": int          -- now, so all deadlines are fixed here
      }

    Response (201 Created, with the auction's URL as Location):
      {
        "success":         bool,
        "auction_id":      str,   -- in its URL, and in every range proof's context
        "organizer_token": str,   -- deletes the auction
        "item_name":       str,
        "min_bid":         int,
        "max_bid":         int,
        "bidders":         [{"bidder_id": str, "name": str, "join_token": str}, ...]
      }

    Each join_token must reach only its bidder, and this is the only time the
    tokens are sent: the server keeps only their digests.
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
        commit_seconds=_phase_seconds(data, "commit_seconds"),
        prove_seconds=_phase_seconds(data, "prove_seconds"),
        reveal_seconds=_phase_seconds(data, "reveal_seconds"),
    )
    created = _service().create(config)
    auction = created.auction

    bidders_info = [
        {"bidder_id": bidder_id, "name": b.name, "join_token": created.join_tokens[bidder_id]}
        for bidder_id, b in auction.bidders.items()
    ]
    body = {
        "success": True,
        "auction_id": auction.auction_id,
        "organizer_token": created.organizer_token,
        "item_name": item_name,
        "min_bid": min_bid,
        "max_bid": max_bid,
        "bidders": bidders_info,
    }
    location = url_for(".get_state", auction_id=auction.auction_id)
    return jsonify(body), 201, {"Location": location}


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


@bp.get("/auctions/<auction_id>")
def get_state(auction_id: str) -> ResponseReturnValue:
    """
    Return the complete public state of an auction.
    """
    return jsonify({"success": True, **_service().public_state(auction_id)})


@bp.get("/auctions/<auction_id>/me")
def get_identity(auction_id: str) -> ResponseReturnValue:
    """
    Say which bidder a join token belongs to, so that a page opened from a
    join link can check the link and greet the bidder before they act.

    Header: Authorization: Bearer <join_token>

    Response:
      { "success": bool, "bidder_id": str, "name": str }
    """
    bidder_id, name = _service().identify(auction_id, _bearer_token())
    return jsonify({"success": True, "bidder_id": bidder_id, "name": name})


# ---------------------------------------------------------------------------
# Commit (Phase 1)
# ---------------------------------------------------------------------------


@bp.post("/auctions/<auction_id>/commit")
def submit_commit(auction_id: str) -> ResponseReturnValue:
    """
    Register the authenticated bidder's commitment, computed by the bidder.

    Header: Authorization: Bearer <join_token>
    Body JSON:
      { "commitment_hex": str }

    commitment_hex is the Pedersen commitment C = bid·G + r·H as a compressed
    point; the bid and the blinding factor r stay with the bidder.

    Response:
      { "success": bool, "phase": str, "message": str }
    """
    service = _service()
    token = _bearer_token()
    service.require_bidder(auction_id, token)  # 404 and 401 come before body validation
    data = _json_object()
    commitment_hex = _str_field(data, "commitment_hex")

    result = service.commit(auction_id, token, commitment_hex)

    return jsonify({"success": True, "phase": result.phase.value, "message": result.message})


# ---------------------------------------------------------------------------
# Prove (Phase 2)
# ---------------------------------------------------------------------------


@bp.post("/auctions/<auction_id>/prove")
def submit_prove(auction_id: str) -> ResponseReturnValue:
    """
    Verify and record the authenticated bidder's ZK range proof.

    Header: Authorization: Bearer <join_token>
    Body JSON:
      { "proof": { "low": {...}, "high": {...} } }

    The proof (RangeProof.to_dict() format) must show that the bidder's
    commitment hides a bid in [min_bid, max_bid], bound to this auction and
    bidder. A well-formed proof that fails verification is recorded as invalid.

    Response:
      { "success": bool, "proof_valid": bool, "phase": str, "message": str }
    """
    service = _service()
    token = _bearer_token()
    service.require_bidder(auction_id, token)  # 404 and 401 come before body validation
    data = _json_object()
    proof = _proof_field(data)

    result = service.prove(auction_id, token, proof)

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


@bp.post("/auctions/<auction_id>/reveal")
def submit_reveal(auction_id: str) -> ResponseReturnValue:
    """
    Reveal the authenticated bidder's (bid, blinding factor) and verify it
    against their commitment.

    Header: Authorization: Bearer <join_token>
    Body JSON:
      { "bid": int, "randomness_hex": str }

    Response:
      {
        "success":  bool,
        "verified": bool,
        "phase":    str,
        "winner":   { "bidder_id", "name", "bid", "commitment_hex" } | null
      }
    """
    service = _service()
    token = _bearer_token()
    service.require_bidder(auction_id, token)  # 404 and 401 come before body validation
    data = _json_object()
    bid = _int_field(data, "bid")
    blinding = _blinding_field(data)

    result = service.reveal(auction_id, token, bid, blinding)

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
# Delete
# ---------------------------------------------------------------------------


@bp.delete("/auctions/<auction_id>")
def delete_auction(auction_id: str) -> ResponseReturnValue:
    """
    Discard an auction, whatever its phase. Only its organizer may.

    Header: Authorization: Bearer <organizer_token>
    """
    _service().delete(auction_id, _bearer_token())
    return jsonify({"success": True, "message": "Auction deleted."})
