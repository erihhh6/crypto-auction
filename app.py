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
"""

from flask import Flask, jsonify, render_template, request

from crypto.auction import Auction, AuctionConfig
from crypto.commitment import commit
from crypto.zkp import RangeProof, prove_range

app = Flask(__name__)

# Single in-memory auction session (one game per server process)
auction: Auction | None = None


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
    data = request.get_json(force=True)

    try:
        item_name = str(data["item_name"]).strip()
        min_bid = int(data["min_bid"])
        max_bid = int(data["max_bid"])
        bidder_names = [str(n).strip() for n in data["bidders"]]
    except (KeyError, ValueError, TypeError) as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    if not item_name:
        return jsonify({"success": False, "error": "item_name cannot be empty."}), 400
    if min_bid >= max_bid:
        return jsonify({"success": False, "error": "min_bid must be less than max_bid."}), 400
    if not bidder_names or len(bidder_names) < 2:
        return jsonify({"success": False, "error": "At least 2 bidders are required."}), 400
    if len(bidder_names) > 10:
        return jsonify({"success": False, "error": "Maximum 10 bidders supported."}), 400

    config = AuctionConfig(
        min_bid=min_bid,
        max_bid=max_bid,
        item_name=item_name,
        bidder_names=bidder_names,
    )
    auction = Auction(config)

    bidders_info = [
        {"bidder_id": bid_id, "name": b.name}
        for bid_id, b in auction.bidders.items()
    ]

    return jsonify({
        "success": True,
        "item_name": item_name,
        "min_bid": min_bid,
        "max_bid": max_bid,
        "bidders": bidders_info,
    })


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

@app.route("/api/state", methods=["GET"])
def get_state():
    """
    Return the complete public state of the current auction.
    """
    if auction is None:
        return jsonify({"success": False, "error": "No auction created yet."}), 404

    return jsonify({"success": True, **auction.get_public_state()})


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
    if auction is None:
        return jsonify({"success": False, "error": "No auction created yet."}), 404

    data = request.get_json(force=True)
    try:
        bidder_id = str(data["bidder_id"])
        bid = int(data["bid"])
    except (KeyError, ValueError, TypeError) as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    if bid < auction.config.min_bid or bid > auction.config.max_bid:
        return jsonify({
            "success": False,
            "error": (
                f"Bid {bid} is outside the allowed range "
                f"[{auction.config.min_bid}, {auction.config.max_bid}]."
            ),
        }), 400

    try:
        c = commit(bid)
        result = auction.submit_commitment(bidder_id, c.commitment_hex)
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    return jsonify({
        "success": True,
        "commitment_hex": c.commitment_hex,
        "randomness_hex": c.randomness_hex,  # returned once; server does not store it
        "phase": result["phase"],
        "message": result["message"],
    })


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
    if auction is None:
        return jsonify({"success": False, "error": "No auction created yet."}), 404

    data = request.get_json(force=True)
    try:
        bidder_id = str(data["bidder_id"])
        bid = int(data["bid"])
        randomness_hex = str(data["randomness_hex"])
    except (KeyError, ValueError, TypeError) as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    if bidder_id not in auction.bidders:
        return jsonify({"success": False, "error": f"Unknown bidder_id '{bidder_id}'."}), 400

    commitment_hex = auction.bidders[bidder_id].commitment_hex
    if commitment_hex is None:
        return jsonify({"success": False, "error": "Bidder has not committed yet."}), 400

    try:
        proof = prove_range(
            bid,
            randomness_hex,
            commitment_hex,
            auction.config.min_bid,
            auction.config.max_bid,
        )
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    proof_dict = {
        "commitment_hex": proof.commitment_hex,
        "min_bid": proof.min_bid,
        "max_bid": proof.max_bid,
        "low_commitment_hex": proof.low_commitment_hex,
        "low_challenge_hex": proof.low_challenge_hex,
        "low_response": proof.low_response,
        "high_commitment_hex": proof.high_commitment_hex,
        "high_challenge_hex": proof.high_challenge_hex,
        "high_response": proof.high_response,
    }

    try:
        result = auction.submit_proof(bidder_id, proof_dict)
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    return jsonify({
        "success": True,
        "proof_valid": result["proof_valid"],
        "proof_public": proof_dict,
        "phase": result["phase"],
        "message": result["message"],
    })


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
    if auction is None:
        return jsonify({"success": False, "error": "No auction created yet."}), 404

    data = request.get_json(force=True)
    try:
        bidder_id = str(data["bidder_id"])
        bid = int(data["bid"])
        randomness_hex = str(data["randomness_hex"])
    except (KeyError, ValueError, TypeError) as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    try:
        result = auction.submit_reveal(bidder_id, bid, randomness_hex)
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    return jsonify({
        "success": True,
        "verified": result["verified"],
        "phase": result["phase"],
        "message": result["message"],
        "winner": result["winner"],
    })


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
    app.run(debug=True, port=5000)
