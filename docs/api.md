# HTTP API

The page talks to the server through this API, and so can any other client.
It lives under `/api` (`http://localhost:5000/api` when run locally). The
examples below are real responses; long tokens and hex strings are shortened
with `…`.

- [Conventions](#conventions)
- [The life of an auction](#the-life-of-an-auction)
- [Status codes](#status-codes)
- Endpoints: [create](#post-apiauctions), [state](#get-apiauctionsid),
  [me](#get-apiauctionsidme), [commit](#post-apiauctionsidcommit),
  [prove](#post-apiauctionsidprove), [reveal](#post-apiauctionsidreveal),
  [delete](#delete-apiauctionsid)
- [Computing the request bodies](#computing-the-request-bodies)

## Conventions

**Requests.** A `POST` body is a JSON object sent as
`Content-Type: application/json` (415 otherwise), of at most 64 KiB (413
otherwise). Integers must lie in `[0, 2^53 − 1]`, the range JavaScript numbers
hold exactly; booleans and fractions are not integers here. Extra fields are
ignored.

**Authentication.** Requests that act for someone carry a token:
`Authorization: Bearer <token>`.

| Token | Issued | Needed for |
|---|---|---|
| Join token, one per bidder | when the auction is created | `GET …/me`, `POST …/commit`, `…/prove`, `…/reveal` |
| Organizer token | when the auction is created | `DELETE` |

The token alone decides who is acting: no request names a bidder. Tokens are
sent once, in the response that creates the auction; the server keeps only
their SHA-256 digests, so they cannot be recovered later. Reading an auction's
state needs no token: its id, 128 random bits, is the key to it.

**Responses.** Every answer is JSON with `"success": true`, or for any error
(including unknown routes, a wrong method and unexpected server errors):

```json
{ "success": false, "error": "Missing or invalid join token for this auction." }
```

A 401 also carries `WWW-Authenticate: Bearer`, and a 405 an `Allow` header.
API responses are never cached (`Cache-Control: no-store`), and every response
carries the security headers (Content-Security-Policy and others; see the
[threat model](threat-model.md#other-websites-and-the-network)).

**No CORS.** The API sends no `Access-Control-Allow-*` headers. A JSON `POST`
or a `DELETE` from another website's script needs a CORS preflight, which is
never approved, so other websites cannot use the API from a visitor's browser.

**Encodings.**

| Value | Encoding |
|---|---|
| Curve point (commitment) | compressed SEC1: 66 lowercase hex characters, starting `02` or `03` |
| Scalar (blinding factor, proof values) | 64 lowercase hex characters, a number below the group order `n` |
| Time | ISO 8601 in UTC, with milliseconds: `2026-10-22T16:40:05.114+00:00` |

## The life of an auction

```
open ──every commitment in──▶ committed ──every proof in──▶ proved ──every reveal in──▶ finished
```

| `state` | Bidders now | The phase ends when |
|---|---|---|
| `open` | commit | every bidder still taking part has committed, or at the commit deadline |
| `committed` | prove | … has sent a proof (valid or not), or at the prove deadline |
| `proved` | reveal | … has revealed, or at the reveal deadline |
| `finished` | — | — |

The three windows follow one another from the moment the auction is created,
so all deadlines are fixed then, and the state lists them. A bidder who misses
a deadline takes no further part: their later requests get a 400, and they
cannot win. Deadlines are applied whenever the auction is asked about, so the
state is always current.

## Status codes

| Code | When |
|---|---|
| 200 | Done |
| 201 | Auction created |
| 400 | The request breaks a rule: a malformed field, the wrong phase, a missed deadline, a step taken twice |
| 401 | Missing or wrong token for this auction |
| 404 | No auction with this id (never created, or deleted); unknown route |
| 405 | Method not allowed on this route |
| 413 | Body larger than 64 KiB |
| 415 | Body not sent as `application/json` |
| 503 | 1000 auctions are running; none can be created until one ends |
| 500 | Unexpected server error (the message reveals nothing about it) |

For bidder requests, 404 and 401 are decided before the body is read (its
content type, a header, is checked first).

## `POST /api/auctions`

Creates an auction. Anyone may; no token is needed.

| Field | Type | Rules |
|---|---|---|
| `item_name` | string | 1–100 characters once trimmed |
| `min_bid`, `max_bid` | integer | `min_bid < max_bid` |
| `bidders` | array of strings | 2–10 names, each 1–100 characters once trimmed, distinct ignoring case |
| `commit_seconds`, `prove_seconds`, `reveal_seconds` | integer, optional | each window's length, 10 to 604 800 (a week); 600 by default |

```http
POST /api/auctions
Content-Type: application/json

{"item_name": "Vintage Watch", "min_bid": 100, "max_bid": 10000,
 "bidders": ["Alice", "Bob"], "commit_seconds": 300}
```

`201 Created`, with `Location: /api/auctions/44cf1b02590e663b1f93b458d35e91e9`:

```json
{
  "success": true,
  "auction_id": "44cf1b02590e663b1f93b458d35e91e9",
  "organizer_token": "O0g0Z9AdTRVgBvp9…",
  "item_name": "Vintage Watch",
  "min_bid": 100,
  "max_bid": 10000,
  "bidders": [
    { "bidder_id": "bidder_0", "name": "Alice", "join_token": "6j6Ztr9sqLbDdQUN…" },
    { "bidder_id": "bidder_1", "name": "Bob", "join_token": "YvGgEKdobi_Eb_ub…" }
  ]
}
```

This is the only time the tokens are sent. Each join token must reach its
bidder and nobody else: the page does this with a join link per bidder,
`/#auction=<auction_id>&token=<join_token>` (a URL fragment, which browsers
never send to the server).

## `GET /api/auctions/{id}`

The auction's public state. No token needed.

```json
{
  "success": true,
  "auction_id": "44cf1b02590e663b1f93b458d35e91e9",
  "state": "proved",
  "item_name": "Vintage Watch",
  "min_bid": 100,
  "max_bid": 10000,
  "server_time": "2026-10-22T16:35:05.462+00:00",
  "deadlines": {
    "commit": "2026-10-22T16:40:05.114+00:00",
    "prove": "2026-10-22T16:50:05.114+00:00",
    "reveal": "2026-10-22T17:00:05.114+00:00"
  },
  "bidders": [
    {
      "bidder_id": "bidder_0",
      "name": "Alice",
      "missed_deadline": null,
      "commitment_hex": "034675aedc418710…",
      "commit_order": 0,
      "proof_valid": true,
      "commitment_verified": null
    },
    { "bidder_id": "bidder_1", "name": "Bob", "…": "…" }
  ],
  "winner": null
}
```

| Field | Meaning |
|---|---|
| `state` | `open`, `committed`, `proved` or `finished` (see [above](#the-life-of-an-auction)) |
| `server_time` | when this state was taken, by the server's clock, which decides the deadlines: count down from it, not from the client's clock |
| `deadlines` | when each step's window closes; a step taken at or after it is too late |
| `missed_deadline` | `null`, or the step (`"commit"`, `"prove"`, `"reveal"`) whose deadline the bidder missed |
| `commitment_hex` | the bidder's commitment, once sent |
| `commit_order` | 0 for the first commitment received, 1 for the next…; breaks ties |
| `proof_valid` | `null` until the bidder proves, then whether the proof verified |
| `commitment_verified` | `null` until the bidder reveals, then whether the opening matched the commitment |
| `revealed_bid`, `randomness_hex` | only once `finished`: each bidder's opening, so anyone can check it against the commitment |
| `winner` | `null`, or once `finished` `{bidder_id, name, bid, commitment_hex}` |

Openings are withheld until the auction is finished, even from bidders who
have revealed: seeing the others' bids, a bidder who has not revealed yet
could otherwise withhold their own when losing.

The winner is the highest bid among bidders whose proof was valid, whose
opening matched, and whose bid lies in `[min_bid, max_bid]`; between equal
bids, the earliest commitment. With no such bidder there is no winner.

## `GET /api/auctions/{id}/me`

Which bidder a join token belongs to. The page uses it to check a join link
before it greets the bidder. Token: a join token.

```json
{ "success": true, "bidder_id": "bidder_0", "name": "Alice" }
```

## `POST /api/auctions/{id}/commit`

Sends the bidder's commitment `C = bid·G + r·H`. The bid and the blinding
factor `r` stay with the bidder. Token: the bidder's join token.

```json
{ "commitment_hex": "034675aedc41871079553afcf96437172870dad2fc705e69efdd48689785685e5b" }
```

```json
{ "success": true, "phase": "open", "message": "Alice committed successfully." }
```

`phase` is the state after this commitment: the last one moves the auction to
`committed`. Refused (400) unless the auction is `open`, the bidder has not
committed yet, the commitment is a canonically encoded curve point, and no
other bidder sent the same one.

## `POST /api/auctions/{id}/prove`

Sends a zero-knowledge proof that the bidder's commitment hides a bid in
`[min_bid, max_bid]`. Token: the bidder's join token.

```json
{
  "proof": {
    "low":  { "bit_commitments": ["03…", "…"], "bit_proofs": [{ "e0": "…", "s0": "…", "e1": "…", "s1": "…" }, "…"] },
    "high": { "bit_commitments": ["…"], "bit_proofs": ["…"] }
  }
}
```

`low` shows that `bid − min_bid` lies in `[0, 2^k)` and `high` that
`max_bid − bid` does, with `k` the bit length of `max_bid − min_bid` (at least
1): one commitment and one bit proof per bit, on each side. Any other number
of bits is invalid. For the range 100–10 000, `k` is 14 and the body is about
10 KB. The proof is bound to this auction, this bidder, their commitment and
the range; see the [README](../README.md#range-proof-bit_proofpy-range_proofpy)
for the construction.

```json
{ "success": true, "proof_valid": true, "phase": "committed", "message": "Alice's proof is valid." }
```

Refused (400) unless the auction is `committed` and the bidder has not proved
yet. A body that is not even a well-formed proof is refused (400) without
being recorded, so a client bug can be retried. A well-formed proof that does
not verify is recorded: `proof_valid: false`, and the bidder can no longer win.

## `POST /api/auctions/{id}/reveal`

Opens the commitment: the first time the bid leaves the bidder. Token: the
bidder's join token.

```json
{ "bid": 4200, "randomness_hex": "e7b39e90e91da7557af4aff70385632b9ef32e5b9104bf9fb29c8c9f1c2b76f1" }
```

```json
{
  "success": true,
  "verified": true,
  "phase": "finished",
  "message": "Bob's reveal is verified.",
  "winner": { "bidder_id": "bidder_1", "name": "Bob", "bid": 7500, "commitment_hex": "0373ab360ee992cc…" }
}
```

`verified: false` means the opening does not match the commitment: the bidder
is marked a cheater and cannot win. `winner` is set by the reveal that
finishes the auction (and stays `null` if nobody qualifies). Refused (400)
unless the auction is `proved` and the bidder has not revealed yet, or if
`randomness_hex` is malformed (again without being recorded).

## `DELETE /api/auctions/{id}`

Discards the auction, whatever its phase. Token: the organizer token.

```json
{ "success": true, "message": "Auction deleted." }
```

## Computing the request bodies

A bidder computes the commitment and the proof, and keeps the bid and the
blinding factor until the reveal. In the browser, `static/auction-crypto.js`
does it (as `window.auctionCrypto` on the page):

```js
const { commitmentHex, blindingHex } = auctionCrypto.commitBid(4200n);
const proof = await auctionCrypto.proveBid({
  bid: 4200n, blindingHex, commitmentHex,
  minBid: 100n, maxBid: 10000n, auctionId, bidderId,
});
```

In Python, with this package:

```python
from crypto_auction.auction import bid_proof_context
from crypto_auction.pedersen import commit, encode_point, encode_scalar
from crypto_auction.range_proof import prove_range

c = commit(4200)  # a fresh random blinding factor
commit_body = {"commitment_hex": encode_point(c.point)}
proof = prove_range(c.point, 4200, c.blinding, 100, 10000, bid_proof_context(auction_id, bidder_id))
prove_body = {"proof": proof.to_dict()}
reveal_body = {"bid": 4200, "randomness_hex": encode_scalar(c.blinding)}
```

Both produce exactly the same formats; `tests/test_browser_interop.py` checks
that the server accepts what the browser computes.
