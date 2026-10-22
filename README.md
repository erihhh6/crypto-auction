# CryptoAuction

[![CI](https://github.com/erihhh6/crypto-auction/actions/workflows/ci.yml/badge.svg)](https://github.com/erihhh6/crypto-auction/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A web application (Flask + vanilla JS) demonstrating a complete 3-phase sealed-bid
auction with applied cryptography: **Commit → ZK Prove → Reveal**.

> Built as a portfolio project to demonstrate applied cryptography concepts,
> using Python's standard library, Flask, and the pure-Python
> [`ecdsa`](https://pypi.org/project/ecdsa/) package for secp256k1 arithmetic
> on the server, and a vendored copy of
> [`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) in the browser.

> [!WARNING]
> **Work in progress.** This started as a prototype and is being hardened step
> by step. The cryptographic guarantees below now hold under the
> honest-but-curious model, but the application around them is not
> production-ready yet: there are no accounts or rate limits, and the
> organizer's page cannot be reopened, among others. See [Limitations](#limitations).

---

## Demo

![CryptoAuction demo](docs/demo.gif)

---

## What This Demonstrates

| Property | Mechanism | Intended guarantee | Status |
|---|---|---|---|
| **Hiding** | Pedersen commitment `C = bid·G + r·H`, computed in the browser | Auctioneer cannot learn bids before reveal | Holds: the server receives only commitments and proofs until the reveal |
| **Binding** | Discrete logarithm hardness on secp256k1 | Bidders cannot change their bid after committing | Holds |
| **Soundness** | ZK range proof (bit decomposition + OR-proofs, Fiat-Shamir) | Bids provably within `[min, max]` without disclosure | Holds |
| **Verifiability** | Commitment opening at reveal | Anyone can audit the final result | Holds: openings are public after the reveal |

---

## Security Model

**Honest-but-curious (semi-honest)**: the auctioneer follows the protocol but
tries to learn bids before the reveal phase. Each bidder's browser computes the
commitment and the range proof itself (`static/auction-crypto.js`), so:

```
Phase 1 — COMMIT:   auctioneer sees only C = bid·G + r·H
Phase 2 — ZK PROVE: auctioneer knows bid ∈ [min, max] without seeing bid
Phase 3 — REVEAL:   auctioneer verifies bid·G + r·H == C
```

The bid and its blinding factor `r` leave the browser only at the reveal; a
test checks exactly what each request sends (`tests/js/app-flow.test.mjs`).

One assumption is inherent to any web application: bidders run JavaScript that
the auctioneer serves. A *malicious* (rather than curious) server could serve
code that leaks bids. Closing that gap would need code the bidder obtains
independently, such as a pinned, reviewed release or a native client.

Bidders are also honest-but-curious among themselves — they see each other's
commitments but not the underlying bid values until phase 3.

**Identities.** Each bidder acts through a secret join token, issued when the
auction is created and sent as `Authorization: Bearer <token>`. Nobody can
commit, prove or reveal for another bidder, and a copy of another bidder's
commitment is rejected. Whoever creates the auction is its organizer and gets
an organizer token, the only one that can delete the auction. The server
stores only SHA-256 digests of the tokens. The organizer receives every join
token to hand out, so tokens protect bidders from each other and from
outsiders, not from the organizer.

The organizer's page lists a **join link** per bidder, which opens the page as
that bidder on their own device; every page polls the auction, so each sees
the others' progress within seconds. The token travels in the link's fragment
(`#auction=…&token=…`), which browsers never send to the server, so it stays
out of server logs and `Referer` headers. A page opened from a link first asks
the server whose token it is (`GET /api/auctions/<id>/me`).

---

## Protocol

```
SETUP
  The organizer creates the auction (any number can run at once, each under
  /api/auctions/<id>); each bidder receives a secret join token, which
  authenticates every request they make below. The commit,
  prove and reveal windows (10 minutes each by default) follow one another,
  so all three deadlines are fixed now

PHASE 1 — COMMIT
  Bidder i chooses bid_i and a random blinding factor r_i ∈ [0, n)
  Computes   C_i = bid_i·G + r_i·H        (Pedersen commitment on secp256k1)
  Sends C_i → auctioneer stores it (bid_i, r_i remain private), unless
  another bidder already submitted the same C_i

PHASE 2 — ZK PROVE
  Bidder i proves that C_i hides a value in [min_bid, max_bid]
  (bit-decomposition range proof with Cramer–Damgård–Schoenmakers OR-proofs,
   non-interactive via Fiat-Shamir, bound to this auction and bidder)
  Auctioneer verifies it against its own statement (C_i, min_bid, max_bid)

PHASE 3 — REVEAL
  Bidder i reveals (bid_i, r_i)
  Auctioneer verifies: bid_i·G + r_i·H == C_i
  Winner = highest verified in-range bid; ties go to the earliest commitment
```

A phase ends once every bidder still taking part has acted, or at its
deadline. A bidder who misses a deadline takes no further part and cannot
win; the others carry on. So a bidder who stays silent, for instance one
who withholds a reveal, cannot stall the auction.

Phases 1 and 2 run in the bidder's browser; the server stores and verifies
what it receives. The Python and JavaScript implementations share one wire
format and one Fiat-Shamir transcript encoding, and
`tests/test_browser_interop.py` checks that the server accepts exactly what the
browser produces.

---

## How to Run

```bash
pip install -r requirements.txt   # installs the crypto_auction package (editable) and Flask
python -m crypto_auction.web
# Open http://localhost:5000
```

The page proves bids with the browser's Web Crypto API, which is only
available in a secure context: open it on `localhost`, or serve it over HTTPS.

Auctions are stored in an SQLite database, so a restart loses nothing. By
default it is `auctions.sqlite3` in Flask's instance folder (`src/instance/`
for this checkout); set `CRYPTO_AUCTION_DATABASE` to use another file. Several
server processes can share one file: each request runs in its own transaction.

For local development with auto-reload and the interactive debugger
(never enable this on a reachable host):

```bash
flask --app crypto_auction.web run --debug
```

Or try the cryptographic building blocks without the web app:

```bash
python examples/commitment_demo.py      # commitment demo
python examples/range_proof_demo.py     # ZK range proof demo
python examples/auction_simulation.py   # full 3-bidder simulation
```

Development setup (tests, coverage, lint, types):

```bash
pip install -r requirements-dev.txt
pytest --cov                # test suite with branch coverage (fails below the floor)
ruff check .                # lint
ruff format --check .       # formatting
python -m mypy              # strict type check of src/ and examples/
node --test "tests/js/*.test.mjs"   # frontend tests: rendering, request flow, browser crypto
```

The frontend tests need Node 22+ and no `npm install`. `pytest` also runs
`tests/test_browser_interop.py`, which drives the browser's crypto module with
Node; without Node those tests are skipped, unless `REQUIRE_NODE=1` (as in CI).

Known, not-yet-fixed bugs are recorded as tests that assert the correct
behaviour, marked `@known_bug(...)` (a strict `xfail`, see `tests/support.py`).
They show up as `XFAIL` with their reason; the commit that fixes a bug
removes its marker, and the suite fails if a marker outlives its bug.

---

## Project Structure

```
crypto-auction/
├── .github/
│   └── workflows/
│       └── ci.yml            # GitHub Actions CI
├── docs/
│   └── demo.gif              # Demo GIF (shown in README)
├── examples/                 # Runnable demos of the package, no web app needed
├── src/
│   └── crypto_auction/       # The installable package
│       ├── __init__.py
│       ├── pedersen.py       # Pedersen commitments on secp256k1
│       ├── bit_proof.py      # ZK OR-proof that a Pedersen commitment hides 0 or 1
│       ├── range_proof.py    # ZK range proof by bit decomposition
│       ├── transcript.py     # Unambiguous encoding for Fiat-Shamir transcripts
│       ├── auction.py        # State machine + auction logic
│       ├── service.py        # Runs the auctions: authenticates callers, verifies what they send
│       ├── store.py          # SQLite storage, one transaction per operation
│       └── web/              # Flask app: create_app(), python -m crypto_auction.web
│           ├── api.py        # /api blueprint: routes and request validation
│           ├── templates/
│           │   └── index.html  # Single page, 3-panel layout
│           └── static/
│               ├── app.js    # Frontend SPA (vanilla JS)
│               ├── auction-crypto.js  # Bidder-side commitments and range proofs
│               ├── style.css # Dark theme CSS
│               └── vendor/   # Pinned third-party code (@noble/secp256k1) and provenance
├── tests/
│   ├── js/
│   │   ├── render.test.mjs   # Rendering: cards updated in place, escaping, phase indicator
│   │   ├── fake-dom.mjs      # Minimal DOM to run app.js under Node, no npm install
│   │   ├── app-flow.test.mjs # What each request sends, and as whom; how failures are shown
│   │   ├── crypto.test.mjs   # Browser crypto: generator, encodings, refusals
│   │   └── bidder_cli.mjs    # Runs the browser crypto for the Python interop tests
│   ├── support.py            # Shared helpers (known_bug marker, fake clock, temporary database)
│   ├── test_pedersen.py      # Pedersen commitments, generators, encoding
│   ├── test_bit_proof.py     # Bit proof: completeness, soundness, binding
│   ├── test_range_proof.py   # Range proof, incl. wrap-around and non-bit attacks
│   ├── test_auction.py       # State machine, proof binding and winner selection
│   ├── test_store.py         # SQLite storage: round trips, restarts, concurrent requests
│   ├── test_api.py           # REST API via Flask's test client
│   ├── test_browser_interop.py  # Server accepts what the browser produces (needs Node)
│   └── test_app.py           # Server entry point (debug mode)
├── pyproject.toml            # Package metadata and tool configuration
├── requirements.txt          # Installs the package and its dependencies
└── requirements-dev.txt      # Test, lint and type-check tooling
```

---

## Cryptographic Primitives

| Primitive | Implementation | Purpose |
|---|---|---|
| Commitment | Pedersen, `C = v·G + r·H` on secp256k1 | Hiding (perfect) + binding (discrete log) |
| Bit proof | Cramer–Damgård–Schoenmakers OR-proof | Shows a commitment hides 0 or 1 |
| Range proof | Bit decomposition of `v − min` and `max − v` | Shows `v ∈ [min, max]` without revealing `v` |
| Fiat-Shamir | SHA-512 over a length-prefixed transcript | Non-interactive proofs bound to their statement |
| Reveal | Opening `(v, r)` checked against `C` | Anyone can audit the result |

### Pedersen Commitments (`pedersen.py`)

```
C = v·G + r·H        r uniform in [0, n)
```

- **Hiding** (perfect): `r·H` is a uniformly random group element, so `C`
  reveals nothing about `v`, even to an unbounded adversary.
- **Binding** (computational): two openings of one `C` would give
  `log_G(H) = (v − v′) / (r′ − r) mod n`, a discrete logarithm on secp256k1.
- **Homomorphic**: `C(v₁, r₁) + C(v₂, r₂) = C(v₁ + v₂, r₁ + r₂)`, which the
  range proof relies on.

`G` is the standard secp256k1 generator. `H` is derived by hashing the tag
`crypto-auction/pedersen/H/v1` to a curve point (try-and-increment, even `y`),
so nobody knows `log_G(H)`. Points travel as compressed SEC1 encodings, and
decoding rejects non-canonical ones (an x-coordinate ≥ p).

### Range Proof (`bit_proof.py`, `range_proof.py`)

With `d = max − min` and `k = bitlen(d)`, the proof shows that both
`x = v − min` (committed by `C − min·G`) and `y = max − v` (committed by
`max·G − C`) lie in `[0, 2^k)`. Each is split into bits: a commitment per bit,
an OR-proof that it hides 0 or 1, and a check that `Σ 2^i·C_i` equals the
side's commitment.

Since `x + y ≡ d (mod n)` and both `x + y < 2^(k+1)` and `d` are far below the
group order `n`, `x + y = d` exactly, so `v ∈ [min, max]`. This needs the
verifier to fix `k` from its own range: a proof free to choose more bits could
make `x + y` wrap around `n` (the test suite includes this attack).

Every bit proof's Fiat-Shamir challenge covers a domain tag, both generators,
the commitment, the range, the auction and bidder, the side and bit position,
and the proof's announcements, so a proof cannot be reused for any other
statement. A proof for a typical bid range (13 bits per side) is about 10 KB
of JSON; it takes about 0.5 s to generate in the browser and under 0.1 s to
verify on the server. Bulletproofs would be far smaller; this construction
trades size for simplicity.

---

## Limitations

- **The page is served by the auctioneer**: bidders trust it to serve the
  genuine `auction-crypto.js` (see [Security Model](#security-model)).
- **Not strictly constant-time**: proofs are generated in JavaScript, where
  BigInt arithmetic cannot be constant-time. `@noble/secp256k1` uses a
  fixed-length ladder with dummy additions to reduce timing leakage; the
  server only verifies public data.
- **Secrets live in page memory**: reloading the page loses a bidder's blinding
  factor, and with it the ability to reveal, unless the bidder saved their
  opening receipt (💾 on their card). Loading it on the setup page carries on
  as that bidder; the page first checks that it opens the commitment the
  auction recorded, since a wrong reveal would count as cheating.
- **Receipts are not encrypted**: a receipt holds the bid, its blinding factor
  and the join token. Whoever gets it before the reveal learns the bid and can
  act as the bidder, so it must be kept as private as the bid itself.
- **Anyone can create auctions**: there are no accounts or rate limits. At
  most 1000 auctions run at once; more are refused (503).
- **Finished auctions are kept indefinitely**: there is no retention policy
  yet, so the database only grows.
- **One request at a time per database**: each holds SQLite's write lock for
  its whole transaction, including verifying a range proof (under 0.1 s).
  Fine for a demo, but it caps throughput under load.
- **The organizer's page cannot be reopened**: the organizer token and the
  join links live in that page only, so after reloading it the organizer can
  no longer delete the auction or copy the links. (It can play every bidder,
  as the demo does; bidders can also use their own links.)
- **Polling, not push**: pages ask for the auction's state every 5 seconds
  while it runs (and not while hidden); server-sent events would cut the
  delay and the requests.
- **No deposits**: a bidder who misses a deadline only loses the chance to
  win. A real deployment would take a deposit that is forfeited along with
  it, so that dropping out has a cost.
- **Single-server model**: Production would use MPC for the auctioneer role.

Known bugs are tracked as `known_bug` tests (see the development setup above);
`pytest -rx` lists them with their reasons.

---

## References

- Commitment Schemes: Goldreich, *Foundations of Cryptography*, Vol. 1
- Pedersen Commitments: Pedersen, *Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing* (CRYPTO 1991)
- OR-Proofs: Cramer, Damgård & Schoenmakers, *Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols* (CRYPTO 1994)
- Fiat-Shamir Transform: Fiat & Shamir, *How to Prove Yourself* (1986)
- Weak vs. Strong Fiat-Shamir: Bernhard, Pereira & Warinschi, *How Not to Prove Yourself* (ASIACRYPT 2012)
- secp256k1: Certicom Research, *SEC 2: Recommended Elliptic Curve Domain Parameters* (2010)
- Sealed-Bid Auctions: Brandt, *How to Obtain Full Privacy in Auctions* (2006)
