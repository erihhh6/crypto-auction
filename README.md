# CryptoAuction

[![CI](https://github.com/erihhh6/crypto-auction/actions/workflows/ci.yml/badge.svg)](https://github.com/erihhh6/crypto-auction/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A web application (Flask + vanilla JS) demonstrating a complete 3-phase sealed-bid
auction with applied cryptography: **Commit → ZK Prove → Reveal**.

> Built as a portfolio project to demonstrate applied cryptography concepts,
> using Python's standard library, Flask, and the pure-Python
> [`ecdsa`](https://pypi.org/project/ecdsa/) package for secp256k1 arithmetic.

> [!WARNING]
> **Work in progress.** This started as a prototype and is being hardened step
> by step. One headline guarantee does **not** hold yet: the server sees every
> bid in plaintext, because it computes commitments and proofs on the bidders'
> behalf. See [Limitations](#limitations) for the current status.

---

## Demo

![CryptoAuction demo](docs/demo.gif)

---

## What This Demonstrates

| Property | Mechanism | Intended guarantee | Status |
|---|---|---|---|
| **Hiding** | Pedersen commitment `C = bid·G + r·H` | Auctioneer cannot learn bids before reveal | **Not yet**: the commitment is perfectly hiding, but the server receives the bid in plaintext |
| **Binding** | Discrete logarithm hardness on secp256k1 | Bidders cannot change their bid after committing | Holds |
| **Soundness** | ZK range proof (bit decomposition + OR-proofs, Fiat-Shamir) | Bids provably within `[min, max]` without disclosure | Holds |
| **Verifiability** | Commitment opening at reveal | Anyone can audit the final result | Holds: openings are public after the reveal |

---

## Security Model

**Target model, honest-but-curious (semi-honest)**: the auctioneer follows the
protocol but tries to learn bids before the reveal phase. The protocol is
designed so that:

```
Phase 1 — COMMIT:   auctioneer sees only C = bid·G + r·H
Phase 2 — ZK PROVE: auctioneer knows bid ∈ [min, max] without seeing bid
Phase 3 — REVEAL:   auctioneer verifies bid·G + r·H == C
```

**The current implementation does not meet this model yet.** The browser sends
the bid to the server, which computes the commitment and the proof itself, so
the auctioneer learns every bid in phase 1.

Bidders are also honest-but-curious among themselves — they see each other's
commitments but not the underlying bid values until phase 3.

---

## Protocol

```
PHASE 1 — COMMIT
  Bidder i chooses bid_i and a random blinding factor r_i ∈ [0, n)
  Computes   C_i = bid_i·G + r_i·H        (Pedersen commitment on secp256k1)
  Sends C_i → auctioneer stores it (bid_i, r_i remain private)

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

This is the intended protocol. In the current implementation the server
performs the bidder's steps in phases 1 and 2 (see [Limitations](#limitations)).

---

## How to Run

```bash
pip install -r requirements.txt   # installs the crypto_auction package (editable) and Flask
python -m crypto_auction.web
# Open http://localhost:5000
```

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
node --test "tests/js/*.test.mjs"   # frontend rendering tests (Node 22+, no npm install)
```

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
│       ├── service.py        # Runs one auction and the server's protocol steps
│       └── web/              # Flask app: create_app(), python -m crypto_auction.web
│           ├── api.py        # /api blueprint: routes and request validation
│           ├── templates/
│           │   └── index.html  # Single page, 3-panel layout
│           └── static/
│               ├── app.js    # Frontend SPA (vanilla JS)
│               └── style.css # Dark theme CSS
├── tests/
│   ├── js/
│   │   └── render.test.mjs   # Frontend rendering (HTML escaping, proof summary), via node --test
│   ├── support.py            # Shared helpers (known_bug marker)
│   ├── test_pedersen.py      # Pedersen commitments, generators, encoding
│   ├── test_bit_proof.py     # Bit proof: completeness, soundness, binding
│   ├── test_range_proof.py   # Range proof, incl. wrap-around and non-bit attacks
│   ├── test_auction.py       # State machine, proof binding and winner selection
│   ├── test_api.py           # REST API via Flask's test client
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
of JSON and takes about 0.1 s to verify in pure Python. Bulletproofs would be
far smaller; this construction trades size for simplicity.

---

## Limitations

- **Bids pass through the server**: the browser sends the bid in plaintext to
  `/api/commit`, and the server computes the commitment and, later, the range
  proof. The auctioneer therefore learns every bid in phase 1. The target
  design computes both in the browser so the server never sees the bid.
- **Not constant-time**: elliptic-curve arithmetic is pure Python (`ecdsa`),
  so its timing depends on secret values. Proofs should be generated where
  timing cannot be observed, which the target design (proving in the bidder's
  browser) provides.
- **No authentication**: any client can act as any bidder or reset the auction.
- **No deadlines**: a bidder who never commits or reveals stalls the auction.
- **Single-server model**: Production would use MPC for the auctioneer role.
- **In-memory state**: No database; a server restart resets the auction.

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
