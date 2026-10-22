# CryptoAuction

[![CI](https://github.com/erihhh6/crypto-auction/actions/workflows/ci.yml/badge.svg)](https://github.com/erihhh6/crypto-auction/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A sealed-bid auction in which the auctioneer cannot see the bids until the
auction is over. Each bidder's browser commits to its bid with a Pedersen
commitment and proves, in zero knowledge, that the bid lies in the allowed
range; only once everyone has committed and proved are the bids opened and
checked against their commitments. **Commit → ZK Prove → Reveal.**

A Flask server and a plain JavaScript page, with no build step. The
cryptography is written out in full (Pedersen commitments, OR-proofs, a range
proof by bit decomposition) on top of curve arithmetic from
[`ecdsa`](https://pypi.org/project/ecdsa/) on the server and a vendored
[`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) in the
browser.

> [!NOTE]
> A portfolio project that began as a prototype and has been hardened commit
> by commit. The cryptographic guarantees hold under the
> [threat model](docs/threat-model.md); the application around them is a
> demo, not a production service: see [Limitations](#limitations).

![CryptoAuction demo](docs/demo.gif)

---

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Security](#security)
- [API](#api)
- [Development](#development)
- [Accessibility](#accessibility)
- [Project structure](#project-structure)
- [Cryptography](#cryptography)
- [Limitations](#limitations)
- [References](#references)

---

## Quick start

```bash
pip install -r requirements.txt   # the crypto_auction package (editable) and Flask
python -m crypto_auction.web      # http://localhost:5000
```

Open the page on `localhost` (or over HTTPS): it computes proofs with the
browser's Web Crypto API, which only secure contexts have. Set up an auction,
then either **Start Auction** and send each bidder their join link, or
**Watch Demo** to see a whole auction play itself out.

Auctions are kept in an SQLite file, so a restart loses nothing:
`auctions.sqlite3` in Flask's instance folder (`src/instance/` in this
checkout), or wherever `CRYPTO_AUCTION_DATABASE` points. Several server
processes can share one file.

For development, with auto-reload and the debugger (never on a reachable host):

```bash
flask --app crypto_auction.web run --debug
```

The cryptography also runs without the web app:

```bash
python examples/commitment_demo.py      # commitments: hiding, binding, homomorphism
python examples/range_proof_demo.py     # a zero-knowledge range proof
python examples/auction_simulation.py   # a whole auction with three bidders
```

---

## How it works

```
SETUP      The organizer creates the auction: item, bid range, bidders, and
           a window for each phase (10 minutes each by default). Each bidder
           gets a secret join token, sent as a join link.

COMMIT     Each bidder's browser picks a random blinding factor r and sends
           C = bid·G + r·H, which hides the bid and binds the bidder to it.

ZK PROVE   Each browser proves that C hides a bid in [min, max], without
           revealing it; the server checks the proof against its own range.

REVEAL     Each bidder sends (bid, r); the server checks bid·G + r·H = C.
           The highest valid bid in range wins; ties go to the earliest
           commitment.
```

- **Each bidder on their own device.** The organizer's page lists a join link
  per bidder (`/#auction=…&token=…`); opening it enters the auction as that
  bidder. Every page polls the auction every 5 seconds, so each sees the
  others' progress.
- **Deadlines.** A phase ends once every bidder still taking part has acted,
  or at its deadline; whoever misses a deadline is out, and the others carry
  on. A bidder who stays silent cannot stall the auction.
- **Openings stay hidden until the end.** Bids revealed early are published
  only once the reveal phase is over, so no bidder can see the others' bids
  and then decide whether to reveal their own.
- **Receipts.** The bid and its blinding factor live only in the page. A
  bidder can save them as a receipt (💾 on their card) and carry on from it
  after a reload, or on another device; the page first checks that the
  receipt opens the commitment the auction recorded.

Phases 1 and 2 run in the browser (`static/auction-crypto.js`); the server
(`auction.py`) stores and verifies what it receives. The Python and JavaScript
implementations share one wire format and one Fiat–Shamir transcript
encoding, and a test checks that the server accepts exactly what the browser
produces.

---

## Security

| Property | Mechanism | Guarantee |
|---|---|---|
| **Hiding** | Pedersen commitment `C = bid·G + r·H`, computed in the browser | The server learns no bid before the reveal: it receives commitments and proofs only |
| **Binding** | Discrete logarithm hardness on secp256k1 | A bidder cannot change their bid after committing |
| **Soundness** | Range proof: bit decomposition + OR-proofs, Fiat–Shamir | Every valid proof's bid lies in `[min, max]` |
| **Verifiability** | Openings published once the auction is finished | Anyone can check every opening, and the winner |

The auctioneer is assumed **honest but curious**: it runs the protocol and
serves the genuine page, but may look at everything it receives. Bidders are
not trusted at all. The page protects itself with a strict
Content-Security-Policy (no inline code, nothing from other origins), bidders
act through secret join tokens kept out of URLs sent to the server, and request
sizes, input sizes and the number of running auctions are all bounded.

**[docs/threat-model.md](docs/threat-model.md)** goes through each actor,
threat and mitigation, what anyone can check afterwards, and what is not
protected.

---

## API

| Request | Token | Does |
|---|---|---|
| `POST /api/auctions` | — | Create an auction; returns the organizer token and every join token |
| `GET /api/auctions/{id}` | — | The public state: phase, deadlines, commitments, verdicts, the winner |
| `GET /api/auctions/{id}/me` | join | Whose join token this is |
| `POST /api/auctions/{id}/commit` | join | Send the bidder's commitment |
| `POST /api/auctions/{id}/prove` | join | Send the bidder's range proof |
| `POST /api/auctions/{id}/reveal` | join | Open the commitment: bid and blinding factor |
| `DELETE /api/auctions/{id}` | organizer | Discard the auction |

JSON in and out, tokens as `Authorization: Bearer <token>`.
**[docs/api.md](docs/api.md)** has every field, rule and status code, with
real examples, and how to compute the request bodies in JavaScript or Python.

---

## Development

```bash
pip install -r requirements-dev.txt
pytest --cov                # Python tests, with branch coverage (fails below the floor)
ruff check .                # lint
ruff format --check .       # formatting
python -m mypy              # strict type check of src/ and examples/

npm ci                      # JavaScript tooling, exactly as package-lock.json records it
npm run lint                # ESLint
npm run format:check        # Prettier: JS, CSS, HTML, JSON, YAML (npm run format fixes)
npm test                    # JavaScript tests

npx playwright install      # once: the browsers the end-to-end tests drive
npm run test:e2e            # whole auctions in Chromium, Firefox and WebKit
```

The JavaScript side needs Node 22.13+. Its npm packages only check the code:
the page has no build step and none of them ships with it, and `.npmrc` keeps
them from running install scripts.

| Tests | What they cover |
|---|---|
| `tests/test_*.py` (pytest) | The cryptography, including attacks on it; the auction's rules and deadlines; storage; the API, request by request; security headers; accessibility of the markup and contrast of the stylesheet |
| `tests/test_browser_interop.py` | The server accepts what the browser's crypto module produces, run under Node (skipped without Node, unless `REQUIRE_NODE=1` as in CI) |
| `tests/js/` (Node's test runner) | The page's logic against a fake DOM: rendering, what each request sends and as whom, how failures are shown; the browser crypto; the vendored library is the npm release |
| `tests/e2e/` (Playwright) | Whole auctions against the real server in three browsers: bidders on separate devices with join links, a bidder carrying on from a receipt; axe-core audits; any page error or CSP violation fails the test |

The end-to-end tests start the server themselves (port 5099, a fresh database);
run them from the Python environment the package is installed in, or name its
interpreter in `PYTHON`.

**CI** (GitHub Actions) runs all of the above on every push: the Python tests
on Python 3.11 to 3.15, and the end-to-end tests in each browser. Actions are
pinned to commit SHAs. **Dependabot** proposes updates of the Python packages,
the npm packages (including the vendored library's version) and the Actions,
once a release is a week old.

Known, not-yet-fixed bugs are recorded as tests asserting the correct
behaviour, marked `@known_bug(...)` (a strict `xfail`, see `tests/support.py`):
`pytest -rx` lists them, and the suite fails if a marker outlives its bug.
Formatting-only commits are listed in `.git-blame-ignore-revs`
(`git config blame.ignoreRevsFile .git-blame-ignore-revs`).

---

## Accessibility

- **Keyboard**: every control is a native button or input with a visible
  focus ring, and Enter commits a bid. The winner is shown in a native modal
  `<dialog>`: focus stays inside it, Escape closes it, and focus then returns
  to where it was (or to the result, if that is gone).
- **Screen readers**: the protocol logs are live regions, phase changes are
  announced, each bidder's card is a group named after them, and what colours
  show (a phase badge's state, the current phase) is also said in words.
  Decorative symbols are hidden from them.
- **Contrast and motion**: all text has at least 4.5:1 contrast (WCAG AA),
  which `tests/test_accessibility.py` checks from the stylesheet; animations
  stop for anyone whose system asks for less motion.

The end-to-end tests audit the setup page, a bidder's page and a finished
auction with its dialog open with axe-core, in each browser.

---

## Project structure

```
crypto-auction/
├── .github/
│   ├── dependabot.yml        # Weekly dependency update pull requests
│   └── workflows/ci.yml      # CI: lint, types, tests, end-to-end tests
├── docs/
│   ├── api.md                # HTTP API reference
│   ├── threat-model.md       # What is protected, from whom, and how
│   └── demo.gif
├── examples/                 # Runnable demos of the cryptography, no web app needed
├── src/crypto_auction/       # The installable package
│   ├── pedersen.py           # Pedersen commitments on secp256k1
│   ├── bit_proof.py          # ZK OR-proof that a commitment hides 0 or 1
│   ├── range_proof.py        # ZK range proof by bit decomposition
│   ├── transcript.py         # Unambiguous encoding for Fiat–Shamir transcripts
│   ├── auction.py            # The auction: phases, deadlines, rules, winner
│   ├── service.py            # Runs the auctions: authenticates callers, verifies what they send
│   ├── store.py              # SQLite storage, one transaction per operation
│   └── web/                  # Flask app: create_app(), python -m crypto_auction.web
│       ├── api.py            # The /api routes and request validation
│       ├── templates/index.html  # The page
│       └── static/
│           ├── app.js            # The page's logic (plain JavaScript)
│           ├── auction-crypto.js # Bidder-side commitments and range proofs
│           ├── style.css
│           └── vendor/           # @noble/secp256k1, pinned, with its provenance
├── tests/
│   ├── e2e/                  # Playwright: whole auctions in real browsers
│   ├── js/                   # Node: the page's logic and crypto; fake DOM
│   ├── support.py            # Shared helpers: known_bug, fake clock, temporary database
│   └── test_*.py             # pytest, one file per module or concern
├── pyproject.toml            # Package metadata, Python tool settings
├── requirements.txt          # Installs the package and its dependencies
├── requirements-dev.txt      # Python test, lint and type-check tools
├── package.json              # JavaScript tools, and the vendored library's version
├── package-lock.json
├── eslint.config.js
├── prettier.config.js        # .prettierignore lists what Prettier leaves alone
├── playwright.config.js      # Browsers, timeouts, and the server the e2e tests start
├── .npmrc                    # No install scripts; exact versions
├── .gitattributes            # Vendored code checked out byte for byte
└── .git-blame-ignore-revs    # Formatting-only commits, skipped by blame
```

---

## Cryptography

| Primitive | Implementation | Purpose |
|---|---|---|
| Commitment | Pedersen, `C = v·G + r·H` on secp256k1 | Hiding (perfect) + binding (discrete log) |
| Bit proof | Cramer–Damgård–Schoenmakers OR-proof | Shows a commitment hides 0 or 1 |
| Range proof | Bit decomposition of `v − min` and `max − v` | Shows `v ∈ [min, max]` without revealing `v` |
| Fiat–Shamir | SHA-512 over a length-prefixed transcript | Non-interactive proofs bound to their statement |
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

Every bit proof's Fiat–Shamir challenge covers domain tags, both generators,
the commitment, the range, the auction and bidder, the side and bit position,
and the proof's announcements, so a proof cannot be reused for any other
statement. For the default range of 100–10 000 (14 bits per side), a proof is
about 10 KB of JSON; the browser computes it in 0.1–0.5 s, depending on the
browser, and the server verifies it in about 80 ms. Bulletproofs would be far
smaller; this construction trades size for simplicity.

---

## Limitations

Beyond what the [threat model](docs/threat-model.md#not-protected) leaves
open by design (a malicious server, the organizer holding every join token,
bids public once the auction is over):

- **No accounts or rate limits.** Anyone can create auctions. At most 1000
  run at once, but one client could create them all, with week-long windows,
  and block new auctions for three weeks.
- **Finished auctions are kept indefinitely**: there is no retention policy,
  so the database only grows.
- **One write at a time per database**: each request holds SQLite's write
  lock for its whole transaction, including verifying a range proof (about
  80 ms). Fine for a demo; it caps throughput under load.
- **The organizer's page cannot be reopened**: the organizer token and the
  join links live in that page only. After a reload the organizer can no
  longer delete the auction or copy the links (bidders keep theirs).
- **Secrets live in page memory**: a bidder who reloads without having saved
  their receipt can no longer reveal. Receipts are not encrypted, and must be
  kept as private as the bid.
- **Polling, not push**: pages ask for the state every 5 seconds (not while
  hidden); server-sent events would cut the delay and the requests. The cards
  can also shift as updates arrive, under a pointer about to click.
- **HTTPS is left to the deployment**: the app sends no
  `Strict-Transport-Security`, which only means something over HTTPS; set it
  where TLS ends, along with TLS itself.
- **Not strictly constant-time** in the browser: BigInt arithmetic cannot be.
  `@noble/secp256k1` uses a fixed-length ladder to reduce timing leakage; the
  server only verifies public data.
- **No deposits**: a bidder who drops out only loses the chance to win.
- **Range proofs are not published**: anyone can check the openings, but
  whether a proof was valid rests on the server's word.
- **A single server**: a production design would distribute the auctioneer's
  role (multi-party computation), so that no one party could even be curious.
- **The demo GIF predates** deadlines, join links and receipts.

---

## References

- Commitment Schemes: Goldreich, *Foundations of Cryptography*, Vol. 1
- Pedersen Commitments: Pedersen, *Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing* (CRYPTO 1991)
- OR-Proofs: Cramer, Damgård & Schoenmakers, *Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols* (CRYPTO 1994)
- Fiat–Shamir Transform: Fiat & Shamir, *How to Prove Yourself* (1986)
- Weak vs. Strong Fiat–Shamir: Bernhard, Pereira & Warinschi, *How Not to Prove Yourself* (ASIACRYPT 2012)
- secp256k1: Certicom Research, *SEC 2: Recommended Elliptic Curve Domain Parameters* (2010)
- Sealed-Bid Auctions: Brandt, *How to Obtain Full Privacy in Auctions* (2006)
