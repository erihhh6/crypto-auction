# Threat model

What CryptoAuction protects, from whom, how, and what it leaves open. Each
mitigation names where it is enforced or tested. The [API reference](api.md)
describes the requests mentioned here.

- [Assets](#assets)
- [Actors and how far each is trusted](#actors-and-how-far-each-is-trusted)
- [Assumptions](#assumptions)
- [Threats and mitigations](#threats-and-mitigations)
- [What anyone can check afterwards](#what-anyone-can-check-afterwards)
- [Not protected](#not-protected)

## Assets

1. **The bids, until the auction is finished.** Nobody, the server included,
   should learn a bid before the reveal phase is over.
2. **Each bidder's say.** Only a bidder can commit, prove or reveal for
   themselves.
3. **A correct outcome.** The winner is the highest bid in `[min, max]` whose
   proof is valid and whose opening matches its commitment; ties go to the
   earliest commitment.
4. **An auction that ends**, and a server that stays up.

## Actors and how far each is trusted

| Actor | Trusted to | Not trusted to |
|---|---|---|
| **Auctioneer** (whoever runs the server) | follow the protocol, and serve the genuine page code | keep from looking: it may read every request, its logs and the database to learn bids early (*honest but curious*) |
| **Organizer** (whoever creates an auction) | hand each bidder their own join link, and nobody else | anything else; it is not the auctioneer |
| **Bidders** | nothing | bid within the range, keep their bid, wait their turn, stay to the end, or leave the others alone |
| **Everyone else**: other websites, holders of a leaked link or receipt, the network, anyone sending requests | nothing | anything |

## Assumptions

- **The discrete logarithm problem on secp256k1 is hard**, and nobody knows
  `log_G(H)`: `H` is derived by hashing a public tag to a curve point
  (`pedersen.py`).
- **SHA-512 behaves as a random oracle** for the Fiat–Shamir transform.
- **Randomness is unpredictable**: blinding factors come from
  `crypto.getRandomValues` in the browser and from `secrets` in Python.
- **The page code reaching bidders is genuine.** Bidders run the JavaScript
  the auctioneer serves; this is the one place they must trust it beyond
  curiosity (see [Not protected](#not-protected)).
- **The deployment uses HTTPS**, so tokens and bids cannot be read or changed
  in transit. The app itself serves plain HTTP; TLS ends at a reverse proxy.
- **The server's clock decides the deadlines.**

## Threats and mitigations

### A curious auctioneer

| Threat | Mitigation | Where |
|---|---|---|
| Learns a bid from a request before the reveal | The browser computes the commitment and the range proof; a Pedersen commitment hides the bid perfectly and the proof is zero-knowledge. The bid and its blinding factor are first sent at the reveal | `static/auction-crypto.js`; request bodies checked in `tests/js/app-flow.test.mjs` and, in real browsers, `tests/e2e/auction.spec.mjs` |
| Reads the database | It holds commitments, proofs and SHA-256 digests of the tokens; openings only once revealed | `auction.py`, `store.py` |

### Bidders

| Threat | Mitigation | Where |
|---|---|---|
| Changes their bid after committing | A commitment binds: two openings of one commitment would give `log_G(H)` | `pedersen.py`, `tests/test_pedersen.py` |
| Bids outside `[min, max]` | The range proof shows `bid − min` and `max − bid` both fit in `k` bits, with `k` fixed by the verifier from its own range: a proof with more bits could make the sum wrap around the group order (the suite runs that attack). The statement comes from the server, never from the proof. The revealed bid is checked against the range again | `range_proof.py`, `tests/test_range_proof.py`, `auction.py` |
| Replays a proof from another auction or bidder, or for another commitment or range | Every Fiat–Shamir challenge covers domain tags, both generators, the bid's commitment, the range, the auction id, the bidder id, the side and position of the bit, the bit's commitment and the proof's announcements | `bit_proof.py`, `range_proof.py`, `tests/test_api.py` |
| Copies another bidder's commitment | Refused; the copier could neither prove nor open it anyway | `auction.py`, `tests/test_api.py` |
| Acts as another bidder | Join tokens are 256 random bits, sent only in the `Authorization` header and compared in constant time. The token alone decides who acts; no request names a bidder | `auction.py`, `service.py`, `tests/test_api.py` |
| Sees the others' bids, then withholds their own reveal when losing (selective abort) | Openings stay hidden until the reveal phase is over, so the bids a bidder could look at before revealing are none | `auction.get_public_state`, `tests/test_api.py` |
| Stalls the auction by not acting | Each phase has a deadline; whoever misses it is out, and the others carry on | `auction.py` (`_advance`), `tests/test_api.py` |
| Wins a tie by timing | Ties go to the earliest commitment, numbered by the server as they arrive | `auction.py` |
| Runs script in other viewers' pages through a name (XSS) | Names are inserted as text; the few HTML templates escape every value from the server; the Content-Security-Policy allows no inline script or style, so injected markup could not run anyway | `static/app.js`, `tests/js/render.test.mjs`, `tests/test_web_security.py`, CSP watched in every e2e test |

### Other websites and the network

| Threat | Mitigation | Where |
|---|---|---|
| A website drives the API from a visitor's browser (CSRF) | Tokens travel in a header, never in cookies, so a browser attaches nothing on its own. POST bodies must be `application/json`, and JSON POSTs and DELETEs from another origin need a CORS preflight, which is never approved | `web/api.py` (`require_json_posts`), `tests/test_api.py` |
| Frames the page to trick clicks (clickjacking) | `frame-ancestors 'none'` and `X-Frame-Options: DENY` | `web/__init__.py`, `tests/test_web_security.py` |
| Leaks a token from a URL | A join link carries the token in the fragment (`#auction=…&token=…`), which browsers never send to the server, so it stays out of server logs and `Referer` headers; `Referrer-Policy: no-referrer` besides. API answers, which carry tokens and live state, are `Cache-Control: no-store` | `static/app.js`, `web/__init__.py` |
| Reaches into the page from a window it opened | `Cross-Origin-Opener-Policy: same-origin` | `web/__init__.py` |
| Reads or alters traffic | HTTPS, set up at the deployment (see [Assumptions](#assumptions)) | — |

### Anyone: denial of service

| Threat | Mitigation | Where |
|---|---|---|
| Sends huge requests | Bodies over 64 KiB are refused (413) before they are read | `web/api.py` (`MAX_REQUEST_BYTES`), `tests/test_api.py` |
| Sends costly input | Every input is bounded: at most 10 bidders, names of 100 characters, integers below 2^53; a proof with any other number of bits than the range needs is invalid without further work | `web/api.py`, `range_proof.py` |
| Creates auctions without end | At most 1000 run at once; more are refused (503) | `service.py`, `tests/test_api.py` |

That cap is also the remaining weakness: there are no accounts or rate
limits, so one client can create the 1000 auctions itself, with week-long
windows, and block new auctions for three weeks. A deployment open to the
public would need rate limits or accounts in front of creation.

### The supply chain

| Threat | Mitigation | Where |
|---|---|---|
| A compromised CDN or library update changes the page's cryptography | The page loads no third-party code at runtime. Its one library, `@noble/secp256k1`, is vendored and pinned, its hash recorded, and a test checks the copy is the npm release byte for byte | `static/vendor/`, `tests/js/vendor.test.mjs` |
| A hijacked npm package runs code on install | The npm packages are development tools only; none ships with the page. Versions are exact, `package-lock.json` holds their hashes, and `.npmrc` refuses install scripts | `package.json`, `.npmrc` |
| A moved tag changes a CI action | Every GitHub Action is pinned to a commit SHA | `.github/workflows/ci.yml` |
| A fresh, malicious release slips in | Dependabot proposes updates, including for the vendored library, only once a release is a week old; CI checks each | `.github/dependabot.yml` |

## What anyone can check afterwards

Once an auction is finished, its public state (`GET /api/auctions/{id}`) lists
every commitment, every opening (bid and blinding factor), the order of the
commitments, and each bidder's verdicts. With it, anyone can check that each
opening matches its commitment, that the winner's bid is the highest valid one
in the range, and that ties went to the earliest commitment.

Two things rest on the server's word:

- **Whether a proof was valid.** The proofs themselves are not published, so a
  dishonest server could disqualify a bidder by calling a valid proof invalid.
  Publishing the proofs would let anyone check them.
- **Whether a deadline was missed.** The server's clock decides.

## Not protected

- **A malicious auctioneer.** A server that serves altered JavaScript could
  read bids in the browser. Closing that needs page code bidders obtain and
  check independently: a pinned, reviewed release or a native client.
- **Bidders from the organizer.** The organizer receives every join token to
  hand out, so it can act as any bidder, and it can delete the auction at any
  time.
- **Bids after the auction.** Every opening is published once the auction is
  finished, so the result can be checked; losing bids do not stay secret.
- **Leaked receipts and links.** A receipt holds the bid, its blinding factor
  and the join token, unencrypted; whoever has it (or a join link) can act as
  that bidder.
- **Timing side channels.** JavaScript's BigInt arithmetic is not
  constant-time; `@noble/secp256k1` reduces the leakage, but cannot remove it.
- **The cost of dropping out.** A bidder who does not reveal only loses the
  chance to win. A real auction would hold a deposit that the bidder forfeits.
- **Collusion between bidders**, such as agreeing on bids beforehand: outside
  what the protocol can see.
