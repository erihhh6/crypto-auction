// Privacy and identity regression tests for the page's protocol flow
// (static/app.js): what each request sends to the server, and as whom. Runs
// app.js in a VM with a fake DOM (fake-dom.mjs), a recording fetch() and a
// stub window.auctionCrypto; the real cryptography is covered by
// crypto.test.mjs and tests/test_browser_interop.py.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

import { fakeDocument } from "./fake-dom.mjs";

const APP_JS = readFileSync(
  new URL("../../src/crypto_auction/web/static/app.js", import.meta.url),
  "utf8",
);

const COMMITMENT = "02" + "aa".repeat(32);
const BLINDING = "bb".repeat(32);
const FAKE_PROOF = { low: { bit_commitments: ["02" + "cc".repeat(32)], bit_proofs: [] }, high: {} };
const TOKENS = { bidder_0: "alices-join-token", bidder_1: "bobs-join-token" };
const ORGANIZER_TOKEN = "organizer-token";

// What creating an auction returns: the only response that carries tokens.
const CREATED = {
  success: true,
  auction_id: "ab".repeat(16),
  organizer_token: ORGANIZER_TOKEN,
  item_name: "x",
  min_bid: 100,
  max_bid: 5000,
  bidders: [
    { bidder_id: "bidder_0", name: "Alice", join_token: TOKENS.bidder_0 },
    { bidder_id: "bidder_1", name: "Bob", join_token: TOKENS.bidder_1 },
  ],
};
const AUCTION = `/api/auctions/${CREATED.auction_id}`;

function loadApp() {
  const document = fakeDocument();
  const requests = [];
  const cryptoCalls = [];
  const alerts = [];
  const timers = [];
  const state = {
    success: true,
    auction_id: CREATED.auction_id,
    state: "open",
    item_name: "x",
    min_bid: 100,
    max_bid: 5000,
    server_time: "2027-01-15T08:00:00.000+00:00",
    deadlines: {
      commit: "2027-01-15T08:10:00.000+00:00",
      prove: "2027-01-15T08:20:00.000+00:00",
      reveal: "2027-01-15T08:30:00.000+00:00",
    },
    winner: null,
    bidders: CREATED.bidders.map(({ bidder_id, name }) => ({ bidder_id, name, commitment_hex: null })),
  };
  const responses = {
    [`GET ${AUCTION}`]: state,
    [`POST ${AUCTION}/commit`]: { success: true, phase: "open", message: "ok" },
    [`POST ${AUCTION}/prove`]: { success: true, proof_valid: true, phase: "committed", message: "ok" },
    [`POST ${AUCTION}/reveal`]: { success: true, verified: true, phase: "proved", message: "ok", winner: null },
    [`DELETE ${AUCTION}`]: { success: true, message: "Auction deleted." },
  };
  const context = vm.createContext({
    console,
    alert: (message) => alerts.push(message),
    confirm: () => true,
    // Recorded, never run: the tests decide what time it is.
    setTimeout: (callback, delay) => timers.push({ callback, delay }),
    clearTimeout() {},
    document,
    fetch: async (path, opts) => {
      requests.push({
        method: opts.method,
        path,
        authorization: opts.headers.Authorization,
        body: opts.body === undefined ? null : JSON.parse(opts.body),
      });
      return { json: async () => responses[`${opts.method} ${path}`] };
    },
    window: {
      auctionCrypto: {
        commitBid(bid) {
          cryptoCalls.push({ commitBid: bid });
          return { commitmentHex: COMMITMENT, blindingHex: BLINDING };
        },
        async proveBid(args) {
          cryptoCalls.push({ proveBid: args });
          return FAKE_PROOF;
        },
      },
    },
  });
  vm.runInContext(APP_JS, context);
  context.rememberAuction(CREATED);
  /** Commit a bid the way a user does: type it into the card, press Commit. */
  async function commitThroughCard(bidderId, bid) {
    document.getElementById(`bid-input-${bidderId}`).value = String(bid);
    await document.getElementById(`btn-commit-${bidderId}`).click();
  }
  return { app: context, requests, cryptoCalls, alerts, timers, state, commitThroughCard };
}

const sentTo = (requests, path) => requests.filter((r) => r.path === path).map((r) => r.body);

test("the bid and its blinding factor reach the server only at the reveal", async () => {
  const { app, requests, cryptoCalls, alerts, commitThroughCard } = loadApp();

  await app.refreshState(); // the cards, as the page first shows them
  await commitThroughCard("bidder_0", 1500);
  // The stub server stays in the commit phase, so the later steps are
  // called directly rather than through their (hidden) buttons.
  await app.proveBid("bidder_0");
  await app.revealBid("bidder_0");
  assert.deepEqual(alerts, []);

  // Commit: only the commitment, computed locally from the typed bid.
  assert.deepEqual(sentTo(requests, `${AUCTION}/commit`), [{ commitment_hex: COMMITMENT }]);
  assert.deepEqual(cryptoCalls[0], { commitBid: 1500n });

  // Prove: only the proof, computed locally for this auction and bidder.
  assert.deepEqual(sentTo(requests, `${AUCTION}/prove`), [{ proof: FAKE_PROOF }]);
  // Spread: the object comes from the VM's realm, whose Object prototype differs.
  assert.deepEqual({ ...cryptoCalls[1].proveBid }, {
    bid: 1500n,
    blindingHex: BLINDING,
    commitmentHex: COMMITMENT,
    minBid: 100n,
    maxBid: 5000n,
    auctionId: CREATED.auction_id,
    bidderId: "bidder_0",
  });

  // Nothing before the reveal mentions the bid or the blinding factor.
  const beforeReveal = requests.slice(0, requests.findIndex((r) => r.path === `${AUCTION}/reveal`));
  for (const { path, body } of beforeReveal) {
    const sent = JSON.stringify(body ?? {});
    assert.ok(!sent.includes(BLINDING), `${path} leaked the blinding factor`);
    assert.ok(!sent.includes("1500"), `${path} leaked the bid`);
  }

  // Reveal: the opening, for the first time.
  assert.deepEqual(sentTo(requests, `${AUCTION}/reveal`), [{ bid: 1500, randomness_hex: BLINDING }]);
});

test("the page refreshes when the current phase's deadline passes, on the server's clock", async () => {
  const { app, timers, state } = loadApp();
  // Far from this computer's clock: only the server's times may matter.
  state.state = "committed";
  state.server_time = "2001-01-01T00:00:00.000+00:00";
  state.deadlines = { ...state.deadlines, prove: "2001-01-01T00:01:30.000+00:00" };

  await app.refreshState();
  assert.equal(timers.length, 1);
  assert.equal(timers[0].callback, app.refreshState);
  assert.equal(timers[0].delay, 90_000 + 250); // just after the deadline

  // Once finished, there is no deadline left to wait for.
  state.state = "finished";
  await app.refreshState();
  assert.equal(timers.length, 1);
});

test("each bidder's requests carry that bidder's join token, and no others do", async () => {
  const { app, requests, alerts, commitThroughCard } = loadApp();

  await app.refreshState();
  await commitThroughCard("bidder_0", 1500);
  await commitThroughCard("bidder_1", 1800);
  await app.proveBid("bidder_1");
  await app.revealBid("bidder_1");
  assert.deepEqual(alerts, []);

  // The token, not the body, says who is acting; reads need none.
  assert.deepEqual(
    requests.map(({ method, path, authorization }) => [method, path, authorization]),
    [
      ["GET", AUCTION, undefined],
      ["POST", `${AUCTION}/commit`, `Bearer ${TOKENS.bidder_0}`],
      ["GET", AUCTION, undefined],
      ["POST", `${AUCTION}/commit`, `Bearer ${TOKENS.bidder_1}`],
      ["GET", AUCTION, undefined],
      ["POST", `${AUCTION}/prove`, `Bearer ${TOKENS.bidder_1}`],
      ["GET", AUCTION, undefined],
      ["POST", `${AUCTION}/reveal`, `Bearer ${TOKENS.bidder_1}`],
      ["GET", AUCTION, undefined],
    ],
  );
});

test("reset deletes the auction on the server, as its organizer", async () => {
  const { app, requests } = loadApp();
  await app.resetAuction();
  assert.deepEqual(
    requests.map(({ method, path, authorization }) => [method, path, authorization]),
    [["DELETE", AUCTION, `Bearer ${ORGANIZER_TOKEN}`]],
  );
});
