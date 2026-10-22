// Privacy and identity regression tests for the page's protocol flow
// (static/app.js): what each request sends to the server, and as whom. Runs
// app.js in a VM with a fake DOM, a recording fetch() and a stub
// window.auctionCrypto; the real cryptography is covered by crypto.test.mjs
// and tests/test_browser_interop.py.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const APP_JS = readFileSync(
  new URL("../../src/crypto_auction/web/static/app.js", import.meta.url),
  "utf8",
);

const COMMITMENT = "02" + "aa".repeat(32);
const BLINDING = "bb".repeat(32);
const FAKE_PROOF = { low: { bit_commitments: ["02" + "cc".repeat(32)], bit_proofs: [] }, high: {} };
const TOKENS = { bidder_0: "alices-join-token", bidder_1: "bobs-join-token" };

// What /api/create returns: the only response that carries join tokens.
const CREATED = {
  success: true,
  auction_id: "ab".repeat(16),
  item_name: "x",
  min_bid: 100,
  max_bid: 5000,
  bidders: [
    { bidder_id: "bidder_0", name: "Alice", join_token: TOKENS.bidder_0 },
    { bidder_id: "bidder_1", name: "Bob", join_token: TOKENS.bidder_1 },
  ],
};

function fakeElement(value = "") {
  return {
    value,
    innerHTML: "",
    textContent: "",
    disabled: false,
    style: {},
    classList: { toggle() {} },
    prepend() {},
  };
}

function loadApp() {
  const elements = new Map([
    ["bid-input-bidder_0", fakeElement("1500")],
    ["bid-input-bidder_1", fakeElement("1800")],
  ]);
  const requests = [];
  const cryptoCalls = [];
  const alerts = [];
  const state = {
    success: true,
    auction_id: CREATED.auction_id,
    state: "open",
    item_name: "x",
    min_bid: 100,
    max_bid: 5000,
    winner: null,
    bidders: CREATED.bidders.map(({ bidder_id, name }) => ({ bidder_id, name, commitment_hex: null })),
  };
  const responses = {
    "/api/state": state,
    "/api/commit": { success: true, phase: "open", message: "ok" },
    "/api/prove": { success: true, proof_valid: true, phase: "committed", message: "ok" },
    "/api/reveal": { success: true, verified: true, phase: "proved", message: "ok", winner: null },
  };
  const context = vm.createContext({
    console,
    alert: (message) => alerts.push(message),
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, fakeElement());
        return elements.get(id);
      },
      createElement: () => fakeElement(),
      querySelectorAll: () => [],
    },
    fetch: async (path, opts) => {
      requests.push({
        path,
        authorization: opts.headers.Authorization,
        body: opts.body === undefined ? null : JSON.parse(opts.body),
      });
      return { json: async () => responses[path] };
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
  return { app: context, requests, cryptoCalls, alerts };
}

const sentTo = (requests, path) => requests.filter((r) => r.path === path).map((r) => r.body);

test("the bid and its blinding factor reach the server only at the reveal", async () => {
  const { app, requests, cryptoCalls, alerts } = loadApp();

  await app.commitBid("bidder_0");
  await app.proveBid("bidder_0");
  await app.revealBid("bidder_0");
  assert.deepEqual(alerts, []);

  // Commit: only the commitment, computed locally from the typed bid.
  assert.deepEqual(sentTo(requests, "/api/commit"), [{ commitment_hex: COMMITMENT }]);
  assert.deepEqual(cryptoCalls[0], { commitBid: 1500n });

  // Prove: only the proof, computed locally for this auction and bidder.
  assert.deepEqual(sentTo(requests, "/api/prove"), [{ proof: FAKE_PROOF }]);
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
  const beforeReveal = requests.slice(0, requests.findIndex((r) => r.path === "/api/reveal"));
  for (const { path, body } of beforeReveal) {
    const sent = JSON.stringify(body ?? {});
    assert.ok(!sent.includes(BLINDING), `${path} leaked the blinding factor`);
    assert.ok(!sent.includes("1500"), `${path} leaked the bid`);
  }

  // Reveal: the opening, for the first time.
  assert.deepEqual(sentTo(requests, "/api/reveal"), [{ bid: 1500, randomness_hex: BLINDING }]);
});

test("each bidder's requests carry that bidder's join token, and no others do", async () => {
  const { app, requests, alerts } = loadApp();

  await app.commitBid("bidder_0");
  await app.commitBid("bidder_1");
  await app.proveBid("bidder_1");
  await app.revealBid("bidder_1");
  assert.deepEqual(alerts, []);

  // The token, not the body, says who is acting; reads need none.
  assert.deepEqual(
    requests.map(({ path, authorization }) => [path, authorization]),
    [
      ["/api/commit", `Bearer ${TOKENS.bidder_0}`],
      ["/api/state", undefined],
      ["/api/commit", `Bearer ${TOKENS.bidder_1}`],
      ["/api/state", undefined],
      ["/api/prove", `Bearer ${TOKENS.bidder_1}`],
      ["/api/state", undefined],
      ["/api/reveal", `Bearer ${TOKENS.bidder_1}`],
      ["/api/state", undefined],
    ],
  );
});
