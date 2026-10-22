// Privacy regression test for the page's protocol flow (static/app.js): what
// each request sends to the server. Runs app.js in a VM with a fake DOM, a
// recording fetch() and a stub window.auctionCrypto; the real cryptography is
// covered by crypto.test.mjs and tests/test_browser_interop.py.

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
  const elements = new Map([["bid-input-bidder_0", fakeElement("1500")]]);
  const requests = [];
  const cryptoCalls = [];
  const alerts = [];
  const state = {
    success: true,
    auction_id: "ab".repeat(16),
    state: "open",
    item_name: "x",
    min_bid: 100,
    max_bid: 5000,
    winner: null,
    bidders: [{ bidder_id: "bidder_0", name: "Alice", commitment_hex: null }],
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
      requests.push({ path, body: opts.body === undefined ? null : JSON.parse(opts.body) });
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
  // Expose the script's top-level `localState` to the test (const bindings
  // are not properties of the global object).
  vm.runInContext(APP_JS + "\nglobalThis.__localState = localState;", context);
  context.__localState.auction = { auction_id: state.auction_id, min_bid: 100, max_bid: 5000 };
  return { app: context, requests, cryptoCalls, alerts, state };
}

const sentTo = (requests, path) => requests.filter((r) => r.path === path).map((r) => r.body);

test("the bid and its blinding factor reach the server only at the reveal", async () => {
  const { app, requests, cryptoCalls, alerts, state } = loadApp();

  await app.commitBid("bidder_0");
  await app.proveBid("bidder_0");
  await app.revealBid("bidder_0");
  assert.deepEqual(alerts, []);

  // Commit: only the commitment, computed locally from the typed bid.
  assert.deepEqual(sentTo(requests, "/api/commit"), [
    { bidder_id: "bidder_0", commitment_hex: COMMITMENT },
  ]);
  assert.deepEqual(cryptoCalls[0], { commitBid: 1500n });

  // Prove: only the proof, computed locally for this auction and bidder.
  assert.deepEqual(sentTo(requests, "/api/prove"), [{ bidder_id: "bidder_0", proof: FAKE_PROOF }]);
  // Spread: the object comes from the VM's realm, whose Object prototype differs.
  assert.deepEqual({ ...cryptoCalls[1].proveBid }, {
    bid: 1500n,
    blindingHex: BLINDING,
    commitmentHex: COMMITMENT,
    minBid: 100n,
    maxBid: 5000n,
    auctionId: state.auction_id,
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
  assert.deepEqual(sentTo(requests, "/api/reveal"), [
    { bidder_id: "bidder_0", bid: 1500, randomness_hex: BLINDING },
  ]);
});
