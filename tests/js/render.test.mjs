// Rendering tests for the frontend script (src/crypto_auction/web/static/app.js),
// run with Node's built-in test runner:
//   node --test tests/js/
//
// app.js is a plain browser script that only touches the DOM when its
// functions run, so it can be loaded into a VM context with a minimal fake
// `document`, and its renderers checked on the HTML strings they produce.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const APP_JS = readFileSync(
  new URL("../../src/crypto_auction/web/static/app.js", import.meta.url),
  "utf8",
);

// Accepted by the API as a bidder or item name (a non-blank string).
const PAYLOAD = '<img src=x onerror="alert(1)">';
const ESCAPED = "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;";

function fakeElement() {
  return {
    innerHTML: "",
    textContent: "",
    className: "",
    style: {},
    classList: { toggle() {} },
    prepend() {},
  };
}

function loadApp() {
  const elements = new Map();
  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, fakeElement());
      return elements.get(id);
    },
    createElement: () => fakeElement(),
    querySelectorAll: () => [],
  };
  const app = vm.createContext({ document, console });
  vm.runInContext(APP_JS, app);
  return { app, html: (id) => elements.get(id).innerHTML };
}

function assertEscaped(html) {
  assert.ok(!html.includes("<img"), `unescaped markup in: ${html}`);
  assert.ok(html.includes(ESCAPED), "the text itself should still be shown, escaped");
}

const DEADLINES = {
  commit: "2027-01-15T08:10:00.000+00:00",
  prove: "2027-01-15T08:20:00.000+00:00",
  reveal: "2027-01-15T08:30:00.000+00:00",
};

function auctionState(overrides = {}) {
  return {
    state: "open",
    item_name: PAYLOAD,
    min_bid: 100,
    max_bid: 5000,
    server_time: "2027-01-15T08:00:00.000+00:00",
    deadlines: DEADLINES,
    winner: null,
    bidders: [
      {
        bidder_id: "bidder_0",
        name: PAYLOAD,
        commitment_hex: null,
        proof_valid: null,
        commitment_verified: null,
      },
    ],
    ...overrides,
  };
}

test("escapeHtml escapes every HTML-significant character", () => {
  const { app } = loadApp();
  assert.equal(
    app.escapeHtml(`<a href="x">&'</a>`),
    "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;",
  );
});

test("bidder cards escape bidder names", () => {
  const { app, html } = loadApp();
  app.renderBidderCards(auctionState());
  assertEscaped(html("bidder-cards"));
});

test("actions panel escapes the item and winner names", () => {
  const { app, html } = loadApp();
  const winner = { bidder_id: "bidder_0", name: PAYLOAD, bid: 1000 };
  app.renderActionsPanel(auctionState({ state: "finished", winner }));
  const rendered = html("actions-content");
  assertEscaped(rendered);
  // Item name and winner name: both occurrences must be escaped.
  assert.equal(rendered.split(ESCAPED).length - 1, 2);
});

test("during the reveal phase, a bidder who revealed is shown as revealed", () => {
  // Public state after Alice revealed: the server publishes that she did
  // (commitment_verified), but no bids until the auction is finished.
  const { app, html } = loadApp();
  const proved = { commitment_hex: "02" + "aa".repeat(32), proof_valid: true };
  const state = auctionState({
    state: "proved",
    bidders: [
      { bidder_id: "bidder_0", name: "Alice", ...proved, commitment_verified: true },
      { bidder_id: "bidder_1", name: "Bob", ...proved, commitment_verified: null },
    ],
  });

  app.renderBidderCards(state);
  const cards = html("bidder-cards");
  assert.ok(!cards.includes("btn-reveal-bidder_0"), "Alice must not be offered a second reveal");
  assert.ok(cards.includes("btn-reveal-bidder_1"), "Bob has yet to reveal");
  assert.ok(cards.includes("✓ Revealed"));
  assert.ok(!cards.includes("NaN"), "no bid is known yet, so none is shown");

  app.renderActionsPanel(state);
  assert.match(html("actions-content"), /Revealed: 1 \/ 2/);
});

test("a bidder who missed a deadline is shown as out, and progress counts the others", () => {
  const { app, html } = loadApp();
  const state = auctionState({
    state: "committed",
    bidders: [
      { bidder_id: "bidder_0", name: "Alice", commitment_hex: "02" + "aa".repeat(32), proof_valid: null },
      { bidder_id: "bidder_1", name: "Bob", commitment_hex: null, missed_deadline: "commit" },
    ],
  });

  app.renderBidderCards(state);
  const cards = html("bidder-cards");
  assert.ok(cards.includes("Missed the commit deadline"));
  assert.ok(cards.includes("btn-prove-bidder_0"), "Alice can still prove");
  assert.ok(!cards.includes("btn-prove-bidder_1"), "Bob takes no further part");

  app.renderActionsPanel(state);
  const panel = html("actions-content");
  assert.match(panel, /ZK Proved: 0 \/ 1/);
  // The prove deadline, in the viewer's time zone.
  const closes = new Date(DEADLINES.prove).toLocaleTimeString("en-GB");
  assert.ok(panel.includes(`closes at <strong>${closes}</strong>`), panel);
});

test("proof summary reads the range proof format the API returns", () => {
  const { app } = loadApp();
  // Shape of RangeProof.to_dict(): per side, one bit commitment per bit.
  const commitments = Array.from({ length: 13 }, (_, i) => "02" + String(i).padStart(64, "0"));
  const proof = { low: { bit_commitments: commitments, bit_proofs: [] }, high: {} };
  const summary = app.proofSummary(proof);
  assert.equal(summary["bits per side"], 13);
  assert.equal(summary["first bit commitment"], "0200000000000000…");
});

test("log entries escape titles, keys and values", () => {
  const { app } = loadApp();
  const entry = app.buildLogEntry("public", `${PAYLOAD} committed`, { [PAYLOAD]: PAYLOAD });
  assertEscaped(entry.innerHTML);
  assert.equal(entry.innerHTML.split(ESCAPED).length - 1, 3);
});
