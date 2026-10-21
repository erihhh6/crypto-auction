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

function auctionState(overrides = {}) {
  return {
    state: "open",
    item_name: PAYLOAD,
    min_bid: 100,
    max_bid: 5000,
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

test("log entries escape titles, keys and values", () => {
  const { app } = loadApp();
  const entry = app.buildLogEntry("public", `${PAYLOAD} committed`, { [PAYLOAD]: PAYLOAD });
  assertEscaped(entry.innerHTML);
  assert.equal(entry.innerHTML.split(ESCAPED).length - 1, 3);
});
