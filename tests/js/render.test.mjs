// Rendering tests for the frontend script (src/crypto_auction/web/static/app.js),
// run with Node's built-in test runner:
//   node --test "tests/js/*.test.mjs"
//
// app.js is a plain browser script that only touches the DOM when its
// functions run, so it can be loaded into a VM context with a fake document
// (fake-dom.mjs), and what its renderers build checked directly.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

import { fakeDocument } from "./fake-dom.mjs";

const APP_JS = readFileSync(
  new URL("../../src/crypto_auction/web/static/app.js", import.meta.url),
  "utf8",
);

// Accepted by the API as a bidder or item name (a non-blank string).
const PAYLOAD = '<img src=x onerror="alert(1)">';
const ESCAPED = "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;";

function loadApp(overrides = {}) {
  const document = fakeDocument(overrides);
  const app = vm.createContext({
    document,
    console,
    window: { addEventListener() {} },
    location: { hash: "", origin: "http://localhost:5000", pathname: "/" },
    URLSearchParams,
  });
  vm.runInContext(APP_JS, app);
  // As on the organizer's page: it holds every bidder's join token, so it
  // offers each bidder their controls.
  app.rememberAuction({
    auction_id: "ab".repeat(16),
    bidders: joinTokens(["bidder_0", "bidder_1"]),
  });
  return {
    app,
    document,
    html: (id) => document.getElementById(id).innerHTML,
    text: (id) => document.getElementById(id).textContent,
    // On the page and not hidden: what the user can see and use.
    shown(id) {
      for (let node = document.getElementById(id); node; node = node.parentNode) {
        if (node.hidden) return false;
        if (node === document.body) return true;
      }
      return false;
    },
  };
}

const joinTokens = (ids) => ids.map((id) => ({ bidder_id: id, join_token: `${id}-token` }));

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

const bidder = (id, name, fields = {}) => ({
  bidder_id: id,
  name,
  commitment_hex: null,
  proof_valid: null,
  commitment_verified: null,
  ...fields,
});

test("escapeHtml escapes every HTML-significant character", () => {
  const { app } = loadApp();
  assert.equal(
    app.escapeHtml(`<a href="x">&'</a>`),
    "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;",
  );
});

test("bidder cards put names in as text, never as markup", () => {
  const { app, document } = loadApp();
  app.renderBidderCards(auctionState());
  const container = document.getElementById("bidder-cards");
  const nodes = [container, ...container.descendants()];
  const name = nodes.find((node) => node.className === "bidder-name");
  assert.equal(name.textContent, PAYLOAD); // shown exactly as typed
  assert.deepEqual(
    nodes.filter((node) => node.innerHTMLWrites > 0),
    [],
  );
});

test("a bid being typed, and the focus, survive a refresh", () => {
  const { app, document } = loadApp();
  const alice = bidder("bidder_0", "Alice");
  const bob = bidder("bidder_1", "Bob");
  app.renderBidderCards(auctionState({ bidders: [alice, bob] }));
  const input = document.getElementById("bid-input-bidder_0");
  input.value = "1234";
  input.focus();

  // Bob commits meanwhile, and the page refreshes.
  const committed = { ...bob, commitment_hex: "02" + "aa".repeat(32) };
  app.renderBidderCards(auctionState({ bidders: [alice, committed] }));
  assert.equal(document.getElementById("bid-input-bidder_0"), input);
  assert.equal(input.value, "1234");
  assert.equal(document.activeElement, input);
  assert.equal(document.getElementById("bid-input-bidder_1"), null, "Bob has committed");
});

test("a new auction starts from fresh cards", () => {
  const { app, document } = loadApp();
  app.renderBidderCards(auctionState({ bidders: [bidder("bidder_0", "Alice")] }));
  document.getElementById("bid-input-bidder_0").value = "1234";

  // Bidder ids repeat across auctions; what was typed for one must not carry over.
  app.rememberAuction({ auction_id: "cd".repeat(16), bidders: joinTokens(["bidder_0"]) });
  app.renderBidderCards(auctionState({ bidders: [bidder("bidder_0", "Carol")] }));
  assert.equal(document.getElementById("bid-input-bidder_0").value, "");
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
  const { app, html, text, shown } = loadApp();
  const proved = { commitment_hex: "02" + "aa".repeat(32), proof_valid: true };
  const state = auctionState({
    state: "proved",
    bidders: [
      bidder("bidder_0", "Alice", { ...proved, commitment_verified: true }),
      bidder("bidder_1", "Bob", proved),
    ],
  });

  app.renderBidderCards(state);
  assert.ok(!shown("btn-reveal-bidder_0"), "Alice must not be offered a second reveal");
  assert.ok(shown("btn-reveal-bidder_1"), "Bob has yet to reveal");
  assert.ok(text("bidder-cards").includes("✓ Revealed"));
  assert.ok(!text("bidder-cards").includes("NaN"), "no bid is known yet, so none is shown");

  app.renderActionsPanel(state);
  assert.match(html("actions-content"), /Revealed: 1 \/ 2/);
});

test("a bidder who missed a deadline is shown as out, and progress counts the others", () => {
  const { app, html, text, shown } = loadApp();
  const state = auctionState({
    state: "committed",
    bidders: [
      bidder("bidder_0", "Alice", { commitment_hex: "02" + "aa".repeat(32) }),
      bidder("bidder_1", "Bob", { missed_deadline: "commit" }),
    ],
  });

  app.renderBidderCards(state);
  assert.ok(text("bidder-cards").includes("Missed the commit deadline"));
  assert.ok(shown("btn-prove-bidder_0"), "Alice can still prove");
  assert.ok(!shown("btn-prove-bidder_1"), "Bob takes no further part");

  app.renderActionsPanel(state);
  const panel = html("actions-content");
  assert.match(panel, /ZK Proved: 0 \/ 1/);
  // The prove deadline, in the viewer's time zone.
  const closes = new Date(DEADLINES.prove).toLocaleTimeString("en-GB");
  assert.ok(panel.includes(`closes at <strong>${closes}</strong>`), panel);
});

test("the phase indicator lights the phase in progress, for screen readers too", () => {
  const { app, document } = loadApp();
  const pills = ["commit", "prove", "reveal", "finished"].map((phase) => {
    const pill = document.createElement("div");
    pill.dataset.phase = phase;
    return pill;
  });
  document.querySelectorAll = () => pills;

  // Each server state names what is complete; the pill shows what comes next.
  const expected = { open: "commit", committed: "prove", proved: "reveal", finished: "finished" };
  for (const [state, phase] of Object.entries(expected)) {
    app.renderPhaseIndicator(auctionState({ state }));
    const lit = pills.filter((p) => p.classList.contains("active")).map((p) => p.dataset.phase);
    assert.deepEqual(lit, [phase], `state "${state}"`);
    const current = pills.filter((p) => p.getAttribute("aria-current") === "step");
    assert.deepEqual(
      current.map((p) => p.dataset.phase),
      [phase],
      `aria-current in "${state}"`,
    );
  }
});

test("a card says in words what its colours show", () => {
  const { app, document } = loadApp();
  const state = auctionState({
    state: "proved",
    bidders: [
      bidder("bidder_0", "Alice", { commitment_hex: "02" + "aa".repeat(32), proof_valid: false }),
    ],
  });
  app.renderBidderCards(state);
  const card = document.getElementById("bidder-cards").firstElementChild;
  // A group named after the bidder, so its buttons are hers to a screen reader.
  assert.equal(card.getAttribute("role"), "group");
  assert.equal(document.getElementById(card.getAttribute("aria-labelledby")).textContent, "Alice");
  const badges = [...card.descendants()].filter((n) => n.className.startsWith("phase-badge"));
  assert.deepEqual(
    badges.map((badge) => badge.textContent),
    ["COMMIT: done", "PROVE: invalid", "REVEAL: not yet"],
  );
});

test("nothing the script builds would be blocked by the page's CSP", () => {
  // The server's policy forbids inline handlers (onclick="...") and style
  // attributes; markup and attributes the script builds must do without too.
  const { app, document } = loadApp();
  app.rememberAuction({
    auction_id: "ab".repeat(16),
    organizer_token: "organizer", // so the join links are built as well
    bidders: [{ bidder_id: "bidder_0", name: "Alice", join_token: "a" }],
  });
  const committed = { commitment_hex: "02" + "aa".repeat(32), proof_valid: true };
  for (const state of ["open", "committed", "proved", "finished"]) {
    const winner =
      state === "finished" ? { bidder_id: "bidder_0", name: "Alice", bid: 1000 } : null;
    const bidders = [bidder("bidder_0", "Alice", committed), bidder("bidder_1", "Bob")];
    app.renderAll(auctionState({ state, winner, bidders }));
  }
  app.addBidderInput();
  app.buildLogEntry("public", "Alice committed", { commitment: "02aa…" });

  // Inside a tag: escaped text such as the item name "&lt;img onerror=…" is harmless.
  const inline = /<[^>]*\s(?:on[a-z]+|style)\s*=/i;
  assert.ok(document.markupWritten.length > 0);
  assert.deepEqual(
    document.markupWritten.filter((markup) => inline.test(markup)),
    [],
  );
  assert.deepEqual(
    document.attributesSet.filter((name) => /^(?:style|on)/i.test(name)),
    [],
  );
});

test("every control of the page is connected by the script", async () => {
  // With no inline handlers, a control the script forgets would do nothing.
  const { document } = loadApp();
  const controls = {
    click: [
      "btn-add-bidder",
      "bidder-inputs",
      "btn-create",
      "btn-demo",
      "btn-stop-demo",
      "btn-clear-log",
      "btn-reset",
      "btn-close-winner",
    ],
    change: ["receipt-file"],
  };
  for (const [type, ids] of Object.entries(controls)) {
    for (const id of ids) {
      assert.ok(document.getElementById(id).listeners[type]?.length, `${id} (${type})`);
    }
  }
  await document.getElementById("btn-add-bidder").click();
  assert.equal(document.getElementById("bidder-inputs").children.length, 1, "a row was added");
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
