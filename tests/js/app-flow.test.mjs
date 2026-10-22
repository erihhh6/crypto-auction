// Tests of the page's protocol flow (static/app.js) against a stub server:
// what each request sends and as whom (privacy and identity), and how the
// page reports what goes wrong. Runs app.js in a VM with a fake DOM
// (fake-dom.mjs), a scriptable fetch() and a stub window.auctionCrypto; the
// real cryptography is covered by crypto.test.mjs and
// tests/test_browser_interop.py.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { setImmediate } from "node:timers/promises";
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

/** A route answering with an API error. */
const failure = (status, error) => ({ status, body: { success: false, error } });
/** A route failing as fetch() does when the server cannot be reached. */
const UNREACHABLE = Symbol("unreachable");

/**
 * The page, loaded with a created auction, unless `created` is false (as for
 * a page just reloaded, or opened from the link in `hash`). `routes`
 * ("METHOD path" → JSON body, failure(...), UNREACHABLE, or a function
 * returning one of these) override the stub server's answers and can be
 * changed while a test runs; `document` overrides fake DOM methods.
 */
function loadApp({
  routes: overrides = {},
  document: documentOverrides = {},
  created = true,
  hash = "",
  clipboardWorks = true,
} = {}) {
  const document = fakeDocument(documentOverrides);
  const requests = [];
  const cryptoCalls = [];
  const alerts = [];
  const timers = [];
  const downloads = [];
  const clipboard = [];
  const windowListeners = {};
  const location = { hash, origin: "http://localhost:5000", pathname: "/", search: "" };
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
  const routes = {
    "POST /api/auctions": CREATED,
    [`GET ${AUCTION}`]: state,
    [`POST ${AUCTION}/commit`]: { success: true, phase: "open", message: "ok" },
    [`POST ${AUCTION}/prove`]: { success: true, proof_valid: true, phase: "committed", message: "ok" },
    [`POST ${AUCTION}/reveal`]: { success: true, verified: true, phase: "proved", message: "ok", winner: null },
    [`DELETE ${AUCTION}`]: { success: true, message: "Auction deleted." },
    ...overrides,
  };
  const context = vm.createContext({
    console,
    alert: (message) => alerts.push(message),
    confirm: () => true,
    // Recorded, never run: the tests decide what time it is.
    setTimeout: (callback, delay) => timers.push({ callback, delay }),
    clearTimeout() {},
    setInterval: () => 0,
    clearInterval() {},
    // A download: the file's contents, as the page hands them to the browser.
    Blob: class {
      constructor(parts, options) {
        this.text = parts.join("");
        this.type = options.type;
      }
    },
    URL: {
      createObjectURL: (blob) => downloads.push(blob) && "blob:download",
      revokeObjectURL() {},
    },
    URLSearchParams,
    location,
    history: {
      replaceState(_state, _title, url) {
        location.hash = new URL(url, location.origin).hash;
      },
    },
    navigator: {
      clipboard: {
        async writeText(text) {
          if (!clipboardWorks) throw new Error("NotAllowedError");
          clipboard.push(text);
        },
      },
    },
    document,
    fetch: async (path, opts) => {
      requests.push({
        method: opts.method,
        path,
        authorization: opts.headers.Authorization,
        body: opts.body === undefined ? null : JSON.parse(opts.body),
      });
      let route = routes[`${opts.method} ${path}`];
      if (typeof route === "function") route = await route();
      if (route === UNREACHABLE) throw new TypeError("Failed to fetch");
      const { status, body } = route.status ? route : { status: 200, body: route };
      // A fresh copy, as a real response is: the page must not see the
      // test's later changes to `state` until it asks again.
      return { status, json: async () => structuredClone(body) };
    },
    window: {
      addEventListener: (type, listener) => (windowListeners[type] = listener),
      auctionCrypto: {
        commitBid(bid) {
          cryptoCalls.push({ commitBid: bid });
          return { commitmentHex: COMMITMENT, blindingHex: BLINDING };
        },
        async proveBid(args) {
          cryptoCalls.push({ proveBid: args });
          return FAKE_PROOF;
        },
        // Only the stub's own commitment, to 1500, opens.
        opensCommitment: (commitment, bid, blinding) =>
          commitment === COMMITMENT && bid === 1500n && blinding === BLINDING,
      },
    },
  });
  vm.runInContext(APP_JS, context);
  if (created) context.rememberAuction(CREATED);

  /** Commit a bid the way a user does: type it into the card, press Commit. */
  async function commitThroughCard(bidderId, bid) {
    document.getElementById(`bid-input-${bidderId}`).value = String(bid);
    await document.getElementById(`btn-commit-${bidderId}`).click();
  }
  /** The error shown on a bidder's card, or null if none is shown. */
  function cardError(bidderId) {
    const error = document.getElementById(`bidder-error-${bidderId}`);
    return error.hidden ? null : error.textContent;
  }
  const toasts = () => document.getElementById("toasts").children.map((t) => t.textContent);

  /** Whether leaving the page now would ask the user first. */
  function leavingAsks() {
    let asked = false;
    windowListeners.beforeunload({ preventDefault: () => (asked = true) });
    return asked;
  }
  /** The text of the setup panel's error, or null if none is shown. */
  function setupError() {
    const error = document.getElementById("setup-error");
    return error.hidden ? null : error.textContent;
  }

  return {
    app: context, document, requests, cryptoCalls, alerts, timers, state, routes, downloads,
    clipboard, location, commitThroughCard, cardError, toasts, leavingAsks, setupError,
  };
}

/** Let the page's pending requests and their follow-ups run. */
async function settle() {
  for (let i = 0; i < 20; i++) await setImmediate();
}

/** A file as the file picker gives it. */
const fileWith = (text) => ({ text: async () => text });

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

test("the page refreshes every few seconds, and just after a deadline", async () => {
  const { app, timers, state } = loadApp();
  // Far from this computer's clock: only the server's times may matter.
  state.state = "committed";
  state.server_time = "2001-01-01T00:00:00.000+00:00";

  state.deadlines = { ...state.deadlines, prove: "2001-01-01T00:01:30.000+00:00" };
  await app.refreshState();
  assert.equal(timers.at(-1).callback, app.refreshState);
  assert.equal(timers.at(-1).delay, 5_000, "the next poll comes first");

  state.deadlines = { ...state.deadlines, prove: "2001-01-01T00:00:02.000+00:00" };
  await app.refreshState();
  assert.equal(timers.at(-1).delay, 2_000 + 250, "just after the deadline");

  // Once finished, there is nothing left to wait for.
  const planned = timers.length;
  state.state = "finished";
  await app.refreshState();
  assert.equal(timers.length, planned);
});

test("a hidden page stops polling, and catches up when shown again", async () => {
  const { app, document, requests, timers } = loadApp();
  document.hidden = true;
  await app.refreshState();
  assert.deepEqual(timers, []);

  document.hidden = false;
  const asked = requests.length;
  for (const listener of document.listeners.visibilitychange) listener();
  await settle();
  assert.equal(requests.length, asked + 1);
  assert.equal(timers.length, 1, "polling again");
});

test("a slow answer does not overwrite a newer one", async () => {
  const { app, routes, state, document } = loadApp();
  let answerOld;
  routes[`GET ${AUCTION}`] = () => new Promise((resolve) => (answerOld = resolve));
  const old = app.refreshState(); // a poll, still on its way
  routes[`GET ${AUCTION}`] = { ...state, state: "committed" };
  await app.refreshState(); // a newer refresh, answered first
  answerOld(state); // the poll's answer, now out of date
  await old;
  assert.equal(vm.runInContext("localState.serverState.state", app), "committed");
  assert.ok(document.getElementById("bidder-cards").children.length > 0);
});

test("whoever's reveal ends the auction, every page shows the winner", async () => {
  const { app, state, document } = loadApp();
  state.state = "proved";
  await app.refreshState();
  assert.equal(document.getElementById("winner-overlay").hidden, true);

  // Bob revealed last, on his own device; this page learns it from a poll.
  state.state = "finished";
  state.winner = { bidder_id: "bidder_1", name: "Bob", bid: 1800 };
  await app.refreshState();
  assert.equal(document.getElementById("winner-overlay").hidden, false);
  assert.equal(document.getElementById("winner-name").textContent, "Bob");
});

test("the organizer's page lists each bidder's join link, to copy and send", async () => {
  const { document, clipboard, toasts } = loadApp();
  assert.equal(document.getElementById("join-links").hidden, false);
  for (const { bidder_id } of CREATED.bidders) {
    const link = new URL(document.getElementById(`join-link-${bidder_id}`).value);
    assert.equal(link.origin + link.pathname, "http://localhost:5000/");
    // In the fragment, which is never sent to the server.
    assert.equal(link.search, "");
    const params = new URLSearchParams(link.hash.slice(1));
    assert.equal(params.get("auction"), CREATED.auction_id);
    assert.equal(params.get("token"), TOKENS[bidder_id]);
  }

  await document.getElementById("btn-copy-link-bidder_0").click();
  assert.deepEqual(clipboard, [document.getElementById("join-link-bidder_0").value]);
  assert.deepEqual(toasts(), ["Alice's join link is copied.✕"]);
});

test("a join link that cannot be copied is selected for copying by hand", async () => {
  const { document, toasts } = loadApp({ clipboardWorks: false });
  await document.getElementById("btn-copy-link-bidder_1").click();
  const field = document.getElementById("join-link-bidder_1");
  assert.ok(field.selected);
  assert.equal(document.activeElement, field);
  assert.match(toasts()[0], /^Could not copy the link; it is selected/);
});

test("a join link opens the auction as that bidder, and only that bidder", async () => {
  const hash = `#${new URLSearchParams({ auction: CREATED.auction_id, token: TOKENS.bidder_0 })}`;
  const { app, document, requests, setupError, location } = loadApp({
    created: false,
    hash,
    routes: { [`GET ${AUCTION}/me`]: { success: true, bidder_id: "bidder_0", name: "Alice" } },
  });
  await settle(); // the page joins as it loads

  assert.equal(setupError(), null);
  assert.equal(document.getElementById("setup-panel").hidden, true);
  assert.equal(document.getElementById("auction-view").hidden, false);
  assert.equal(document.getElementById("phase-indicator").hidden, false);
  const [me] = requests.filter((r) => r.path === `${AUCTION}/me`);
  assert.equal(me.authorization, `Bearer ${TOKENS.bidder_0}`, "the link is checked first");
  assert.equal(document.getElementById("auction-item-label").textContent, "x — bidding as Alice");
  assert.ok(document.getElementById("bid-input-bidder_0"), "Alice can bid");
  assert.equal(document.getElementById("bid-input-bidder_1"), null, "for Alice only");
  assert.equal(document.getElementById("join-links").hidden, true, "no organizer here");
  assert.equal(document.getElementById("btn-reset").textContent, "Leave");

  // Leaving takes the link out of the address bar, so a reload does not rejoin.
  await app.resetAuction();
  assert.equal(location.hash, "");
  assert.deepEqual(requests.filter((r) => r.method === "DELETE"), []);
});

test("an invalid join link is explained on the setup page", async () => {
  const hash = `#${new URLSearchParams({ auction: CREATED.auction_id, token: "not-a-token" })}`;
  const { document, setupError } = loadApp({
    created: false,
    hash,
    routes: { [`GET ${AUCTION}/me`]: failure(401, "Missing or invalid join token for this auction.") },
  });
  await settle();
  assert.equal(setupError(), "Could not open this join link: it is not valid for this auction.");
  assert.equal(document.getElementById("setup-panel").hidden, false);
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

test("a rejected commit is explained on the bidder's card, not in a dialog", async () => {
  const reason = "Bidder 'Alice' missed the commit deadline and takes no further part.";
  const { app, document, alerts, commitThroughCard, cardError } = loadApp({
    routes: { [`POST ${AUCTION}/commit`]: failure(400, reason) },
  });
  await app.refreshState();
  await commitThroughCard("bidder_0", 1500);

  assert.equal(cardError("bidder_0"), `Commit failed: ${reason}`);
  assert.equal(cardError("bidder_1"), null);
  assert.deepEqual(alerts, []);
  const button = document.getElementById("btn-commit-bidder_0");
  assert.equal(button.disabled, false, "the bidder can try again");
});

test("a card's error goes once the auction moves to another phase", async () => {
  const { app, state, commitThroughCard, cardError } = loadApp({
    routes: { [`POST ${AUCTION}/commit`]: failure(400, "Not now.") },
  });
  await app.refreshState();
  await commitThroughCard("bidder_0", 1500);
  await app.refreshState();
  assert.equal(cardError("bidder_0"), "Commit failed: Not now.", "same phase: still relevant");

  state.state = "committed";
  await app.refreshState();
  assert.equal(cardError("bidder_0"), null);
});

test("a bid that is not a whole number in range is explained, and nothing is sent", async () => {
  const { app, document, requests, commitThroughCard, cardError } = loadApp();
  await app.refreshState();
  const sent = () => sentTo(requests, `${AUCTION}/commit`).length;

  // A commitment binds the bidder to exactly the number committed.
  await commitThroughCard("bidder_0", "12.5");
  assert.equal(cardError("bidder_0"), "Enter a whole number of dollars.");
  assert.equal(document.activeElement, document.getElementById("bid-input-bidder_0"));
  await commitThroughCard("bidder_0", 99);
  assert.equal(cardError("bidder_0"), "Bids must be between $100 and $5,000.");
  assert.equal(sent(), 0);

  await commitThroughCard("bidder_0", 1500);
  assert.equal(cardError("bidder_0"), null);
  assert.equal(sent(), 1);
});

test("a failed refresh is shown, retried, and cleared once it works", async () => {
  const { app, routes, state, timers, toasts } = loadApp({
    routes: { [`GET ${AUCTION}`]: UNREACHABLE },
  });
  await app.refreshState();
  assert.deepEqual(toasts(), [
    "Could not refresh the auction: The server could not be reached. Retrying…✕",
  ]);
  assert.equal(timers.at(-1).delay, 10_000);

  routes[`GET ${AUCTION}`] = failure(500, "Database is locked.");
  await timers.at(-1).callback();
  // Replaced, not stacked: the same problem shows once.
  assert.deepEqual(toasts(), ["Could not refresh the auction: Database is locked. Retrying…✕"]);

  routes[`GET ${AUCTION}`] = state;
  await timers.at(-1).callback();
  assert.deepEqual(toasts(), []);
});

test("a deleted auction is reported, and not asked for again", async () => {
  const { app, timers, toasts } = loadApp({
    routes: { [`GET ${AUCTION}`]: failure(404, "No auction with id '…'.") },
  });
  await app.refreshState();
  assert.deepEqual(toasts(), ["This auction no longer exists on the server.✕"]);
  assert.deepEqual(timers, []);
});

test("reset says when the server could not delete the auction", async () => {
  const { app, document, toasts } = loadApp({
    routes: { [`DELETE ${AUCTION}`]: failure(500, "Database is locked.") },
  });
  await app.resetAuction();
  assert.deepEqual(toasts(), [
    "The auction could not be deleted on the server: Database is locked.✕",
  ]);
  assert.equal(document.getElementById("setup-panel").hidden, false, "reset anyway");
});

test("reset says nothing when the auction was already gone", async () => {
  const { app, toasts } = loadApp({
    routes: { [`DELETE ${AUCTION}`]: failure(404, "No auction with id '…'.") },
  });
  await app.resetAuction();
  assert.deepEqual(toasts(), []);
});

test("a receipt saved before a reload lets the bidder carry on and reveal", async () => {
  // Alice commits, and saves her receipt.
  const before = loadApp();
  await before.app.refreshState();
  await before.commitThroughCard("bidder_0", 1500);
  await before.document.getElementById("btn-receipt-bidder_0").click();
  const [file] = before.downloads;
  assert.equal(file.type, "application/json");
  const receipt = JSON.parse(file.text);
  assert.deepEqual(
    { ...receipt, note: undefined },
    {
      type: "crypto-auction/opening-receipt",
      version: 1,
      note: undefined,
      auction_id: CREATED.auction_id,
      item_name: "x",
      bidder_id: "bidder_0",
      bidder_name: "Alice",
      join_token: TOKENS.bidder_0,
      bid: 1500,
      randomness_hex: BLINDING,
      commitment_hex: COMMITMENT,
    },
  );

  // The page is reloaded: it knows nothing. Meanwhile the auction has moved
  // on to the reveal.
  const after = loadApp({ created: false });
  Object.assign(after.state, { state: "proved" });
  Object.assign(after.state.bidders[0], { commitment_hex: COMMITMENT, proof_valid: true });
  Object.assign(after.state.bidders[1], { commitment_hex: "02" + "dd".repeat(32), proof_valid: true });
  await after.app.resumeFromReceipt(fileWith(file.text));

  assert.equal(after.setupError(), null);
  assert.equal(after.document.getElementById("setup-panel").hidden, true);
  // It acts for Alice only: Bob's card offers nothing.
  assert.equal(after.document.getElementById("btn-reveal-bidder_1"), null);
  await after.document.getElementById("btn-reveal-bidder_0").click();
  const [reveal] = after.requests.filter((r) => r.path === `${AUCTION}/reveal`);
  assert.equal(reveal.authorization, `Bearer ${TOKENS.bidder_0}`);
  assert.deepEqual(reveal.body, { bid: 1500, randomness_hex: BLINDING });

  // A bidder is not the organizer: leaving does not try to delete the auction.
  await after.app.resetAuction();
  assert.deepEqual(after.requests.filter((r) => r.method === "DELETE"), []);
});

test("a receipt for another commitment than the auction's is refused", async () => {
  const { app, state, setupError, document } = loadApp({ created: false });
  state.bidders[0].commitment_hex = "02" + "dd".repeat(32); // Alice committed to something else
  const receipt = {
    type: "crypto-auction/opening-receipt", version: 1, auction_id: CREATED.auction_id,
    bidder_id: "bidder_0", join_token: TOKENS.bidder_0, bid: 1500,
    randomness_hex: BLINDING, commitment_hex: COMMITMENT,
  };
  await app.resumeFromReceipt(fileWith(JSON.stringify(receipt)));
  assert.equal(
    setupError(),
    "Could not continue from this receipt: The auction recorded a different commitment for Alice.",
  );
  assert.equal(document.getElementById("setup-panel").hidden, false);
});

test("files that are not sound receipts are refused before anything is asked", async () => {
  const valid = {
    type: "crypto-auction/opening-receipt", version: 1, auction_id: CREATED.auction_id,
    bidder_id: "bidder_0", join_token: TOKENS.bidder_0, bid: 1500,
    randomness_hex: BLINDING, commitment_hex: COMMITMENT,
  };
  const files = {
    "{not json": "it is not JSON.",
    [JSON.stringify({ hello: "world" })]: "This file is not an auction receipt.",
    [JSON.stringify({ ...valid, version: 2 })]: "this page reads version 1.",
    [JSON.stringify({ ...valid, join_token: undefined })]: "a field is missing or malformed.",
    [JSON.stringify({ ...valid, bid: 1500.5 })]: "a field is missing or malformed.",
    // Revealing this would mark Alice a cheater.
    [JSON.stringify({ ...valid, bid: 1501 })]: "its bid and secret do not open its commitment.",
  };
  for (const [text, reason] of Object.entries(files)) {
    const { app, requests, setupError } = loadApp({ created: false });
    await app.resumeFromReceipt(fileWith(text));
    assert.ok(setupError()?.endsWith(reason), `${text}: ${setupError()}`);
    assert.deepEqual(requests, []);
  }
});

test("leaving the page asks first while an opening is still needed", async () => {
  const { app, state, leavingAsks, commitThroughCard } = loadApp();
  await app.refreshState();
  assert.equal(leavingAsks(), false, "nothing to lose yet");
  await commitThroughCard("bidder_0", 1500);
  assert.equal(leavingAsks(), true, "Alice's opening would be lost");
  state.state = "finished";
  await app.refreshState();
  assert.equal(leavingAsks(), false, "the auction is over");
});

test("the setup buttons work again once a demo has started", async () => {
  const names = [{ value: "Alice" }, { value: "Bob" }];
  const { app, document } = loadApp({
    document: { querySelectorAll: (selector) => (selector === ".bidder-name-input" ? names : []) },
  });
  const fields = { "item-name": "x", "min-bid": "100", "max-bid": "5000", "phase-minutes": "10" };
  for (const [id, value] of Object.entries(fields)) document.getElementById(id).value = value;

  app.startDemo(); // runs on until its (never firing) timers; only its start matters here
  for (let i = 0; i < 10; i++) await setImmediate();

  assert.equal(document.getElementById("setup-panel").hidden, true, "the demo started");
  for (const id of ["btn-create", "btn-demo"]) {
    assert.equal(document.getElementById(id).disabled, false, `${id} after a reset`);
  }
  assert.equal(document.getElementById("btn-demo").textContent, "▶ Watch Demo");
});
