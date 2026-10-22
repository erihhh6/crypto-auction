"use strict";

// ---------------------------------------------------------------------------
// Local state. bidderSecrets holds each bidder's opening, created in this
// browser at commit time: the bid and randomness_hex (the commitment's
// blinding factor r). Both stay here until the reveal. joinTokens prove to
// the server which bidder is acting; this page plays every bidder, so it
// holds all of them.
// ---------------------------------------------------------------------------
const localState = {
  auction: null,           // config returned by /api/create (includes auction_id)
  serverState: null,       // latest public state from /api/state
  joinTokens: {},          // { bidder_id: join_token }, from /api/create
  bidderSecrets: {},       // { bidder_id: { bid: int, randomness_hex: str, commitment_hex: str } }
};

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/**
 * Escape text for interpolation into HTML (element content or a quoted
 * attribute value). Names, messages and other server data can contain
 * markup, so every dynamic string built into innerHTML must pass through
 * here; otherwise a bidder named `<img src=x onerror=...>` runs script in
 * every viewer's browser.
 */
function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * Whether a bidder has revealed. The server publishes this (as
 * commitment_verified) at once, but the bid itself only when the auction is
 * finished, so revealed_bid cannot tell.
 */
function hasRevealedBid(bidder) {
  return bidder.commitment_verified !== null && bidder.commitment_verified !== undefined;
}

/** Log fields describing a range proof: one bit commitment per bit, per side. */
function proofSummary(proof) {
  return {
    "bits per side": proof.low.bit_commitments.length,
    "first bit commitment": truncHex(proof.low.bit_commitments[0]),
  };
}

/** Truncate a hex string for display: first 16 chars + "…" */
function truncHex(hex) {
  if (!hex) return "—";
  return hex.length > 20 ? hex.substring(0, 16) + "…" : hex;
}

/** Format a USD amount */
function fmtBid(amount) {
  return "$" + Number(amount).toLocaleString();
}

/** The URL of this page's auction, or of one of its actions ("/commit", ...). */
function auctionUrl(suffix = "") {
  return `/api/auctions/${encodeURIComponent(localState.auction.auction_id)}${suffix}`;
}

/** Current time as HH:MM:SS */
function timestamp() {
  return new Date().toLocaleTimeString("en-GB");
}

/**
 * Safe fetch with JSON body: returns the parsed JSON, or throws an Error
 * whose message can be shown to the user, with the HTTP status as
 * error.status (0 when the server could not be reached). A token (a bidder's
 * join token, or the organizer token) authenticates the request.
 */
async function apiFetch(path, method = "GET", body = null, token = null) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (token !== null) opts.headers.Authorization = `Bearer ${token}`;
  if (body !== null) opts.body = JSON.stringify(body);
  let res;
  try {
    res = await fetch(path, opts);
  } catch {
    throw Object.assign(new Error("The server could not be reached."), { status: 0 });
  }
  // Not JSON at all, e.g. a proxy's error page: say so rather than "Unexpected token <".
  const json = await res.json().catch(() => null);
  if (!json?.success) {
    const message = json?.error ?? `The server answered with an error (HTTP ${res.status}).`;
    throw Object.assign(new Error(message), { status: res.status });
  }
  return json;
}

// ---------------------------------------------------------------------------
// Notifications. A problem with one bidder's action (a rejected commit, say)
// shows on that bidder's card; one that concerns the whole page (a failed
// refresh) in a toast. Neither blocks the page the way alert() did.
// ---------------------------------------------------------------------------

const TOAST_SECONDS = 8;

/**
 * Show a toast. A toast with the same key replaces the previous one, so a
 * problem that repeats shows once; a sticky one stays until dismissed, by
 * the user or by dismissToast(key) once the problem is over.
 */
function showToast(message, { key = "", sticky = false, kind = "error" } = {}) {
  if (key) dismissToast(key);
  const toast = el("div", `toast ${kind}`);
  toast.dataset.key = key;
  // Announced by screen readers: an error at once, other news politely.
  toast.setAttribute("role", kind === "error" ? "alert" : "status");
  const close = el("button", "toast-close", "✕");
  close.type = "button";
  close.setAttribute("aria-label", "Dismiss");
  close.addEventListener("click", () => toast.remove());
  toast.append(el("span", "toast-text", message), close);
  document.getElementById("toasts").append(toast);
  if (!sticky) setTimeout(() => toast.remove(), TOAST_SECONDS * 1000);
}

function dismissToast(key) {
  for (const toast of [...document.getElementById("toasts").children]) {
    if (toast.dataset.key === key) toast.remove();
  }
}

/**
 * Have screen readers read a message out, politely: after what they are
 * reading. For what changes without the reader's doing, like a new phase.
 */
function announce(message) {
  document.getElementById("announcer").textContent = message;
}

/** What screen readers hear when the auction moves on to a state. */
function phaseAnnouncement(state) {
  if (state.state === "committed") {
    return "The commit phase is over: bidders now prove that their bids are in range.";
  }
  if (state.state === "proved") return "The proving phase is over: bidders now reveal their bids.";
  if (state.winner) {
    return `The auction is over: ${state.winner.name} wins with ${fmtBid(state.winner.bid)}.`;
  }
  return "The auction is over, with no winner.";
}

/**
 * Show what went wrong with a bidder's last action on their card ("" clears
 * it). It stays until they try again or the auction moves to another phase.
 */
function showBidderError(bidderId, message) {
  const view = bidderCards.get(bidderId);
  if (!view) {
    if (message) showToast(message);
    return;
  }
  view.error.textContent = message;
  view.error.hidden = !message;
  view.errorPhase = localState.serverState?.state;
}

// ---------------------------------------------------------------------------
// Setup panel helpers
// ---------------------------------------------------------------------------

function addBidderInput() {
  const container = document.getElementById("bidder-inputs");
  if (container.children.length >= 10) return;
  const input = el("input", "bidder-name-input");
  input.type = "text";
  input.placeholder = "Bidder name";
  input.setAttribute("aria-label", "Bidder name");
  // Its clicks are handled by the listener on #bidder-inputs (see wireUp).
  const remove = el("button", "btn-remove-bidder", "✕");
  remove.setAttribute("aria-label", "Remove bidder");
  const row = el("div", "bidder-input-row");
  row.append(input, remove);
  container.append(row);
  input.focus();
}

function removeBidderInput(btn) {
  const container = document.getElementById("bidder-inputs");
  if (container.children.length <= 2) return;  // minimum 2 bidders
  btn.closest(".bidder-input-row").remove();
}

// ---------------------------------------------------------------------------
// Create auction
// ---------------------------------------------------------------------------

/**
 * The /api/create request described by the setup form, or null after showing
 * what is wrong. Every step (commit, prove, reveal) gets the same window.
 */
function readSetupForm() {
  document.getElementById("setup-error").hidden = true;

  const itemName = document.getElementById("item-name").value.trim();
  const minBid   = parseInt(document.getElementById("min-bid").value, 10);
  const maxBid   = parseInt(document.getElementById("max-bid").value, 10);
  const minutes  = parseInt(document.getElementById("phase-minutes").value, 10);
  const names    = [...document.querySelectorAll(".bidder-name-input")]
                     .map(i => i.value.trim())
                     .filter(Boolean);

  if (!itemName)            { showSetupError("Item name is required."); return null; }
  if (isNaN(minBid) || isNaN(maxBid)) { showSetupError("Bid bounds must be numbers."); return null; }
  if (minBid >= maxBid)     { showSetupError("Min bid must be less than max bid."); return null; }
  if (names.length < 2)     { showSetupError("At least 2 bidder names are required."); return null; }
  if (isNaN(minutes) || minutes < 1) { showSetupError("Each phase needs at least 1 minute."); return null; }

  const seconds = minutes * 60;
  return {
    item_name:      itemName,
    min_bid:        minBid,
    max_bid:        maxBid,
    bidders:        names,
    commit_seconds: seconds,
    prove_seconds:  seconds,
    reveal_seconds: seconds,
  };
}

async function createAuction() {
  const request = readSetupForm();
  if (!request) return;

  try {
    const btn = document.getElementById("btn-create");
    btn.disabled = true;
    btn.textContent = "Creating…";

    const data = await apiFetch("/api/auctions", "POST", request);

    rememberAuction(data);
    showAuctionView(data.item_name);

    await refreshState();
    addPublicLogEntry("Auction created", {
      item: data.item_name,
      range: `${fmtBid(data.min_bid)} – ${fmtBid(data.max_bid)}`,
      bidders: data.bidders.map(b => b.name).join(", "),
    });
  } catch (err) {
    showSetupError(err.message);
  } finally {
    const btn = document.getElementById("btn-create");
    if (btn) { btn.disabled = false; btn.textContent = "Start Auction →"; }
  }
}

function showSetupError(msg) {
  const error = document.getElementById("setup-error");
  error.textContent = msg;
  error.hidden = false;
}

/**
 * Start a session from the create response, which carries every bidder's join
 * token and the organizer token (kept in localState.auction).
 */
function rememberAuction(data) {
  localState.auction = data;
  localState.joinTokens = Object.fromEntries(data.bidders.map(b => [b.bidder_id, b.join_token]));
  localState.bidderSecrets = {};
  // Bidder ids repeat across auctions: start from fresh cards, not the last
  // auction's (with whatever was typed into them).
  bidderCards.clear();
  document.getElementById("bidder-cards").replaceChildren();
  renderJoinLinks(data);
  // A page for one bidder (from a join link or a receipt) can only leave.
  document.getElementById("btn-reset").textContent = data.organizer_token ? "Reset" : "Leave";
}

/** Leave the setup panel for the auction view. */
function showAuctionView(itemName) {
  document.getElementById("setup-panel").hidden = true;
  document.getElementById("auction-view").hidden = false;
  document.getElementById("phase-indicator").hidden = false;
  document.getElementById("auction-item-label").textContent = itemName;
}

/**
 * Enter an auction as one of its bidders, from a join link or a receipt:
 * the page then acts for that bidder only, and is not the organizer.
 */
function enterAsBidder(state, bidderId, name, joinToken) {
  rememberAuction({
    auction_id: state.auction_id,
    item_name:  state.item_name,
    min_bid:    state.min_bid,
    max_bid:    state.max_bid,
    bidders:    [{ bidder_id: bidderId, name, join_token: joinToken }],
  });
  showAuctionView(`${state.item_name} — bidding as ${name}`);
}

// ---------------------------------------------------------------------------
// Join links. The organizer sends each bidder a link that opens this page as
// them, so that everyone bids from their own device. The join token travels
// in the URL's fragment, which browsers never send to the server: it stays
// out of server logs and Referer headers.
// ---------------------------------------------------------------------------

/** The link that opens an auction as the bidder whose join token it carries. */
function joinLink(auctionId, joinToken) {
  const fragment = new URLSearchParams({ auction: auctionId, token: joinToken });
  return `${location.origin}${location.pathname}#${fragment}`;
}

/** The auction id and join token in this page's URL, if it was opened from a join link. */
function joinLinkParams() {
  const params = new URLSearchParams(location.hash.slice(1));
  const auctionId = params.get("auction");
  const token = params.get("token");
  return auctionId && token ? { auctionId, token } : null;
}

/** On the organizer's page: every bidder's join link, to copy and send. */
function renderJoinLinks(data) {
  const box = document.getElementById("join-links");
  box.replaceChildren();
  box.hidden = !data.organizer_token;
  if (box.hidden) return;
  box.append(
    el("div", "action-section-title", "Join links"),
    el("div", "action-info",
       "Send each bidder their own link to bid from their own device. Keep the links " +
       "private: whoever has one can act as that bidder."),
  );
  for (const b of data.bidders) {
    const field = el("input", "join-link-field");
    field.type = "text";
    field.id = `join-link-${b.bidder_id}`;
    field.readOnly = true;
    field.value = joinLink(data.auction_id, b.join_token);
    field.setAttribute("aria-label", `Join link for ${b.name}`);
    const copy = el("button", "btn btn-copy", "Copy");
    copy.id = `btn-copy-link-${b.bidder_id}`;
    copy.addEventListener("click", () => copyJoinLink(b.name, field));
    const row = el("div", "join-link");
    row.append(el("span", "join-link-name", b.name), field, copy);
    box.append(row);
  }
}

async function copyJoinLink(name, field) {
  try {
    await navigator.clipboard.writeText(field.value);
    showToast(`${name}'s join link is copied.`, { kind: "info" });
  } catch {
    // No clipboard access (an older browser, or a page not served securely):
    // select the link, to be copied by hand.
    field.focus();
    field.select();
    showToast("Could not copy the link; it is selected, so copy it with Ctrl+C (⌘C on a Mac).");
  }
}

/** Open the auction as the bidder of the join link this page was opened from. */
async function joinFromLink({ auctionId, token }) {
  try {
    const url = `/api/auctions/${encodeURIComponent(auctionId)}`;
    const me = await apiFetch(`${url}/me`, "GET", null, token); // checks the link first
    const state = await apiFetch(url);
    enterAsBidder(state, me.bidder_id, me.name, token);
    await refreshState();
    addPublicLogEntry(`Joined as ${me.name}`, { from: "join link" });
  } catch (err) {
    const reason = err.status === 401 ? "it is not valid for this auction." : err.message;
    showSetupError(`Could not open this join link: ${reason}`);
  }
}

// ---------------------------------------------------------------------------
// Opening receipts. A bidder's secrets live only in this page's memory, so a
// reload would lose them, and with them the chance to reveal. The receipt is
// a file with everything needed to carry on as that bidder elsewhere or
// later: the auction, the join token and the opening (bid and blinding
// factor). Until the reveal it is as secret as the bid itself.
// ---------------------------------------------------------------------------

const RECEIPT_TYPE = "crypto-auction/opening-receipt";
const RECEIPT_VERSION = 1;

/** The receipt of a bidder whose opening this page holds. */
function makeReceipt(bidderId) {
  const secret = localState.bidderSecrets[bidderId];
  return {
    type:           RECEIPT_TYPE,
    version:        RECEIPT_VERSION,
    note:           "Keep this file private until the reveal: it holds your bid and secrets.",
    auction_id:     localState.auction.auction_id,
    item_name:      localState.auction.item_name,
    bidder_id:      bidderId,
    bidder_name:    getBidderName(bidderId),
    join_token:     localState.joinTokens[bidderId],
    bid:            secret.bid,
    randomness_hex: secret.randomness_hex,
    commitment_hex: secret.commitment_hex,
  };
}

/** Save a bidder's receipt as a JSON file, through the browser's downloads. */
function downloadReceipt(bidderId) {
  const receipt = makeReceipt(bidderId);
  const blob = new Blob([JSON.stringify(receipt, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `receipt-${receipt.auction_id.slice(0, 8)}-${bidderId}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  // Revoked later, not at once: the download may not have started yet.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/**
 * The receipt in a file's text, checked: well-formed, and its bid and
 * blinding factor open its commitment. Throws an Error saying what is wrong.
 */
function parseReceipt(text) {
  let receipt;
  try {
    receipt = JSON.parse(text);
  } catch {
    throw new Error("This file is not a receipt: it is not JSON.");
  }
  if (receipt?.type !== RECEIPT_TYPE) throw new Error("This file is not an auction receipt.");
  if (receipt.version !== RECEIPT_VERSION) {
    throw new Error(`This receipt has version ${receipt.version}; this page reads version ${RECEIPT_VERSION}.`);
  }
  const wellFormed =
    /^[0-9a-f]{32}$/.test(receipt.auction_id) &&
    typeof receipt.bidder_id === "string" &&
    typeof receipt.join_token === "string" &&
    Number.isSafeInteger(receipt.bid) && receipt.bid >= 0 &&
    /^[0-9a-f]{64}$/.test(receipt.randomness_hex) &&
    /^0[23][0-9a-f]{64}$/.test(receipt.commitment_hex);
  if (!wellFormed) throw new Error("This receipt is damaged: a field is missing or malformed.");
  // A reveal that does not open the commitment marks the bidder a cheater.
  if (!window.auctionCrypto.opensCommitment(
    receipt.commitment_hex, BigInt(receipt.bid), receipt.randomness_hex,
  )) {
    throw new Error("This receipt is damaged: its bid and secret do not open its commitment.");
  }
  return receipt;
}

/**
 * Carry on as the bidder of a receipt (chosen on the setup panel), in the
 * auction it belongs to, provided that auction recorded this very commitment.
 */
async function resumeFromReceipt(file) {
  const input = document.getElementById("receipt-file");
  document.getElementById("setup-error").hidden = true;
  try {
    const receipt = parseReceipt(await file.text());
    const state = await apiFetch(`/api/auctions/${encodeURIComponent(receipt.auction_id)}`);
    const bidder = state.bidders.find(b => b.bidder_id === receipt.bidder_id);
    if (!bidder) throw new Error("The auction has no such bidder.");
    if (bidder.commitment_hex !== receipt.commitment_hex) {
      throw new Error(`The auction recorded a different commitment for ${bidder.name}.`);
    }

    enterAsBidder(state, bidder.bidder_id, bidder.name, receipt.join_token);
    localState.bidderSecrets[bidder.bidder_id] = {
      bid:            receipt.bid,
      randomness_hex: receipt.randomness_hex,
      commitment_hex: receipt.commitment_hex,
    };
    await refreshState();
    addPublicLogEntry(`Resumed as ${bidder.name}`, { from: "opening receipt" });
  } catch (err) {
    showSetupError(`Could not continue from this receipt: ${err.message}`);
  } finally {
    input.value = ""; // so choosing the same file again tries again
  }
}

// Leaving the page loses the openings this page holds: ask first while any
// is still needed for a reveal.
window.addEventListener("beforeunload", (event) => {
  const state = localState.serverState;
  const needed = state && state.state !== "finished" && state.bidders.some(
    b => localState.bidderSecrets[b.bidder_id] && !hasRevealedBid(b) && !b.missed_deadline,
  );
  if (needed) {
    event.preventDefault();
    event.returnValue = true; // what older browsers look for instead
  }
});

// Opened from a join link: go straight into the auction as that bidder.
const openedWith = joinLinkParams();
if (openedWith) joinFromLink(openedWith);

// ---------------------------------------------------------------------------
// Bidder-side protocol steps. The bid and its blinding factor stay in this
// browser until the reveal: the server receives only the commitment and the
// zero-knowledge proof, both computed here by auction-crypto.js.
// ---------------------------------------------------------------------------

/** POST a step ("commit", ...) as a bidder, who is identified by their join token alone. */
function postAsBidder(bidderId, step, body) {
  return apiFetch(auctionUrl(`/${step}`), "POST", body, localState.joinTokens[bidderId]);
}

/** Commit to a bid locally and send only the commitment. */
async function submitCommitment(bidderId, bid) {
  const { commitmentHex, blindingHex } = window.auctionCrypto.commitBid(BigInt(bid));
  await postAsBidder(bidderId, "commit", { commitment_hex: commitmentHex });
  // Kept only in memory, and sent at the reveal.
  localState.bidderSecrets[bidderId] = {
    bid,
    randomness_hex: blindingHex,
    commitment_hex: commitmentHex,
  };
  return { commitmentHex, blindingHex };
}

/** Prove locally that the committed bid lies in the auction's range; send only the proof. */
async function submitProof(bidderId) {
  const secret = localState.bidderSecrets[bidderId];
  const { auction_id, min_bid, max_bid } = localState.auction;
  const proof = await window.auctionCrypto.proveBid({
    bid:           BigInt(secret.bid),
    blindingHex:   secret.randomness_hex,
    commitmentHex: secret.commitment_hex,
    minBid:        BigInt(min_bid),
    maxBid:        BigInt(max_bid),
    auctionId:     auction_id,
    bidderId,
  });
  const data = await postAsBidder(bidderId, "prove", { proof });
  return { proof, data };
}

/** Reveal the opening: the first time the bid itself leaves the browser. */
function submitReveal(bidderId) {
  const secret = localState.bidderSecrets[bidderId];
  return postAsBidder(bidderId, "reveal", {
    bid:            secret.bid,
    randomness_hex: secret.randomness_hex,
  });
}

// ---------------------------------------------------------------------------
// Phase 1 — Commit
// ---------------------------------------------------------------------------

async function commitBid(bidderId) {
  const inputEl = document.getElementById(`bid-input-${bidderId}`);
  if (!inputEl) return;
  showBidderError(bidderId, "");

  // A commitment binds the bidder to exactly this number, so nothing is
  // rounded or cut off: "12.5" is refused, not committed as 12.
  const typed = inputEl.value.trim();
  const bid = Number(typed);
  const { min_bid, max_bid } = localState.auction;
  let problem = "";
  if (typed === "" || !Number.isSafeInteger(bid)) problem = "Enter a whole number of dollars.";
  else if (bid < min_bid || bid > max_bid) {
    problem = `Bids must be between ${fmtBid(min_bid)} and ${fmtBid(max_bid)}.`;
  }
  if (problem) {
    showBidderError(bidderId, problem);
    inputEl.focus();
    return;
  }

  const btn = document.getElementById(`btn-commit-${bidderId}`);
  if (btn) { btn.disabled = true; btn.textContent = "Committing…"; }

  try {
    const { commitmentHex, blindingHex } = await submitCommitment(bidderId, bid);

    const bidderName = getBidderName(bidderId);
    addPublicLogEntry(`${bidderName} committed`, {
      commitment: truncHex(commitmentHex),
    });
    addPrivateLogEntry(bidderId, `${bidderName} — your secrets`, {
      bid:        fmtBid(bid),
      "blinding r": truncHex(blindingHex) + " (keep private)",
      "to reveal after a reload": "save the receipt (💾 on the card)",
    });

    await refreshState();
  } catch (err) {
    showBidderError(bidderId, `Commit failed: ${err.message}`);
    if (btn) { btn.disabled = false; btn.textContent = "Commit"; }
  }
}

/** The explanation when this browser holds no opening for a bidder. */
const NO_SECRET =
  "This browser has no record of the bid: it was committed elsewhere, or the page was reloaded.";

// ---------------------------------------------------------------------------
// Phase 2 — ZK Prove
// ---------------------------------------------------------------------------

async function proveBid(bidderId) {
  showBidderError(bidderId, "");
  const secret = localState.bidderSecrets[bidderId];
  if (!secret) { showBidderError(bidderId, NO_SECRET); return; }

  const btn = document.getElementById(`btn-prove-${bidderId}`);
  if (btn) { btn.disabled = true; btn.textContent = "Proving…"; }

  try {
    const { proof, data } = await submitProof(bidderId);

    const bidderName = getBidderName(bidderId);
    addPublicLogEntry(
      `${bidderName} ZK proof ${data.proof_valid ? "✓ valid" : "✗ invalid"}`,
      proofSummary(proof),
    );

    await refreshState();
  } catch (err) {
    showBidderError(bidderId, `Proof failed: ${err.message}`);
    if (btn) { btn.disabled = false; btn.textContent = "ZK Prove"; }
  }
}

// ---------------------------------------------------------------------------
// Phase 3 — Reveal
// ---------------------------------------------------------------------------

async function revealBid(bidderId) {
  showBidderError(bidderId, "");
  const secret = localState.bidderSecrets[bidderId];
  if (!secret) { showBidderError(bidderId, NO_SECRET); return; }

  const btn = document.getElementById(`btn-reveal-${bidderId}`);
  if (btn) { btn.disabled = true; btn.textContent = "Revealing…"; }

  try {
    const data = await submitReveal(bidderId);

    const bidderName = getBidderName(bidderId);
    if (data.verified) {
      addPublicLogEntry(`${bidderName} revealed bid ✓`, { bid: fmtBid(secret.bid) });
    } else {
      addPublicLogEntry(`${bidderName} reveal FAILED — cheater detected`, { bid: fmtBid(secret.bid) });
    }

    await refreshState(); // shows the winner if this reveal was the last
  } catch (err) {
    showBidderError(bidderId, `Reveal failed: ${err.message}`);
    if (btn) { btn.disabled = false; btn.textContent = "Reveal"; }
  }
}

// ---------------------------------------------------------------------------
// Fetch and render server state
// ---------------------------------------------------------------------------

// After a failed refresh, the next try comes this much later.
const REFRESH_RETRY_SECONDS = 10;

// Numbers the refreshes, so that a slow answer cannot overwrite a newer one.
let refreshCount = 0;

async function refreshState() {
  const count = ++refreshCount;
  try {
    const data = await apiFetch(auctionUrl());
    if (count !== refreshCount) return; // a later refresh has started since
    const previousPhase = localState.serverState?.state;
    const finishedNow = data.state === "finished" && previousPhase !== "finished";
    localState.serverState = data;
    dismissToast("refresh");
    renderAll(data);
    scheduleNextRefresh(data);
    // The phase is shown by colour; a screen reader is told it changed.
    if (previousPhase && previousPhase !== data.state) announce(phaseAnnouncement(data));
    // However the auction ended: by this page's reveal, another bidder's on
    // their own device, or a deadline.
    if (finishedNow && data.winner) showWinnerModal(data.winner);
  } catch (err) {
    if (count !== refreshCount) return;
    if (err.status === 404) {
      showToast("This auction no longer exists on the server.", { key: "refresh", sticky: true });
      return;
    }
    // Keep trying: the page relies on refreshes to follow the deadlines.
    showToast(`Could not refresh the auction: ${err.message} Retrying…`, { key: "refresh", sticky: true });
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(refreshState, REFRESH_RETRY_SECONDS * 1000);
  }
}

// ---------------------------------------------------------------------------
// Deadlines. Each phase waits for one step, which names its deadline in the
// public state; the server applies deadlines whenever it is asked.
// ---------------------------------------------------------------------------

const PHASE_STEP = { open: "commit", committed: "prove", proved: "reveal" };

// While an auction runs, the page asks for its state this often, so that what
// other bidders do on their own devices shows up here.
const POLL_SECONDS = 5;

// The next scheduled refresh: the next poll, the current deadline, or a retry.
let refreshTimer = null;

/** The deadline (ISO 8601) of the phase in progress. */
function currentDeadline(state) {
  return state.deadlines[PHASE_STEP[state.state]];
}

/**
 * Plan the next refresh: in POLL_SECONDS, or just after the current phase's
 * deadline if that comes first, so the page shows who missed it at once. The
 * deadline is measured on the server's clock, which decides, so a wrong clock
 * on this computer does not matter. Nothing is planned once the auction is
 * finished, nor while the page is hidden.
 */
function scheduleNextRefresh(state) {
  clearTimeout(refreshTimer);
  refreshTimer = null;
  if (state.state === "finished" || document.hidden) return;
  const untilDeadline = Date.parse(currentDeadline(state)) - Date.parse(state.server_time);
  const delay = Math.min(POLL_SECONDS * 1000, Math.max(untilDeadline, 0) + 250);
  refreshTimer = setTimeout(refreshState, delay);
}

// A hidden page stops asking (see above); shown again, it catches up at once.
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && localState.auction) refreshState();
});

function renderAll(state) {
  renderPhaseIndicator(state);
  renderBidderCards(state);
  renderActionsPanel(state);
}

// ---------------------------------------------------------------------------
// Phase indicator
// ---------------------------------------------------------------------------

// A state names what is complete ("committed": every commitment is in), the
// pill what happens now (proving), so the pill comes from PHASE_STEP.
function renderPhaseIndicator(state) {
  const pills = document.querySelectorAll(".phase-pill");
  const activePill = PHASE_STEP[state.state] ?? "finished";
  pills.forEach(pill => {
    const active = pill.dataset.phase === activePill;
    pill.classList.toggle("active", active);
    // The colour shows the step in progress; aria-current tells screen readers.
    if (active) pill.setAttribute("aria-current", "step");
    else pill.removeAttribute("aria-current");
  });
}

// ---------------------------------------------------------------------------
// Bidder cards. Each card is built once per auction and then updated in
// place, so a bid being typed (not committed yet) and the focus survive every
// refresh. Text goes in as textContent, so it is never parsed as HTML.
// ---------------------------------------------------------------------------

// bidder_id → the elements of that bidder's card; emptied for a new auction.
const bidderCards = new Map();

/** A new element with a class and, optionally, text. */
function el(tag, className, text = "") {
  const node = document.createElement(tag);
  node.className = className;
  if (text) node.textContent = text;
  return node;
}

/**
 * Give node exactly these children, in this order, leaving those already in
 * place untouched: detaching an element, even briefly, drops its focus.
 */
function setChildren(node, children) {
  children.forEach((child, i) => {
    if (node.children[i] !== child) node.insertBefore(child, node.children[i] ?? null);
  });
  while (node.children.length > children.length) node.lastElementChild.remove();
}

/** A phase badge: its label on screen, and (filled in later) its status in words. */
function phaseBadge(label) {
  const badge = el("span", "phase-badge");
  const status = el("span", "sr-only");
  badge.append(el("span", "", label), status);
  return { badge, status };
}

/** A bidder's card: its elements, created once, which updateBidderCard fills in. */
function createBidderCard(bidderId) {
  const view = {
    card:         el("div", "bidder-card"),
    name:         el("span", "bidder-name"),
    badges: {
      commit:     phaseBadge("COMMIT"),
      prove:      phaseBadge("PROVE"),
      reveal:     phaseBadge("REVEAL"),
    },
    hash:         el("div", "bidder-commitment-hash"),
    status:       el("div", ""),
    winner:       el("div", "bidder-winner-badge", "🏆 Winner!"),
    actions:      el("div", "bidder-actions"),
    error:        el("div", "bidder-error"),  // see showBidderError
    errorPhase:   undefined,
    // The controls last as long as the card; only which ones show changes.
    bidForm:      el("div", "bidder-bid-input"),
    bidInput:     el("input", ""),
    commitButton: el("button", "btn btn-commit", "Commit"),
    proveButton:  el("button", "btn btn-prove", "ZK Prove"),
    revealButton: el("button", "btn btn-reveal", "Reveal"),
    receiptButton: el("button", "btn btn-receipt", "💾 Save receipt"),
    note:         el("span", "bidder-note"),
  };
  view.bidInput.type = "number";
  view.bidInput.id = `bid-input-${bidderId}`;
  view.commitButton.id = `btn-commit-${bidderId}`;
  view.proveButton.id = `btn-prove-${bidderId}`;
  view.revealButton.id = `btn-reveal-${bidderId}`;
  view.commitButton.addEventListener("click", () => commitBid(bidderId));
  view.proveButton.addEventListener("click", () => proveBid(bidderId));
  view.revealButton.addEventListener("click", () => revealBid(bidderId));
  view.receiptButton.id = `btn-receipt-${bidderId}`;
  view.receiptButton.title = "Lets you reveal even if this page is closed or reloaded";
  view.receiptButton.setAttribute("aria-label", "Save receipt"); // not "floppy disk, save…"
  view.receiptButton.addEventListener("click", () => downloadReceipt(bidderId));
  // Enter commits, as in a form.
  view.bidInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") commitBid(bidderId);
  });
  view.bidForm.append(view.bidInput, view.commitButton);
  view.error.id = `bidder-error-${bidderId}`;
  view.error.setAttribute("role", "alert");  // announced by screen readers
  view.error.hidden = true;
  view.bidInput.setAttribute("aria-describedby", view.error.id);

  // A group named after the bidder: a screen reader says whose Commit
  // button it is, as the card's layout shows.
  view.name.id = `bidder-name-${bidderId}`;
  view.card.setAttribute("role", "group");
  view.card.setAttribute("aria-labelledby", view.name.id);
  const avatar = el("div", "bidder-avatar", "👤");
  avatar.setAttribute("aria-hidden", "true");
  const name = el("div", "bidder-card-name");
  name.append(avatar, view.name);
  const phases = el("div", "bidder-phases");
  phases.append(view.badges.commit.badge, view.badges.prove.badge, view.badges.reveal.badge);
  view.card.append(name, phases, view.hash, view.status, view.winner, view.actions, view.error);
  return view;
}

/** The card's status line, as [class, text]; no text when there is nothing to say. */
function bidderStatus(b) {
  if (b.missed_deadline) {
    return ["bidder-missed", `⏱ Missed the ${b.missed_deadline} deadline — out of the auction`];
  }
  if (!hasRevealedBid(b)) return ["", ""];
  if (!b.commitment_verified) return ["bidder-cheater", "⚠ Cheater detected — bid invalid"];
  if (b.revealed_bid === undefined) {
    return ["bidder-revealed-pending", "✓ Revealed — bids are shown once everyone has"];
  }
  return ["bidder-revealed-bid", fmtBid(b.revealed_bid)];
}

/**
 * The controls the card shows now: what this bidder can do in this phase,
 * and saving their receipt while it is still needed.
 */
function bidderActions(view, b, state) {
  // A page resumed from a receipt acts for that bidder only.
  if (!localState.joinTokens[b.bidder_id]) return [];
  const actions = stepActions(view, b, state);
  const needsReceipt = localState.bidderSecrets[b.bidder_id] && !hasRevealedBid(b)
    && !b.missed_deadline && state.state !== "finished";
  return needsReceipt ? [...actions, view.receiptButton] : actions;
}

/** The controls for this phase's step. */
function stepActions(view, b, state) {
  const hasProved = b.proof_valid !== null && b.proof_valid !== undefined;
  const note = (kind, text) => {
    view.note.className = `bidder-note ${kind}`;
    view.note.textContent = text;
    return view.note;
  };
  // Only ever disabled here, never enabled: a button may be disabled because
  // its request is in flight, and commitBid & co. re-enable it themselves.
  const stepButton = (button, hint) => {
    if (localState.bidderSecrets[b.bidder_id]) return [button];
    button.disabled = true;
    button.title = hint;
    return [button, note("dim", "Secret not in memory")];
  };

  if (state.state === "open") {
    if (b.commitment_hex) return [note("commit", "✓ Committed")];
    view.bidInput.min = state.min_bid;
    view.bidInput.max = state.max_bid;
    view.bidInput.placeholder = `${state.min_bid}–${state.max_bid}`;
    view.bidInput.setAttribute(
      "aria-label", `${b.name}'s bid, from ${fmtBid(state.min_bid)} to ${fmtBid(state.max_bid)}`,
    );
    return [view.bidForm];
  }
  if (state.state === "committed") {
    if (hasProved) return [note("prove", `✓ Proved (${b.proof_valid ? "valid" : "invalid"})`)];
    if (!b.commitment_hex) return [];  // missed the commit deadline
    return stepButton(view.proveButton, "Commit this bidder in this browser session first");
  }
  if (state.state === "proved" && hasProved && !hasRevealedBid(b)) {
    return stepButton(view.revealButton, "Secret not in memory");
  }
  return [];
}

function updateBidderCard(view, b, state) {
  const hasCommitted = !!b.commitment_hex;
  const hasProved    = b.proof_valid !== null && b.proof_valid !== undefined;
  const hasRevealed  = hasRevealedBid(b);
  const isWinner     = !!state.winner && state.winner.bidder_id === b.bidder_id;

  let cardClass = "bidder-card";
  if (isWinner)               cardClass += " winner";
  else if (b.missed_deadline) cardClass += " missed";
  else if (hasRevealed)       cardClass += " revealed";
  else if (hasProved)         cardClass += " proved";
  else if (hasCommitted)      cardClass += " committed";
  view.card.className = cardClass;
  view.name.textContent = b.name;

  // Each badge says done, invalid or not yet: in colour, and in words for
  // screen readers.
  const setBadge = ({ badge, status }, step, done, valid = true) => {
    badge.className = `phase-badge ${done ? (valid ? `done ${step}` : "invalid") : ""}`;
    status.textContent = done ? (valid ? ": done" : ": invalid") : ": not yet";
  };
  setBadge(view.badges.commit, "commit", hasCommitted);
  setBadge(view.badges.prove, "prove", hasProved, b.proof_valid);
  setBadge(view.badges.reveal, "reveal", hasRevealed, b.commitment_verified);

  view.hash.textContent = hasCommitted ? `C: ${truncHex(b.commitment_hex)}` : "";
  view.hash.hidden = !hasCommitted;

  const [statusClass, statusText] = bidderStatus(b);
  view.status.className = statusClass;
  view.status.textContent = statusText;
  view.status.hidden = !statusText;

  view.winner.hidden = !isWinner;

  setChildren(view.actions, bidderActions(view, b, state));
  view.actions.hidden = view.actions.children.length === 0;
  // An error from an earlier phase no longer applies.
  if (!view.error.hidden && view.errorPhase !== state.state) showBidderError(b.bidder_id, "");
}

function renderBidderCards(state) {
  const cards = state.bidders.map(b => {
    if (!bidderCards.has(b.bidder_id)) bidderCards.set(b.bidder_id, createBidderCard(b.bidder_id));
    const view = bidderCards.get(b.bidder_id);
    updateBidderCard(view, b, state);
    return view.card;
  });
  setChildren(document.getElementById("bidder-cards"), cards);
}

// ---------------------------------------------------------------------------
// Actions panel — contextual per phase
// ---------------------------------------------------------------------------

function renderActionsPanel(state) {
  const container = document.getElementById("actions-content");
  const phase     = state.state;
  const bidders   = state.bidders;

  // Bidders who missed a deadline are out, so progress counts the others.
  const taking    = bidders.filter(b => !b.missed_deadline);
  const committed = taking.filter(b => b.commitment_hex).length;
  const proved    = taking.filter(b => b.proof_valid !== null && b.proof_valid !== undefined).length;
  const revealed  = taking.filter(hasRevealedBid).length;
  const total     = taking.length;

  let html = "";

  // Phase description. `tone` names the phase's colour (a CSS class, as the
  // page has no inline styles).
  const phaseDescriptions = {
    open:      { title: "Phase 1 — Commit", tone: "commit",
      desc: "Each bidder commits to their bid with a Pedersen commitment <code>C = bid·G + r·H</code> on secp256k1, computed in this browser. The auctioneer receives only C, which hides the bid; the bidder cannot change it afterwards." },
    committed: { title: "Phase 2 — ZK Prove", tone: "prove",
      desc: "Each bidder proves in zero knowledge that the committed bid lies in <strong>[min, max]</strong>: a range proof made of one OR-proof per bit, checked without revealing the bid." },
    proved:    { title: "Phase 3 — Reveal", tone: "reveal",
      desc: "Each bidder reveals <code>(bid, r)</code>. Anyone can check that <code>bid·G + r·H</code> equals the commitment. Highest verified bid wins; ties go to the earliest commitment." },
    finished:  { title: "Auction Complete", tone: "finish",
      desc: "The reveal phase is over. The winner has been determined from the verified bids." },
  };

  const desc = phaseDescriptions[phase] || phaseDescriptions.open;

  html += `
    <div class="action-section tone-${desc.tone}">
      <div class="action-section-title phase-title">${desc.title}</div>
      <div class="action-info">${desc.desc}</div>
    </div>`;

  // Progress
  if (phase !== "finished") {
    const [label, done] = {
      open:      [`Committed: ${committed} / ${total}`, committed],
      committed: [`ZK Proved: ${proved} / ${total}`, proved],
      proved:    [`Revealed: ${revealed} / ${total}`, revealed],
    }[phase];

    html += `
      <div class="action-section tone-${desc.tone}">
        <div class="action-section-title">Progress</div>
        <div class="action-info">${label}</div>
        <progress class="progress" max="${Math.max(total, 1)}" value="${done}"
                  aria-label="${label}"></progress>
      </div>`;

    const closes = new Date(currentDeadline(state)).toLocaleTimeString("en-GB");
    html += `
      <div class="action-section">
        <div class="action-section-title">Deadline</div>
        <div class="action-info">
          This phase closes at <strong>${closes}</strong> at the latest. Bidders
          who have not acted by then are out of the auction.
        </div>
      </div>`;
  }

  // Auction config
  html += `
    <div class="action-section">
      <div class="action-section-title">Auction Config</div>
      <div class="action-info">
        <strong>Item:</strong> ${escapeHtml(state.item_name)}<br/>
        <strong>Min bid:</strong> ${fmtBid(state.min_bid)}<br/>
        <strong>Max bid:</strong> ${fmtBid(state.max_bid)}<br/>
        <strong>Bidders:</strong> ${bidders.length}
      </div>
    </div>`;

  // Winner summary
  if (state.winner) {
    html += `
      <div class="action-section winner-section">
        <div class="action-section-title">🏆 Winner</div>
        <div class="action-info">
          <strong>${escapeHtml(state.winner.name)}</strong><br/>
          Winning bid: <strong class="winning-bid">${fmtBid(state.winner.bid)}</strong><br/>
          <span class="fine-print">Commitment verified ✓</span>
        </div>
      </div>`;
  } else if (phase === "finished") {
    html += `
      <div class="action-section">
        <div class="action-section-title">No winner</div>
        <div class="action-info">No bidder completed every step with a valid, verified bid.</div>
      </div>`;
  }

  container.innerHTML = html;
}

// ---------------------------------------------------------------------------
// Protocol log
// ---------------------------------------------------------------------------

function addPublicLogEntry(title, data) {
  const container = document.getElementById("public-log");
  const entry = buildLogEntry("public", title, data);
  container.prepend(entry);
}

function addPrivateLogEntry(bidderId, title, data) {
  const container = document.getElementById("private-log");
  const entry = buildLogEntry("private", title, data);
  container.prepend(entry);
}

function buildLogEntry(type, title, data) {
  const div = document.createElement("div");
  div.className = `log-entry ${type}`;

  let dataLines = "";
  if (data && typeof data === "object") {
    dataLines = Object.entries(data)
      .map(([k, v]) => `<code>${escapeHtml(k)}: ${escapeHtml(v)}</code>`)
      .join("");
  }

  div.innerHTML = `
    <div class="log-entry-header">
      <span class="log-entry-title">${escapeHtml(title)}</span>
      <span class="log-entry-time">${timestamp()}</span>
    </div>
    ${dataLines}`;
  return div;
}

function clearLog() {
  document.getElementById("public-log").innerHTML = "";
  document.getElementById("private-log").innerHTML = "";
}

// ---------------------------------------------------------------------------
// Winner modal
// ---------------------------------------------------------------------------

// A native <dialog>, opened modally: the browser keeps the keyboard focus
// inside it, makes the page behind it inert, and closes it on Escape.

// What had the focus before the dialog opened, to give it back afterwards.
let focusBeforeWinner = null;

function showWinnerModal(winner) {
  document.getElementById("winner-name").textContent = winner.name;
  document.getElementById("winner-bid").textContent  = fmtBid(winner.bid);
  const dialog = document.getElementById("winner-modal");
  if (dialog.open) return;
  focusBeforeWinner = document.activeElement;
  dialog.showModal();
}

function closeWinnerModal() {
  const dialog = document.getElementById("winner-modal");
  if (dialog.open) dialog.close(); // fires "close", see wireUp
}

/**
 * Return the focus where it was, however the dialog was closed (button or
 * Escape). Often that element is gone: the auction's end removes the button
 * that was pressed. The focus then goes to the actions panel, which holds the
 * result, rather than back to the top of the page.
 */
function onWinnerClosed() {
  const before = focusBeforeWinner;
  focusBeforeWinner = null;
  if (before?.isConnected && before !== document.body) before.focus();
  else document.getElementById("actions-content").focus();
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

async function resetAuction() {
  const organizerToken = localState.auction.organizer_token;
  const question = organizerToken
    ? "Reset the auction? It is deleted, for every bidder."
    : "Leave the auction? Unless you saved your receipt, this page forgets your bid.";
  if (!confirm(question)) return;
  try {
    // As the organizer, the auction is deleted on the server too. A page for
    // one bidder (join link, receipt) is no organizer: it just leaves.
    if (organizerToken) await apiFetch(auctionUrl(), "DELETE", null, organizerToken);
  } catch (err) {
    // The page resets anyway. If the auction is already gone, so much the better.
    if (err.status !== 404) {
      showToast(`The auction could not be deleted on the server: ${err.message}`);
    }
  }

  // Clear client state
  clearTimeout(refreshTimer);
  refreshCount++; // an answer still on its way is for the auction just left
  dismissToast("refresh");
  // A join link in the address bar would open the auction again on reload.
  if (location.hash) history.replaceState(null, "", location.pathname + location.search);
  localState.auction = null;
  localState.serverState = null;
  localState.joinTokens = {};
  localState.bidderSecrets = {};

  // Reset UI
  document.getElementById("auction-view").hidden = true;
  document.getElementById("phase-indicator").hidden = true;
  document.getElementById("setup-panel").hidden = false;
  document.getElementById("setup-error").hidden = true;
  closeWinnerModal();
  clearLog();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getBidderName(bidderId) {
  if (!localState.serverState) return bidderId;
  const b = localState.serverState.bidders.find(x => x.bidder_id === bidderId);
  return b ? b.name : bidderId;
}

// ---------------------------------------------------------------------------
// Demo — self-playing simulation
// ---------------------------------------------------------------------------

const demo = {
  running: false,
  aborted: false,
};

/** Pause for `ms` milliseconds, respecting abort. */
function sleep(ms) {
  return new Promise((resolve, reject) => {
    const id = setTimeout(() => {
      if (demo.aborted) reject(new Error("Demo stopped"));
      else resolve();
    }, ms);
    // If aborted before timer fires, reject immediately on next tick
    const check = setInterval(() => {
      if (demo.aborted) { clearTimeout(id); clearInterval(check); reject(new Error("Demo stopped")); }
    }, 50);
    // Clean up interval once timer resolves
    setTimeout(() => clearInterval(check), ms + 100);
  });
}

/** Shuffle an array in-place (Fisher-Yates). */
function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/** Random integer in [lo, hi] inclusive. */
function randInt(lo, hi) {
  return Math.floor(Math.random() * (hi - lo + 1)) + lo;
}

function setDemoStatus(text) {
  document.getElementById("demo-status-text").textContent = text;
}

async function startDemo() {
  const request = readSetupForm();
  if (!request) return;

  // Create the auction on the server
  const createBtn = document.getElementById("btn-create");
  const demoBtn   = document.getElementById("btn-demo");
  createBtn.disabled = true;
  demoBtn.disabled   = true;
  demoBtn.textContent = "Starting…";

  let auctionData;
  try {
    auctionData = await apiFetch("/api/auctions", "POST", request);
  } catch (err) {
    showSetupError(err.message);
    return;
  } finally {
    // Usable again whether the demo started or not: they stayed disabled
    // after a demo, so the setup form was dead after a reset.
    createBtn.disabled = false;
    demoBtn.disabled   = false;
    demoBtn.textContent = "▶ Watch Demo";
  }

  rememberAuction(auctionData);
  showAuctionView(auctionData.item_name);
  document.getElementById("demo-banner").hidden = false;

  await refreshState();
  addPublicLogEntry("Auction created (Demo mode)", {
    item:    auctionData.item_name,
    range:   `${fmtBid(auctionData.min_bid)} – ${fmtBid(auctionData.max_bid)}`,
    bidders: auctionData.bidders.map(b => b.name).join(", "),
  });

  // Assign each bidder a random bid (chosen now, revealed only in phase 3)
  const bidderIds = auctionData.bidders.map(b => b.bidder_id);
  const assignedBids = {};
  bidderIds.forEach(id => {
    assignedBids[id] = randInt(auctionData.min_bid, auctionData.max_bid);
  });

  demo.running = true;
  demo.aborted = false;

  try {
    // PHASE 1 — COMMIT (random order)
    setDemoStatus("Phase 1 — Committing bids…");
    const commitOrder = shuffle([...bidderIds]);
    for (const bidderId of commitOrder) {
      if (demo.aborted) break;
      const bid  = assignedBids[bidderId];
      const name = getBidderNameFromData(auctionData, bidderId);
      setDemoStatus(`Phase 1 — ${name} is committing…`);
      await sleep(randInt(800, 1600));
      if (demo.aborted) break;

      const { commitmentHex, blindingHex } = await submitCommitment(bidderId, bid);

      addPublicLogEntry(`${name} committed`, { commitment: truncHex(commitmentHex) });
      addPrivateLogEntry(bidderId, `${name} — secret (demo)`, {
        bid:        fmtBid(bid),
        "blinding r": truncHex(blindingHex),
      });
      await refreshState();
    }

    // PHASE 2 — ZK PROVE (random order)
    const proveOrder = shuffle([...bidderIds]);
    for (const bidderId of proveOrder) {
      if (demo.aborted) break;
      const name   = getBidderNameFromData(auctionData, bidderId);
      setDemoStatus(`Phase 2 — ${name} is generating ZK proof…`);
      await sleep(randInt(900, 1800));
      if (demo.aborted) break;

      const { proof, data } = await submitProof(bidderId);
      addPublicLogEntry(
        `${name} ZK proof ${data.proof_valid ? "valid" : "INVALID"}`,
        proofSummary(proof),
      );
      await refreshState();
    }

    // PHASE 3 — REVEAL (random order)
    const revealOrder = shuffle([...bidderIds]);
    for (const bidderId of revealOrder) {
      if (demo.aborted) break;
      const name   = getBidderNameFromData(auctionData, bidderId);
      const secret = localState.bidderSecrets[bidderId];
      setDemoStatus(`Phase 3 — ${name} is revealing bid…`);
      await sleep(randInt(900, 1700));
      if (demo.aborted) break;

      const data = await submitReveal(bidderId);

      if (data.verified) {
        addPublicLogEntry(`${name} revealed bid`, { bid: fmtBid(secret.bid) });
      } else {
        addPublicLogEntry(`${name} reveal FAILED`, { bid: fmtBid(secret.bid) });
      }
      await refreshState();

      if (data.winner) {
        setDemoStatus("Auction complete!");
        await sleep(600);
        showWinnerModal(data.winner);
      }
    }

  } catch (err) {
    if (err.message !== "Demo stopped") {
      addPublicLogEntry("Demo error", { error: err.message });
      showToast(`The demo stopped: ${err.message}`);
    }
  } finally {
    demo.running = false;
    demo.aborted = false;
    document.getElementById("demo-banner").hidden = true;
  }
}

function stopDemo() {
  demo.aborted = true;
  document.getElementById("demo-banner").hidden = true;
  addPublicLogEntry("Demo stopped by user", {});
}

/** Look up a bidder name directly from the create-response data (before serverState is set). */
function getBidderNameFromData(auctionData, bidderId) {
  const b = auctionData.bidders.find(x => x.bidder_id === bidderId);
  return b ? b.name : bidderId;
}

// ---------------------------------------------------------------------------
// Wiring. The page has no inline handlers (onclick="..."), which the server's
// Content-Security-Policy forbids: its controls are connected here, once.
// ---------------------------------------------------------------------------

function wireUp() {
  const on = (id, type, handler) => document.getElementById(id).addEventListener(type, handler);
  on("btn-add-bidder", "click", addBidderInput);
  // One listener for every remove button, including those of rows added later.
  on("bidder-inputs", "click", (event) => {
    const button = event.target.closest(".btn-remove-bidder");
    if (button) removeBidderInput(button);
  });
  on("btn-create", "click", createAuction);
  on("btn-demo", "click", startDemo);
  on("receipt-file", "change", (event) => {
    const [file] = event.target.files;
    if (file) resumeFromReceipt(file);
  });
  on("btn-stop-demo", "click", stopDemo);
  on("btn-clear-log", "click", clearLog);
  on("btn-reset", "click", resetAuction);
  on("btn-close-winner", "click", closeWinnerModal);
  on("winner-modal", "close", onWinnerClosed);
}

wireUp();
