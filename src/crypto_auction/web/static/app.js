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
function showToast(message, { key = "", sticky = false } = {}) {
  if (key) dismissToast(key);
  const toast = el("div", "toast");
  toast.dataset.key = key;
  toast.setAttribute("role", "alert");  // announced by screen readers
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
  const row = document.createElement("div");
  row.className = "bidder-input-row";
  row.innerHTML = `
    <input type="text" class="bidder-name-input" placeholder="Bidder name" />
    <button class="btn-remove-bidder" onclick="removeBidderInput(this)">✕</button>
  `;
  container.appendChild(row);
  row.querySelector("input").focus();
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
  document.getElementById("setup-error").style.display = "none";

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

    document.getElementById("setup-panel").style.display = "none";
    document.getElementById("auction-view").style.display = "grid";
    document.getElementById("phase-indicator").style.display = "flex";
    document.getElementById("auction-item-label").textContent = data.item_name;

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
  const el = document.getElementById("setup-error");
  el.textContent = msg;
  el.style.display = "block";
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
}

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

    await refreshState();

    if (data.winner) {
      showWinnerModal(data.winner);
    }
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

async function refreshState() {
  try {
    const data = await apiFetch(auctionUrl());
    localState.serverState = data;
    dismissToast("refresh");
    renderAll(data);
    scheduleDeadlineRefresh(data);
  } catch (err) {
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

// The next scheduled refresh: at the current deadline, or a retry.
let refreshTimer = null;

/** The deadline (ISO 8601) of the phase in progress. */
function currentDeadline(state) {
  return state.deadlines[PHASE_STEP[state.state]];
}

/**
 * Refresh once the current phase's deadline has passed, so the page shows who
 * missed it. The delay is measured on the server's clock, which decides, so a
 * wrong clock on this computer does not matter.
 */
function scheduleDeadlineRefresh(state) {
  clearTimeout(refreshTimer);
  refreshTimer = null;
  if (state.state === "finished") return;
  const delay = Date.parse(currentDeadline(state)) - Date.parse(state.server_time);
  refreshTimer = setTimeout(refreshState, Math.max(delay, 0) + 250);
}

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
    pill.classList.toggle("active", pill.dataset.phase === activePill);
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

/** A bidder's card: its elements, created once, which updateBidderCard fills in. */
function createBidderCard(bidderId) {
  const view = {
    card:         el("div", "bidder-card"),
    name:         el("span", "bidder-name"),
    badges: {
      commit:     el("span", "phase-badge", "COMMIT"),
      prove:      el("span", "phase-badge", "PROVE"),
      reveal:     el("span", "phase-badge", "REVEAL"),
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
  view.bidForm.append(view.bidInput, view.commitButton);
  view.error.id = `bidder-error-${bidderId}`;
  view.error.setAttribute("role", "alert");  // announced by screen readers
  view.error.hidden = true;
  view.bidInput.setAttribute("aria-describedby", view.error.id);

  const name = el("div", "bidder-card-name");
  name.append(el("div", "bidder-avatar", "👤"), view.name);
  const phases = el("div", "bidder-phases");
  phases.append(view.badges.commit, view.badges.prove, view.badges.reveal);
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

/** The controls the card shows now: what this bidder can do in this phase. */
function bidderActions(view, b, state) {
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

  view.badges.commit.className = `phase-badge ${hasCommitted ? "done commit" : ""}`;
  view.badges.prove.className  = `phase-badge ${hasProved ? (b.proof_valid ? "done prove" : "invalid") : ""}`;
  view.badges.reveal.className = `phase-badge ${hasRevealed ? (b.commitment_verified ? "done reveal" : "invalid") : ""}`;

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

  // Phase description
  const phaseDescriptions = {
    open:      { title: "Phase 1 — Commit", color: "var(--color-commit)",
      desc: "Each bidder commits to their bid with a Pedersen commitment <code>C = bid·G + r·H</code> on secp256k1, computed in this browser. The auctioneer receives only C, which hides the bid; the bidder cannot change it afterwards." },
    committed: { title: "Phase 2 — ZK Prove", color: "var(--color-prove)",
      desc: "Each bidder proves in zero knowledge that the committed bid lies in <strong>[min, max]</strong>: a range proof made of one OR-proof per bit, checked without revealing the bid." },
    proved:    { title: "Phase 3 — Reveal", color: "var(--color-reveal)",
      desc: "Each bidder reveals <code>(bid, r)</code>. Anyone can check that <code>bid·G + r·H</code> equals the commitment. Highest verified bid wins; ties go to the earliest commitment." },
    finished:  { title: "Auction Complete", color: "var(--color-finish)",
      desc: "The reveal phase is over. The winner has been determined from the verified bids." },
  };

  const desc = phaseDescriptions[phase] || phaseDescriptions.open;

  html += `
    <div class="action-section">
      <div class="action-section-title" style="color:${desc.color}">${desc.title}</div>
      <div class="action-info">${desc.desc}</div>
    </div>`;

  // Progress
  if (phase !== "finished") {
    let progressLabel = "", progressPct = 0, progressClass = "";
    if (phase === "open") {
      progressLabel = `Committed: ${committed} / ${total}`;
      progressPct   = total > 0 ? (committed / total) * 100 : 0;
      progressClass = "progress-commit";
    } else if (phase === "committed") {
      progressLabel = `ZK Proved: ${proved} / ${total}`;
      progressPct   = total > 0 ? (proved / total) * 100 : 0;
      progressClass = "progress-prove";
    } else if (phase === "proved") {
      progressLabel = `Revealed: ${revealed} / ${total}`;
      progressPct   = total > 0 ? (revealed / total) * 100 : 0;
      progressClass = "progress-reveal";
    }

    html += `
      <div class="action-section ${progressClass}">
        <div class="action-section-title">Progress</div>
        <div class="action-info">${progressLabel}</div>
        <div class="progress-bar">
          <div class="progress-bar-fill" style="width:${progressPct.toFixed(0)}%"></div>
        </div>
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
      <div class="action-section" style="border-color:var(--gold)">
        <div class="action-section-title" style="color:var(--gold)">🏆 Winner</div>
        <div class="action-info">
          <strong>${escapeHtml(state.winner.name)}</strong><br/>
          Winning bid: <strong style="color:var(--green)">${fmtBid(state.winner.bid)}</strong><br/>
          <span style="font-size:10px;color:var(--text-dim)">Commitment verified ✓</span>
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

function showWinnerModal(winner) {
  document.getElementById("winner-name").textContent = winner.name;
  document.getElementById("winner-bid").textContent  = fmtBid(winner.bid);
  document.getElementById("winner-overlay").style.display = "flex";
}

function closeWinnerModal() {
  document.getElementById("winner-overlay").style.display = "none";
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

async function resetAuction() {
  if (!confirm("Reset the auction? All state will be lost.")) return;
  try {
    // As the organizer: the auction is deleted on the server too.
    await apiFetch(auctionUrl(), "DELETE", null, localState.auction.organizer_token);
  } catch (err) {
    // The page resets anyway. If the auction is already gone, so much the better.
    if (err.status !== 404) {
      showToast(`The auction could not be deleted on the server: ${err.message}`);
    }
  }

  // Clear client state
  clearTimeout(refreshTimer);
  dismissToast("refresh");
  localState.auction = null;
  localState.serverState = null;
  localState.joinTokens = {};
  localState.bidderSecrets = {};

  // Reset UI
  document.getElementById("auction-view").style.display = "none";
  document.getElementById("phase-indicator").style.display = "none";
  document.getElementById("setup-panel").style.display = "flex";
  document.getElementById("setup-error").style.display = "none";
  document.getElementById("winner-overlay").style.display = "none";
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
  const el = document.getElementById("demo-status-text");
  if (el) el.textContent = text;
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

  // Switch to auction view
  document.getElementById("setup-panel").style.display = "none";
  document.getElementById("auction-view").style.display = "grid";
  document.getElementById("phase-indicator").style.display = "flex";
  document.getElementById("auction-item-label").textContent = auctionData.item_name;
  document.getElementById("demo-banner").style.display = "flex";

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
    document.getElementById("demo-banner").style.display = "none";
  }
}

function stopDemo() {
  demo.aborted = true;
  document.getElementById("demo-banner").style.display = "none";
  addPublicLogEntry("Demo stopped by user", {});
}

/** Look up a bidder name directly from the create-response data (before serverState is set). */
function getBidderNameFromData(auctionData, bidderId) {
  const b = auctionData.bidders.find(x => x.bidder_id === bidderId);
  return b ? b.name : bidderId;
}
