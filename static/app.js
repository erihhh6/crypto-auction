"use strict";

// ---------------------------------------------------------------------------
// Local state — nothing here is ever sent to the server unnecessarily.
// bidderSecrets stores (bid, randomness_hex) received once from /api/commit.
// The server discards randomness_hex after returning it; only the client holds it.
// ---------------------------------------------------------------------------
const localState = {
  auction: null,           // config returned by /api/create
  serverState: null,       // latest public state from /api/state
  bidderSecrets: {},       // { bidder_id: { bid: int, randomness_hex: str } }
};

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/** Truncate a hex string for display: first 16 chars + "…" */
function truncHex(hex) {
  if (!hex) return "—";
  return hex.length > 20 ? hex.substring(0, 16) + "…" : hex;
}

/** Format a USD amount */
function fmtBid(amount) {
  return "$" + Number(amount).toLocaleString();
}

/** Current time as HH:MM:SS */
function timestamp() {
  return new Date().toLocaleTimeString("en-GB");
}

/** Safe fetch with JSON body, returns parsed JSON or throws */
async function apiFetch(path, method = "GET", body = null) {
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body !== null) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  const json = await res.json();
  if (!json.success) throw new Error(json.error || "Unknown error");
  return json;
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

async function createAuction() {
  const errEl = document.getElementById("setup-error");
  errEl.style.display = "none";

  const itemName = document.getElementById("item-name").value.trim();
  const minBid   = parseInt(document.getElementById("min-bid").value, 10);
  const maxBid   = parseInt(document.getElementById("max-bid").value, 10);
  const names    = [...document.querySelectorAll(".bidder-name-input")]
                     .map(i => i.value.trim())
                     .filter(Boolean);

  if (!itemName)            { showSetupError("Item name is required."); return; }
  if (isNaN(minBid) || isNaN(maxBid)) { showSetupError("Bid bounds must be numbers."); return; }
  if (minBid >= maxBid)     { showSetupError("Min bid must be less than max bid."); return; }
  if (names.length < 2)     { showSetupError("At least 2 bidder names are required."); return; }

  try {
    const btn = document.getElementById("btn-create");
    btn.disabled = true;
    btn.textContent = "Creating…";

    const data = await apiFetch("/api/create", "POST", {
      item_name: itemName,
      min_bid:   minBid,
      max_bid:   maxBid,
      bidders:   names,
    });

    localState.auction = data;
    localState.bidderSecrets = {};

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

// ---------------------------------------------------------------------------
// Phase 1 — Commit
// ---------------------------------------------------------------------------

async function commitBid(bidderId) {
  const inputEl = document.getElementById(`bid-input-${bidderId}`);
  if (!inputEl) return;
  const bid = parseInt(inputEl.value, 10);

  if (isNaN(bid)) { alert("Please enter a valid bid amount."); return; }
  const { min_bid, max_bid } = localState.auction;
  if (bid < min_bid || bid > max_bid) {
    alert(`Bid must be between ${fmtBid(min_bid)} and ${fmtBid(max_bid)}.`);
    return;
  }

  const btn = document.getElementById(`btn-commit-${bidderId}`);
  if (btn) { btn.disabled = true; btn.textContent = "Committing…"; }

  try {
    const data = await apiFetch("/api/commit", "POST", { bidder_id: bidderId, bid });

    // Store secrets locally — do NOT re-send to server unnecessarily
    localState.bidderSecrets[bidderId] = {
      bid,
      randomness_hex: data.randomness_hex,
    };

    const bidderName = getBidderName(bidderId);
    addPublicLogEntry(`${bidderName} committed`, {
      commitment: truncHex(data.commitment_hex),
    });
    addPrivateLogEntry(bidderId, `${bidderName} — your secrets`, {
      bid:        fmtBid(bid),
      randomness: truncHex(data.randomness_hex) + " (keep private)",
    });

    await refreshState();
  } catch (err) {
    alert(`Commit failed: ${err.message}`);
    if (btn) { btn.disabled = false; btn.textContent = "Commit"; }
  }
}

// ---------------------------------------------------------------------------
// Phase 2 — ZK Prove
// ---------------------------------------------------------------------------

async function proveBid(bidderId) {
  const secret = localState.bidderSecrets[bidderId];
  if (!secret) { alert("No local secret found. Did you commit first?"); return; }

  const btn = document.getElementById(`btn-prove-${bidderId}`);
  if (btn) { btn.disabled = true; btn.textContent = "Proving…"; }

  try {
    const data = await apiFetch("/api/prove", "POST", {
      bidder_id:     bidderId,
      bid:           secret.bid,
      randomness_hex: secret.randomness_hex,
    });

    const bidderName = getBidderName(bidderId);
    addPublicLogEntry(`${bidderName} ZK proof ${data.proof_valid ? "✓ valid" : "✗ invalid"}`, {
      low_commitment:  truncHex(data.proof_public.low_commitment_hex),
      high_commitment: truncHex(data.proof_public.high_commitment_hex),
    });

    await refreshState();
  } catch (err) {
    alert(`Prove failed: ${err.message}`);
    if (btn) { btn.disabled = false; btn.textContent = "ZK Prove"; }
  }
}

// ---------------------------------------------------------------------------
// Phase 3 — Reveal
// ---------------------------------------------------------------------------

async function revealBid(bidderId) {
  const secret = localState.bidderSecrets[bidderId];
  if (!secret) { alert("No local secret found. Did you commit?"); return; }

  const btn = document.getElementById(`btn-reveal-${bidderId}`);
  if (btn) { btn.disabled = true; btn.textContent = "Revealing…"; }

  try {
    const data = await apiFetch("/api/reveal", "POST", {
      bidder_id:     bidderId,
      bid:           secret.bid,
      randomness_hex: secret.randomness_hex,
    });

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
    alert(`Reveal failed: ${err.message}`);
    if (btn) { btn.disabled = false; btn.textContent = "Reveal"; }
  }
}

// ---------------------------------------------------------------------------
// Fetch and render server state
// ---------------------------------------------------------------------------

async function refreshState() {
  try {
    const data = await apiFetch("/api/state");
    localState.serverState = data;
    renderAll(data);
  } catch (err) {
    console.error("refreshState error:", err);
  }
}

function renderAll(state) {
  renderPhaseIndicator(state);
  renderBidderCards(state);
  renderActionsPanel(state);
}

// ---------------------------------------------------------------------------
// Phase indicator
// ---------------------------------------------------------------------------

const PHASE_ORDER = ["open", "committed", "proved", "revealed", "finished"];
const PHASE_PILL_MAP = {
  open:      "commit",
  committed: "commit",
  proved:    "prove",
  revealed:  "reveal",
  finished:  "finished",
};

function renderPhaseIndicator(state) {
  const pills = document.querySelectorAll(".phase-pill");
  const activePill = PHASE_PILL_MAP[state.state] || "commit";
  pills.forEach(pill => {
    pill.classList.toggle("active", pill.dataset.phase === activePill);
  });
}

// ---------------------------------------------------------------------------
// Bidder cards
// ---------------------------------------------------------------------------

function renderBidderCards(state) {
  const container = document.getElementById("bidder-cards");
  const phase     = state.state;

  container.innerHTML = "";
  state.bidders.forEach(b => {
    const hasCommitted = !!b.commitment_hex;
    const hasProved    = b.proof_valid !== null && b.proof_valid !== undefined;
    const hasRevealed  = b.revealed_bid !== null && b.revealed_bid !== undefined;
    const isWinner     = state.winner && state.winner.bidder_id === b.bidder_id;
    const isCheater    = hasRevealed && b.commitment_verified === false;
    const secret       = localState.bidderSecrets[b.bidder_id];

    // Card CSS classes
    let cardClass = "bidder-card";
    if (isWinner)        cardClass += " winner";
    else if (hasRevealed) cardClass += " revealed";
    else if (hasProved)   cardClass += " proved";
    else if (hasCommitted) cardClass += " committed";

    // Phase badges
    const commitBadge = `<span class="phase-badge ${hasCommitted ? "done commit" : ""}">COMMIT</span>`;
    const proveBadge  = `<span class="phase-badge ${hasProved ? (b.proof_valid ? "done prove" : "invalid") : ""}">PROVE</span>`;
    const revealBadge = `<span class="phase-badge ${hasRevealed ? (b.commitment_verified ? "done reveal" : "invalid") : ""}">REVEAL</span>`;

    // Commitment hash line
    const commitLine = hasCommitted
      ? `<div class="bidder-commitment-hash">C: ${truncHex(b.commitment_hex)}</div>`
      : "";

    // Revealed bid
    let revealedLine = "";
    if (hasRevealed && b.commitment_verified) {
      revealedLine = `<div class="bidder-revealed-bid">${fmtBid(b.revealed_bid)}</div>`;
    } else if (hasRevealed && !b.commitment_verified) {
      revealedLine = `<div style="color:var(--red);font-size:12px;margin-bottom:6px;">⚠ Cheater detected — bid invalid</div>`;
    }

    // Winner badge
    const winnerBadge = isWinner
      ? `<div class="bidder-winner-badge">🏆 Winner!</div>`
      : "";

    // Action buttons
    let actionHTML = "";

    if (phase === "open") {
      if (!hasCommitted) {
        actionHTML = `
          <div class="bidder-bid-input">
            <input id="bid-input-${b.bidder_id}" type="number"
              min="${state.min_bid}" max="${state.max_bid}"
              placeholder="${state.min_bid}–${state.max_bid}"
              style="width:100px" />
            <button id="btn-commit-${b.bidder_id}"
              class="btn btn-commit"
              onclick="commitBid('${b.bidder_id}')">Commit</button>
          </div>`;
      } else {
        actionHTML = `<span style="font-size:11px;color:var(--color-commit)">✓ Committed</span>`;
      }
    } else if (phase === "committed") {
      if (hasCommitted && !hasProved) {
        const hasSecret = !!localState.bidderSecrets[b.bidder_id];
        actionHTML = `
          <button id="btn-prove-${b.bidder_id}"
            class="btn btn-prove"
            ${hasSecret ? "" : "disabled title='Commit this bidder in this browser session first'"}
            onclick="proveBid('${b.bidder_id}')">ZK Prove</button>
          ${!hasSecret ? '<span style="font-size:10px;color:var(--text-dim);display:block;margin-top:4px">Secret not in memory</span>' : ""}`;
      } else if (hasProved) {
        actionHTML = `<span style="font-size:11px;color:var(--color-prove)">✓ Proved (${b.proof_valid ? "valid" : "invalid"})</span>`;
      }
    } else if (phase === "proved" || phase === "revealed") {
      if (hasProved && !hasRevealed) {
        const hasSecret = !!localState.bidderSecrets[b.bidder_id];
        actionHTML = `
          <button id="btn-reveal-${b.bidder_id}"
            class="btn btn-reveal"
            ${hasSecret ? "" : "disabled title='Secret not in memory'"}
            onclick="revealBid('${b.bidder_id}')">Reveal</button>
          ${!hasSecret ? '<span style="font-size:10px;color:var(--text-dim);display:block;margin-top:4px">Secret not in memory</span>' : ""}`;
      }
    }

    container.innerHTML += `
      <div class="${cardClass}">
        <div class="bidder-card-name">
          <div class="bidder-avatar">👤</div>
          ${b.name}
        </div>
        <div class="bidder-phases">
          ${commitBadge}${proveBadge}${revealBadge}
        </div>
        ${commitLine}
        ${revealedLine}
        ${winnerBadge}
        ${actionHTML ? `<div class="bidder-actions">${actionHTML}</div>` : ""}
      </div>`;
  });
}

// ---------------------------------------------------------------------------
// Actions panel — contextual per phase
// ---------------------------------------------------------------------------

function renderActionsPanel(state) {
  const container = document.getElementById("actions-content");
  const phase     = state.state;
  const bidders   = state.bidders;

  const committed = bidders.filter(b => b.commitment_hex).length;
  const proved    = bidders.filter(b => b.proof_valid !== null && b.proof_valid !== undefined).length;
  const revealed  = bidders.filter(b => b.revealed_bid !== null && b.revealed_bid !== undefined).length;
  const total     = bidders.length;

  let html = "";

  // Phase description
  const phaseDescriptions = {
    open:      { title: "Phase 1 — Commit", color: "var(--color-commit)",
      desc: "Each bidder submits a cryptographic commitment <code>C = SHA256(bid ‖ r)</code>. The auctioneer sees only the hash, not the bid." },
    committed: { title: "Phase 2 — ZK Prove", color: "var(--color-prove)",
      desc: "Each bidder proves their bid is in the valid range <strong>[min, max]</strong> using a Sigma-protocol ZK range proof, without revealing the bid." },
    proved:    { title: "Phase 3 — Reveal", color: "var(--color-reveal)",
      desc: "Each bidder reveals <code>(bid, randomness)</code>. The auctioneer verifies the commitment opening. Highest verified bid wins." },
    revealed:  { title: "Phase 3 — Reveal", color: "var(--color-reveal)",
      desc: "Revealing bids…" },
    finished:  { title: "Auction Complete", color: "var(--color-finish)",
      desc: "All bids have been revealed and verified. The winner has been determined." },
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
    } else if (phase === "revealed") {
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
  }

  // Auction config
  html += `
    <div class="action-section">
      <div class="action-section-title">Auction Config</div>
      <div class="action-info">
        <strong>Item:</strong> ${state.item_name}<br/>
        <strong>Min bid:</strong> ${fmtBid(state.min_bid)}<br/>
        <strong>Max bid:</strong> ${fmtBid(state.max_bid)}<br/>
        <strong>Bidders:</strong> ${total}
      </div>
    </div>`;

  // Winner summary
  if (state.winner) {
    html += `
      <div class="action-section" style="border-color:var(--gold)">
        <div class="action-section-title" style="color:var(--gold)">🏆 Winner</div>
        <div class="action-info">
          <strong>${state.winner.name}</strong><br/>
          Winning bid: <strong style="color:var(--green)">${fmtBid(state.winner.bid)}</strong><br/>
          <span style="font-size:10px;color:var(--text-dim)">Commitment verified ✓</span>
        </div>
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
      .map(([k, v]) => `<code>${k}: ${v}</code>`)
      .join("");
  }

  div.innerHTML = `
    <div class="log-entry-header">
      <span class="log-entry-title">${title}</span>
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
    await apiFetch("/api/reset", "POST");
  } catch (_) { /* ignore */ }

  // Clear client state
  localState.auction = null;
  localState.serverState = null;
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
  // Validate setup form (same as createAuction)
  const errEl = document.getElementById("setup-error");
  errEl.style.display = "none";

  const itemName = document.getElementById("item-name").value.trim();
  const minBid   = parseInt(document.getElementById("min-bid").value, 10);
  const maxBid   = parseInt(document.getElementById("max-bid").value, 10);
  const names    = [...document.querySelectorAll(".bidder-name-input")]
                     .map(i => i.value.trim())
                     .filter(Boolean);

  if (!itemName)         { showSetupError("Item name is required."); return; }
  if (isNaN(minBid) || isNaN(maxBid)) { showSetupError("Bid bounds must be numbers."); return; }
  if (minBid >= maxBid)  { showSetupError("Min bid must be less than max bid."); return; }
  if (names.length < 2)  { showSetupError("At least 2 bidder names are required."); return; }

  // Create the auction on the server
  const createBtn = document.getElementById("btn-create");
  const demoBtn   = document.getElementById("btn-demo");
  createBtn.disabled = true;
  demoBtn.disabled   = true;
  demoBtn.textContent = "Starting…";

  let auctionData;
  try {
    auctionData = await apiFetch("/api/create", "POST", {
      item_name: itemName, min_bid: minBid, max_bid: maxBid, bidders: names,
    });
  } catch (err) {
    showSetupError(err.message);
    createBtn.disabled = false;
    demoBtn.disabled   = false;
    demoBtn.textContent = "▶ Watch Demo";
    return;
  }

  localState.auction = auctionData;
  localState.bidderSecrets = {};

  // Switch to auction view
  document.getElementById("setup-panel").style.display = "none";
  document.getElementById("auction-view").style.display = "grid";
  document.getElementById("phase-indicator").style.display = "flex";
  document.getElementById("auction-item-label").textContent = auctionData.item_name;
  document.getElementById("demo-banner").style.display = "flex";

  await refreshState();
  addPublicLogEntry("Auction created (Demo mode)", {
    item:    auctionData.item_name,
    range:   `${fmtBid(minBid)} – ${fmtBid(maxBid)}`,
    bidders: auctionData.bidders.map(b => b.name).join(", "),
  });

  // Assign each bidder a random bid (chosen now, revealed only in phase 3)
  const bidderIds = auctionData.bidders.map(b => b.bidder_id);
  const assignedBids = {};
  bidderIds.forEach(id => {
    assignedBids[id] = randInt(minBid, maxBid);
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

      const data = await apiFetch("/api/commit", "POST", { bidder_id: bidderId, bid });
      localState.bidderSecrets[bidderId] = { bid, randomness_hex: data.randomness_hex };

      addPublicLogEntry(`${name} committed`, { commitment: truncHex(data.commitment_hex) });
      addPrivateLogEntry(bidderId, `${name} — secret (demo)`, {
        bid:        fmtBid(bid),
        randomness: truncHex(data.randomness_hex),
      });
      await refreshState();
    }

    // PHASE 2 — ZK PROVE (random order)
    const proveOrder = shuffle([...bidderIds]);
    for (const bidderId of proveOrder) {
      if (demo.aborted) break;
      const name   = getBidderNameFromData(auctionData, bidderId);
      const secret = localState.bidderSecrets[bidderId];
      setDemoStatus(`Phase 2 — ${name} is generating ZK proof…`);
      await sleep(randInt(900, 1800));
      if (demo.aborted) break;

      const data = await apiFetch("/api/prove", "POST", {
        bidder_id:      bidderId,
        bid:            secret.bid,
        randomness_hex: secret.randomness_hex,
      });
      addPublicLogEntry(`${name} ZK proof ${data.proof_valid ? "valid" : "INVALID"}`, {
        low_commitment:  truncHex(data.proof_public.low_commitment_hex),
        high_commitment: truncHex(data.proof_public.high_commitment_hex),
      });
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

      const data = await apiFetch("/api/reveal", "POST", {
        bidder_id:      bidderId,
        bid:            secret.bid,
        randomness_hex: secret.randomness_hex,
      });

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
