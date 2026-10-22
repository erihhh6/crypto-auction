// Whole auctions in real browsers (Chromium, Firefox, WebKit) against the
// real server: the page's own cryptography, verified by the server's; join
// links, with each bidder on a device of their own; polling; receipts. The
// unit tests (tests/js, tests/*.py) check each of these with fakes on one
// side; here both sides are real.

import { expect, expectAccessible, test } from "./fixtures.mjs";

/** A bidder's card: a group named after them (see app.js createBidderCard). */
const card = (page, name) => page.getByRole("group", { name, exact: true });

/**
 * The card's badge for a step says it is done. (Its notes, such as
 * "✓ Committed", last only until the phase ends, which the last bidder to
 * take a step ends at once.)
 */
const done = (page, name, step) =>
  expect(card(page, name).getByText(`${step}: done`)).toBeVisible();

/**
 * The organizer sets up an auction for these bidders and starts it; returns
 * each bidder's join link, as the organizer's page lists them.
 */
async function createAuction(page, { item, bidders }) {
  await page.goto("/");
  await page.getByLabel("Item Name").fill(item);
  const rows = page.getByRole("textbox", { name: "Bidder name" });
  while ((await rows.count()) > bidders.length) {
    await page.getByRole("button", { name: "Remove bidder" }).last().click();
  }
  for (const [i, name] of bidders.entries()) await rows.nth(i).fill(name);
  await page.getByRole("button", { name: "Start Auction" }).click();

  const links = {};
  for (const name of bidders) {
    links[name] = await page.getByRole("textbox", { name: `Join link for ${name}` }).inputValue();
  }
  return links;
}

// The steps are taken with the keyboard. A poll can grow another card (a
// commitment line, a "revealed" line) and move a button just as the mouse
// clicks where it was, which happened in WebKit; the focus stays put.

// Enter in the bid field commits, as in a form.
async function commit(page, name, bid) {
  const field = card(page, name).getByRole("spinbutton");
  await field.fill(String(bid));
  await field.press("Enter");
  await done(page, name, "COMMIT");
}

// The button shows once every bidder has committed, which a page learns at
// its next poll: the locator waits for it. "done" means the proof was valid.
async function prove(page, name) {
  await card(page, name).getByRole("button", { name: "ZK Prove" }).press("Enter");
  await done(page, name, "PROVE");
}

// "done" means the opening matched the commitment.
async function reveal(page, name) {
  await card(page, name).getByRole("button", { name: "Reveal" }).press("Enter");
  await done(page, name, "REVEAL");
}

/** The body of each protocol step this page sends: { commit, prove, reveal }. */
function recordSteps(page) {
  const sent = {};
  page.on("request", (request) => {
    const step = /\/api\/auctions\/[^/]+\/(commit|prove|reveal)$/.exec(request.url())?.[1];
    if (step) sent[step] = request.postDataJSON();
  });
  return sent;
}

/** Whether value appears anywhere in a JSON body, as a number or a string. */
function mentions(body, value) {
  if (body === value || body === String(value)) return true;
  return (
    typeof body === "object" && body !== null && Object.values(body).some((v) => mentions(v, value))
  );
}

const finished = (page) => page.getByRole("dialog", { name: "Auction Complete!" });

test("a full auction, each bidder on their own device", async ({ page, openDevice }) => {
  const bids = { Alice: 4200, Bob: 7500, Carol: 6100 };
  const names = Object.keys(bids);

  await page.goto("/");
  await test.step("the setup page passes an accessibility audit", () => expectAccessible(page));
  const links = await createAuction(page, { item: "Vintage Watch", bidders: names });

  const bidders = {};
  for (const name of names) {
    const device = await openDevice(links[name]);
    bidders[name] = { page: device, sent: recordSteps(device) };
    await expect(device.getByText(`Vintage Watch — bidding as ${name}`)).toBeVisible();
  }
  await test.step("a bidder's page passes an accessibility audit", () =>
    expectAccessible(bidders.Alice.page));

  for (const name of names) await commit(bidders[name].page, name, bids[name]);
  for (const name of names) await prove(bidders[name].page, name);
  for (const name of names) await reveal(bidders[name].page, name);

  // The last reveal ends the auction; every page learns of it, the
  // organizer's included.
  for (const p of [page, ...names.map((name) => bidders[name].page)]) {
    await expect(finished(p)).toContainText("Bob");
    await expect(finished(p)).toContainText("$7,500");
  }
  await test.step("the finished page, its dialog open, passes an accessibility audit", () =>
    expectAccessible(page));

  await test.step("each bid left its browser only at the reveal", () => {
    for (const name of names) {
      const { commit: committed, prove: proved, reveal: revealed } = bidders[name].sent;
      expect(Object.keys(committed)).toEqual(["commitment_hex"]);
      expect(Object.keys(proved)).toEqual(["proof"]);
      expect(mentions(committed, bids[name]) || mentions(proved, bids[name])).toBe(false);
      expect(revealed.bid).toBe(bids[name]);
    }
  });
});

test("a bidder who closes the page carries on from their receipt", async ({
  page,
  openDevice,
}, testInfo) => {
  const links = await createAuction(page, { item: "Old Map", bidders: ["Alice", "Bob"] });
  const alice = await openDevice(links.Alice);
  await commit(alice, "Alice", 9000);

  const download = alice.waitForEvent("download");
  await card(alice, "Alice").getByRole("button", { name: "Save receipt" }).click();
  const receipt = testInfo.outputPath("receipt.json");
  await (await download).saveAs(receipt);

  await test.step("closing the page asks first: it holds the only copy of the bid", async () => {
    const asked = alice.waitForEvent("dialog");
    await alice.close({ runBeforeUnload: true });
    const dialog = await asked;
    expect(dialog.type()).toBe("beforeunload");
    await dialog.accept();
  });

  // Later, on another device: the receipt is all Alice has.
  const aliceAgain = await openDevice("/");
  await aliceAgain.getByLabel("Continue as a bidder").setInputFiles(receipt);
  await expect(aliceAgain.getByText("Old Map — bidding as Alice")).toBeVisible();

  const bob = await openDevice(links.Bob);
  await commit(bob, "Bob", 3000);
  await prove(aliceAgain, "Alice");
  await prove(bob, "Bob");
  await reveal(aliceAgain, "Alice");
  await reveal(bob, "Bob");

  await expect(finished(aliceAgain)).toContainText("Alice");
  await expect(finished(aliceAgain)).toContainText("$9,000");
});
