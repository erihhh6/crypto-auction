// Shared fixtures for the end-to-end tests.
//
// Every page a test opens, the organizer's and each bidder's, is watched: an
// uncaught exception, a console error or anything the Content-Security-Policy
// blocks fails the test, even when what the test checks still works.

import AxeBuilder from "@axe-core/playwright";
import { test as base, expect } from "@playwright/test";

export { expect };

function watch(page, problems) {
  page.on("pageerror", (error) => problems.push(`uncaught: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error") problems.push(`console: ${message.text()}`);
  });
  // The standard event, reported alike by every browser (their console
  // wording differs).
  return page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) => {
      console.error(
        `CSP blocked ${event.blockedURI || "inline code"} (${event.violatedDirective})`,
      );
    });
  });
}

export const test = base.extend({
  problems: [
    async ({}, use) => {
      const problems = [];
      await use(problems);
      expect(problems, "errors on the test's pages").toEqual([]);
    },
    { auto: true },
  ],

  page: async ({ page, problems }, use) => {
    await watch(page, problems);
    await use(page);
  },

  // Opens a URL on another device: a browser context of its own, sharing
  // nothing (storage, cookies, memory) with the other pages of the test.
  openDevice: async ({ browser, problems }, use) => {
    const contexts = [];
    await use(async (url) => {
      const context = await browser.newContext();
      contexts.push(context);
      const page = await context.newPage();
      await watch(page, problems);
      await page.goto(url);
      return page;
    });
    await Promise.all(contexts.map((context) => context.close()));
  },
});

/** An axe-core audit of the page as it is now finds nothing. */
export async function expectAccessible(page) {
  const { violations } = await new AxeBuilder({ page }).analyze();
  const found = violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(", ")}`);
  expect(found, "axe-core violations").toEqual([]);
}
