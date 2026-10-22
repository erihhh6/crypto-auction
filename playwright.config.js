// Playwright: whole auctions in real browsers against the real server
// (`npm run test:e2e`, tests in tests/e2e/). Start it from the Python
// environment the package is installed in, or name its interpreter in PYTHON.
import { defineConfig, devices } from "@playwright/test";
import { tmpdir } from "node:os";
import path from "node:path";

const PORT = 5099;
const PYTHON = process.env.PYTHON ?? "python";
const SERVER = [
  "import logging",
  "from crypto_auction.web import create_app",
  "logging.getLogger('werkzeug').setLevel(logging.WARNING)",
  `create_app().run(port=${PORT})`,
].join("; ");

// Each run gets a database of its own, removed afterwards by
// tests/e2e/teardown.mjs. The test workers inherit this environment, so they
// agree on the name rather than make up their own.
process.env.E2E_DATABASE ??= path.join(tmpdir(), `crypto-auction-e2e-${process.pid}.sqlite3`);

export default defineConfig({
  testDir: "tests/e2e",
  // A page learns of the other bidders' steps by polling every 5 seconds, so
  // a full auction takes three polls at least, plus the proofs and the axe
  // audits: about 20 s in Chromium, up to a minute in WebKit on Windows.
  timeout: 120_000,
  expect: { timeout: 15_000 },
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    locale: "en-US", // the page formats amounts in the browser's locale: "$7,500"
    trace: "retain-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: {
    // Flask's own server, without the debugger. It reports problems (a
    // traceback, say) but not every request, which would bury the results.
    command: `"${PYTHON}" -c "${SERVER}"`,
    url: `http://127.0.0.1:${PORT}/`,
    env: { CRYPTO_AUCTION_DATABASE: process.env.E2E_DATABASE },
    reuseExistingServer: false,
  },
  globalTeardown: "./tests/e2e/teardown.mjs",
});
