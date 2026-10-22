// After the end-to-end run: remove its database (see playwright.config.js).
import { rmSync } from "node:fs";

export default function teardown() {
  rmSync(process.env.E2E_DATABASE, { force: true });
}
