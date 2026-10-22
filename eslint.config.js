// ESLint configuration: `npm run lint`, also run by CI.
import { includeIgnoreFile } from "@eslint/compat";
import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";
import { fileURLToPath } from "node:url";

const STATIC = "src/crypto_auction/web/static";

export default defineConfig([
  // ESLint does not read .gitignore itself: without this it would lint the
  // virtual environment's JavaScript (coverage and Werkzeug pages).
  includeIgnoreFile(fileURLToPath(new URL(".gitignore", import.meta.url))),
  // Third-party code, copied verbatim (see its README): not ours to change.
  globalIgnores([`${STATIC}/vendor/`]),

  js.configs.recommended,
  {
    linterOptions: { reportUnusedDisableDirectives: "error" },
    rules: {
      // The page's Content-Security-Policy forbids evaluating strings as code
      // (no 'unsafe-eval'); these catch such code before a browser refuses it.
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      eqeqeq: "error",
      "no-shadow": "error",
      "prefer-const": "error",
      "no-var": "error",
    },
  },

  // The page's main script: a classic script, whose top-level functions the
  // tests reach as globals (see tests/js/render.test.mjs).
  {
    files: [`${STATIC}/app.js`],
    languageOptions: { sourceType: "script", globals: globals.browser },
  },
  // Loaded with <script type="module"> by the page, and imported by Node tests.
  {
    files: [`${STATIC}/auction-crypto.js`],
    languageOptions: { sourceType: "module", globals: globals.browser },
  },
  {
    files: ["tests/js/**/*.mjs", "*.config.js"],
    languageOptions: { sourceType: "module", globals: globals.node },
  },
  // Playwright tests run in Node, but the functions they hand to the page
  // (addInitScript, evaluate) run in the browser.
  {
    files: ["tests/e2e/**/*.mjs"],
    languageOptions: { sourceType: "module", globals: { ...globals.node, ...globals.browser } },
    // A fixture that needs no other fixture is written `async ({}, use) => ...`.
    rules: { "no-empty-pattern": "off" },
  },
]);
