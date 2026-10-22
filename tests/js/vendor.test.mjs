// The page's copy of noble-secp256k1 (static/vendor/) must be the npm
// package listed in package.json, byte for byte. Listing it there lets
// Dependabot propose its updates and report its security advisories, which it
// cannot do for a copied file. When it does, this test fails until the new
// version has been reviewed and copied (see static/vendor/README.md).
//
// Needs `npm ci` first: the package is read from node_modules.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (path) => readFileSync(new URL(path, import.meta.url));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const VENDOR = "../../src/crypto_auction/web/static/vendor/";
const PACKAGE = "../../node_modules/@noble/secp256k1/";
const vendored = read(`${VENDOR}noble-secp256k1.js`);
const { version } = JSON.parse(read(`${PACKAGE}package.json`));

test("the vendored noble-secp256k1 is the npm package's index.js", () => {
  assert.equal(
    sha256(vendored),
    sha256(read(`${PACKAGE}index.js`)),
    `static/vendor/noble-secp256k1.js is not @noble/secp256k1 ${version}: review and copy it`,
  );
});

test("the vendor README records the version and hash in use", () => {
  const readme = read(`${VENDOR}README.md`).toString();
  assert.ok(readme.includes(`| ${version} |`), `the README does not name version ${version}`);
  assert.ok(readme.includes(sha256(vendored)), "the README's SHA-256 is out of date");
});
