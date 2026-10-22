// Tests for the bidder-side cryptography (static/auction-crypto.js), run with
//   node --test "tests/js/*.test.mjs"
// Whether the server accepts its proofs is checked from the Python side, in
// tests/test_browser_interop.py; these tests cover the module on its own.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  H_HEX,
  bidProofContext,
  commitBid,
  commitWith,
  encodeParts,
  proveBit,
  proveRange,
} from "../../src/crypto_auction/web/static/auction-crypto.js";
import { etc, Point } from "../../src/crypto_auction/web/static/vendor/noble-secp256k1.js";

const N = Point.CURVE().n;
const P = Point.CURVE().p;
const hex = (bytes) => etc.bytesToHex(bytes);

test("H matches a fresh derivation from its tag", async () => {
  // Same try-and-increment as pedersen._hash_to_curve: the first
  // SHA-256(tag || counter) that is a valid x-coordinate, with even y.
  const tag = new TextEncoder().encode("crypto-auction/pedersen/H/v1");
  for (let counter = 0; counter < 256; counter++) {
    const input = etc.concatBytes(tag, Uint8Array.of(counter));
    const x = etc.bytesToNumberBE(new Uint8Array(await crypto.subtle.digest("SHA-256", input)));
    if (x >= P) continue;
    let point;
    try {
      point = Point.fromHex("02" + x.toString(16).padStart(64, "0")); // "02": even y
    } catch {
      continue; // x³ + 7 is not a square: no point with this x
    }
    assert.equal(point.toHex(true), H_HEX);
    return;
  }
  assert.fail("no counter produced a curve point");
});

test("encodeParts length-prefixes every part", () => {
  const ascii = (s) => new TextEncoder().encode(s);
  assert.equal(hex(encodeParts(ascii("ab"), ascii("c"))), "0000000261620000000163");
  assert.equal(hex(encodeParts(new Uint8Array(0))), "00000000");
  // Without the prefixes these two would encode identically.
  assert.notEqual(
    hex(encodeParts(ascii("ab"), ascii("c"))),
    hex(encodeParts(ascii("a"), ascii("bc"))),
  );
});

test("commitments are homomorphic and canonically encoded", () => {
  const G = Point.BASE;
  const H = Point.fromHex(H_HEX);
  assert.ok(commitWith(1n, 0n).equals(G));
  assert.ok(commitWith(0n, 1n).equals(H));
  const sum = commitWith(1200n, 7n).add(commitWith(300n, 11n));
  assert.ok(sum.equals(commitWith(1500n, 18n)));

  const { commitmentHex, blindingHex } = commitBid(1500n);
  assert.match(commitmentHex, /^0[23][0-9a-f]{64}$/);
  assert.match(blindingHex, /^[0-9a-f]{64}$/);
  assert.ok(BigInt("0x" + blindingHex) < N);
  assert.ok(Point.fromHex(commitmentHex).equals(commitWith(1500n, BigInt("0x" + blindingHex))));
});

test("commitWith rejects scalars outside [0, n)", () => {
  for (const bad of [-1n, N, 1, "1"]) {
    assert.throws(() => commitWith(bad, 1n), RangeError);
  }
});

test("the prover refuses false statements", async () => {
  const context = bidProofContext("0".repeat(32), "bidder_0");
  const two = commitWith(2n, 5n);
  await assert.rejects(proveBit(two, 1n, 5n, context), /does not open to a bit/);

  const c = commitWith(1500n, 9n);
  await assert.rejects(proveRange(c, 1500n, 10n, 100n, 5000n, context), /does not open/);
  const high = commitWith(9999n, 9n);
  await assert.rejects(proveRange(high, 9999n, 9n, 100n, 5000n, context), RangeError);
  await assert.rejects(proveRange(c, 1500n, 9n, 5000n, 100n, context), RangeError);
});

test("range proofs have one canonically encoded bit per bit of max - min", async () => {
  const blinding = 123456789n;
  const c = commitWith(1500n, blinding);
  const proof = await proveRange(c, 1500n, blinding, 100n, 5000n, bidProofContext("a", "b"));
  for (const side of [proof.low, proof.high]) {
    assert.equal(side.bit_commitments.length, (5000 - 100).toString(2).length);
    assert.equal(side.bit_proofs.length, side.bit_commitments.length);
    for (const commitment of side.bit_commitments) assert.match(commitment, /^0[23][0-9a-f]{64}$/);
    for (const bitProof of side.bit_proofs) {
      assert.deepEqual(Object.keys(bitProof), ["e0", "s0", "e1", "s1"]);
      for (const scalar of Object.values(bitProof)) assert.match(scalar, /^[0-9a-f]{64}$/);
    }
  }
});
