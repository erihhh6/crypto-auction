// Bidder-side cryptography, run in the browser so the server never sees a bid
// before it is revealed: Pedersen commitments and the zero-knowledge range
// proof. Mirrors src/crypto_auction/{pedersen,transcript,bit_proof,
// range_proof}.py and Auction.proof_context exactly (tags, transcript bytes,
// JSON format); tests/test_browser_interop.py checks the server accepts what
// this produces.
//
// Curve arithmetic: vendored @noble/secp256k1 (see vendor/README.md). Its
// multiply() runs a fixed-length ladder with dummy additions to reduce timing
// leakage, but JavaScript BigInt arithmetic cannot be strictly constant-time.

import { etc, Point } from "./vendor/noble-secp256k1.js";

const N = Point.CURVE().n;
const G = Point.BASE;
// H = hash_to_curve("crypto-auction/pedersen/H/v1"), pinned exactly as in
// tests/test_pedersen.py; tests/js/crypto.test.mjs re-derives it.
export const H_HEX = "02dcff14ee3f07929f95960463a3d806af79655299b20bfea66261ed5cd270ec38";
const H = Point.fromHex(H_HEX);

// Range proofs support bounds up to 2^64 - 1 (range_proof.MAX_VALUE).
const MAX_VALUE = 2n ** 64n - 1n;

const BIT_DOMAIN = "crypto-auction/bit-proof/v1";
const RANGE_DOMAIN = "crypto-auction/range-proof/v1";
const BID_DOMAIN = "crypto-auction/bid-range-proof/v1";

const ascii = (text) => new TextEncoder().encode(text);

/** k·P for any scalar k in [0, n); noble's multiply() rejects k = 0. */
const mul = (point, scalar) => (scalar === 0n ? Point.ZERO : point.multiply(scalar));

/** A uniformly random scalar: 64 random bytes reduced mod n (bias about 2^-256). */
export function randomScalar() {
  return etc.bytesToNumberBE(crypto.getRandomValues(new Uint8Array(64))) % N;
}

export const encodePoint = (point) => point.toHex(true); // compressed SEC1, lowercase
export const encodeScalar = (scalar) => scalar.toString(16).padStart(64, "0");

/** transcript.encode_parts: each part prefixed with its length as 4 big-endian bytes. */
export function encodeParts(...parts) {
  const framed = [];
  for (const part of parts) {
    const length = new Uint8Array(4);
    new DataView(length.buffer).setUint32(0, part.length);
    framed.push(length, part);
  }
  return etc.concatBytes(...framed);
}

/** transcript.encode_int: a non-negative integer as 32 big-endian bytes. */
const encodeInt = (value) => etc.numberToBytesBE(value);
const pointBytes = (point) => ascii(encodePoint(point)); // as hashed by the Python side

/** Auction.proof_context: binds a range proof to one auction and one bidder. */
export const bidProofContext = (auctionId, bidderId) =>
  encodeParts(ascii(BID_DOMAIN), ascii(auctionId), ascii(bidderId));

/** pedersen.commit_with: value·G + blinding·H. */
export function commitWith(value, blinding) {
  for (const scalar of [value, blinding]) {
    if (typeof scalar !== "bigint" || scalar < 0n || scalar >= N) {
      throw new RangeError("Scalars must be bigints in [0, n).");
    }
  }
  return mul(G, value).add(mul(H, blinding));
}

/** Fiat-Shamir challenge of bit_proof._challenge: SHA-512 of the transcript, mod n. */
async function bitChallenge(commitment, context, a0, a1) {
  const transcript = encodeParts(
    ascii(BIT_DOMAIN),
    pointBytes(G),
    pointBytes(H),
    pointBytes(commitment),
    context,
    pointBytes(a0),
    pointBytes(a1),
  );
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-512", transcript));
  return etc.bytesToNumberBE(digest) % N;
}

/** bit_proof.prove_bit: OR-proof that commitment hides 0 or 1, without saying which. */
export async function proveBit(commitment, bit, blinding, context) {
  if ((bit !== 0n && bit !== 1n) || !commitment.equals(commitWith(bit, blinding))) {
    throw new Error("The commitment does not open to a bit with this blinding.");
  }
  const branchPoints = [commitment, commitment.subtract(G)]; // r·H if b = 0, resp. b = 1
  const real = Number(bit);
  const fake = 1 - real;
  const k = randomScalar();
  const eFake = randomScalar();
  const sFake = randomScalar();

  const announcements = [];
  announcements[real] = mul(H, k); // real Schnorr announcement
  // Simulated branch: (e, s) chosen first, then the announcement that makes them verify.
  announcements[fake] = mul(H, sFake).add(mul(branchPoints[fake], (N - eFake) % N));

  const e = await bitChallenge(commitment, context, announcements[0], announcements[1]);
  const eReal = (((e - eFake) % N) + N) % N;
  const sReal = (k + eReal * blinding) % N;
  return real === 0
    ? { e0: eReal, s0: sReal, e1: eFake, s1: sFake }
    : { e0: eFake, s0: sFake, e1: eReal, s1: sReal };
}

function bitsFor(minValue, maxValue) {
  for (const bound of [minValue, maxValue]) {
    if (typeof bound !== "bigint" || bound < 0n || bound > MAX_VALUE) {
      throw new RangeError(`Bounds must be bigints in [0, ${MAX_VALUE}].`);
    }
  }
  if (minValue > maxValue) throw new RangeError("min is greater than max.");
  const width = maxValue - minValue;
  // At least one bit, as in range_proof._bits_for.
  return width === 0n ? 1 : width.toString(2).length;
}

const rangeContext = (commitment, minValue, maxValue, side, context) =>
  encodeParts(
    ascii(RANGE_DOMAIN),
    pointBytes(commitment),
    encodeInt(minValue),
    encodeInt(maxValue),
    ascii(side),
    context,
  );

const bitContext = (sideContext, index) => encodeParts(sideContext, encodeInt(BigInt(index)));

/** range_proof._prove_non_negative, serialised as NonNegativeProof.to_dict(). */
async function proveNonNegative(value, blinding, bits, context) {
  // Random blindings for all bits but the last, which is chosen so that
  // Σ 2^i·blinding_i ≡ blinding (mod n) and the bit commitments sum to the input.
  const blindings = Array.from({ length: bits - 1 }, randomScalar);
  const partial = blindings.reduce((sum, b, i) => sum + (b << BigInt(i)), 0n) % N;
  const inverse = etc.invert(1n << BigInt(bits - 1), N);
  blindings.push((((((blinding - partial) % N) + N) % N) * inverse) % N);

  const bitCommitments = [];
  const bitProofs = [];
  for (const [i, bitBlinding] of blindings.entries()) {
    const bit = (value >> BigInt(i)) & 1n;
    const bitCommitment = commitWith(bit, bitBlinding);
    const proof = await proveBit(bitCommitment, bit, bitBlinding, bitContext(context, i));
    bitCommitments.push(encodePoint(bitCommitment));
    bitProofs.push(Object.fromEntries(Object.entries(proof).map(([k, v]) => [k, encodeScalar(v)])));
  }
  return { bit_commitments: bitCommitments, bit_proofs: bitProofs };
}

/**
 * range_proof.prove_range, serialised as RangeProof.to_dict(): proves that
 * commitment hides a value in [minValue, maxValue]. Refuses false statements.
 */
export async function proveRange(commitment, value, blinding, minValue, maxValue, context) {
  const bits = bitsFor(minValue, maxValue);
  if (!commitment.equals(commitWith(value, blinding))) {
    throw new Error("(value, blinding) does not open the given commitment.");
  }
  if (value < minValue || value > maxValue) {
    throw new RangeError(`Value ${value} is not within [${minValue}, ${maxValue}].`);
  }
  const ctx = (side) => rangeContext(commitment, minValue, maxValue, side, context);
  return {
    low: await proveNonNegative(value - minValue, blinding, bits, ctx("low")),
    high: await proveNonNegative(maxValue - value, (N - blinding) % N, bits, ctx("high")),
  };
}

// ---------------------------------------------------------------------------
// What the page uses (all numbers as bigints, hex strings as on the wire)
// ---------------------------------------------------------------------------

/** Commit to a bid with a fresh blinding factor; only commitmentHex is sent. */
export function commitBid(bid) {
  const blinding = randomScalar();
  return {
    commitmentHex: encodePoint(commitWith(bid, blinding)),
    blindingHex: encodeScalar(blinding),
  };
}

/**
 * Whether (bid, blindingHex) opens commitmentHex: the check the server makes at
 * the reveal (pedersen.verify), run before trusting a saved opening.
 */
export function opensCommitment(commitmentHex, bid, blindingHex) {
  if (!/^[0-9a-f]{64}$/.test(blindingHex)) return false;
  try {
    return encodePoint(commitWith(bid, BigInt("0x" + blindingHex))) === commitmentHex;
  } catch {
    return false; // a bid or blinding factor out of range opens nothing
  }
}

/** Prove, for this auction and bidder, that the committed bid lies in [minBid, maxBid]. */
export function proveBid({ bid, blindingHex, commitmentHex, minBid, maxBid, auctionId, bidderId }) {
  return proveRange(
    Point.fromHex(commitmentHex),
    bid,
    BigInt("0x" + blindingHex),
    minBid,
    maxBid,
    bidProofContext(auctionId, bidderId),
  );
}

if (typeof window !== "undefined") {
  window.auctionCrypto = Object.freeze({ commitBid, proveBid, opensCommitment });
}
