// Runs the browser's bidder-side cryptography from the command line, so the
// Python tests (tests/test_browser_interop.py) can check that the server
// accepts exactly what the page produces.
//
// stdin:  a JSON array of requests; stdout: a JSON array of results.
//   {"action": "commit", "bid": 1500}
//   {"action": "prove", "bid", "randomness_hex", "commitment_hex",
//    "min_bid", "max_bid", "auction_id", "bidder_id"}
//   {"action": "encode_parts", "parts_hex": ["6162", "63"]}
// A request that throws yields {"error": "<message>"} instead of a result.

import { etc } from "../../src/crypto_auction/web/static/vendor/noble-secp256k1.js";
import {
  commitBid,
  encodeParts,
  proveBid,
} from "../../src/crypto_auction/web/static/auction-crypto.js";

async function handle(request) {
  switch (request.action) {
    case "commit": {
      const { commitmentHex, blindingHex } = commitBid(BigInt(request.bid));
      return { commitment_hex: commitmentHex, randomness_hex: blindingHex };
    }
    case "prove":
      return {
        proof: await proveBid({
          bid: BigInt(request.bid),
          blindingHex: request.randomness_hex,
          commitmentHex: request.commitment_hex,
          minBid: BigInt(request.min_bid),
          maxBid: BigInt(request.max_bid),
          auctionId: request.auction_id,
          bidderId: request.bidder_id,
        }),
      };
    case "encode_parts":
      return { hex: etc.bytesToHex(encodeParts(...request.parts_hex.map(etc.hexToBytes))) };
    default:
      throw new Error(`unknown action ${request.action}`);
  }
}

let input = "";
for await (const chunk of process.stdin) input += chunk;
const results = [];
for (const request of JSON.parse(input)) {
  try {
    results.push(await handle(request));
  } catch (error) {
    results.push({ error: String(error.message) });
  }
}
process.stdout.write(JSON.stringify(results));
