"""Prove that a committed bid lies in a range, without revealing it."""

import json
import time

from crypto_auction.pedersen import commit
from crypto_auction.range_proof import prove_range, verify_range


def main() -> None:
    print("=== ZK Range Proof Demo ===\n")

    min_b, max_b = 100, 5000
    context = b"demo-auction/bidder-0"  # binds the proof to where it is used

    # 1. Commit to bid = 1500
    bid_value = 1500
    c = commit(bid_value)
    print(f"Bid: {bid_value}  Range: [{min_b}, {max_b}]")

    # 2. Generate the range proof
    start = time.perf_counter()
    proof = prove_range(c.point, bid_value, c.blinding, min_b, max_b, context)
    elapsed = time.perf_counter() - start
    bits = len(proof.low.bit_commitments)
    print(f"\nRange proof generated in {elapsed * 1000:.0f} ms: {bits} bits per side,")
    print(f"{len(json.dumps(proof.to_dict()))} bytes as JSON.")

    # 3. Verify it
    valid = verify_range(c.point, proof, min_b, max_b, context)
    print(f"Verify proof -> {valid}")
    if valid is not True:
        raise SystemExit("Valid proof should verify as True")

    # 4. The proof says nothing about any other statement
    print(f"Verify for range [0, 10]       -> {verify_range(c.point, proof, 0, 10, context)}")
    print(f"Verify in another context      -> {verify_range(c.point, proof, min_b, max_b, b'x')}")

    # 5. A bid outside the range cannot be proven
    low = commit(50)
    try:
        prove_range(low.point, 50, low.blinding, min_b, max_b, context)
        print("ERROR: should have raised ValueError")
    except ValueError as e:
        print(f"\nAttempt with bid=50 (below min=100) -> ValueError: {e}")

    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
