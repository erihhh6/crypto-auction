"""Commit to a bid with a Pedersen commitment and show what that guarantees."""

from crypto_auction.pedersen import N, commit, commit_with, encode_point, verify


def main() -> None:
    print("=== Pedersen Commitment Demo (C = v·G + r·H on secp256k1) ===\n")

    # 1. Commit to bid = 1500
    bid_value = 1500
    c = commit(bid_value)
    print(f"Bid: {bid_value}")
    blinding_hex = f"{c.blinding:064x}"
    print(f"Commitment (public):      {encode_point(c.point)}")
    print(f"Blinding factor (private): {blinding_hex[:16]}...  (32 bytes)")

    # 2. The opening verifies
    result_correct = verify(c.point, bid_value, c.blinding)
    print(f"\nVerify(bid=1500, correct blinding) -> {result_correct}")
    if result_correct is not True:
        raise SystemExit("Correct verification should return True")

    # 3. Binding: the same commitment does not open to another bid
    result_wrong_bid = verify(c.point, 9999, c.blinding)
    print(f"Verify(bid=9999, correct blinding) -> {result_wrong_bid}")
    if result_wrong_bid is not False:
        raise SystemExit("Wrong bid should return False")

    # 4. Hiding: two commitments to the same bid look unrelated
    c2 = commit(bid_value)
    print(f"\nTwo commitments to bid={bid_value}:")
    print(f"  C1 = {encode_point(c.point)}")
    print(f"  C2 = {encode_point(c2.point)}")
    if c.point == c2.point:
        raise SystemExit("Two commits should differ (hiding)")

    # 5. Homomorphism: commitments add up like the values inside them
    a, b = commit(1200), commit(300)
    summed = commit_with(1500, (a.blinding + b.blinding) % N)
    print(f"\nC(1200) + C(300) == C(1500) with the summed blinding: {a.point + b.point == summed}")
    if a.point + b.point != summed:
        raise SystemExit("Commitments should be additively homomorphic")

    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
