"""Commit to a bid, then show that the commitment hides and binds it."""

from crypto_auction.commitment import commit, verify


def main() -> None:
    print("=== Commitment Scheme Demo ===\n")

    # 1. Commit to bid = 1500
    bid_value = 1500
    c = commit(bid_value)
    print(f"Bid: {bid_value}")
    print(f"Commitment (public): {c.commitment_hex}")
    print(f"Randomness (private): {c.randomness_hex[:16]}...  ({len(c.randomness_hex) // 2} bytes)")

    # 2. Verify with correct values → True
    result_correct = verify(bid_value, c.randomness_hex, c.commitment_hex)
    print(f"\nVerify(bid=1500, correct randomness) -> {result_correct}")
    if result_correct is not True:
        raise SystemExit("Correct verification should return True")

    # 3. Verify with wrong bid -> False
    result_wrong_bid = verify(9999, c.randomness_hex, c.commitment_hex)
    print(f"Verify(bid=9999, correct randomness) -> {result_wrong_bid}")
    if result_wrong_bid is not False:
        raise SystemExit("Wrong bid should return False")

    # 4. Two commits to the same bid produce different commitments (hiding / IND-CPA)
    c2 = commit(bid_value)
    print(f"\nTwo commitments to bid={bid_value}:")
    print(f"  C1 = {c.commitment_hex}")
    print(f"  C2 = {c2.commitment_hex}")
    print(f"  Are different: {c.commitment_hex != c2.commitment_hex}")
    if c.commitment_hex == c2.commitment_hex:
        raise SystemExit("Two commits should differ (hiding)")

    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
