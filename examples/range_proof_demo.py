"""Generate and verify a range proof for a committed bid."""

from crypto_auction.commitment import commit
from crypto_auction.zkp import prove_range, verify_range_proof


def main() -> None:
    print("=== ZK Range Proof Demo ===\n")

    min_b, max_b = 100, 5000

    # 1. Commit to bid = 1500
    bid_value = 1500
    c = commit(bid_value)
    print(f"Bid: {bid_value}  Range: [{min_b}, {max_b}]")
    print(f"Commitment: {c.commitment_hex[:16]}...")

    # 2. Generate range proof
    proof = prove_range(bid_value, c.randomness_hex, c.commitment_hex, min_b, max_b)
    print("\nRange proof generated.")

    # 3. Verify proof → True
    valid = verify_range_proof(proof)
    print(f"Verify proof -> {valid}")
    if valid is not True:
        raise SystemExit("Valid proof should verify as True")

    # 4. Attempt proof with bid=50 (below min) → ValueError
    try:
        prove_range(50, c.randomness_hex, c.commitment_hex, min_b, max_b)
        print("ERROR: should have raised ValueError")
    except ValueError as e:
        print(f"\nAttempt with bid=50 (below min=100) -> ValueError: {e}")

    # 5. Display complete public proof structure
    print("\n--- Public Proof Structure ---")
    print(f"  commitment_hex:      {proof.commitment_hex[:16]}...")
    print(f"  min_bid:             {proof.min_bid}")
    print(f"  max_bid:             {proof.max_bid}")
    print(f"  low_commitment_hex:  {proof.low_commitment_hex[:16]}...")
    print(f"  low_challenge_hex:   {proof.low_challenge_hex[:16]}...")
    print(f"  low_response:        {proof.low_response}")
    print(f"  high_commitment_hex: {proof.high_commitment_hex[:16]}...")
    print(f"  high_challenge_hex:  {proof.high_challenge_hex[:16]}...")
    print(f"  high_response:       {proof.high_response}")

    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
