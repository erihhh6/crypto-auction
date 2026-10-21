"""Run a full three-bidder auction (commit, prove, reveal) without the web app."""

from crypto_auction.auction import Auction, AuctionConfig
from crypto_auction.commitment import commit
from crypto_auction.zkp import prove_range


def main() -> None:
    print("=== Full Auction Simulation: Alice, Bob, Carol ===\n")

    config = AuctionConfig(
        min_bid=100,
        max_bid=5000,
        item_name="Rare NFT #42",
        bidder_names=["Alice", "Bob", "Carol"],
    )
    auction = Auction(config)

    bids = {
        "bidder_0": ("Alice", 1200),
        "bidder_1": ("Bob", 1800),
        "bidder_2": ("Carol", 1500),
    }

    # Store secrets keyed by bidder_id (simulating what each bidder holds locally)
    secrets: dict = {}

    print("--- PHASE 1: COMMIT ---")
    for bidder_id, (name, bid) in bids.items():
        c = commit(bid)
        secrets[bidder_id] = {"bid": bid, "randomness_hex": c.randomness_hex}
        result = auction.submit_commitment(bidder_id, c.commitment_hex)
        print(f"  {name}: commitment={c.commitment_hex[:16]}...  -> phase={result['phase']}")

    print(f"\nAuction state: {auction.state.value}")

    print("\n--- PHASE 2: ZK PROVE ---")
    for bidder_id, (name, bid) in bids.items():
        s = secrets[bidder_id]
        # The bidder retrieves their own commitment from public state
        commitment_hex = auction.bidders[bidder_id].commitment_hex
        proof = prove_range(
            bid, s["randomness_hex"], commitment_hex, config.min_bid, config.max_bid
        )
        proof_dict = {
            "commitment_hex": proof.commitment_hex,
            "min_bid": proof.min_bid,
            "max_bid": proof.max_bid,
            "low_commitment_hex": proof.low_commitment_hex,
            "low_challenge_hex": proof.low_challenge_hex,
            "low_response": proof.low_response,
            "high_commitment_hex": proof.high_commitment_hex,
            "high_challenge_hex": proof.high_challenge_hex,
            "high_response": proof.high_response,
        }
        result = auction.submit_proof(bidder_id, proof_dict)
        print(f"  {name}: proof_valid={result['proof_valid']}  -> phase={result['phase']}")

    print(f"\nAuction state: {auction.state.value}")

    print("\n--- PHASE 3: REVEAL ---")
    for bidder_id, (name, _) in bids.items():
        s = secrets[bidder_id]
        result = auction.submit_reveal(bidder_id, s["bid"], s["randomness_hex"])
        print(
            f"  {name}: bid={s['bid']}, verified={result['verified']}  -> phase={result['phase']}"
        )

    print(f"\nAuction state: {auction.state.value}")

    winner = auction.get_winner()
    print(f"\n=== WINNER: {winner['name']} with bid {winner['bid']} ===")

    public = auction.get_public_state()
    print("\nPublic state summary:")
    for b in public["bidders"]:
        print(
            f"  {b['name']}: commitment={str(b['commitment_hex'])[:16]}...  "
            f"proof_valid={b['proof_valid']}  "
            f"bid={b.get('revealed_bid')}  "
            f"verified={b['commitment_verified']}"
        )


if __name__ == "__main__":
    main()
