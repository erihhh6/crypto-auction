"""Run a full three-bidder auction (commit, prove, reveal) without the web app."""

from crypto_auction.auction import Auction, AuctionConfig
from crypto_auction.commitment import Commitment, commit
from crypto_auction.zkp import prove_range


def main() -> None:
    print("=== Full Auction Simulation: Alice, Bob, Carol ===\n")

    config = AuctionConfig(
        min_bid=100,
        max_bid=5000,
        item_name="Rare NFT #42",
        bidder_names=("Alice", "Bob", "Carol"),
    )
    auction = Auction(config)

    bids = {
        "bidder_0": ("Alice", 1200),
        "bidder_1": ("Bob", 1800),
        "bidder_2": ("Carol", 1500),
    }

    # What each bidder keeps locally: their commitment and its opening.
    secrets: dict[str, Commitment] = {}

    print("--- PHASE 1: COMMIT ---")
    for bidder_id, (name, bid) in bids.items():
        c = commit(bid)
        secrets[bidder_id] = c
        committed = auction.submit_commitment(bidder_id, c.commitment_hex)
        print(f"  {name}: commitment={c.commitment_hex[:16]}...  -> phase={committed.phase.value}")

    print(f"\nAuction state: {auction.state.value}")

    print("\n--- PHASE 2: ZK PROVE ---")
    for bidder_id, (name, bid) in bids.items():
        c = secrets[bidder_id]
        proof = prove_range(bid, c.randomness_hex, c.commitment_hex, config.min_bid, config.max_bid)
        proved = auction.submit_proof(bidder_id, proof.to_dict())
        print(f"  {name}: proof_valid={proved.proof_valid}  -> phase={proved.phase.value}")

    print(f"\nAuction state: {auction.state.value}")

    print("\n--- PHASE 3: REVEAL ---")
    for bidder_id, (name, bid) in bids.items():
        revealed = auction.submit_reveal(bidder_id, bid, secrets[bidder_id].randomness_hex)
        print(f"  {name}: bid={bid}, verified={revealed.verified}  -> phase={revealed.phase.value}")

    print(f"\nAuction state: {auction.state.value}")

    winner = auction.get_winner()
    if winner is None:
        raise SystemExit("No eligible bidder: the auction has no winner.")
    print(f"\n=== WINNER: {winner.name} with bid {winner.bid} ===")

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
