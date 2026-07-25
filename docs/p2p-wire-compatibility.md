# Standard P2P wire compatibility

`hns-p2p-wire` is the runtime-independent standard Handshake packet layer. Its
oracle is `handshake-org/hsd@698e252ebc7b5c1dd0a9587e342fdd153d020ae4`.
The fixture lineage is the `wire-v1` oracle generated and retained in the
audited HSRD source extraction.

The crate pins:

- protocol version 3 and minimum version 1;
- mainnet, testnet, regtest, and simnet magic values;
- the 9-byte `magic || packet-type || payload-length` frame;
- every standard packet type from `VERSION` (0) through `AIRDROP` (29);
- inventory kinds, 88-byte peer addresses, version packets, locators, header
  batches, rejects, fee filters, compact-block negotiation, tree-proof
  requests, and strict Urkel-proof responses;
- exact HSD quirks for reserved service words, unsupported address kinds,
  high-bit inbound text, and `noRelay`; and
- complete-input parsing, canonical compact sizes, bounded item counts, an
  8,000,000-byte payload ceiling, and a bounded incremental decoder.

Transactions use `hns-transaction`; headers use `hns-header-consensus`; blocks
use the bounded syntactic codec in `hns-mining`; proof responses use
`hns-urkel-proof`. Compact blocks use structured HSD/BIP152 codecs, collision
handling, bounded missing-transaction recovery, and a final commitment/body
check before reconstruction succeeds. Packets whose nested primitive is
outside the canonical workspace today (Bloom/merkle data, claims, and
airdrops) retain an allocation-bounded byte payload without rewriting it. The
extracted full-node implementation supplies those complete nested codecs.

The standard packet layer deliberately contains no socket, Tokio, Brontide,
peer manager, database, wallet, or MeshMine dependency. Brontide session
establishment and peer policy belong to the full node.

Tests pin exact HSD frames for all four networks and exact HSD payloads for
version, address, inventory, locator, headers, reject, fee-filter, compact
negotiation, compact-block, missing-transaction request, and response packets.
Negative coverage includes wrong magic, incomplete and oversized frames,
noncanonical counts, trailing packet data, short-ID collisions, mismatched
reconstructed commitments, unsupported address normalization, and
noncanonical proofs.

Run:

```sh
cargo test -p hns-p2p-wire
cargo clippy -p hns-p2p-wire --all-targets -- -D warnings
```
