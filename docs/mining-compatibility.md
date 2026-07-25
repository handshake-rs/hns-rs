# Mining compatibility

`hns-mining` contains the runtime-independent portion of Handshake template and
candidate handling. Its consensus oracle is
`handshake-org/hsd@698e252ebc7b5c1dd0a9587e342fdd153d020ae4`; its immutable-job
binding matches the extracted Rust mining node.

The crate implements:

- HSD's integer subsidy schedule and network halving intervals;
- the deterministic ordinary coinbase layout, including height, generation
  sequence, payout, and three-item witness, with checked generation conversion;
- domain-separated BLAKE2b-256 transaction and witness Merkle roots;
- exact base-size, witness-size, and block-weight accounting;
- bounded block and transaction decoding, non-contextual body/commitment
  checks, ordinary name-covenant shape sanity, per-transaction and per-block
  open/update/renewal caps, and cross-transaction exclusive-name rejection;
- immutable jobs bound to network, committed tip generation, parent, next name
  tree root, target, time floor, every transaction byte, and the opened-mask
  commitment;
- testnet target-reset expiry, exact-mask reconstruction, stale-generation
  rejection, and local proof-of-work admission; and
- a bounded prepared-job set.

The HSD-derived deterministic coinbase vector is retained in
`fixtures/hsd/mining-template-v1-core.json`. Tests pin its raw bytes, txid,
witness hash, sizes, single/even/odd Merkle roots, subsidy boundaries,
generation overflow, malformed covenant shapes, name-operation ceilings, and
exclusive-name behavior.

This shared crate does not select mempool packages, validate chain state, issue
mining authority, publish blocks, run Stratum, or carry MeshMine settlement
data. Claim ownership proofs, airdrop proofs, and reserved-name membership are
also validated by the full node, which owns their state and proof codecs. Those
are full-node and mining-application responsibilities. A prepared body is not
authorization to mine; the consuming node must issue it only from an
authoritative committed snapshot and must re-run full contextual consensus
before publication.

Run:

```sh
cargo test -p hns-mining
cargo clippy -p hns-mining --all-targets -- -D warnings
```
