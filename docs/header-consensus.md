# Header consensus

`hns-header-consensus` is the canonical, runtime-independent Handshake header
implementation.

It provides:

- exact 236-byte little-endian header encoding;
- the Handshake subheader, preheader, share-hash, mask, and proof-of-work
  algorithms;
- canonical compact-target decoding and encoding;
- checked 256-bit chainwork, proof, and work-based retarget arithmetic;
- mainnet, testnet, regtest, and simnet packet magic, ports, proof limits,
  timing parameters, and genesis headers; and
- contextual previous-block, time, difficulty, genesis, and proof validation.

Every root and hash has a distinct semantic Rust type. Amounts, heights,
timestamps, targets, and chainwork use integers only.

The network constants and half-timespan retarget vector are pinned against the
existing Rust node implementation derived from hsd. The tests independently
recompute and validate all four known genesis hashes and proof targets.

Run:

```sh
cargo test -p hns-header-consensus
cargo clippy -p hns-header-consensus --all-targets -- -D warnings
```
