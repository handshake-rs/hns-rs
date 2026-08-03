# hns-covenants

Canonical Handshake name covenant, authenticated-state, and resource values.

This crate covers every assigned covenant wire tag, HNS name hashing, blind
bids, HSD's exact NameState value encoding, mandatory authenticated key/name
binding, owner-outpoint semantics, and lossless typed version-zero resource
decoding. Typed `TransferCovenant` and `FinalizeCovenant` values construct and
strictly parse HSD's exact field layouts; FINALIZE construction can project the
authenticated name, claim, weak-proof, and renewal state directly from
`NameState`. NameState resource bytes remain opaque until the caller explicitly
requests the fallible resource projection. It is part of the
[`hns-rs`](https://github.com/handshake-rs/hns-rs) protocol workspace.

```bash
cargo add hns-covenants
```

The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-covenants).

Licensed under either Apache-2.0 or MIT.
