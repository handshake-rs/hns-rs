# hns-transaction

Canonical Handshake transaction and witness encoding.

This crate provides transaction, witness, address, output, coin, and
non-coinbase covenant-link validation primitives. Its public `Outpoint` remains
available here as a re-export of the shared primitive also used by NameState
ownership. It is part of the
[`hns-rs`](https://github.com/handshake-rs/hns-rs) protocol workspace.

```bash
cargo add hns-transaction
```

The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-transaction).

Licensed under either Apache-2.0 or MIT.
