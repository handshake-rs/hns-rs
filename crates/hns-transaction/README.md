# hns-transaction

Canonical Handshake transaction and witness encoding.

This crate provides transaction, witness, address, output, coin, and
non-coinbase covenant-link validation primitives. Its public `Outpoint` remains
available here as a re-export of the shared primitive also used by NameState
ownership. Name TRANSFER helpers preserve the locked owner value and address
while committing the independently selected recipient. FINALIZE helpers bind
an exact confirmed TRANSFER coin to authenticated current `NameState`, preserve
the locked value, use the committed recipient, and carry the caller-supplied
renewal block. Both transitions expose bounded unsigned transaction builders
and strict index-zero verifiers without moving construction into a wallet.
Caller-supplied suffixes may contain funding or independent batched covenant
transitions; the index-zero helpers deliberately leave those suffix transitions
to the complete transaction's covenant-link and wallet checks.
Current-tip ownership, transfer-lock maturity, renewal-block eligibility,
funding-input signatures, balance, and fee policy remain chain or wallet
checks. It is part of the
[`hns-rs`](https://github.com/handshake-rs/hns-rs) protocol workspace.

```bash
cargo add hns-transaction
```

The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-transaction).

Licensed under either Apache-2.0 or MIT.
