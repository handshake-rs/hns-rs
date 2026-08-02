# hns-swap

HIP-0001 and Shakedex-compatible atomic name-swap primitives.

This crate implements fixed-price swaps and bounded reverse-Dutch auctions,
including proof encoding, validation, signing, and verification. It also
provides:

- canonical, bounded `FixedPriceListing` and `ListingCancellation` envelopes
  with network/genesis binding, expiration, monotonic sequences, content
  hashes, and domain-separated low-S secp256k1 signatures;
- a canonical `HnsHtlc` descriptor and nonzero SHA-256
  hashlock/absolute-timelock HNS witness script, exact funding verification,
  strict `SIGHASH_ALL`, redeem/refund witness builders, consensus-backed spend
  verification, checked preimage extraction, and redacted secret diagnostics.

Marketplace callers must still persist per-seller/name sequence state to reject
replays, verify the embedded `SwapProof` against the current FINALIZE coin, and
derive confirmation/reorg evidence from a synchronized Handshake chain. The
listing and cancellation activity helpers authenticate their signatures before
reporting an object active. The HTLC helpers are protocol primitives; timeout
selection, confirmation policy, fee policy, and crash recovery remain wallet
responsibilities.

It is part of the [`hns-rs`](https://github.com/handshake-rs/hns-rs) protocol
workspace.

```bash
cargo add hns-swap
```

The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-swap).

Licensed under either Apache-2.0 or MIT.
