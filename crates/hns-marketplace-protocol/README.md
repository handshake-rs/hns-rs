# hns-marketplace-protocol

Canonical, bounded, runtime-independent wire objects for the Handshake name
market and bilateral market-price cross-chain swaps.

The crate contains no wallet, database, async runtime, network client, Bitcoin
runtime, Ethereum runtime, browser API, or platform ABI. Every decoder bounds
variable input and requires complete consumption. Money uses integer base units
and prices use reduced rational values; floating-point arithmetic is never used.

Fill grants delegate an independent per-session maker settlement key from the
long-term marketplace identity. Session hellos bind both settlement
authorities, exact amounts, SHA-256 hashlock, descriptor commitments, and
timeouts; native HNS sides can be constructed and verified directly against
`hns-swap::HnsHtlc`. New-funding admission is time-gated separately from
historical status and reorganization validation.

An empty `OfferInventory` is the canonical response when a name-market board
has no listings. Empty `GetOffers` requests and empty `Offers` object batches
remain invalid, so an empty response cannot be confused with an empty request
or a malformed object transfer.

It is part of the [`hns-rs`](https://github.com/handshake-rs/hns-rs) workspace
and supports Rust 1.89 or later.

Licensed under either Apache-2.0 or MIT.
