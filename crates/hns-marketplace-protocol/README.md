# hns-marketplace-protocol

Canonical, bounded, runtime-independent wire objects for the Handshake name
market and bilateral direct fixed-terms HNS/BTC swaps.

The crate contains no wallet, database, async runtime, network client, Bitcoin
runtime, Ethereum runtime, browser API, or platform ABI. Every decoder bounds
variable input and requires complete consumption. Money uses integer base units
and exchange terms use exact signed integer amounts; floating-
point arithmetic is never used.

Each direct offer delegates an independent offer-scoped settlement key from
the setter's long-term marketplace identity and signs a nonzero session
identifier alongside it. That key is precommitted for the setter's eventual
taker role. A responder's signed acceptance repeats the immutable offer and
session identifiers and binds the responder's maker settlement key. The
responder then signs a proposal as execution maker; the original offer setter
verifies and countersigns it as taker. Session hellos bind both settlement
authorities, the exact offer amounts with their sides reversed into the
maker's perspective, SHA-256 hashlock, descriptor commitments, and timeouts.
Native HNS sides can be constructed and verified directly against
`hns-swap::HnsHtlc`.
New-funding admission is time-gated separately from existing settlement status and
reorganization validation.

An empty `OfferInventory` is the canonical response when a name-market board
has no listings. Empty `GetOffers` requests and empty `Offers` object batches
remain invalid, so an empty response cannot be confused with an empty request
or a malformed object transfer.

It is part of the [`hns-rs`](https://github.com/handshake-rs/hns-rs) workspace
and supports Rust 1.89 or later.

Licensed under either Apache-2.0 or MIT.
