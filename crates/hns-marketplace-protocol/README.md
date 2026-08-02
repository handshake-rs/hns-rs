# hns-marketplace-protocol

Canonical, bounded, runtime-independent wire objects for the Handshake name
market and bilateral market-price cross-chain swaps.

The crate contains no wallet, database, async runtime, network client, Bitcoin
runtime, Ethereum runtime, browser API, or platform ABI. Every decoder bounds
variable input and requires complete consumption. Money uses integer base units
and prices use reduced rational values; floating-point arithmetic is never used.

It is part of the [`hns-rs`](https://github.com/handshake-rs/hns-rs) workspace
and supports Rust 1.89 or later.

Licensed under either Apache-2.0 or MIT.
