# hns-hnsr-protocol

Runtime-independent wire types for draft HIP #78 HNSR.

This crate provides bounded rendezvous records, routing state, authenticated
relay tickets, message envelopes, and the versioned HNSA named-service route
adapter. Unnamed `HNS_NODE_V1` records retain their existing encoding; named
records carry and validate the transport-independent `hsa1` authority chain.

**The associated Denuo wire assignments are experimental and are not official
Handshake protocol assignments.**

```bash
cargo add hns-hnsr-protocol
```

The crate is part of the
[`hns-rs`](https://github.com/handshake-rs/hns-rs) workspace and supports Rust
1.89 or later. API documentation is available on
[docs.rs](https://docs.rs/hns-hnsr-protocol).

Licensed under either Apache-2.0 or MIT.
