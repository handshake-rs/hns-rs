# hns-hnsr-protocol

Runtime-independent wire types for draft HIP #78 HNSR.

This crate provides bounded rendezvous records, routing state, authenticated
relay tickets, message envelopes, and the versioned HNSA named-service route
adapter. Unnamed `HNS_NODE_V1` records retain their existing encoding; named
records carry and validate the transport-independent `hsa1` authority chain.
Its synchronous service types execute reservation, renewal, confirmation,
withdrawal, route publication, and route lookup against bounded in-memory
state so an embedding node can own transport, persistence, clocks, and peer
policy without duplicating protocol validation.
The owner-bound `hns.chat` adapter derives that same authority chain from a
current `hnschat` resource and canonical single-key owner output; it does not
weaken generic `hsa1` verification.

**The associated Denuo wire assignments are experimental and are not official
Handshake protocol assignments.**

The in-memory service types are not by themselves a durable relay deployment.
Restart recovery and network behavior must be supplied and qualified by the
embedding product.

```bash
cargo add hns-hnsr-protocol
```

The crate is part of the
[`hns-rs`](https://github.com/handshake-rs/hns-rs) workspace and supports Rust
1.89 or later. API documentation is available on
[docs.rs](https://docs.rs/hns-hnsr-protocol).

Licensed under either Apache-2.0 or MIT.
