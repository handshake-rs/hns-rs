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
Its runtime-neutral requester and opaque-relay state machines add exact
ticket-to-connection admission, bounded directional flow control, retained
write acknowledgements, cumulative byte ceilings, deadlines, disconnect and
policy revocation, and checksummed fail-closed restart snapshots. Adapters
still own authenticated outer connections, clocks, scheduling, and atomic
snapshot storage; circuit plaintext never enters the relay runtime.
Snapshots retain a trusted-time high-water mark and require a caller-held
minimum generation on restore, so clock rollback and replay of settings from
before a later opt-out/configuration generation fail closed. Relay actions,
including one-credit WINDOW traffic, are bounded globally, per circuit, and
per destination peer until acknowledged.
The owner-bound `hns.chat` adapter derives that same authority chain from a
current `hnschat` resource and canonical single-key owner output; it does not
weaken generic `hsa1` verification.

**The associated Denuo wire assignments are experimental and are not official
Handshake protocol assignments.**

The service types and snapshots are not by themselves a deployed relay.
Network behavior, atomic persistence, fresh process-session IDs on restore,
and product qualification remain the embedding product's responsibility.

```bash
cargo add hns-hnsr-protocol
```

The crate is part of the
[`hns-rs`](https://github.com/handshake-rs/hns-rs) workspace and supports Rust
1.89 or later. API documentation is available on
[docs.rs](https://docs.rs/hns-hnsr-protocol).

Licensed under either Apache-2.0 or MIT.
