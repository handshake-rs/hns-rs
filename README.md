# hns-rs

Canonical Rust protocol primitives for the Handshake ecosystem.

This workspace is intentionally independent of async runtimes, databases, wallets,
browser shells, and mining applications. Experimental peer-to-peer assignments are
identified as **Denuo Experimental V1 — not an official Handshake protocol
assignment**.

The initial implemented layer contains:

- semantic Handshake value types;
- allocation-bounded binary encoding and decoding;
- the canonical Denuo Experimental Handshake P2P Registry v1;
- semantic wire-assignment profiles;
- the versioned Denuo extension envelope and registry negotiation messages.

See `docs/experimental-p2p-registry.md` for assignment status and governance.

