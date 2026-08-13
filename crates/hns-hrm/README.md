# hns-hrm

Canonical objects and bounded validation for the draft Handshake Resource
Manifest protocol.

The crate treats HNS TXT commitments, retrieval locations, and fetched bytes as
untrusted input. It implements deterministic CBOR, current commitment
selection, network-bound controller signatures, complete manifest snapshots,
and profile-neutral validation interfaces. It does not change Handshake
consensus or grant authority to a retrieval server.

Retrieval adapters are a security boundary. They must enforce the byte,
object, redirect, and elapsed-time budget supplied by this crate before
allocating a response, and must apply local URI-scheme and network-access
policy (including loopback/private-network restrictions where appropriate).
Retrieval URIs and transport metadata never establish authority.

The protocol remains a draft. No public resource profile, permanent wire
assignment, or production-changing adapter is enabled by this crate.

Licensed under either Apache-2.0 or MIT.
