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

`AuthenticatedNameState` and `ResolvedManifest` are caller-constructible
inputs at that trust boundary; their Rust types are not chain proofs. Browser
pages, extension messages, mobile WebViews, and wire peers must never populate
them directly. Only a trusted full node, native proof verifier, or authority
broker may authenticate current HNS state and construct those inputs.

A successful authorization exposes an opaque authenticated current-snapshot
view for resource-profile consumers. Its resource, controller, complete
delegation list, manifest sequence/hash, validity interval, and exact
reorganization evidence all come from the same validated envelope; callers do
not pair a summary result with separately supplied raw manifest bytes.
`validate_current_manifest` exposes the same opaque provenance without
requiring a resource to exist, allowing a profile to treat absence from the
complete current snapshot as revocation while retaining the HRM rollback and
cache bounds. Its summary and snapshot fields are read-only accessors so they
cannot be paired with a forged expiry or observation.

These validators are deliberately pure and therefore **uncommitted**. A
production profile must durably combine the subject-wide rollback observation,
trusted-time high-water, and profile-specific replay/tombstone state before it
uses a result. HRM-backed HNSA consumers should use
`hns-service-authority::authority_state::NamedServiceAuthorityState`, which
owns validation and exact compare-and-swap and withholds operational results
until persistence is acknowledged. Retrieval failure paths must still persist
trusted time through that boundary.

The protocol remains a draft. No public resource profile, permanent wire
assignment, or production-changing adapter is enabled by this crate.

Licensed under either Apache-2.0 or MIT.
