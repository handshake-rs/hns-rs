# Transaction and covenant compatibility

`hns-transaction` and `hns-covenants` use Handshake's exact on-wire ordering:
transaction base fields precede all witnesses, addresses use a one-byte version
and one-byte program length, and covenants use a type byte followed by canonical
compact-size item encodings.

The implementation is allocation-bounded and rejects non-minimal compact sizes,
truncation, trailing bytes, oversized witnesses, oversized covenant items, and
invalid address programs. It computes transaction IDs from the base encoding and
witness hashes from `BLAKE2b-256(txid || BLAKE2b-256(witnesses))`.
The codec distinguishes HSD's 1,000,000-byte base-size ceiling from its
4,000,000-unit weight and raw protocol bounds, so a witness-heavy transaction
that is larger than one megabyte remains valid when its exact weight is within
consensus limits. Claimed stream lengths are checked against the remaining
weight-derived budget before copying.

Non-coinbase covenant validation preserves the consensus-visible input/output
index linkage used by HSD. It covers BID-to-REVEAL blind commitments, locked
value and address preservation, transfer destinations, revoked outputs, unknown
covenant isolation, and name/start-height continuity. Coinbase covenant issuance
is intentionally routed to a separate, context-aware verifier.

The canonical `Outpoint` value now lives in `hns-primitives` and remains
re-exported by `hns-transaction`. Transaction inputs use its fixed 36-byte
encoding; NameState ownership uses HSD's distinct 32-byte hash plus canonical
compact-size index encoding. Both surfaces share the exact all-zero-hash,
`u32::MAX` null sentinel.

`hns-covenants` also owns the runtime-independent HSD NameState value codec.
The external Urkel NameHash is not serialized twice, and decoding a non-null
state requires `hash_name(state.name)` to equal the supplied proof key. Raw
resource bytes remain consensus-opaque; the separate resource projection
recognizes all assigned version-zero records without silently accepting an
unknown suffix as parsed data.

## Oracle provenance

Positive transaction and covenant codec vectors generated against
`handshake-org/hsd` revision
`698e252ebc7b5c1dd0a9587e342fdd153d020ae4` (reported HSD version `8.99.0`) are
embedded directly in `crates/hns-transaction/src/lib.rs` and
`crates/hns-covenants/src/lib.rs`. The source tests assert the exact transaction
bytes, txid, witness hash, covenant bytes, SHA3 name hashes, and BLAKE2b
blind-bid commitment. Covenant linkage behavior is also covered by source
tests; there is no separate checked-in linkage fixture.

The checked-in differential document for NameState values, authenticated name
hashes, and resource bytes is `fixtures/hsd/name-state-resource-v1.txt`, with
its adjacent SHA-256 sidecar. Mutation and boundary tests cover malformed
canonical encodings and unsafe allocations.
