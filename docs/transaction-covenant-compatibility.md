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

## Oracle provenance

Positive byte and hash vectors come from deterministic fixtures generated
against `handshake-org/hsd` revision
`698e252ebc7b5c1dd0a9587e342fdd153d020ae4` (reported HSD version `8.99.0`):

- `fixtures/hsd/transactions/codec-v1.json`
- `fixtures/hsd/covenants/codec-v1.json`
- `fixtures/hsd/covenants/linkage-v1.json`
- `fixtures/hsd/name-states/name-hash-v1.json`

The embedded tests assert the exact transaction bytes, txid, witness hash,
covenant bytes, SHA3 name hashes, and BLAKE2b blind-bid commitment. Mutation and
boundary tests cover malformed canonical encodings and unsafe allocations.
