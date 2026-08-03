# Protocol authority

Consensus-visible behavior follows current compatible HSD behavior, its tests,
and reproducible fixtures before prose or architectural inference.

Published and workspace-defined protocol behavior follows, in order, the exact
proposal and implementation commits recorded by the integration audit, their
deterministic fixtures, the independent Rust implementation, and the applicable
Denuo Experimental Registry V1 or V2 authority. "Experimental" identifies the
private Denuo assignment namespace, not the implementation quality or support
level. Disagreements require a minimal positive fixture, mutation-derived
negative fixtures, and recorded results from both implementations.

Current HSD differential fixtures record
`handshake-org/hsd@698e252ebc7b5c1dd0a9587e342fdd153d020ae4`
and are identified per subsystem in the compatibility documents. Experimental
proposal and implementation revisions are recorded in the HIP-specific
compatibility documents.

`fixtures/hsd/fee-policy-v1.txt` binds HSD's sigop-adjusted virtual-size and
minimum-fee behavior to exact `tx.js`, `policy.js`, and `consensus.js` source
hashes. The fixture retains HSD's floor division and its distinct rule that a
nonzero size/rate pair with a zero quotient pays the full rate. Standardness
bounds remain separate from arithmetic, matching the pinned implementation.

`fixtures/hsd/name-state-resource-v1.txt` binds HSD's exact NameState value
ordering, optional-field bitmap, compact integers, null-owner convention, and
version-zero resource record/compression bytes. Its generator verifies the
pinned `namestate.js`, `resource.js`, and BNS name-encoding source hashes before
executing that existing oracle. The authenticated NameHash remains the Urkel
key rather than a duplicated value field; the Rust decoder requires every
non-null decoded name to hash to the caller-supplied key.

Consensus permits the NameState resource field to contain any byte string up
to 512 bytes. The state codec therefore preserves those bytes without
interpreting them. Typed resource decoding is a separate operation that fully
consumes known version-zero records and fails closed on malformed compression,
unknown record tags, truncation, or oversize input.

The canonical marketplace and native-HNS settlement boundary is versioned by
`fixtures/protocol-v1/`. Its source-independent generator implements the wire
encoding and RFC6979 signatures without calling Rust code, and cross-checks its
signer against the pre-existing fixed-price listing and cancellation
signatures before emitting artifacts. The listing/cancellation envelopes are
hns-rs-defined values and therefore have source-independent rather than
third-party differential vectors. Static FINALIZE vectors cover exact HSD wire
and witness-program behavior but do not replace live-chain maturity, renewal
ancestry, relay-policy, or reorg qualification.
