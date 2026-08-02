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

The canonical marketplace and native-HNS settlement boundary is versioned by
`fixtures/protocol-v1/`. Its source-independent generator implements the wire
encoding and RFC6979 signatures without calling Rust code, and cross-checks its
signer against a pre-existing pinned Rust signature before emitting artifacts.
