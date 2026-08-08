# HIP pull request #79 compatibility

`hns-service-authority` implements the transport-independent objects in the
Named Service Authority proposal at `handshake-org/HIPs` pull request #79,
commit `a5c2e83`.

The implementation includes exact `hsa1` TXT parsing, bounded canonical
service authorization and endpoint delegation codecs, strict DER and low-S
secp256k1 verification, context and lifetime validation, stable service
identity, conflict-safe replacement selection, candidate-count limits, fixed
positive vectors, and aggregate parser-conformance coverage.

The service-name grammar matches the HIP exactly: 1 through 63 lowercase ASCII
letters, digits, or hyphens, with no leading/trailing hyphen and no periods.
Dotted profile labels are a separate layer. Selection counts candidates before
signature verification, ignores invalid or unrelated authorizations, and
requires profiles to scope endpoint-sequence comparison with their logical
endpoint predicate.

`EndpointDelegationV1::verify` requires a service authorization that the caller
has validated at the current Handshake height. Callers must repeat that
authorization check as the chain advances; no conversion between block height
and wall-clock time is invented by this crate.

The HNSR crate preserves the unnamed-node scope of HIP PR #78 and also
implements the local companion draft `HIP-xxxx-HNSA-HNSR.md`. Named route
version 2 embeds the exact HNSA authorization and endpoint delegation, derives
a stable route key from `ServiceIdentity`, binds profile-aware relay tickets,
and verifies the complete chain against current authenticated HNS state supplied
by the caller. The HNSR-specific unnamed endpoint delegation is not treated as
HNSA.

The proposal is a draft. It assigns no permanent profile identifiers. HNSR,
HTTPS, QUIC, and application profiles must define their endpoint records,
discovery, transport, browser-origin policy, and limits independently.
