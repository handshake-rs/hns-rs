# HNSA compatibility and HRM-backed migration

The root compatibility types in `hns-service-authority` implement the earlier
Named Service Authority experiment from `handshake-org/HIPs` pull request #79
through commits `c0487e5` and `a5c2e83`. That model uses `hsa1`, fixed
`ServiceAuthorizationV1`, its original endpoint delegation, and HNSR named
route version 2. It is retained only behind explicitly selected legacy APIs.

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

Legacy `EndpointDelegationV1::verify` requires a service authorization that the
caller has validated at the current Handshake height. Callers must repeat that
authorization check as the chain advances; no conversion between block height
and wall-clock time is invented by this crate.

The current `hrm` and `authority_state` modules instead implement the local
`HIP-xxxx-HRM.md` and `HIP-xxxx-HNSA.md` drafts. They validate the
`hns.named-service/v1` HRM resource/delegation and bounded endpoint authority,
then durably combine one subject-wide HRM rollback root with per-service
generation/withdrawal observations and trusted time. Production results are
released only through exact committed create/CAS state; the pure validators are
uncommitted primitives.

The HNSR crate preserves the unnamed-node scope of HIP PR #78 and implements
the local `HIP-xxxx-HNSA-HNSR.md` as named route version 3/type 2. V3 binds the
current HRM/HNSA chain, independently persists endpoint and route product
counters, and keeps finite rendezvous storage separate from permanent requester
state. It never reinterprets or falls back to version 2. The HNSR-specific
unnamed endpoint delegation is not treated as HNSA.

All of these proposals are drafts. They assign no permanent application
profile identifiers. HNSR, HTTPS, QUIC, and application profiles must define
their endpoint records, discovery, transport, browser-origin policy, limits,
and qualification independently. No HRM-backed named route is implicitly
enabled for mainnet by these codecs.
