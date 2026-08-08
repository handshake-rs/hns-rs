# hns-service-authority

Transport-independent authority objects for the Named Service Authority draft
in Handshake HIPs pull request #79.

The crate implements canonical `hsa1` TXT parsing, service authorizations,
endpoint delegations, signature verification, replacement selection, and
stable service identities. Discovery and transport remain the responsibility
of profiles such as direct HTTPS, QUIC, or HNSR.
HIP-compliant HNSA service names contain only lowercase ASCII letters, digits,
and hyphens; periods are rejected. Dotted labels such as `hns.chat` belong to
profile registries or other higher layers, not the HNSA service-name field.

Replacement selection validates the bounded candidate set before comparing
sequences. Service authorizations are selected for one exact service identity,
and endpoint delegations require a profile-supplied logical-endpoint predicate.

An endpoint verifier must first validate its service authorization against the
current authenticated HNS name state and current block height. The endpoint
check uses wall-clock expiry and does not guess a timestamp for a future block.

The proposal is still a draft. Profile identifiers are not official Handshake
assignments.

Licensed under either Apache-2.0 or MIT.
