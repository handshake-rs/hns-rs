# hns-service-authority

Transport-independent authority objects for the Named Service Authority draft
in Handshake HIPs pull request #79.

The crate implements canonical `hsa1` TXT parsing, service authorizations,
endpoint delegations, signature verification, replacement selection, and
stable service identities. Discovery and transport remain the responsibility
of profiles such as direct HTTPS, QUIC, or HNSR.

An endpoint verifier must first validate its service authorization against the
current authenticated HNS name state and current block height. The endpoint
check uses wall-clock expiry and does not guess a timestamp for a future block.

The proposal is still a draft. Profile identifiers are not official Handshake
assignments.

Licensed under either Apache-2.0 or MIT.
