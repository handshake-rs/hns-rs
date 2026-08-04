# hns-chat-protocol

Runtime-independent protocol values for owner-bound HNS Chat.

This crate parses the authenticated `hnschat` resource binding, proves its
x-only secp256k1 key against the current standard single-key Handshake owner
output without assuming a public-key parity, synthesizes the existing HNSA
root authority for `hns.chat`, and encodes bounded opaque NIP-59 gift-wrap and
encrypted-acknowledgement payloads for HIP-78 transport.

The public boundary includes the canonical wire version, payload and exact
encoded-size limits, validation for programmatically constructed values, and
the owner-binding proof types used by downstream nodes and wallets. The
versioned valid/invalid release vectors and SHA-256 sidecar under
`fixtures/chat-v1/` are included in the normalized crate source package along
with an external-consumer integration test.

It does not own wallets, private keys, Nostr signing, NIP-44 conversation keys,
storage, networking, or browser APIs. In particular, it never creates a second
long-term chat identity.

Status: source implemented for standard version-zero single-key owner outputs,
but unreleased and not qualified for a deployed mailbox or mainnet use. See
the repository release and owner-identity documents for the remaining gates.
