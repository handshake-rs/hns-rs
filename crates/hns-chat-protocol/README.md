# hns-chat-protocol

Runtime-independent protocol values for owner-bound HNS Chat.

This crate parses the authenticated `hnschat` resource binding, proves its
x-only secp256k1 key against the current standard single-key Handshake owner
output without assuming a public-key parity, synthesizes the existing HNSA
root authority for `hns.chat`, and encodes bounded opaque NIP-59 gift-wrap and
encrypted-acknowledgement payloads for HIP-78 transport.

It does not own wallets, private keys, Nostr signing, NIP-44 conversation keys,
storage, networking, or browser APIs. In particular, it never creates a second
long-term chat identity.
