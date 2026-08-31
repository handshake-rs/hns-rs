# Canonical marketplace protocol

`hns-marketplace-protocol` is the runtime-independent authority for Handshake
name-market messages and bilateral direct HNS/BTC market messages. It contains
no wallet database, async runtime, network client, browser API, or chain
synchronizer.

## Direct HNS/BTC offers

A direct offer is a maker-signed, indivisible promise to exchange one exact
native HNS amount for one exact native BTC amount. It has no price reporter,
source commitment, oracle, historical-rate, or third-party API dependency.
The maker chooses the terms; a taker either accepts that particular signed
offer or does not.

The maker's long-term identity signs an offer ID, a distinct per-offer maker
settlement key, the network binding, pair, offered and received asset IDs,
exact amounts, sequence, creation time, and expiry. A cancellation is signed
by that same long-term identity. A take binds that immutable offer ID to a
nonzero swap-session ID and a distinct taker settlement key. All identifiers
and signatures are domain-separated BLAKE2b-256/secp256k1 values and are
recomputed during encoding and decoding; mutating signed or hashed fields
fails closed.

Wallets may present live active offers grouped by their exact reduced
BTC-per-HNS ratio. That is a discovery display only: a grouped level cannot
change the signed amounts, and funding always verifies one original offer and
one corresponding take. There is no protocol price calculation, rate history,
average, feed, reporter, source, quorum, or remote policy to trust.

## HTLC sessions

A maker whose offer is taken signs a complete `SwapSessionProposal`. The
identified taker verifies it against the locally retained direct offer and
their take, then signs the identical terms to produce a `SwapSessionHello`.
The accepted hello binds both settlement authorities, exact amounts, SHA-256
hashlock, each chain's lock-descriptor commitment, Unix-time refund deadline,
and minimum confirmation depth. Funding validation requires this accepted
hello; a proposal alone is never funding authority.

The maker funds the offered-asset chain first and that lock has the later
deadline. The taker then funds the received-asset chain with the shorter
deadline. Redemption authority is the opposite party for each chain and refund
authority is its funder. Wallet policy must leave a safety margin for finality
and fees. `verify_new_funding_at` closes with the signed funding window, while
authenticated reorg, redeem, refund, and recovery evidence may still be
processed afterward. Third-party status signatures are rejected.

Native HNS uses `build_hns_htlc`, `build_and_bind_hns_htlc`, and
`verify_hns_htlc` to join a hello side directly to the exact `HnsHtlc`
network, amount, hashlock, keys, descriptor hash, and refund locktime. HSD
encodes time in 512-second units; conversion rounds upward so an effective HNS
refund time can never precede the signed Unix-time promise.

## Bounds and transport

Primitive encodings are at most 256 bytes, signed market/session objects at
most 8 KiB, and typed Shakescape name-market and cross-chain payloads at most
512 KiB. All decoders require complete input and reject noncanonical compact
lengths, signatures, presence/state values, and invalid public keys.

Cross-chain Shakescape protocol version 2 carries direct-offer inventory, offer
request/response, cancellation, take, accepted session proposal/hello, and
funding/redeem/refund status messages. An empty direct-offer inventory is a
valid response meaning that no live offers are currently available. Requests
for one or more particular offers remain nonempty, so an empty response cannot
be confused with a malformed request.
