# Canonical marketplace protocol

`hns-marketplace-protocol` is the runtime-independent authority for Handshake
name-market messages and bilateral direct HNS/BTC market messages. It contains
no wallet database, async runtime, network client, browser API, or chain
synchronizer.

## Direct HNS/BTC offers

A direct offer is an offer setter's signed, indivisible intent to exchange one
exact native HNS amount for one exact native BTC amount. It has no price
reporter, source commitment, oracle, historical-rate, or third-party API
dependency. A responder either accepts that particular signed intent or does
not.

The offer setter's long-term identity signs the offer ID, a distinct
offer-scoped settlement key, a nonzero session ID, the network binding, pair,
offered and requested asset IDs, exact amounts, sequence, creation time, and
expiry. That settlement key is precommitted for the setter's eventual role as
the atomic-swap taker. A cancellation is signed by the same long-term
identity. An acceptance binds the immutable offer and session IDs to the
responder's distinct maker settlement key. All identifiers and signatures are
domain-separated BLAKE2b-256/secp256k1 values and are recomputed during
encoding and decoding; mutating signed or hashed fields fails closed.

Wallets may present live active offers grouped by their exact reduced
BTC-per-HNS ratio. That is a discovery display only: a grouped level cannot
change the signed amounts, and funding always verifies one original offer and
one corresponding acceptance. There is no protocol price calculation, rate history,
average, feed, reporter, source, quorum, or remote policy to trust.

## HTLC sessions

The offer responder initializes the executable swap and signs a complete
`SwapSessionProposal` as maker. The original offer setter verifies it against
the locally retained offer and acceptance, then signs the identical terms as
taker to produce a `SwapSessionHello`. The proposal expresses asset sides from
the maker's perspective, so its offered side is the public offer's requested
side and its received side is the public offer's offered side. The accepted
hello binds both identities and settlement authorities, exact amounts,
SHA-256 hashlock, each chain's lock-descriptor commitment, Unix-time refund
deadline, and minimum confirmation depth. Funding validation requires this
accepted hello; an offer, acceptance, or maker-only proposal is never funding
authority.

The responding maker funds first: it locks the asset requested by the public
offer, using the later refund deadline. The offer setter, now the execution
taker, funds the originally offered asset second with the shorter deadline.
Redemption authority is the opposite party for each chain and refund authority
is its funder. Wallet policy must leave a safety margin for finality and fees.
`verify_new_funding_at` closes with the signed funding window, while
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

Cross-chain Shakescape protocol version 4 carries direct-offer inventory,
offer request/response, cancellation, acceptance, session proposal/hello,
receiver watch-readiness, and funding/redeem/refund status messages. Version 4
carries the sole supported role-model tag, preventing an incompatible peer
from silently assigning the settlement keys or first-funding duty to the
opposite participants. Other role tags and protocol versions are rejected.
An empty direct-offer inventory is a valid response meaning that no live offers
are currently available. Requests for one or more particular offers remain
nonempty, so an empty response cannot be confused with a malformed request.
