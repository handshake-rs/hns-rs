# Denuo marketplace protocols

Denuo registry V2 is an additive registry. It retains every V1 assignment and
introduces cross-chain marketplace protocol ID `0x0002`; V1 remains byte-for-byte
reproducible with fingerprint
`95774db08c569b36fa7b7e4a071930f563b7251fc30934ba986732379a6e542d`.
These remain experimental assignments, not official Handshake wire numbers.

## Name market (`0x0001`, protocol version 1)

`NameMarketMessage` provides typed, bounded payloads for all existing atomic
name-market messages:

| Type | Payload |
| ---: | --- |
| 1 | network-bound market hello |
| 2 | empty inventory request |
| 3 | sorted unique listing-content-hash inventory |
| 4 | sorted unique batch request |
| 5 | sorted unique batch of signed fixed-price listings |
| 6 | one listing-content-hash request |
| 7 | one signed fixed-price listing |
| 8 | one signed listing cancellation/tombstone |

The typed decoder accepts the name protocol under V1 or V2. Listing content is
still verified locally; inventory is only discovery metadata. A hello must
carry nonzero Handshake magic and genesis values as well as a bounded nonzero
receive limit.

## Cross-chain market (`0x0002`, protocol version 1)

The V2-only protocol assigns:

| Type | Message |
| ---: | --- |
| 1–4 | `MARKET_INTENT_INV`, `GET_MARKET_INTENT`, `MARKET_INTENT`, `CANCEL_MARKET_INTENT` |
| 5–8 | `PRICE_OBSERVATION_INV`, `GET_PRICE_OBSERVATION`, `PRICE_OBSERVATION`, `PRICE_ROUND` |
| 9–11 | `MATCH_REQUEST`, `FILL_GRANT`, `MATCH_REJECT` |
| 12–15 | `SWAP_SESSION_HELLO`, `SWAP_FUNDING_STATUS`, `SWAP_REDEEM_STATUS`, `SWAP_REFUND_STATUS` |

Inventories contain at most 4096 nonzero, sorted, unique content hashes. The
typed Denuo payload maximum is 512 KiB and remains below the outer extension
packet bound. Full objects have their own tighter bounds. Protocol version,
registry availability, zero flags, message type, canonical nested payload, and
complete input are checked on every decode.

Denuo status messages are authenticated coordination hints. Wallets must derive
funding, confirmation, redemption, preimage, refund, and reorganization state
from locally verified chain evidence rather than trusting a peer status.
Funding statuses repeat the frozen chain-specific lock commitment and exact
native amount so a hint cannot be confused with another session's funding.
Session hellos contain maker and taker settlement authorities and two
domain-separated signatures over identical terms. The maker/intent authority
proposes; the grant-designated taker accepts. Funding is rejected until both
signatures verify. Funding and refund status on a chain is authorized by that
chain's funder (maker for the offered chain, taker for the received chain);
redeem status is authorized by the opposite party. Statuses signed by any third
party are rejected, but remain hints even when authorized.
The chain module still verifies the actual transaction, inclusion, finality,
script or contract state, and reorganization status.
Version 1 swap-session hashlocks are SHA-256 commitments to exact 32-byte
preimages on every supported settlement chain.
