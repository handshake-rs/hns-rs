# Shakescape marketplace protocols

Shakescape Registry V1 assigns the name market and cross-chain marketplace
protocol IDs `0x0001` and `0x0002`. The registry remains a private experimental assignment;
that describes governance of the packet numbers, not a fallback wire format.

## Name market (`0x0001`, protocol version 1)

The name market retains its bounded hello, inventory, listing request/response,
and signed cancellation messages. Listing verification remains local; inventory
is discovery metadata and `OfferInventory` alone may represent an empty board.

## Direct HNS/BTC market (`0x0002`, protocol version 4)

The cross-chain protocol uses this registry:

| Type | Message |
| ---: | --- |
| 1 | `DIRECT_OFFER_INVENTORY` |
| 2 | `GET_DIRECT_OFFER` |
| 3 | `DIRECT_OFFER` |
| 4 | `CANCEL_DIRECT_OFFER` |
| 5 | `ACCEPT_DIRECT_OFFER` |
| 6 | `SWAP_SESSION_PROPOSAL` |
| 7 | `SWAP_SESSION_HELLO` |
| 8–10 | funding, redeem, and refund status |
| 11 | `SWAP_WATCH_READY` |

A direct offer is the offer setter's signed, exact HNS/BTC intent. It names a
distinct offer-scoped settlement key and nonzero session; that key belongs to
the setter's eventual taker role. A response accepts that exact offer and binds
the responder's maker settlement key. A cancellation is signed by the offer
setter's long-term identity. There is no price observation, price round,
reporter, source, quorum, oracle, feed, matching engine, or partial-fill
reservation in the protocol.

Inventories contain at most 4096 sorted unique nonzero offer IDs. The empty
inventory is a valid response meaning no live offers are available. A request
for a particular offer remains nonempty. Typed payloads are capped at 512 KiB;
objects have tighter internal bounds and every decoder validates version,
registry availability, zero flags, canonical nested encoding, and complete
input.

The responding maker's proposal reverses the public offer's asset sides: the
responder offers what the setter requested and funds that first; the original
offer setter countersigns as taker and funds the originally offered asset
second. The accepted hello binds the original offer, its acceptance, both
settlement authorities, exact amounts, SHA-256 hashlock, lock commitments,
confirmation requirements, and refund deadlines. Shakescape status and watch
messages are authenticated coordination only. Funding, confirmation,
redemption, preimage, refund, and reorganization state must come from
independently verified local chain evidence. New funding requires the fully
accepted hello; later signed status may still be verified for recovery.

Version 4 is the sole supported cross-chain role model. Its role tag prevents
an incompatible peer from silently applying the opposite key assignment or
funding order; any other tag or protocol version is rejected.
