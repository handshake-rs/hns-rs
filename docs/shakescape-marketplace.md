# Shakescape marketplace protocols

Shakescape Registry V1 assigns the name market and cross-chain marketplace
protocol IDs `0x0001` and `0x0002`. The registry remains a private experimental assignment;
that describes governance of the packet numbers, not a fallback wire format.

## Name market (`0x0001`, protocol version 1)

The name market retains its bounded hello, inventory, listing request/response,
and signed cancellation messages. Listing verification remains local; inventory
is discovery metadata and `OfferInventory` alone may represent an empty board.

## Direct HNS/BTC market (`0x0002`, protocol version 3)

The cross-chain protocol uses this registry:

| Type | Message |
| ---: | --- |
| 1 | `DIRECT_OFFER_INVENTORY` |
| 2 | `GET_DIRECT_OFFER` |
| 3 | `DIRECT_OFFER` |
| 4 | `CANCEL_DIRECT_OFFER` |
| 5 | `TAKE_DIRECT_OFFER` |
| 6 | `SWAP_SESSION_PROPOSAL` |
| 7 | `SWAP_SESSION_HELLO` |
| 8–10 | funding, redeem, and refund status |

A direct offer is the maker's signed, exact HNS/BTC terms. It names a distinct
maker settlement key; a take chooses that exact offer and binds the taker's
settlement key and a nonzero session. A cancellation is signed by the maker's
long-term identity. There is no price observation, price round, reporter,
source, quorum, oracle, feed, matching engine, or partial-fill reservation in
the protocol.

Inventories contain at most 4096 sorted unique nonzero offer IDs. The empty
inventory is a valid response meaning no live offers are available. A request
for a particular offer remains nonempty. Typed payloads are capped at 512 KiB;
objects have tighter internal bounds and every decoder validates version,
registry availability, zero flags, canonical nested encoding, and complete
input.

The maker proposal and accepted hello bind the original offer, the take, both
settlement authorities, exact amounts, SHA-256 hashlock, lock commitments,
confirmation requirements, and refund deadlines. Shakescape status messages are
authenticated coordination hints only. Funding, confirmation, redemption,
preimage, refund, and reorganization state must come from independently
verified local chain evidence. New funding requires the fully accepted hello;
later signed status may still be verified for recovery.
