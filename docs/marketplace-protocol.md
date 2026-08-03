# Canonical marketplace protocol

`hns-marketplace-protocol` is the runtime-independent authority for bilateral
HNS/BTC and HNS/ETH market messages. It contains no wallet database, async
runtime, network client, browser API, or chain synchronizer.

## Identity and amounts

Chain and asset identifiers are unsigned 16-bit semantic values. Version 1
assigns Handshake `1`, Bitcoin `2`, and Ethereum `3`; native HNS, BTC, and ETH
use asset sub-ID `0`. A supported pair contains exactly one Handshake asset and
one counterchain asset. `NetworkBinding` commits to Handshake magic and genesis
as well as counterchain ID, network ID, and genesis.

Amounts are unsigned 128-bit native base units. Prices are positive reduced
`u128/u128` rationals denominated as quote-asset units per base-asset unit.
Comparison uses an overflow-free continued-fraction algorithm, while conversion
exposes explicit up/down rounding and fails on overflow. No wire or verifier
path uses floating point. A fill grant uses one canonical conversion rule in
both directions: the amount received is rounded down. Offering base computes
`floor(offered * numerator / denominator)`; offering quote computes
`floor(offered * denominator / numerator)`.

## Signed objects

Price observations, intents, intent cancellations, match requests/rejections,
fill grants, and swap session/status messages use domain-separated BLAKE2b-256
digests with compact low-S secp256k1 signatures. Their signed fields include
network/genesis binding, pair, signer, a nonzero monotonic sequence, creation
time, and expiry where applicable. Object identifiers and reservation hashes
are recomputed during encode and decode; mutating a signed or hashed field
therefore fails closed.

An intent states only the offered asset, maximum quantity, minimum fill, partial
fill policy, and expiry. It does not contain a user-selected rate. A fill grant
binds the exact intent/sequence, session, independent maker settlement key,
ephemeral counterparty settlement key, both native amounts, frozen price-round
hash, expiry, and reservation sequence. The long-term maker identity signs the
grant and thereby delegates only this session to the maker settlement key. The
two settlement keys must be valid and distinct from each other and from the
maker's long-term identity. Match requests likewise require the taker's
ephemeral settlement key to differ from its request-signing identity. A grant
authorizes a reservation only; it does not move funds.

A swap-session hello freezes the verified grant and round hashes, both native
amounts, SHA-256 hashlock, each chain's lock-descriptor commitment, Unix-time
refund deadline, and minimum confirmation depth. The delegated maker
settlement authority signs the complete proposal, then the grant's designated
taker settlement authority signs the same bytes. The hello continues to carry
the long-term maker identity in its header and verification requires it to
match the grant signer. Funding validation requires both settlement signatures,
and a `Confirmed` funding status must meet the chain-specific minimum
confirmation count frozen in those signed terms. The maker funds the
offered-asset chain and the taker funds the received-asset chain; redemption
authority is the opposite party for each chain, while refund authority is its
funder. Third-party status signatures are rejected.

The intent publisher always funds the offered-asset chain first, and that lock
has the later deadline; this gives the counterparty time to use the revealed
preimage after the shorter second lock is redeemed. Verification requires the
current time and the hello expiry to precede the shorter deadline. Wallet
policy must require a margin large enough for both chains' finality and fee
conditions; version 1 intentionally does not invent that deployment-specific
minimum. Chain modules define and verify their descriptor preimages; the
generic protocol commits to them without duplicating Bitcoin or Ethereum wire
types. Native HNS is the exception because `build_hns_htlc`,
`build_and_bind_hns_htlc`, and `verify_hns_htlc` join a hello side directly to
the exact `HnsHtlc` network, amount, SHA-256 hashlock, keys, descriptor hash,
and refund locktime. HSD represents time in 512-second units, so this safety
conversion rounds upward: the effective refund time can be later than the
promised Unix deadline but can never be earlier.

`verify_new_funding_at` is the action gate for admitting a new broadcast and
closes with the signed funding window. Session status validation authenticates
the immutable agreement without reopening funding, allowing current signed
`Reorged`, refund, and recovery evidence to be processed after that deadline.
Each status object must still have a currently valid header and correct session
authority.

## Price rounds

Every observation commits to its rational price, source, reporter, observation
and validity times, both chain anchors, and replay sequence. A round carries the
complete signed observations in content-hash order and explicit sorted
reporter/source sets.

Verification requires a caller-owned `PriceRoundVerifier`: an exact expected
policy plus bounded, sorted admission sets for reporter public keys and source
IDs. Those trust inputs are never learned from an untrusted round. Verification
rejects policy downgrades, unadmitted identities, stale observations,
mismatched networks or anchors, duplicate reporters, duplicate sources, weak
quorum, and noncanonical sets. The supplied previous round is checked against
the same trust inputs, preventing an admitted current round from linking to an
unadmitted history.

Prices are sorted exactly, the configured number of values is trimmed from
both ends, and the lower median of the retained set is canonical. A round is
usable only after its interval closes, cannot outlive any included observation,
and cannot remain valid beyond the policy's maximum observation age. The round
hash commits to the embedded policy and all fields. A non-genesis round must
link the previous round hash and stay within its checked rational basis-point
movement limit; otherwise the circuit breaker stops matching. No valid quorum
means no usable new price round.

## Bounds

Primitive encodings are at most 256 bytes, signed market/session objects at most
8 KiB, observations at most 4 KiB, and rounds at most 256 KiB with at most 64
observations. Typed name-market and cross-chain Denuo payloads are both capped
at 512 KiB; the registry's outer atomic-market assignment can advertise a wider
transport limit without weakening this parser boundary. Inventory and Denuo
payload bounds are documented in
[`denuo-marketplace.md`](denuo-marketplace.md). All decoders require complete
input and reject noncanonical compact lengths, rationals, sets, signatures, and
presence/state values.

The name-market `OfferInventory` response uses a canonical zero compact count
when the board is empty. Empty `GetOffers` requests and empty `Offers` batches
remain invalid; cross-chain inventories also remain nonempty.
