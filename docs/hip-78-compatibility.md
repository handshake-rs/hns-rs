# HIP #78 compatibility

`hns-hnsr-protocol` is the runtime-independent implementation of the draft
Handshake rendezvous and authenticated relay protocol. Its source snapshots
are:

- HIPs pull request #78 through commit
  `53b962e901ffa796f4ccf66a5d53956d7421c58c`; and
- hsd pull request #960 through commit
  `2fc40f1c61ff16a2f39d9514cd950d1560430ced`.

The assignments are experimental: rendezvous service `0x04000000`, relay
service `0x08000000`, and packet type `0xf3`. Public use requires the Denuo
registry handshake and collision isolation from `hns-p2p-experimental`.

## Shared protocol surface

The crate provides:

- the exact 12-byte HNSR v1 envelope and all 21 opcodes;
- bounded bodies for discovery, route storage, reservation, renewal,
  withdrawal, circuit establishment, opaque data, flow control, close, and
  error exchanges;
- network-, relay-, context-, reservation-, and domain-bound reservation and
  renewal signatures;
- canonical strict-low-S secp256k1 relay tickets, endpoint confirmations,
  unnamed endpoint delegations, and route records;
- exact route-key and rendezvous-node-ID derivation;
- authenticated, age-limited public rendezvous contacts and XOR ordering;
- route expiry, increasing-sequence replacement, deterministic sampling, and
  bounded total/per-key/per-source in-memory storage, with capacity preflight
  and global/per-source verification-rate limits before expensive signature
  checks;
- bounded synchronous reservation, renewal, confirmation, withdrawal,
  route-publication, and route-lookup services that accept canonical packets
  from an embedding transport;
- runtime-neutral requester and opaque circuit-relay state machines with exact
  authenticated-peer routing, ticket/reservation admission, acceptance
  deadlines, directional credit, retained write acknowledgements, per-circuit
  queues, signed per-circuit and per-reservation byte ceilings, and explicit
  disconnect, reservation, expiry, and policy revocation;
- versioned BLAKE2b-256-checksummed requester and relay snapshots that preserve
  exact settings and counters while revoking, rather than resurrecting, every
  snapshotted live circuit under a mandatory fresh process session;
- version-2 HNSA named routes with stable service-derived keys, profile-aware
  relay tickets, full-client verification, bounded rendezvous admission, and
  exclusion from unnamed route sampling; and
- the hsd Phase 2 regtest evidence artifact at
  `fixtures/hsd/hnsr-regtest-phase1.json`.

The parser bounds lengths before allocation and rejects unsupported versions,
reserved flags/opcodes, invalid or high-S signatures, wrong networks, expired
records, route-key substitution, nonzero trailing bytes, zero identifiers,
invalid windows, and non-public contacts outside an explicit private test
profile.

## Trust and scope

`HNS_NODE_V1` carries a complete end-to-end Brontide Handshake peer session.
The relay handles opaque bytes only; it is never consensus, DNS, DANE, or
application authority and cannot select a caller-provided local target.

The compatibility snapshot implements the unnamed endpoint-key authority
chain. Named service identity is supplied only by the HNSA adapter and current
authenticated HNS state from the consuming node or browser; it is never
inferred from a rendezvous response.

This crate deliberately contains no socket runtime, Tokio, persistent
database, wallet, browser, mobile, or MeshMine dependency. Consumers bind each
opaque `HnsrPeerId` to one exact authenticated live connection, acknowledge
every queued relay write, call the explicit disconnect/expiry/revocation
entrypoints, persist snapshots atomically, and provide a fresh nonzero process
session on restore. Consumers also remain responsible for iterative lookup
scheduling, three-store publication quorum, replication, inner Brontide, and
priority below direct blockchain traffic. Snapshot restore deliberately drops
all live connection authority; it is durable recovery, not circuit resumption.

Requester/client and opaque relay participation default on and have independent
persistent opt-outs. Endpoint/output-node and rendezvous-directory
participation default off and require explicit opt-in. Enabling or disabling
one HNSR role never grants another role; in particular, neither default role
grants endpoint or rendezvous authority, and disabled roles must not advertise.

## Verification

Run:

```sh
cargo test -p hns-hnsr-protocol
cargo clippy -p hns-hnsr-protocol --all-targets -- -D warnings
```

Tests cover the exact envelope and hash derivations, network/relay/context
signature binding, renewal predecessor binding, ticket and route authorization
chains, wrong network, expiry, high-S rejection, public-contact policy, XOR
ordering, sequence replacement, expiry, source quotas, deterministic sampling,
verification-rate limits, capacity-before-signature admission, reservation
replay and cross-source rejection, complete live
reservation-to-route lookup, flow-control bounds, and trailing-data rejection.
Focused circuit-runtime source tests additionally cover full open/accept/data/
window routing, authenticated peer binding, retained queue accounting, failed
write and generation revocation, exact snapshot round trips, corruption
rejection, persistent opt-outs, and fail-closed restart recovery.
