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
  bounded total/per-key/per-source in-memory storage; and
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

The hsd compatibility snapshot implements the unnamed endpoint-key authority
chain. Named `HNS_WEB_V1` authorization requires authenticated HNS resource
state and belongs in the consuming node/browser layers; it must not be inferred
from an unauthenticated route record.

This crate deliberately contains no socket runtime, Tokio, persistent
database, wallet, browser, mobile, or MeshMine dependency. Consumers remain
responsible for iterative lookup scheduling, three-store publication quorum,
replication, reservations bound to live peers, disconnect revocation, circuit
queues, directional credit, rate limits, deadlines, inner Brontide, and
priority below direct blockchain traffic.

All endpoint, relay, and rendezvous roles are opt-in and must not advertise
while disabled.

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
flow-control bounds, and trailing-data rejection.
