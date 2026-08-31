# Shakescape Experimental Handshake P2P Registries

Status: **Production-supported Shakescape Experimental V1 — not an official
Handshake protocol assignments**. "Experimental" is the assignment namespace
and does not mark these parsers or compatibility commitments as prototypes.

This registry gives one collision-detectable identity to the private assignments
used by the Rust ecosystem. The values are compatible with the cited draft HIP
and HSD pull requests, but neither those drafts nor this registry creates an
official Handshake assignment.

## Assignments

| Semantic capability | Kind | Value |
|---|---:|---:|
| HNSR rendezvous | service bit | `0x04000000` |
| HNSR relay | service bit | `0x08000000` |
| Shakescape extension envelope | service bit | `0x10000000` |
| P2P ODoH | service bit | `0x20000000` |
| P2P DNS relay | service bit | `0x40000000` |
| Reserved in v1 | service bit | `0x80000000` |
| `GETDNSRELAY` | packet | `0xf0` |
| `DNSRELAY` | packet | `0xf1` |
| `ODNS` | packet | `0xf2` |
| `HNSR` | packet | `0xf3` |
| `SHAKESCAPE_EXT` | packet | `0xf4` |
| Reserved in v1 | packet range | `0xf5..=0xff` |
| Registry negotiation | Shakescape protocol | `0x0000` |
| Atomic name marketplace | Shakescape protocol | `0x0001` |
| Cross-chain marketplace | Shakescape protocol | `0x0002` |
| Reserved in v1 | Shakescape protocol range | `0x0003..=0xffff` |

The machine-readable authority is `registry/shakescape-experimental-v1.toml`.
Its checked-in `.bin` is a canonical,
length-delimited little-endian encoding of every metadata field and assignment;
the corresponding `.sha256` identifies that binary. Ordinary TOML
serialization is never hashed.

Version 1 fingerprint:
`04fce3f12b717c4254bb66ac07474a6c9f61bd2916efc18ebfc79df82a89a66b`.

## HNSR service profiles

HNSR named routes use a separate generated service-profile registry so adding
a profile cannot change the Shakescape packet-registry fingerprint or reinterpret
an existing packet assignment.

| Semantic profile | Kind | Value |
|---|---:|---:|
| Native HNS node v1 | HNSR service profile | `0x0001` |
| HNS web v1 | HNSR service profile | `0x0002` |
| Owner-bound `hns.chat` v1 | HNSR service profile | `0x0003` |
| Shakescape atomic swap v1 | HNSR service profile | `0x0004` |
| Reserved | HNSR service profile range | `0x0005..=0xffff` |

The machine-readable authority is
`registry/hnsr-service-profiles-v1.toml`; its canonical fingerprint is
`59f47afa6e536afe784ba65823eb1a028fa0ace72d7e721888b4be586a687ad2`.
These are private Shakescape Experimental profile assignments, not official
Handshake assignments.

Consumers obtain the name, versions, profile, fingerprint, and limits from
`hns-p2p-experimental`; they do not copy the digest or private message numbers.
The canonical full `SHAKESCAPE_EXT` packet payload limit is 1,048,576 bytes. Its
26-byte envelope leaves at most 1,048,550 bytes for a nested payload, and a
registry-negotiation payload is further limited to 16,384 bytes.
Typed name-market and cross-chain marketplace decoders both impose a tighter
512 KiB payload cap.

The HIP-76 assignment rows retain the draft's DNS-body limits: 4,096 bytes for
`getdnsrelay` and 65,535 bytes for `dnsrelay`. Their complete message payloads,
including request ID, status, and length fields, are 4,106 and 65,546 bytes
respectively. Code that bounds complete packet payloads must use the complete
payload constants from `hns-dns-relay-protocol`, not the registry body fields.

The pre-organization-migration checkpoint used fingerprint
`c6f99e2403d5a9a2b257b995eca35082b51c75fa903a7fd3e354a1567529f1ff`.
The fingerprint changed because canonical source URLs are encoded registry
metadata and now name `handshake-rs/hns-rs`; no numeric assignment, message
meaning, payload bound, or consent default changed in that migration.

## Required negotiation

On public networks, private packets `0xf0..=0xf3` are interpreted only after the
peer advertises the semantic service and `SHAKESCAPE_EXT`, completes the ordinary
Handshake connection, and negotiates the registry fingerprint, versions,
protocols, bounds, network, and genesis hash. A mismatch disables the affected
experimental protocol; it does not by itself ban the peer or stop ordinary
Handshake P2P.

The first compatible extension exchange uses protocol `0x0000`, version 1.
Typed Hello and HelloAck constructors bind that identity and a nonzero
correlation ID. A completed negotiation must include protocol `0x0000` version
1 even when a peer advertises a wider forward-compatible version range.
Peers advertise the Shakescape Registry V1 fingerprint and may negotiate
protocol `0x0002`. The bounded `Auto` profile selector resolves to that one
supported Shakescape profile. Disabled-role and controlled-network legacy
selections remain unchanged; unknown official profiles continue to fail closed.

Legacy draft compatibility has no registry negotiation and is restricted to
regtest or an explicitly controlled network. It is reported as `Legacy Draft
Compatibility`, never as a successful Shakescape negotiation.

## Security status

Brontide authenticates the peer connection, not DNS content or marketplace
claims. Relay and ODoH results still require local HNS-state, DNS correlation,
DNSSEC, TLSA, and DANE validation. Marketplace advertisements remain untrusted,
best-effort gossip until their proofs and active-chain state are verified.
