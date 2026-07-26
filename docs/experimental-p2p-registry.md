# Denuo Experimental Handshake P2P Registry, Version 1

Status: **Denuo Experimental V1 — Not an official Handshake protocol
assignment**.

This registry gives one collision-detectable identity to the private assignments
used by the Rust ecosystem. The values are compatible with the cited draft HIP
and HSD pull requests, but neither those drafts nor this registry creates an
official Handshake assignment.

## Assignments

| Semantic capability | Kind | Value |
|---|---:|---:|
| HNSR rendezvous | service bit | `0x04000000` |
| HNSR relay | service bit | `0x08000000` |
| Denuo extension envelope | service bit | `0x10000000` |
| P2P ODoH | service bit | `0x20000000` |
| P2P DNS relay | service bit | `0x40000000` |
| Reserved in v1 | service bit | `0x80000000` |
| `GETDNSRELAY` | packet | `0xf0` |
| `DNSRELAY` | packet | `0xf1` |
| `ODNS` | packet | `0xf2` |
| `HNSR` | packet | `0xf3` |
| `DENUO_EXT` | packet | `0xf4` |
| Reserved in v1 | packet range | `0xf5..=0xff` |
| Registry negotiation | Denuo protocol | `0x0000` |
| Atomic name marketplace | Denuo protocol | `0x0001` |

The machine-readable authority is
`registry/denuo-experimental-v1.toml`. The checked-in `.bin` is a canonical,
length-delimited little-endian encoding of every metadata field and assignment.
The `.sha256` file identifies that binary. Ordinary TOML serialization is never
hashed.

Version 1 fingerprint:
`95774db08c569b36fa7b7e4a071930f563b7251fc30934ba986732379a6e542d`.

## Required negotiation

On public networks, private packets `0xf0..=0xf3` are interpreted only after the
peer advertises the semantic service and `DENUO_EXT`, completes the ordinary
Handshake connection, and negotiates the registry fingerprint, versions,
protocols, bounds, network, and genesis hash. A mismatch disables the affected
experimental protocol; it does not by itself ban the peer or stop ordinary
Handshake P2P.

Legacy draft compatibility has no registry negotiation and is restricted to
regtest or an explicitly controlled network. It is reported as `Legacy Draft
Compatibility`, never as a successful Denuo negotiation.

## Security status

Brontide authenticates the peer connection, not DNS content or marketplace
claims. Relay and ODoH results still require local HNS-state, DNS correlation,
DNSSEC, TLSA, and DANE validation. Marketplace advertisements remain untrusted,
best-effort gossip until their proofs and active-chain state are verified.
