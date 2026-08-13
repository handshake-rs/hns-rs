# HRM-backed HNSA migration

Status: implementation design for draft protocols; not a wire assignment or a
production enablement statement.

This document fixes the compatibility and repository boundaries for the draft
Handshake Resource Manifests (HRM), HRM-backed Named Service Authority (HNSA),
and the HRM/HNSA profile for Handshake P2P Rendezvous (HNSR). It is based on
the draft documents named `HIP-xxxx-HRM.md`, `HIP-xxxx-HNSA.md`, and
`HIP-xxxx-HNSA-HNSR.md`.

The drafts replace the earlier experimental HNSA authority model. The existing
`hsa1` TXT record, fixed `ServiceAuthorizationV1`, legacy endpoint delegation,
and `NamedRouteRecordV2` are not HRM objects. They must not be reinterpreted,
implicitly converted, used as fallback, or allowed to share an application or
browser origin with the HRM-backed model.

## Compatibility boundary

The implementation keeps three route formats distinct:

| Route | Version | Authority type | Authority model | Policy |
| --- | ---: | ---: | --- | --- |
| Unnamed HNS node | 1 | 0 | HNSR endpoint self-authorization | Remains wire compatible |
| Legacy named experiment | 2 | 1 | `hsa1` and `ServiceAuthorizationV1` | Explicit compatibility mode only |
| HRM-backed named service | 3 | 2 | Current HRM and HNSA delegation | New default named-service model |

The stable named-route key formula is unchanged. A version-3 record is a
compact, internally verifiable route object, not an HRM proof. Every consuming
client must validate current authenticated HNS state and the complete current
HRM/HNSA chain before accepting application data. A relay does not become an
identity authority, and a rendezvous store that performs only internal checks
must never present those checks as name authorization.

## Repository ownership

The implementation is deliberately split rather than added to consensus:

- `hns-rs` owns canonical HRM objects, deterministic encoding, signatures,
  profile validation, HRM-backed HNSA objects, and HNSR version-3 wire types.
- `hns-node-rs` supplies authenticated current name state, bounded retrieval
  composition, optional cache and diagnostics, and current-chain validation.
  HRM does not change Handshake consensus.
- `hns-wallet-rs` owns encrypted controller/service/endpoint keys, offline
  manifest construction and signing, publication workflows, and user consent.
  The HNS owner key is never reused as another authority merely for
  convenience.
- `hns-dane-engine` owns the stable-origin, rollback-resistant, read-only
  consuming boundary used by native browser hosts.
- browser-extension and mobile products receive minimized verified results
  from their native boundary. A URL, TLS session, relay, gateway, downloaded
  script, or extension package is never an HRM trust root.

## HRM Core tranche

The core crate must provide all of the following before HNSA migration:

1. An `hrm1` TXT commitment parser and selector that preserves HNS TXT
   character-string boundaries. It validates canonical decimal sequences,
   exact unpadded base64url SHA-256 hashes, printable ASCII, singleton fields,
   extension-field rules, and at least one URI. Greatest sequence wins;
   equal-greatest different hashes fail closed; equivalent locator sets may be
   merged.
2. A bounded deterministic-CBOR codec for the exact integer-keyed envelope,
   payload, controller, resource, authority, and delegation maps. It rejects
   duplicate or unknown critical keys, indefinite lengths, floats,
   non-preferred integers or lengths, invalid UTF-8, trailing bytes, and any
   input whose canonical re-encoding differs.
3. Network-bound controller signing with the exact
   `HNS-HRM-v1\0` BLAKE2b-256 domain, compressed secp256k1 keys, strict DER,
   and low-S signatures. The complete envelope commitment is SHA-256.
4. Bounded validation with current owner/lifecycle evidence, subject/network/
   sequence/time matching, duplicate-resource detection, profile dispatch,
   external-proof hooks, parent-delegation recursion, cycle detection,
   containment, rights and constraints checks.
5. Retrieval and validation as separate interfaces. Locators and retrieved
   bytes remain untrusted. A failed current fetch never authorizes stale
   fallback.

Initial hard limits follow the drafts unless a consuming product selects a
smaller value: 1 MiB per envelope, 1,024 resources, 4,096 delegations, four
locators per object, parent depth 16 (always no more than 32), 64 fetched
objects, and 8 MiB fetched bytes per decision.

## HNSA tranche

HNSA consumes a verified HRM result. It does not duplicate or weaken HRM
validation.

The new implementation validates the deterministic-CBOR named-service
identifier and SHA-256 resource ID for profile `hns.named-service/v1`. It
accepts only the profile's HNS-local origin and exactly one current `operate`
delegation with the canonical rights array, same-subject/same-resource mapping,
nonzero service generation, bounded endpoint lifetime, capability mask,
constraints hash, and no subdelegation. That mapping is a typed HNSA exception;
it is not a generic relaxation of HRM delegation rules.

The HRM-backed endpoint object is a distinct type and encoding. It binds the
service resource ID, service delegation ID, service generation, endpoint key
and sequence, validity, capabilities, and constraints. It uses the draft's
`HNS-HRM-HNSA-ENDPOINT-DELEGATION-V1\0` signature domain, SHA-256 complete-object
ID, strict DER low-S signature, and 320-byte bound. Legacy endpoint bytes are
not accepted by this decoder.

## HNSR version-3 tranche

`NamedRouteRecordV3` carries the service resource ID, service delegation ID,
generation, controller key, complete HRM-backed endpoint delegation, one to
eight relay tickets, and an endpoint signature under the exact
`HNSR-HRM-HNSA-ROUTE-RECORD-V3\0` domain. It enforces the 8,192-byte record
bound and every duplicate ID, key, profile, network, lifetime, and ticket
binding before expensive work.

Storage admission may prove only internal consistency. Full requester
validation additionally matches every compact field to the current verified
HRM/HNSA state. Named routes remain excluded from unauthenticated route
sampling. Replacement sequence is scoped to `(route_key, endpoint_key)`;
equal-sequence different bytes fail closed.

## Browser, mobile, and wallet safety

The stable security origin is the exact tuple `(network_magic, name_hash,
canonical_service_name, application_profile_id)`. Controller, endpoint,
provider, relay, URI, and route rotation never merge or change that origin.
Legacy and HRM-backed services use separate origin model/version state.

Read-only browser and mobile clients need not advertise a role, accept inbound
circuits, publish routes, mine, or store records for others. Verification
grants no wallet signing, value transfer, local-network, VPN, device, or
background permission. Any conventional-web representation is either fully
validated under the selected application profile or clearly labelled
unverified; it is not a silent fallback under the HNSA identity.

The wallet keeps four authorities separate: HNS owner, HRM controller, service
controller, and endpoint. Sequence and generation reservations must be durable
before signing; gaps after a crash are safe, reuse is not. Publication uploads
and verifies the envelope before constructing an ordinary HNS update that
preserves unrelated version-0 resource records.

## Qualification gates

Implementation completion and protocol deployment are separate claims. Each
code tranche must include deterministic positive and negative vectors and
bounded parser tests. Before any public named-route enablement, independent
Rust and JavaScript implementations must agree byte-for-byte on commitment,
CBOR, signature, resource/delegation ID, endpoint, and route vectors.

Regtest qualification must cover replacement, revocation, expiry, owner
transfer, controller/service/endpoint rotation, unavailable and equivocating
retrieval, chain reorganization, multiple relays, route conflicts, and restart
rollback state. Testnet multi-operator and load evidence follows. Permanent
profile or wire assignments and mainnet publication remain out of scope while
the drafts and their application profiles are unassigned.

The current drafts do not define a web, payment, wallet-address, username,
pool-statistics, or inner-session application profile. Implementations must not
invent those semantics inside HRM Core or HNSA. Each such use requires a
separately documented experimental profile with its own identifiers, payload,
origin/permission rules, limits, vectors, and security review.
