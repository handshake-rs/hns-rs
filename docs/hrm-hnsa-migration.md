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
| HRM-backed named service | 3 | 2 | Current HRM and HNSA delegation | Draft opt-in; no public application profile assigned |

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
6. One authenticated subject-wide rollback observation and trusted-time
   high-water that are durably committed before an operational profile result
   is released. Exact accepted-reorganization evidence replaces that root and
   invalidates every profile decision rooted in the prior branch; uncommitted
   pure validation results are not a production authority boundary.

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

The pilot applies two fail-closed interpretations while the draft remains
ambiguous. Every delegation in the complete current snapshot that names the
expected parent resource and contains `operate` counts toward the one-candidate
limit, even when that candidate is future-dated, expired, or otherwise
malformed; the sole candidate is then validated completely. Signers use
deterministic RFC 6979 ECDSA for reproducible vectors, but the endpoint ID is
still the digest of the exact complete signed object. A different valid low-S
signature over the same body is therefore a different endpoint object, not an
alias for the fixture ID.

Service generation is rollback state independent of HRM sequence. Production
consumers use one bounded `NamedServiceAuthorityState` per exact
`(network_magic, subject)`, not unrelated per-service files, and expose it for
mutation only through `ReconfirmedNamedServiceAuthorityState` after a leased
authenticated load. Its canonical snapshot combines the subject-wide HRM
rollback root and trusted-time high-water with sorted per-resource generation
observations and withdrawal tombstones. A later snapshot cannot lower a
generation; equal generation with different canonical delegation bytes fails
closed without replacing the retained observation. Restoration after removal
requires a greater generation, except when exact accepted-reorganization
evidence atomically resets the whole subject lineage.

The aggregate uses create-if-absent followed by exact
`(revision, full-snapshot fingerprint)` compare-and-swap. Active and withdrawn
results are withheld until durable acknowledgement, and an ambiguous write is
retried unchanged before another decision. Successful HRM validation commits
the new subject root even if HNSA validation or capacity then fails. An exact
accepted reorganization atomically clears every service observation from the
old branch before observing any service on the new one; merely carrying exact
anchor-change evidence on a forward manifest never permits a reset. Resolver
and validation failures still persist trusted time so restart cannot revive an
expired object. Sync and owned-snapshot async APIs enforce the same boundary.

`ServiceGenerationObservation::encode` remains the bounded versioned
per-resource component. The pure `validate_current_manifest` and
`observe_named_service` APIs are deliberately low-level and uncommitted;
operational consumers obtain `CommittedNamedService` from the aggregate and
rebind it through
`ReconfirmedNamedServiceAuthorityState::bind_current_at(committed,
trusted_now)` as `CurrentCommittedNamedService` immediately before downstream
use. The operation time must exactly equal the settled authority trusted-time
high-water; active authority also requires
`validated_at <= trusted_now < cache_until`.
The domain-separated checksums and fingerprints detect accidental corruption
only. The embedding remains responsible for authenticated atomic storage and a
caller-held minimum revision.

The guard's Rust borrow proves only local-lineage currentness. Production
embeddings enter `HeldAuthorityLease::run` or its task-local async counterpart,
perform the authenticated load and mandatory `reconfirm` after acquisition,
and hold that namespace-wide exclusive/fenced authority-broker lease through
acknowledgement and the complete dependent use. Exact CAS must atomically check
the namespace and fencing token, but CAS or a last-moment revision reread is
not exclusion: another tab, worker, or process can commit immediately after the
check. Acquire composed locks in a fixed order—authority first, then requester
or rendezvous—and route every writer through the same broker.

Endpoint sequence is scoped to a profile-defined logical endpoint. The generic
HNSA selector therefore does not guess a durable key from endpoint keys,
capabilities, or predicate behavior. Each assigned application profile must
specify a canonical logical-endpoint identifier and persist its own sequence
high-water under a key that includes the exact HNSA service identity.

Removal inside an authenticated complete HRM snapshot produces the typed
service-withdrawal tombstone above. Absence of an `hrm1` commitment, loss of a
current owner, or another unusable HNS lifecycle state cannot produce a
`ValidatedCurrentManifest`; the node's authenticated namestate adapter must
atomically invalidate every affected service and route while retaining their
generation and sequence high-water state. A retrieval timeout, unavailable
locator, or invalid fetched envelope is only a validation failure and MUST NOT
be reclassified as an authenticated withdrawal or authorize stale fallback.

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
sampling. This adapter defines the exact endpoint public key as the logical
endpoint, so both endpoint-delegation and route counters have an exact
`(route_key, endpoint_key)` scope. Different endpoint keys remain concurrent.

The stateless current-verification helpers are explicitly hidden,
`*_uncommitted` primitives. The only production sync and async requester APIs
are `retrieve_select_and_observe_current_persisted` and its async counterpart.
They retry pending requester persistence and durably advance the exact trusted
operation time before invoking the route-retrieval closure or constructing its
future. The closure must start every transport, lookup, and response operation
when invoked and return the complete raw bounded iterator. A preloaded batch,
previously started request/future, already-decoded record, or direct raw
current selector is not a valid production boundary. Unavailable retrieval is
a typed operation error returned only after requester time is durable; the
composite lease is rechecked after retrieval before bytes are inspected.
The raw batch is then bounded and canonically decoded, matched to an
exact-current `CurrentCommittedNamedService`, fully product-reduced, and
durably observed. Only afterward does the API return a non-cloneable
`CurrentNamedRouteV3` that owns the selected decoded record while borrowing
both authority and requester state. The guard must remain held through
profile-specific authenticated session establishment. It cannot survive a
later authority revision, requester counter advance, or conflict merely
because the signed route or earlier cache deadline has not expired.
The local borrows do not replace the ordered authority-then-requester broker
leases, which must span restore/recheck, both acknowledged CAS transitions,
and session promotion. Expiring leases require an abortable scoped operation
or broker-owned transport/session promotion; pointwise validity checks are
raceable.

`HeldNamedRouteV3OperationLeases` implements that fixed acquisition order. Its
requester half protects the entire multi-origin aggregate for one physical
storage namespace and network, not an origin-, subject-, frame-, or tab-local
partition. Both authority and requester loaders run after acquisition and are
reconfirmed against the exact opaque composite witness. Browser and mobile
async paths are task-local and do not require `Send`, but they retain the same
ordering and fenced-CAS contract.

The two counters form an independent product state with no lexicographic
priority. Every fully verified candidate observes both dimensions: lower is
stale, greater advances and clears only that dimension's conflict, equal same
value is idempotent, and equal different value creates a fail-closed tombstone.
A route is usable only when that exact record realizes both final
nonconflicting high-waters. Split endpoint/route maxima persist both counters
but remove live bytes. Batch and sequential processing converge regardless of
input order.

The rendezvous ledger is a finite admission cache. After each fully internally
verified candidate it sets `retain_until` to the maximum of the previous
horizon, the signed route expiry, and `now.saturating_add(7_200)`, retains the
scope while trusted `now < retain_until`, and may prune at or after that bound.
Invalid input cannot mutate or renew it. Publisher counter reservations and
requester high-waters are separate permanent state: publishers reserve before
signing, and requesters never silently expire or evict replay state on route
expiry, withdrawal, controller rotation, or restart. Requester observations
use exact CAS and commit trusted time even for empty, invalid, expired, stale,
conflicting, and withdrawn results.

The current-service result has a separate local `cache_until` revalidation
deadline. A shorter HRM cache policy does not rewrite the signed payload,
resource, delegation, or endpoint authority intervals: an otherwise contained
endpoint may outlive the cached decision, but it cannot be used through that
decision at or after `cache_until` without current HRM/HNSA revalidation.

Legacy version-2 and HRM-backed version-3 records use separate storage and
replacement namespaces even though their stable lookup key formula is the
same. Once two cryptographically valid records in one namespace have the same
replacement sequence and different canonical bytes, that endpoint scope is
marked ambiguous and no prior first-seen record remains usable. Invalid input
does not poison an otherwise valid scope.

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

Read-only does not mean stateless. Browser, extension, and mobile clients keep
the same permanent authority/requester observations as native clients.
IndexedDB, extension storage, or a mobile database must receive an owned
canonical proposal, enforce exact transactional CAS, and be awaited through
durable acknowledgement before a service or route is exposed. In addition,
one sole-owner/fenced broker lease must exclude competing tabs, workers, and
processes for the whole authenticated operation; every context sharing the
requester snapshot uses one aggregate-wide requester lease. CAS alone is
insufficient. A SharedWorker/background owner, Web Lock plus fenced storage,
or native/mobile actor may provide that boundary. A scheduled write,
`postMessage`, or in-memory update is not acknowledgement or completed
fence-tagged session promotion.

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
rollback state. It must also cover split endpoint/route maxima in every batch
and sequential order, exact-CAS failure and ambiguous retry, trusted-time
rollback, finite-ledger pruning, and sync/async result withholding. Testnet
multi-operator and load evidence follows. Permanent profile or wire assignments
and mainnet publication remain out of scope while the drafts and their
application profiles are unassigned.

The current drafts do not define a web, payment, wallet-address, username,
pool-statistics, or inner-session application profile. Implementations must not
invent those semantics inside HRM Core or HNSA. Each such use requires a
separately documented experimental profile with its own identifiers, payload,
origin/permission rules, limits, vectors, and security review.

The shared conformance fixture uses profile `0xff00` and the label
`pool-stats` only as private test data. It is not enabled as a production
profile, an allocation request, or a definition of pool-statistics semantics.
Its service-generation, endpoint-delegation, and route-publication counters,
plus a persisted trusted-time/pruning-floor vector, exceed JavaScript's exact
`Number` range so browser and extension implementations must demonstrate
`BigInt`-safe parsing. The fixture also pins canonical authority, requester,
and storage-ledger snapshots so a second implementation can reproduce restart
state rather than only the signed network objects.
