# hns-hnsr-protocol

Runtime-independent wire types for draft HIP #78 HNSR.

This crate provides bounded rendezvous records, routing state, authenticated
relay tickets, message envelopes, and the versioned HNSA named-service route
adapter. Unnamed `HNS_NODE_V1` records retain their version-1/type-0 encoding.
The superseded `hsa1`-backed version-2/type-1 named experiment remains
available only through explicit compatibility APIs and is disabled by default
for publication in the rendezvous runtime. Ordinary wire lookup never returns
V2; an embedding must invoke the explicitly named legacy lookup API.
HRM/HNSA-backed named services use the distinct version-3/type-2 record,
validate its complete endpoint delegation, relay
tickets, duplicated bindings, and endpoint signature for storage admission,
then require a provenance-bearing current HRM/HNSA result for requester trust.
Its synchronous service types execute reservation, renewal, confirmation,
withdrawal, route publication, and route lookup against bounded in-memory
state so an embedding node can own transport, persistence, clocks, and peer
policy without duplicating protocol validation.
Unnamed and legacy route admission applies storage-capacity checks before
signature verification. V3 admission charges bounded global and per-source
verification windows, canonically decodes the record, and applies a cheap
structural sequence/capacity matrix before expensive cryptography. A candidate
that survives every internal signature and binding check is subjected to the
same matrix again immediately before mutation. The cheap pass may perform
trusted local-time pruning, but unverified candidate bytes cannot create,
advance, conflict, or clear a ledger scope. Known lower sequences and
structurally impossible capacity requests can therefore fail cheaply. An
existing-scope candidate is rejected before cryptography only when neither
counter dimension can mutate and the existing retention horizon covers its
entire possible interval. Endpoint-stale/route-greater and
endpoint-greater/route-stale candidates must be fully verified because the
non-stale dimension can still advance. Only valid input may extend durable
retention or mutate either dimension before returning `StaleSequence` or
`ConflictingSequence`.
HRM-backed and legacy named routes occupy separate replacement/conflict
namespaces and are never sampled. The V3 adapter defines one logical endpoint
as the exact endpoint public key; a different endpoint key is a concurrent new
identity, not a rotation of the old one. Within each exact
`(route_key, endpoint_key)` scope, endpoint-delegation sequence/ID and route
sequence/hash form an independent product lattice with no lexicographic
priority. Every fully verified record observes and updates both dimensions. A
valid equal-sequence equivocation tombstones its dimension, while a greater
observation advances and clears only that dimension's tombstone. If endpoint
and route maxima came from different records, live bytes are removed and no
route is advertised; a record is usable only when it realizes both final,
nonconflicted high-waters. Joining verified observations is order-independent,
so reversing records in one batch cannot change the resulting product state.
Malformed or incorrectly signed input cannot mutate either counter or
conflict tombstone.

The storage-admission ledger is deliberately bounded, not a permanent
publisher counter. After each verified V3 observation, the exact
`(route_key, endpoint_key)` scope is retained through the maximum of its prior
deadline, the candidate's signed expiry, and 7,200 seconds after the trusted
observation time. Consequently, a lower record that was already valid when a
greater record was observed cannot be admitted later during that overlap,
even if this node had not seen the lower record first. A lower candidate
rejected by a provably sufficient cheap stale check is not treated as a
verified observation. If a later stale candidate's declared interval or new
7,200-second observation horizon extends beyond current retention, it must pass
full verification before retention and the ledger revision advance. Invalid
stale input never renews the horizon. A publisher that creates another lower
sequence after the finite horizon is outside this storage cache's guarantee;
durable publisher counters and the requester's permanent endpoint-delegation
and route high-water state provide end-to-end rollback protection. Both global
ledger capacity and the configured per-route-key scope count are enforced and
bound into snapshots, so conflict tombstones or endpoint churn cannot consume
unbounded scopes under one route key.

Current-aware stores can explicitly revalidate V3 state after controller or
generation rotation and apply provenance-bearing withdrawal tombstones without
lowering storage replay state. A full-current idempotent PUT or successful
current revalidation replaces the prior local cache deadline with the newly
authenticated `cache_until`, including refresh exactly at the old deadline.
Admission-only idempotence never extends an existing current-aware deadline;
full current verification can upgrade admission-only live bytes.

`RouteStore` and `RendezvousService` expose the V3 ledger revision, the
`pruned_through` clock floor, deterministic snapshot/restore, current
revalidation, and withdrawal APIs, but they are explicitly volatile
compatibility surfaces and do not enforce persistence-before-reply. The floor
advances only when expired ledger scopes are actually deleted. Fallible V3
admission and maintenance reject a clock earlier than that floor, while
infallible V3 reads clamp their effective time to it. Restore also takes a
caller-held minimum revision and rejects an older snapshot.

Persistent nodes use `LeasedPersistentRendezvousService`, a non-cloneable
production stage which owns an embedding-provided sole-writer guard. `open` and
`open_async` acquire that guard before invoking the authenticated ledger loader;
the loader is trusted to perform or reconfirm its external read inside that
callback, not capture a pre-acquisition value, and atomically validate the
supplied namespace/fence. Rust cannot prove external I/O freshness. The
namespace binds the nonzero storage identifier, network, private-route policy,
and finite-store limits. Every create or exact `(revision, fingerprint)` CAS
also carries the acquisition's nonzero fencing token. Storage must atomically
reject a stale namespace or token even if the revision still matches. This is
suitable for an extension background broker/Web Locks plus a durable epoch, a
mobile single-owner service, or an OS lock backed by a durable epoch.

Packet outcomes cross only `handle_and_emit` or `handle_and_emit_async`: the
stage owns the guard through durable mutation/lookup and through completed
emission of either the response or protocol error. A persistence failure emits
nothing. Emission success means actual delivery completed while held, or a
broker atomically promoted a fence-tagged outcome which stale consumers cannot
use; merely queueing work or calling `postMessage` is not success. Retained
outcomes remain broker-owned until that promotion. Lease loss, callback unwind,
ambiguous emission, or cancellation poisons the stage and immediately discards
its volatile inner cache; drop it, reacquire, and reload before continuing.
Current-authority V3 put, revalidation, and exact-time withdrawal methods also
recheck the independent committed HNSA authority lease before and after their
route-ledger CAS and release only post-CAS diagnostics. Async storage callbacks
receive an owned proposal suitable for IndexedDB or mobile databases. Callback
success means those exact bytes are durable or were idempotently installed by
an earlier outcome-ambiguous attempt.

This ordering includes a PUT that returns `ConflictingSequence`: the verified
conflict mutates the fail-closed ledger and crosses the durable CAS before the
error escapes. A verified stale PUT may likewise extend retention before
returning `StaleSequence`. The fingerprint is domain-separated over the exact
checksummed encoding. A revision is monotonic within one lineage, but by
itself cannot distinguish two revision-`N + 1` forks concurrently derived from
revision `N`. The snapshot's unkeyed checksum and fingerprint detect
accidental change only; they provide neither authentication nor rollback
protection. Live route bytes are never part of this durability claim: a
restored service starts without them and must fully re-admit or revalidate
newly received bytes before advertising them.

`HrmNamedRoutePolicy` independently specifies allowed and required service
flags (required must be an allowed subset), endpoint capabilities, constraint
hashes, and route lifetime. The hidden
`NamedRouteRecordV3::verify_current_uncommitted` and
`select_named_route_v3_uncommitted` primitives produce point-in-time historical
evidence only; a bare `VerifiedNamedService` or `VerifiedNamedRouteV3` is not a
production authority capability. A verified route's cache deadline is the
minimum of the current HRM/HNSA cache decision, endpoint, route, and ticket
deadlines; a local cache limit triggers fresh HRM validation and does not
shorten a signed authority interval.

Read-only mobile browsers and extensions can keep the same requester
high-waters and authenticated HRM/HNSA observations without publishing routes
or operating a rendezvous node. Production requester state uses exact endpoint
keys as logical identities, independently joins both counter dimensions across
the complete batch, and persists both equivocation tombstones. It releases a
route only if one verified record realizes the final endpoint and route
components, regardless of batch order. Native compare-and-swap callbacks—and
owned-snapshot asynchronous CAS in IndexedDB, browser extension storage, or a
mobile database—must complete before a route is released. The result is a
non-cloneable `CurrentNamedRouteV3` guard that borrows both the exact-current
HNSA authority and requester state. It must remain held through authenticated
session establishment; a later authority/requester revision, counter advance,
or conflict invalidates the older binding even before `cache_until`.
The only production batch entry points are
`retrieve_select_and_observe_current_persisted` and its task-local async
counterpart. They retry pending requester persistence and durably acknowledge
the one trusted operation time before invoking the supplied retrieval closure
or constructing its future. That closure must start all route transport and
lookup work when invoked and return the complete raw bounded iterator; passing
a preloaded batch, a previously started request/future, or already-decoded
records violates the boundary. Unavailable retrieval therefore returns its
typed retrieval error only after time is durable. The composite lease is
rechecked after retrieval, then raw records are bounded and canonically
decoded, the complete product is reduced and persisted, and only then can the
owned selected record enter `CurrentNamedRouteV3`.
Every production lookup first acquires
`HeldNamedRouteV3OperationLeases`: the subject authority lease followed by the
single whole-aggregate requester lease. The requester key deliberately omits
origin and HNS subject, so all tabs, frames, workers, extension pages, or
mobile views that share one requester snapshot serialize through the same
broker. Inside the scoped witness callback, both authority and requester state
must be loaded or reconfirmed from authenticated storage after acquisition;
only `ReconfirmedNamedRouteV3RequesterState` can return a current route. Its
CAS expectation carries the requester namespace and fence separately from the
authority lineage. `run_async`, `reconfirm_async`, and owned-snapshot CAS
callbacks impose no `Send` requirement, allowing Web Locks/IndexedDB,
extension-background, and mobile single-owner adapters without weakening the
ordering. The composite leases remain held through actual session
establishment or a broker-owned fence-tagged atomic promotion; merely queueing
work to another context does not complete the protected operation.
Low-level `NamedRouteRecordV3::sign_current_uncommitted` reserves neither
counter and returns only historical inspection evidence. Before calling it, a
production publisher must atomically reserve and durably persist fresh nonzero
endpoint-delegation and route counters for their respective exact scopes. Crash
gaps are safe; reuse is not. The wallet-backed durable publisher workflow
belongs to the wallet integration layer rather than this wire crate.
Its runtime-neutral requester and opaque-relay state machines add exact
ticket-to-connection admission, bounded directional flow control, retained
write acknowledgements, cumulative byte ceilings, deadlines, disconnect and
policy revocation, and checksummed fail-closed restart snapshots. Adapters
still own authenticated outer connections, clocks, scheduling, and atomic
snapshot storage; circuit plaintext never enters the relay runtime.
Circuit bodies admit any nonzero profile so the profile selected by a named or
unnamed reservation flows unchanged through its ticket, route, OPEN, and
INCOMING messages. Relay allowlists and exact requester/ticket/reservation
matching remain the authority for profile admission; unnamed route records
remain restricted to `HNS_NODE_V1`, while named records reject that profile.
Snapshots retain a trusted-time high-water mark and require a caller-held
minimum generation on restore, so clock rollback and replay of settings from
before a later opt-out/configuration generation fail closed. Relay actions,
including one-credit WINDOW traffic, are bounded globally, per circuit, and
per destination peer until acknowledged.
The owner-bound `hns.chat` profile adapter derives that same authority chain
from a current `hnschat` resource and canonical single-key owner output while
using `chat` as its HNSA service name. The dotted profile label is a separate
layer and does not weaken or change generic `hsa1` verification.

**The associated Denuo wire assignments are experimental and are not official
Handshake protocol assignments.**

The service types and snapshots are not by themselves a deployed relay.
Network behavior, atomic persistence, fresh process-session IDs on restore,
and product qualification remain the embedding product's responsibility.

```bash
cargo add hns-hnsr-protocol
```

The crate is part of the
[`hns-rs`](https://github.com/handshake-rs/hns-rs) workspace and supports Rust
1.89 or later. API documentation is available on
[docs.rs](https://docs.rs/hns-hnsr-protocol).

Licensed under either Apache-2.0 or MIT.
