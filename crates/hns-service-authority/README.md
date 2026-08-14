# hns-service-authority

Transport-independent authority objects for the Named Service Authority draft.

The `hrm` module implements the current HRM-backed
`hns.named-service/v1` profile: deterministic-CBOR service identities and
resource IDs, exact HRM service-controller delegations, authenticated
current-snapshot validation, persistent generation high-water/tombstone state,
and bounded service-signed endpoint delegations. Its verified service result
can only be constructed from HRM Core's provenance-bearing
`ValidatedCurrentManifest`; raw manifests are not accepted as current authority.
The resulting service-generation observation is also opaque and read-only, so
callers cannot construct or downgrade a high-water mark or withdrawal tombstone
by mutating its fields. Its bounded, versioned canonical encoding preserves the
HRM rollback provenance and active/withdrawn state across restarts.

Production consumers acquire an embedding-backed `lease::HeldAuthorityLease`
for the exact durable namespace, network, and subject, then enter its scoped
`run` or task-local `run_async` callback. Inside that callback they create or
restore `authority_state::NamedServiceAuthorityState` and call `reconfirm` with
an authenticated loader that performs its read after lease acquisition. The
resulting `ReconfirmedNamedServiceAuthorityState` is the only production
mutation and current-binding surface. Its
`retrieve_validate_and_observe` sync and task-local async operations first
finish any pending transition and durably acknowledge the exact trusted time
`T`, then invoke the caller's retrieval closure, run
`validate_current_manifest`, observe HNSA, and commit the result. The public
surface does not accept an already resolved manifest. It maintains one
subject-global HRM rollback floor plus sorted per-resource generation
observations/tombstones, and withholds active and withdrawn results until an
exact durable compare-and-swap is acknowledged. The aggregate is bound to one
exact network and subject, has a configured capacity, monotonic revision and
trusted-time high-water, and restores against caller-supplied binding,
capacity, time, and minimum-revision floors. A new aggregate uses
create-if-absent; every later transition requires the exact prior revision and
full-snapshot fingerprint. Failed or ambiguous writes remain pending and are
retried unchanged before another decision. Retrieval, authority, and durable
storage failures remain distinct in `NamedServiceAuthorityOperationError`.

The retrieval closure is part of the embedding's trusted computing boundary.
It must begin all fallible current namestate, commitment, and envelope I/O only
when the ordered operation invokes it, and it must use the exact `T` passed to
it. Capturing preloaded bytes or results, a previously started request/future,
or validation performed before the call defeats the ordering contract and is
not a conforming integration.

An owned `CommittedNamedService` is durable historical evidence at its
recorded revision, not a reusable current-authority capability. Immediately
before an operational use, bind it through
`ReconfirmedNamedServiceAuthorityState::bind_current_at(committed,
trusted_now)` and pass the resulting non-cloneable
`CurrentCommittedNamedService` guard downstream. Binding requires a settled
aggregate, the exact current subject-wide revision, the exact current
per-resource observation, the same opaque authority-lease witness, and
`trusted_now` equal to the snapshot's trusted-time high-water. An active result
additionally requires `validated_at <= trusted_now < cache_until`. Any
trusted-time or HRM-root transition, unrelated service transition,
replacement, withdrawal, reorganization, or lease loss makes an older owned
result stale.

The Rust borrow prevents only that local authority instance from advancing; it
does not prove storage-global currentness. Production embeddings must map
every tab, worker, or process that can reach the same subject aggregate to one
namespace-wide exclusive/fenced authority broker, route every writer through
it, and hold it from before the authenticated load/reconfirmation through both
CAS acknowledgement and the complete authenticated dependent use. The storage
transaction must atomically validate the namespace and fencing token carried
by `NamedServiceAuthorityExpectation`; a point check plus an unfenced CAS is
not equivalent. When authority is composed with requester or rendezvous state,
acquire authority first and the dependent namespace second in one fixed order.
Expiring leases require broker-owned emission/session promotion or an
abortable scoped operation; a final pointwise lease/revision check is not
sufficient.

Successful HRM validation is persisted even if HNSA service observation or
capacity checks subsequently fail. An exact accepted chain reorganization
atomically clears all prior service observations for that subject before the
selected service is re-observed, preventing different resources from retaining
generation floors rooted in divergent chains. Applications must invalidate
cached owned results from older authority revisions after such a reset; the
`bind_current_at` check rejects them before operational use. Both synchronous
and task-local async ordered paths are provided. The async retrieval and
persistence futures need not be `Send`, and its persistence callback accepts an
owned snapshot for IndexedDB, extension, mobile, or other browser storage
adapters. Retrieval failure is returned only after the exact time transition
is durable, so unavailable I/O cannot lose the high-water mark across restart.
The separate `advance_trusted_time_persisted` methods remain available for
explicit time-only operations, not as a prerequisite that callers must
correctly sequence around a preloaded manifest.

Snapshot and individual-observation checksums detect corruption but are
unkeyed. They do not authenticate storage. The adapter must store canonical
bytes atomically in authenticated local state and enforce the supplied CAS
expectation. Returning success means those exact bytes are durable (or an
earlier ambiguous attempt already installed them).

The `hrm::observe_named_service` primitive and
`hrm::ObservedNamedService::into_active` remain available for tests and
specialized composition, but they are explicitly low-level and **uncommitted**;
they must not be used as a production authority boundary.

Application profile identifiers, flags, capabilities, and detached constraint
hashes are supplied by a separately reviewed application profile through a
trusted policy object. This crate does not invent a web, payment, wallet,
username, or other application profile assignment.

The crate root retains the earlier experimental `hsa1` TXT parser, fixed
service authorization, and legacy endpoint delegation for explicitly selected
compatibility code. Those legacy objects are wire- and type-distinct from the
`hrm` module and are never an implicit fallback.

HNSA service names contain only lowercase ASCII letters, digits,
and hyphens; periods are rejected. Dotted labels such as `hns.chat` belong to
profile registries or other higher layers, not the HNSA service-name field.

Replacement selection validates the bounded candidate set before comparing
sequences. Service authorizations are selected for one exact service identity,
and endpoint delegations require a profile-supplied logical-endpoint predicate.
The generic endpoint selector is intentionally stateless because only the
application profile can define the canonical logical-endpoint identifier and
durable endpoint-sequence key. Consumers must persist that profile-keyed
high-water themselves; endpoint keys and capability masks are not substitutes
for a profile-defined replacement scope.

HRM-backed endpoint validation binds the active network, resource and
delegation IDs, service generation, service and endpoint keys, capability and
constraint policy, current wall-clock interval, and complete current HRM
snapshot. A rendezvous admission check can verify internal object consistency
without claiming current name authority.
The verified service's `cache_until` is a local revalidation deadline, not a
shortening of the signed endpoint-authority interval. Endpoints may remain
signed and valid beyond it, but a consumer must obtain a fresh current-service
result before using them at or after that deadline.

The proposal is still a draft. Profile identifiers are not official Handshake
assignments.

Licensed under either Apache-2.0 or MIT.
