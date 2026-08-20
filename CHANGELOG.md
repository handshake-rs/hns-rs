# Changelog

All notable changes to the `hns-rs` workspace are documented in this file.
The workspace crates use a shared version and follow Semantic Versioning.

## Unreleased

- Add a distinct canonical maker-signed swap-session proposal and Denuo
  message so two independent wallets can complete the maker-to-taker
  countersigning round trip before either wallet is allowed to fund.

## 0.3.0 - 2026-08-15

- Add a platform-neutral, canonical external anti-rollback journal contract
  with installation/network/role/key binding, explicit privileged provisioning
  and enrollment, exact fenced journal CAS, sealed old/new snapshots, a
  no-abort prepared transition, deterministic crash recovery, terminal
  retirement, honest protection classes, and fail-closed native,
  browser-extension, and mobile integration requirements.
- Add the first HRM Core implementation: chunk-preserving `hrm1` commitment
  parsing and selection, strict deterministic CBOR, typed payload/envelope,
  network-bound controller signing and verification, profile-neutral resource
  and delegation objects, bounded recursive validation interfaces, and exact
  migration boundaries for HRM-backed HNSA and HNSR named-route version 3.
- Add source-independent HRM Core vectors and a standard-library Python oracle,
  plus subject/action-bound profile dispatch, authenticated external-proof
  expiry, pre-allocation retrieval budgets, and event-scoped rollback evidence.
- Add the HRM-backed `hns.named-service/v1` resource and service-delegation
  profile, bounded service-signed endpoint delegations, and a durable bounded
  subject-wide authority aggregate with trusted-time, exact CAS, generation
  tombstones, and atomic accepted-reorganization invalidation.
- Add HNSR named-route version 3 with separate internal-admission and
  current-HRM requester verification, independent endpoint/route product
  counters, finite storage ledgers, permanent requester replay state, exact
  sync/async fenced CAS, ordered authority/requester operation leases,
  committed-authority production wrappers, and a leased
  persistence-before-emission rendezvous boundary.
- Add source-independent HNSA/HNSR v3 vectors covering the complete HRM,
  resource, service delegation, endpoint delegation, relay ticket, and route
  chain plus canonical authority/requester/storage snapshots, including
  replacement, withdrawal/restoration, equivocation, malformed-object,
  persistence/restart, and JavaScript-unsafe-integer cases.
- Keep the prior `hsa1`, fixed service authorization, endpoint delegation, and
  named-route version 2 model explicitly legacy rather than reinterpreting it
  as HRM-backed authority.

Dated release-source commit
`d0cde9ded6f8f93f96f16daafc094849c6d484bf` passed the complete locked CI
gate and RustSec in run `31863271873`, all four configured CodeQL analyses in
run `31863271863`, and all 19 Cargo publication dry-runs in release-preflight
run `31863520941`. On 2026-08-15 UTC, all 19 packages were published
non-yanked from that exact source commit and independently verified against
their normalized local archives and crates.io checksums. The exact archive
hashes are retained in `release/0.3.0-crates.sha256`; annotated tag `v0.3.0`
peels directly to the published source commit. These artifacts qualify the
protocol packages only, not any deployed node, wallet, browser, relay,
marketplace, or production value workflow.

## 0.2.0 - 2026-08-10

Release source for the modular wallet and marketplace boundary:

- bounded live HNSR reservation, renewal, confirmation, withdrawal,
  named-route publication, and lookup state machines, plus runtime-neutral
  requester and opaque circuit-relay routing with exact authenticated-peer and
  ticket admission, nonzero profile-preserving OPEN/INCOMING establishment,
  deadlines, directional credit, retained write accounting, signed byte
  ceilings, disconnect/policy revocation, and checksummed
  fail-closed snapshots with caller-held anti-rollback generations and trusted
  time high-water marks, plus global/per-circuit/per-peer action bounds and
  exact pending-context translation, with sockets and atomic persistence left
  to the embedding product;
- HIP PR #79-aligned HNSA service names with periods forbidden, bounded
  validation-before-selection for one exact service identity, profile-scoped
  logical endpoint replacement, and HNSR capacity preflight plus global and
  per-source signature-verification windows;
- owner-bound HNS Chat resource parsing, both-parity current-owner proof,
  owner-derived verification for the HIP-compliant HNSA service name `chat`,
  bounded opaque HIP-78 mailbox values, separate `hns.chat` profile assignment,
  fixtures, and fuzz/conformance parser coverage without a separate long-term
  chat key, plus exact public wire bounds, programmatic validation,
  SHA-256-authenticated valid/invalid release vectors, external-consumer
  coverage, and normalized source-package checks;
- exact HSD sigop-adjusted policy virtual size and minimum-policy-fee
  arithmetic with public weight, sigop, virtual-byte, and fee-rate units,
  checked bounds, input-coin binding, and source-hash-pinned vectors;
- exact, bounded HSD NameState value encoding with mandatory external
  name-hash binding, shared null-owner outpoint semantics, canonical optional
  fields, and complete-input rejection;
- lossless version-zero HSD resource bytes plus a separate typed parser for all
  seven assigned record types, including bounded DNS compression handling;
- deterministic pinned-HSD NameState/resource vectors and SHA-256 sidecar;
- additive Denuo Experimental Registry V2, preserving the exact V1 identity
  while assigning the separately negotiated cross-chain marketplace protocol;
- canonical bounded market intents, observations, deterministic price rounds,
  fill grants with independent maker settlement delegation, and bilateral
  swap-session/status messages;
- signed fixed-price name listings and cancellations;
- native SHA-256 Handshake HTLC funding, redeem, refund, and preimage
  primitives;
- canonical Shakedex buyer fulfillment and explicit-recipient two-stage
  cancellation construction, authentication, and spend classification;
- strict typed HSD TRANSFER/FINALIZE covenant parsing, owner-preserving linked
  output and transaction construction, authenticated NameState finalization,
  and listing-independent Shakedex lock descriptors and recovery construction
  from a seed-derived seller key, explicit network binding, and
  chain-discovered exact locking coin, with the exact FINALIZE-branch witness;
- canonical zero-entry name-market offer inventories while empty offer
  requests and object batches remain rejected;
- an exact native-HNS HTLC/session join with deadline-safe upward conversion
  to HSD's 512-second time-lock granularity;
- recovery-safe status validation after the new-funding window closes;
- exact recognized Denuo versions with zero flags and a 512 KiB typed
  marketplace cap;
- source-independent, versioned, SHA-256-sidecarred protocol vectors covering
  signed objects, full envelopes, descriptors, transactions, signature hashes,
  and transaction IDs;
- one canonical, dependency-ordered publication allowlist plus a cheap
  metadata/version/private-package gate, package-local release notes, common
  normalized-archive inventory checks, and an explicit version confirmation
  before any irreversible upload, with pre-upload archive inspection, a
  separately triggered full publish-dry-run workflow, a validated crates.io
  cooldown, and exact post-upload archive verification before dependent
  publication;
- resumable publication checks requiring exact `.crate` bytes and release VCS
  identity before an existing package version is skipped; and
- default-on HIP-76/HIP-77 requester policy, opaque ODoH proxying, and HNSR
  requester/opaque-relay participation with independent opt-outs, direct-relay
  fallback where policy permits it, automatic bounded Denuo profile selection,
  and all plaintext output, target, endpoint, and rendezvous roles still
  default-off.

All public workspace packages advance together so changed crates never attempt
to overwrite the already-published `0.1.0` line. The immediately preceding
undated release-preparation commit
`abf11ff3b16920c08f3c0b6d32d2e1af7cbe37b2` passed locked CI run
`31385655990` and the explicit 17-package release preflight run `31386373480`.
Its CodeQL run `31385656053` completed Python, Rust, and Actions analysis but
not JavaScript/TypeScript analysis, which remained queued, so it is not a
complete CodeQL qualification. The dated source commit
`b24b66c382de53330ec21dd3137e056a2bea3e2d` then passed exact-head locked CI
run `31398600728`, complete Python, JavaScript/TypeScript, Rust, and Actions
CodeQL run `31398598588`, and the explicit 17-package release preflight run
`31399004538`. On 2026-08-14 UTC, all 17 packages were published non-yanked
from that exact source commit; the registry archives and checksums are recorded
in `release/0.2.0-crates.sha256`. No `v0.2.0` tag was created. Those artifacts
qualify the exact protocol packages only, not any live deployment or downstream
product. Any later source commit must pass its own exact-head gates.

## 0.1.0 - 2026-07-29

Initial crates.io release of all 14 public, runtime-independent Handshake
protocol crates:

- bounded wire encoding and semantic protocol values;
- name covenants, transactions, script validation, headers, proof of work,
  Urkel proofs, swaps, mining commitments, and standard P2P codecs;
- the explicitly experimental Denuo registry and draft HIP #76, #77, and #78
  protocol values.

The conformance harness, fuzz package, and deterministic registry generator are
development tools and are not published.
