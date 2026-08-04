# Changelog

All notable changes to the `hns-rs` workspace are documented in this file.
The workspace crates use a shared version and follow Semantic Versioning.

## 0.2.0 - unreleased

Release-candidate source for the modular wallet and marketplace boundary:

- bounded live HNSR reservation, renewal, confirmation, withdrawal,
  named-route publication, and lookup state machines, plus runtime-neutral
  requester and opaque circuit-relay routing with exact authenticated-peer and
  ticket admission, deadlines, directional credit, retained write accounting,
  signed byte ceilings, disconnect/policy revocation, and checksummed
  fail-closed snapshots, with sockets and atomic persistence left to the
  embedding product;
- owner-bound HNS Chat resource parsing, both-parity current-owner proof,
  owner-derived `hns.chat` HNSA verification, bounded opaque HIP-78 mailbox
  values, canonical profile assignment, fixtures, and fuzz/conformance parser
  coverage without a separate long-term chat key, plus exact public wire
  bounds, programmatic validation, SHA-256-authenticated valid/invalid release
  vectors, external-consumer coverage, and normalized source-package checks;
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
  and transaction IDs; and
- resumable publication checks requiring exact `.crate` bytes and release VCS
  identity before an existing package version is skipped; and
- default-on HIP-76/HIP-77 requester policy, opaque ODoH proxying, and HNSR
  requester/opaque-relay participation with independent opt-outs, direct-relay
  fallback where policy permits it, automatic bounded Denuo profile selection,
  and all plaintext output, target, endpoint, and rendezvous roles still
  default-off.

All public workspace packages advance together so changed crates never attempt
to overwrite the already-published `0.1.0` line. No `0.2.0` package or tag is
published by this source commit. The fee-policy, name-transition/recovery,
live HNSR, and owner-bound chat additions are source- and, where applicable,
fixture-reviewed only until the converged commit passes the consolidated
locked qualification gate.

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
