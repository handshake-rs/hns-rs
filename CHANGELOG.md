# Changelog

All notable changes to the `hns-rs` workspace are documented in this file.
The workspace crates use a shared version and follow Semantic Versioning.

## 0.2.0 - unreleased

Release-candidate source for the modular wallet and marketplace boundary:

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
- an exact native-HNS HTLC/session join with deadline-safe upward conversion
  to HSD's 512-second time-lock granularity;
- recovery-safe status validation after the new-funding window closes;
- exact recognized Denuo versions with zero flags and a 512 KiB typed
  marketplace cap;
- source-independent, versioned, SHA-256-sidecarred protocol vectors covering
  signed objects, full envelopes, descriptors, transactions, signature hashes,
  and transaction IDs; and
- resumable publication checks requiring exact `.crate` bytes and release VCS
  identity before an existing package version is skipped.

All public workspace packages advance together so changed crates never attempt
to overwrite the already-published `0.1.0` line. No `0.2.0` package or tag is
published by this source commit.

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
