# Changelog

All notable changes to the `hns-rs` workspace are documented in this file.
The workspace crates use a shared version and follow Semantic Versioning.

## 0.2.0 - unreleased

Release-candidate source for the modular wallet and marketplace boundary:

- additive Denuo Experimental Registry V2, preserving the exact V1 identity
  while assigning the separately negotiated cross-chain marketplace protocol;
- canonical bounded market intents, observations, deterministic price rounds,
  fill grants, and bilateral swap-session/status messages;
- signed fixed-price name listings and cancellations; and
- native SHA-256 Handshake HTLC funding, redeem, refund, and preimage
  primitives.

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
