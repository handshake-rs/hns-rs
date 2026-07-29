# Changelog

All notable changes to the `hns-rs` workspace are documented in this file.
The workspace crates use a shared version and follow Semantic Versioning.

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
