# Changelog

All notable changes to the `hns-rs` workspace are documented in this file.
The workspace crates use a shared version and follow Semantic Versioning.

## Unreleased

- Add an opt-in `shakedex-json` feature to `hns-swap` that reads and writes Shakedex v2 auction JSON, the listing format LearnHNS Market serves, Bob Wallet imports, and the shakedex CLI writes. Only version 2 is accepted, `expiresAt` is carried through unenforced, a `feeAddr` paired with a zero fee decodes as no fee output, and every price step still passes `DutchAuction::new`. Decoding is verified against two live LearnHNS Market listings, which round-trip unchanged.

## 0.5.0 - 2026-09-28

- Make the signed direct-offer responder the swap maker throughout the
  marketplace protocol, preserving the same role in session and swap messages.
- Remove the pre-release direct-offer role model and its incompatible wire
  decoding paths from the experimental peer protocol.
- Release the coherent nineteen-crate protocol cohort so dependent wallets and
  applications resolve one version and type graph.
