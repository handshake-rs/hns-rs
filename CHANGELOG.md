# Changelog

All notable changes to the `hns-rs` workspace are documented in this file.
The workspace crates use a shared version and follow Semantic Versioning.

## 0.5.1 - 2026-10-24

- Upgrade secp256k1 ECDSA to k256 0.14 and crypto-bigint 0.7.7 to address RUSTSEC-2026-0387.
- Preserve canonical low-S signatures and SEC1 encoding across marketplace, swap, HRM, and script validation.
- Update ctutils to 0.4.5 to address RUSTSEC-2026-0385.

## 0.5.0 - 2026-09-28

- Make the signed direct-offer responder the swap maker throughout the
  marketplace protocol, preserving the same role in session and swap messages.
- Remove the pre-release direct-offer role model and its incompatible wire
  decoding paths from the experimental peer protocol.
- Release the coherent nineteen-crate protocol cohort so dependent wallets and
  applications resolve one version and type graph.
