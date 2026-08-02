# Parser fuzzing

The `hns-conformance` crate is the stable, bounded parser harness. It invokes
the production parsers directly and provides deterministic truncation,
extension, length-byte, and bit-flip mutations under both case-count and
aggregate-byte ceilings. Parser errors are ordinary outcomes; any panic fails
the smoke test.

`fuzz/fuzz_targets/production_parsers.rs` is the matching `cargo-fuzz`
entrypoint. It is kept outside the release workspace so libFuzzer and a nightly
compiler never become dependencies of the protocol crates. The deterministic
smoke corpus remains part of the normal stable-toolchain gate.

Canonical Denuo name-market and cross-chain-market envelopes are included as
exact seeds, and their typed production decoders share this target. DNS
wire/DNSSEC/TLSA, native messaging, and proxy request heads live in downstream
repositories and must join the cross-project qualification gate as those
production parsers land.
