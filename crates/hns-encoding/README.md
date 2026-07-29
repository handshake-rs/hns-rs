# hns-encoding

Strict, allocation-bounded binary encoding for Handshake wire protocols.

This crate provides little-endian integers, canonical compact sizes, bounded
variable-length byte strings, and complete-input decoding. It is runtime
independent and shared by the protocol crates in the
[`hns-rs`](https://github.com/handshake-rs/hns-rs) workspace.

```bash
cargo add hns-encoding
```

The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-encoding).

Licensed under either Apache-2.0 or MIT.
