# hns-script

Handshake script, signature hashing, and fee-policy primitives.

This crate provides HSD-compatible signature hashing and a production script
interpreter, including Handshake `OP_TYPE`. It also exposes input-coin-bound
sigop counting, sigop-adjusted policy virtual size, and HSD's exact minimum-fee
rounding through explicit weight, sigop, virtual-byte, and fee-rate units. It
is part of the [`hns-rs`](https://github.com/handshake-rs/hns-rs) protocol
workspace.

```bash
cargo add hns-script
```

The minimum supported Rust version is 1.89. API documentation is available on
[docs.rs](https://docs.rs/hns-script).

Licensed under either Apache-2.0 or MIT.
