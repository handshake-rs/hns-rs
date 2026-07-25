# Urkel proof compatibility

`hns-urkel-proof` implements the proof encoding used by HSD's Handshake name
tree at `handshake-org/hsd@698e252ebc7b5c1dd0a9587e342fdd153d020ae4`.
It supports dead-end, short, collision, and inclusion terminals; compressed
ancestor paths; BLAKE2b-256 leaf/internal hashes; and both inclusion and
non-inclusion verification against a typed tree root and name hash.

Two decoders make the trust decision explicit:

- `decode_hsd` reproduces upstream behavior, including ignored trailing bytes;
- `decode_strict` requires one complete, canonically encoded proof.

Network admission and persisted data must use the strict decoder. Compatibility
tools may use the HSD decoder only when they deliberately need to reproduce an
upstream parse. Both paths apply the upstream maximum proof bound before any
variable allocation.

Tests pin exact HSD-generated inclusion, empty-tree, short non-inclusion, and
collision non-inclusion proofs. They also cover wrong roots, wrong keys,
terminal mutation, noncanonical prefixes, truncation, and the upstream
trailing-byte difference.

Run:

```sh
cargo test -p hns-urkel-proof
cargo clippy -p hns-urkel-proof --all-targets -- -D warnings
```
