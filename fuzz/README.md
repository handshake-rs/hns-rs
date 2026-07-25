# Fuzzing

`production_parsers` sends the same bounded input to the production header,
block, transaction, script, covenant, standard-frame, Denuo envelope, HIP #76,
HIP #77, HIP #78, Urkel-proof, and swap-proof parsers.

Run the deterministic stable-toolchain smoke corpus:

```sh
./scripts/fuzz-smoke.sh
```

Run libFuzzer when `cargo-fuzz` and a compatible nightly toolchain are
available:

```sh
cargo fuzz run production_parsers -- -max_len=4000000
```
