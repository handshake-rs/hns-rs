# Script compatibility

`hns-script` contains the runtime-independent HSD script interpreter, witness
program gate, signature hashing, compact secp256k1 verification, sigop
accounting, lock predicates, and Handshake `OP_TYPE` introspection.

The differential corpus in `fixtures/hsd/script-tests-v1.txt` contains all 876
cases from
`handshake-org/hsd@698e252ebc7b5c1dd0a9587e342fdd153d020ae4`
`test/data/script-tests.json`. It pins the upstream corpus SHA-256
`71548a587d1c7921cb899de192f59ed1833c85a6cd62d9dac8cd5b86b1225c86`.
Each case retains the exact encoded script, witness stack, amount, locktime,
sequence, flags, and HSD result code. The Rust test reconstructs HSD's funding
and spending transactions and requires the production witness/interpreter path
to return the same result.

`generators/generate-hsd-script-vectors.js` regenerates the fixture only after
verifying both the pinned corpus hash and the pinned HSD `script.js` hash. It
uses the JavaScript cryptography backend so native addons are not required:

```sh
node generators/generate-hsd-script-vectors.js /path/to/hsd
cargo test -p hns-script
cargo clippy -p hns-script --all-targets -- -D warnings
```

The witness verifier binds the supplied resolved coin to the transaction's
exact input outpoint before using its address or value. Version-zero 20-byte
and 32-byte witness programs execute with HSD's mandatory limits and failure
codes; unknown witness versions remain forward-compatible unless standard
policy explicitly discourages them.
