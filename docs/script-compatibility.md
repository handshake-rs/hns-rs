# Script compatibility

`hns-script` contains the runtime-independent HSD script interpreter, witness
program gate, signature hashing, compact secp256k1 verification, sigop
accounting, sigop-adjusted policy virtual size, minimum-policy-fee arithmetic,
lock predicates, and Handshake `OP_TYPE` introspection.

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

## Fee-policy arithmetic

The fee-policy boundary follows
`handshake-org/hsd@698e252ebc7b5c1dd0a9587e342fdd153d020ae4`.
`lib/primitives/tx.js#getSigopsSize` takes the larger of serialized transaction
weight and sigop cost multiplied by `lib/protocol/policy.js`'s 20 bytes per
sigop, then ceiling-divides by the consensus witness scale factor of four.
`transaction_policy_virtual_size` obtains that sigop cost only through the
existing transaction/input-coin outpoint binding.

`minimum_policy_fee` reproduces `lib/protocol/policy.js#getMinFee`: rates are
dollarydoos per 1,000 policy virtual bytes, multiplication is floor-divided by
1,000, and a nonzero size/rate pair whose quotient is zero returns the full
rate. It does not substitute the separate HSD `getRoundFee` whole-kilobyte
operation. `TransactionWeight`, `SigopCost`, `PolicyVirtualSize`, and `FeeRate`
make each public unit explicit. Rust arithmetic is checked, the public scalar
units are bounded to `u32`, and fees use the canonical `Dollarydoos` value.

Standardness remains a separate decision, as it is in HSD. The exact pinned
caps are exposed as `MAX_POLICY_TRANSACTION_WEIGHT` (400,000 weight units) and
`MAX_POLICY_TRANSACTION_SIGOPS` (16,000), but the size function does not hide
evidence for an out-of-policy transaction by applying those checks itself.

`fixtures/hsd/fee-policy-v1.txt` covers ceiling, sigop-dominant, floor,
nonzero-rate fallback, maximum unsigned fee rate, standard-policy, and
consensus boundaries. Its generator refuses source drift by authenticating
these exact pinned files before calling the HSD oracle:

- `lib/primitives/tx.js` SHA-256
  `7681f599330cba3ff72529da899ed309daa628f3efd500c5d04ba89dd5be9300`;
- `lib/protocol/policy.js` SHA-256
  `1d8840bc6b8b6b4c78fa2e73337f3665b5b65329d650c44589b4a8a67a44a60e`;
- `lib/protocol/consensus.js` SHA-256
  `9342ee033ca27fe1539b6047fbd3529bb912ae2cdbe456adf7828798fb5cc8a2`.

This tranche initially had static source, fixture, and sidecar review only.
Converged feature head `b33b346780c8f6a9bb18a54390019486cdab0221`
subsequently passed the complete locked gate in CI run `31369025777`, and
undated release-preparation commit
`abf11ff3b16920c08f3c0b6d32d2e1af7cbe37b2` passed locked CI run
`31385655990` plus the manual 17-package release preflight run `31386373480`.
Its CodeQL run `31385656053` remained incomplete because the
JavaScript/TypeScript job did not leave the queue. Dated source commit
`b24b66c382de53330ec21dd3137e056a2bea3e2d` then passed exact-head locked CI
and RustSec run `31398600728`, all four configured CodeQL analyses in run
`31398598588`, and the manual 17-package release preflight run `31399004538`.
The non-yanked `0.2.0` package was subsequently verified against that exact
source commit as recorded in `docs/releasing.md`. Any later source commit
requires its own gates; this package record does not qualify a downstream
wallet, node, or other product.
