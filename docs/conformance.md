# Conformance

Current canonical protocol coverage:

| Requirement | Crate | Evidence |
| --- | --- | --- |
| semantic values and checked integer arithmetic | `hns-primitives` | unit tests and strict Clippy |
| bounded little-endian/compact encoding | `hns-encoding` | canonical, truncation, trailing, and bound tests |
| headers, PoW, targets, chainwork, retargets, networks, genesis | `hns-header-consensus` | HSD/genesis differential vectors |
| transactions, IDs, witness behavior | `hns-transaction` | HSD transaction/sighash fixtures |
| lock predicates, sighash, swap script primitives | `hns-script` | HSD mode matrix and mutation tests |
| name covenants, validation, hashes, linkage | `hns-covenants`, `hns-transaction` | round-trip and state-link tests |
| Urkel proof parsing and verification | `hns-urkel-proof` | exact HSD positive and mutation-derived negative vectors |
| standard P2P frames and packets | `hns-p2p-wire` | exact HSD `wire-v1` vectors and bounded-stream negatives |
| experimental registry and negotiation | `hns-p2p-experimental` | canonical registry fingerprint and collision tests |
| HIP #76 | `hns-dns-relay-protocol` | exact draft envelope and policy tests |
| HIP #77 | `hns-odoh-protocol` | exact draft/RFC cryptographic vectors |
| HIP #78 | `hns-hnsr-protocol` | exact draft records, signatures, store, and envelope vectors |
| HIP-0001/Shakedex v2 | `hns-swap` | exact script/sighash plus price and locktime regressions |

This is a living qualification index, not a claim that the wider ecosystem is
already complete. Mining primitives, a complete standalone script VM in this
repository, dedicated conformance/fuzz packages, and cross-project regtest
qualification remain tracked by the integration matrix until implemented and
green.
