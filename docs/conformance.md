# Conformance

Current canonical protocol coverage:

| Requirement | Crate | Evidence |
| --- | --- | --- |
| semantic values and checked integer arithmetic | `hns-primitives` | unit tests and strict Clippy |
| bounded little-endian/compact encoding | `hns-encoding` | canonical, truncation, trailing, and bound tests |
| headers, PoW, targets, chainwork, retargets, networks, genesis | `hns-header-consensus` | HSD/genesis differential vectors |
| transactions, IDs, witness behavior | `hns-transaction` | HSD transaction/sighash fixtures |
| script execution, `OP_TYPE`, lock predicates, sighash | `hns-script` | exact results for all 876 pinned HSD script cases plus mode and coin-binding tests |
| name covenants, validation, hashes, linkage | `hns-covenants`, `hns-transaction` | round-trip and state-link tests |
| Urkel proof parsing and verification | `hns-urkel-proof` | exact HSD positive and mutation-derived negative vectors |
| standard P2P frames and packets | `hns-p2p-wire` | exact HSD `wire-v1` and compact-block vectors, bounded-stream and reconstruction negatives |
| block commitments and mining jobs | `hns-mining` | HSD subsidy/coinbase vectors, domain-separated roots, stale/mask/time/PoW tests |
| cross-protocol parser hardening | `hns-conformance`, `fuzz/` | exact protocol seeds plus bounded truncation/extension/length/bit mutations against production parsers |
| private Denuo registry and negotiation | `hns-p2p-experimental` | canonical V1/V2 registry fingerprints, exact-version/zero-flag classification, and collision tests |
| HIP #76 | `hns-dns-relay-protocol` | exact draft envelope and policy tests |
| HIP #77 | `hns-odoh-protocol` | exact draft/RFC cryptographic vectors |
| HIP #78 | `hns-hnsr-protocol` | exact draft records, signatures, store, and envelope vectors |
| HIP-0001/Shakedex v2 | `hns-swap` | exact proof, seller digest, presigned transaction, buyer fulfillment, recovery transfer, IDs, script, price, and locktime vectors |
| signed name listings and native HNS HTLC | `hns-swap` | fixed listing/cancellation plus exact descriptor, script, address, funding, redeem, refund, sighash, TXID, and preimage vectors |
| market intents, price rounds, fill grants, and swap sessions | `hns-marketplace-protocol` | externally generated exact signed bytes plus arithmetic, quorum/outlier/circuit-breaker, identity, timeout, status, and replay negatives |
| typed Denuo name/cross-chain markets | `hns-marketplace-protocol`, `hns-conformance`, `fuzz/` | exact full envelopes plus bounded full-consumption production parsers |

This is a living qualification index, not a claim that the wider ecosystem is
already complete. Cross-project differential generators, downstream parser
targets, sustained fuzz campaigns, benchmarks, and regtest qualification
remain tracked by the integration matrix until implemented and green.

The checked-in V1 oracle documents and SHA-256 sidecars live under
`fixtures/protocol-v1/`. Tests consume those files directly; constants are not
copied into a second test-only representation.
