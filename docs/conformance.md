# Conformance

Current canonical protocol coverage:

| Requirement | Crate | Evidence |
| --- | --- | --- |
| semantic values and checked integer arithmetic | `hns-primitives` | unit tests and strict Clippy |
| bounded little-endian/compact encoding | `hns-encoding` | canonical, truncation, trailing, and bound tests |
| headers, PoW, targets, chainwork, retargets, networks, genesis | `hns-header-consensus` | HSD/genesis differential vectors |
| transactions, IDs, witness behavior | `hns-transaction` | HSD transaction/sighash fixtures |
| script execution, `OP_TYPE`, lock predicates, sighash, fee policy | `hns-script` | exact results for all 876 pinned HSD script cases plus coin-bound sigops and source-hash-pinned virtual-size/minimum-fee vectors |
| name covenants, validation, hashes, linkage | `hns-covenants`, `hns-transaction` | round-trip and state-link tests |
| authenticated NameState and resources | `hns-covenants`, `hns-primitives` | exact pinned-HSD value/resource bytes, key/name binding, shared null-owner outpoint, compression, truncation, unknown-bit/tag, noncanonical, trailing, and allocation-bound cases |
| Urkel proof parsing and verification | `hns-urkel-proof` | exact HSD positive and mutation-derived negative vectors |
| standard P2P frames and packets | `hns-p2p-wire` | exact HSD `wire-v1` and compact-block vectors, bounded-stream and reconstruction negatives |
| block commitments and mining jobs | `hns-mining` | HSD subsidy/coinbase vectors, domain-separated roots, stale/mask/time/PoW tests |
| cross-protocol parser hardening | `hns-conformance`, `fuzz/` | exact protocol seeds plus bounded truncation/extension/length/bit mutations against production parsers |
| private Denuo registry and negotiation | `hns-p2p-experimental` | canonical V1/V2 registry fingerprints, exact-version/zero-flag classification, and collision tests |
| HIP #76 | `hns-dns-relay-protocol` | exact draft envelope and policy tests |
| HIP #77 | `hns-odoh-protocol` | exact draft/RFC cryptographic vectors |
| HIP #78 | `hns-hnsr-protocol` | exact draft records, signatures, bounded stores and envelopes, plus live reservation/renewal/confirmation/withdrawal and route publication/lookup state-machine tests |
| HNSA/HNSR named routes | `hns-service-authority`, `hns-hnsr-protocol`, `hns-conformance` | version-2 route round trip, complete authority validation, stable identity key, capabilities, ticket binding, bounded storage admission, and parser mutation coverage |
| owner-bound HNS Chat | `hns-chat-protocol`, `hns-hnsr-protocol`, `hns-conformance`, `fuzz/` | strict resource fixtures, even/odd original owner parity, raw witness-program matching, stale/P2WSH rejection, HNSA generation binding, opaque envelope/acknowledgement bounds, duplicate IDs, complete route-chain admission, and parser mutation coverage |
| HIP-0001/Shakedex v2 | `hns-swap` | exact proof, seller digest, presigned transaction, buyer fulfillment, recovery transfer, later FINALIZE transaction/witness, IDs, script, price, and locktime vectors |
| signed name listings and native HNS HTLC | `hns-swap` | complete fixed listing/cancellation envelopes plus exact descriptor, script, address, funding, redeem, refund, sighash, TXID, and preimage vectors |
| market intents, price rounds, fill grants, and swap sessions | `hns-marketplace-protocol` | externally generated exact signed bytes plus arithmetic, quorum/outlier/circuit-breaker, identity, timeout, status, and replay negatives |
| typed Denuo name/cross-chain markets | `hns-marketplace-protocol`, `hns-conformance`, `fuzz/` | exact full envelopes plus bounded full-consumption production parsers |

This is a living qualification index, not a claim that the wider ecosystem is
already complete. Cross-project differential generators, downstream parser
targets, sustained fuzz campaigns, benchmarks, and regtest qualification
remain tracked by the integration matrix until implemented and green.

The checked-in V1 settlement/market oracle documents and SHA-256 sidecars live
under `fixtures/protocol-v1/`. Exact HSD NameState/resource bytes and source
hashes live in `fixtures/hsd/name-state-resource-v1.txt`; exact fee-policy
vectors and their transaction/policy/consensus source hashes live in
`fixtures/hsd/fee-policy-v1.txt`. Tests consume these documents directly; the
conformance mutation harness also routes NameState and resource inputs through
the same public decoders. HNS Chat grammar vectors live under
`fixtures/chat-v1/` and are consumed by both the crate and aggregate harness.

The NameState/resource, fee-policy, typed TRANSFER/FINALIZE,
listing-independent Shakedex recovery, empty name-market inventory, live HNSR
service, and owner-bound chat tranches retain focused source tests and exact
vectors where applicable. The repository's full locked qualification gate was
not rerun for their converged `main` commit; that remains required before the
unreleased 0.2.0 line can be published. Static vectors and in-memory service
tests do not establish live-chain ownership, transfer maturity, renewal-block
eligibility, durable relay recovery, deployed peer policy, or reorg behavior.
