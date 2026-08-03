# hns-rs

Canonical Rust protocol primitives for the Handshake ecosystem.

This production protocol workspace is intentionally independent of async
runtimes, databases, wallets, browser shells, and mining applications. Private
peer-to-peer assignments retain the name **Denuo Experimental — not official
Handshake protocol assignments**; that label describes assignment governance,
not implementation maturity. Registry V2 is additive and preserves the exact
V1 identity.

The implemented protocol layer contains:

- semantic Handshake value types;
- allocation-bounded binary encoding, canonical compact sizes, and varbytes;
- 236-byte headers, PoW/share hashing, compact targets, chainwork, retargeting,
  network parameters, and genesis vectors;
- canonical transactions, witness hashing, addresses, outputs, and coins;
- all assigned name-covenant wire tags, HNS name hashing, blind bids, exact
  HSD NameState values, typed lossless resource decoding, authenticated
  name/key and owner-outpoint semantics, strict TRANSFER/FINALIZE field and
  linked-transaction construction, and non-coinbase covenant-link validation;
- HSD-compatible signature hashing, absolute/relative lock predicates, and
  sigop-adjusted minimum-fee policy arithmetic with explicit units;
- a production script interpreter differentially matched to all 876 pinned HSD
  script vectors, including Handshake `OP_TYPE`;
- HIP-0001/Shakedex v2 fixed-price and bounded reverse-Dutch swap primitives,
  including canonical buyer fulfillment, seller cancellation transactions,
  and listing-independent lock descriptors and recovery construction from a
  seed-derived seller key, explicit network binding, and chain-discovered exact
  locking coin;
- signed fixed-price listing/cancellation wrappers and native HNS HTLC
  primitives joined directly to bilateral session commitments;
- canonical HNS/BTC and HNS/ETH asset, intent, price-round, fill-grant, and
  bilateral swap-session wire values;
- bounded HSD-compatible Urkel inclusion and non-inclusion proofs;
- runtime-independent standard HSD framing and all standard packet IDs;
- HSD-compatible block commitments, subsidy/coinbase vectors, and immutable
  opened-mask mining jobs;
- a bounded cross-protocol production-parser mutation and libFuzzer harness;
- the canonical Denuo Experimental Handshake P2P Registries v1 and v2;
- semantic wire-assignment profiles;
- the versioned Denuo extension envelope and registry negotiation messages;
- HIP #76 DNS relay, HIP #77 ODoH/HPKE, HIP #78 HNSR protocol values, HIP PR
  #79 HNSA service-authority objects, and the local versioned HNSA/HNSR named
  route adapter;
- bounded in-process HNSR reservation, renewal, confirmation, withdrawal,
  named-route publication, and lookup state machines for composition by an
  authenticated transport owner;
- strict owner-bound HNS Chat resource identity, original owner-key parity
  recovery, HNSA authority synthesis for `hns.chat`, and bounded opaque NIP-59
  gift-wrap and encrypted-acknowledgement values for HIP-78 transport.

Source-independent exact V1 settlement and marketplace vectors live in
`fixtures/protocol-v1/` with SHA-256 sidecars and a standard-library generator.
Pinned-HSD NameState and compressed resource vectors live in
`fixtures/hsd/name-state-resource-v1.txt` with their own deterministic oracle
generator and SHA-256 sidecar. Pinned sigop-size and minimum-policy-fee vectors
live beside them in `fixtures/hsd/fee-policy-v1.txt`.
Source-independent HNS Chat resource grammar fixtures live in
`fixtures/chat-v1/`.

See `docs/protocol-authority.md` and `docs/provenance.md` for fixture authority,
`docs/experimental-p2p-registry.md` for assignment status and governance, and
`docs/marketplace-protocol.md` for the canonical market verifier.

## Crates

The public crates are:

- `hns-encoding` and `hns-primitives`;
- `hns-covenants`, `hns-transaction`, `hns-header-consensus`,
  `hns-urkel-proof`, and `hns-script`;
- `hns-swap`, `hns-marketplace-protocol`, `hns-mining`, and `hns-p2p-wire`;
- `hns-p2p-experimental`, `hns-dns-relay-protocol`,
  `hns-odoh-protocol`, `hns-hnsr-protocol`, `hns-service-authority`, and
  `hns-chat-protocol`.

The conformance harness, fuzz package, and deterministic registry generator are
development tooling and are intentionally private. See `docs/releasing.md` for
the release allowlist, dependency order, and publication procedure.

## Qualification

Run the locked protocol, registry reproducibility, dependency-policy,
feature-matrix, release, fuzz-compilation, and deterministic parser-smoke gates
with:

```bash
./scripts/check.sh
```

CI also audits the root and independent fuzz lockfiles with a pinned RustSec
scanner.

The HNSR service state machines are an embeddable protocol boundary, not a
durable daemon or network transport. Persistence, restart recovery, peer
policy, and deployment qualification remain responsibilities of the embedding
node and must pass that product's release gate.
