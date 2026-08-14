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
- deterministic-CBOR Handshake Resource Manifest commitments, envelopes,
  controller signatures, resources, delegations, and bounded validation;
- semantic wire-assignment profiles;
- the versioned Denuo extension envelope and registry negotiation messages;
- HIP #76 DNS relay, HIP #77 ODoH/HPKE, HIP #78 HNSR protocol values, HIP PR
  #79 legacy HNSA compatibility objects, the HRM-backed
  `hns.named-service/v1` profile and endpoint authority, and explicitly
  separated HNSA/HNSR named-route versions 2 and 3;
- bounded in-process HNSR reservation, renewal, confirmation, withdrawal,
  named-route publication, and lookup state machines for composition by an
  authenticated transport owner;
- strict owner-bound HNS Chat resource identity, original owner-key parity
  recovery, an owner-bound authority adapter for the HIP-compliant HNSA service
  name `chat`, and bounded opaque NIP-59 gift-wrap and
  encrypted-acknowledgement values for the `hns.chat` HIP-78 profile.

Source-independent exact V1 settlement and marketplace vectors live in
`fixtures/protocol-v1/` with SHA-256 sidecars and a standard-library generator.
Pinned-HSD NameState and compressed resource vectors live in
`fixtures/hsd/name-state-resource-v1.txt` with their own deterministic oracle
generator and SHA-256 sidecar. Pinned sigop-size and minimum-policy-fee vectors
live beside them in `fixtures/hsd/fee-policy-v1.txt`.
Source-independent HNS Chat resource, owner-parity, envelope, acknowledgement,
and rejection vectors live in `fixtures/chat-v1/` with a SHA-256 sidecar. The
same authenticated assets and their external-consumer test are included in the
`hns-chat-protocol` source package.
Source-independent deterministic-CBOR, controller-signature, envelope,
commitment, and rejection vectors for HRM Core live in `fixtures/hrm-v1/` with
a standard-library Python oracle and authenticated package copy.
Source-independent HRM-backed HNSA and HNSR NamedRouteV3 vectors live in
`fixtures/hnsa-hnsr-v3/`. They pin the complete signed chain, generation and
route replacement failures, durable authority/requester/storage snapshots,
and 64-bit values beyond JavaScript's exact `Number` range; profile `0xff00`
remains fixture-private test data rather than a deployed application
assignment.

See `docs/protocol-authority.md` and `docs/provenance.md` for fixture authority,
`docs/experimental-p2p-registry.md` for assignment status and governance, and
`docs/marketplace-protocol.md` for the canonical market verifier.

## Crates

The public crates are:

- `hns-encoding`, `hns-hrm`, and `hns-primitives`;
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

Release metadata, the shared version, internal dependency order, package docs,
licenses, changelogs, and private-package boundaries can be checked without a
build:

```bash
python3 scripts/verify-release.py --toolchain 1.89.0
```

See `docs/releasing.md` before any package dry-run or irreversible publication.

The workspace is an unpublished `0.3.0` development line. The prior dated
`0.2.0` source commit
`b24b66c382de53330ec21dd3137e056a2bea3e2d` passed exact-head CI, complete
four-language CodeQL analysis, and the explicit 17-package release preflight;
`v0.1.0` remains the latest published and tagged release. Those results qualify
only that exact source commit and do not qualify the 18-package `0.3.0` line.
Any later source commit must repeat the release gates documented in
`docs/releasing.md` before publication.

The HNSR service state machines are an embeddable protocol boundary, not a
durable daemon or network transport. Persistence, restart recovery, peer
policy, and deployment qualification remain responsibilities of the embedding
node and must pass that product's release gate.
