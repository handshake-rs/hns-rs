# hns-rs

Canonical Rust protocol primitives for the Handshake ecosystem.

This workspace is intentionally independent of async runtimes, databases, wallets,
browser shells, and mining applications. Experimental peer-to-peer assignments are
identified as **Denuo Experimental V1 — not an official Handshake protocol
assignment**.

The implemented protocol layer contains:

- semantic Handshake value types;
- allocation-bounded binary encoding, canonical compact sizes, and varbytes;
- 236-byte headers, PoW/share hashing, compact targets, chainwork, retargeting,
  network parameters, and genesis vectors;
- canonical transactions, witness hashing, addresses, outputs, and coins;
- all assigned name-covenant wire tags, HNS name hashing, blind bids, resource
  bounds, and non-coinbase covenant-link validation;
- HSD-compatible signature hashing and absolute/relative lock predicates;
- a production script interpreter differentially matched to all 876 pinned HSD
  script vectors, including Handshake `OP_TYPE`;
- HIP-0001/Shakedex v2 fixed-price and bounded reverse-Dutch swap primitives;
- bounded HSD-compatible Urkel inclusion and non-inclusion proofs;
- runtime-independent standard HSD framing and all standard packet IDs;
- HSD-compatible block commitments, subsidy/coinbase vectors, and immutable
  opened-mask mining jobs;
- a bounded cross-protocol production-parser mutation and libFuzzer harness;
- the canonical Denuo Experimental Handshake P2P Registry v1;
- semantic wire-assignment profiles;
- the versioned Denuo extension envelope and registry negotiation messages;
- HIP #76 DNS relay, HIP #77 ODoH/HPKE, and HIP #78 HNSR protocol values.

See `docs/protocol-authority.md` and `docs/provenance.md` for fixture authority,
and `docs/experimental-p2p-registry.md` for assignment status and governance.

## Qualification

Run the locked protocol, registry reproducibility, dependency-policy,
feature-matrix, release, fuzz-compilation, and deterministic parser-smoke gates
with:

```bash
./scripts/check.sh
```

CI also audits the root and independent fuzz lockfiles with a pinned RustSec
scanner.
