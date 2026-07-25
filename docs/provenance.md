# Provenance

The canonical workspace is a clean-room Rust implementation built from pinned
public protocol sources, differential fixtures, and independently written
tests.

| Surface | Authority snapshot | Status |
| --- | --- | --- |
| Handshake consensus and standard wire | `handshake-org/hsd@698e252ebc7b5c1dd0a9587e342fdd153d020ae4` | official deployed behavior |
| HIP-0001 swap construction | HIP-0001 plus `kurumiimari/shakedex@ab5687b04cb61d2548937b8cee3c056c1c75bbdc` | published HIP and ecosystem implementation |
| DNS relay | HIP PR 76 and HSD PR 958, as recorded by the integration reference audit | draft; Denuo Experimental V1 |
| ODoH relay | HIP PR 77 at `d3ae6be483663ed6cf0ead4f4b4f17a80b1d1162`; HSD PR 959 at `909311d97c794eb59ed2eb0b095a122607ae078e` | draft; Denuo Experimental V1 |
| HNSR | HIP PR 78 at `53b962e901ffa796f4ccf66a5d53956d7421c58c`; HSD PR 960 at `2fc40f1c61ff16a2f39d9514cd950d1560430ced` | draft; Denuo Experimental V1 |
| Experimental assignment registry | `registry/denuo-experimental-v1.toml` and its canonical binary/hash | Denuo Experimental V1, not official |

Source archives named in the assignment were not present in the supplied
workspace. The integration source audit records that absence and the exact
public repositories used instead. No value inferred from prose is promoted
over a conflicting pinned implementation fixture.

Generated artifacts carry their oracle revision in their manifest. Registry
bytes are produced by `hns-registry-gen` from a deterministic canonical
encoding; ordinary TOML/JSON serialization is never hashed as the registry
fingerprint.
