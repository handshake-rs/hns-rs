# Repository constraints

- Rust edition 2024, MSRV 1.89, workspace resolver 3.
- Keep shared protocol crates independent of Tokio, storage engines, wallets,
  platform ABIs, browser code, and MeshMine.
- Bound every wire allocation before allocating and require complete input
  consumption.
- Refer to packet and service assignments semantically. Never describe Denuo
  Experimental V1 values as official Handshake assignments.
- Do not push from this repository.

