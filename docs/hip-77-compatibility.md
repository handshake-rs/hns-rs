# HIP #77 compatibility

`hns-odoh-protocol` is the runtime-independent implementation of the draft
Handshake P2P Oblivious DNS Relay protocol. Its compatibility targets are:

- HIPs pull request #77 through commit
  `d3ae6be483663ed6cf0ead4f4b4f17a80b1d1162`;
- hsd pull request #959 through commit
  `909311d97c794eb59ed2eb0b095a122607ae078e`; and
- RFC 9230 message/configuration encoding and RFC 9180 base-mode HPKE using
  DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.

These are draft, experimental assignments. The Denuo v1 profile uses service
bit `0x20000000` and packet type `0xf2`; negotiation and collision isolation
are provided by `hns-p2p-experimental`.

## Implemented shared protocol surface

The crate implements:

- strict little-endian `ODNS` v1 envelopes and opcodes;
- capability, configuration, client-query, target-query, response, cancel, and
  generic-error bodies;
- direct Brontide locators bound to a compressed secp256k1 peer identity;
- public-address enforcement with an explicit private-address test profile;
- RFC 9230 config lists, key IDs, plaintext padding, messages, query HPKE, and
  response AEAD derivation;
- strict-low-S DER target configuration signatures, network/locator binding,
  configuration lifetime validation, and record identifiers;
- exact allocation limits, complete-input checks, all-zero padding checks, and
  zeroization of decrypted queries, response secrets, and stored query
  plaintext; and
- the published hsd deterministic fixture in
  `fixtures/hsd/odoh-v1-vectors.json`.

The direct target locator is fixed by its signed record. No protocol function
accepts an arbitrary resolver host or port independently of that authenticated
record.

## Runtime responsibilities

This crate intentionally has no network runtime, database, wallet, UI, or
MeshMine dependency. The consuming node or browser runtime remains responsible
for independent per-hop request IDs, replay windows, bounded proxy maps,
cancellation propagation, key rotation and overlap, retired-key wiping,
requester/proxy/target policy, rate limits, deadlines, disconnect cleanup, and
local HNS-state, DNSSEC, and DANE validation.

An HNSR target locator is only accepted after HIP #78 is enabled and
authenticated. It belongs to the shared HNSR transport layer rather than being
silently interpreted as a direct locator here.

Opaque ODoH proxy participation defaults on and has an independent persistent
opt-out. Target/output-node participation defaults off and requires explicit
opt-in. Proxy consent never enables the target role, and the target never
inherits requester settings.

`OBLIVIOUS_REQUIRED` must never fall back to direct relay. The shared policy
types express that distinction; consuming runtimes must persist and enforce
the selected mode.

## Verification

Run:

```sh
cargo test -p hns-odoh-protocol
cargo clippy -p hns-odoh-protocol --all-targets -- -D warnings
```

The tests cover the exact published locator, config, key-ID, padded plaintext,
response KDF, signed record, and record-ID vectors; a complete requester/target
HPKE round trip; strict bodies; wrong keys; invalid public targets; and nonzero
or trailing padding.
