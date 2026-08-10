# Owner-bound HNS Chat protocol

Status: source-implemented protocol boundary for software-controlled standard
single-key owner outputs. Installed-device, full Nostr-vector, regtest,
publication, release, and mainnet qualification remain separate gates.

## Release-source boundary

`hns-chat-protocol` is the sole canonical Rust owner-binding and opaque mailbox
value boundary. Downstream repositories consume its public values rather than
copying wire structs, version bytes, limits, resource parsing, or owner-key
logic. The public API includes the wire version, exact maximum encoded sizes,
payload/retention limits, validation for programmatically constructed values,
and the opaque verified-owner result used to derive an HNSA authority record.

The crate manifest has an explicit source-package inventory containing its
source, licenses, README, integration test, valid/invalid vectors, and vector
SHA-256 sidecar. The release preflight inspects Cargo's normalized `.crate`,
requires every boundary file, rejects any surviving path dependency, and
authenticates the packaged vector bytes. A focused preflight is available as
`./scripts/publish.sh --dry-run hns-chat-protocol`; it neither publishes nor
tags. Until `0.2.0` is intentionally published, downstream release source must
use an immutable repository revision rather than a sibling path, and must not
claim a crates.io release exists.

## Identity and resource binding

The canonical authenticated resource text is:

```text
hnschat=v1;key=owner;pk=<64-lowercase-hex>;generation=<nonzero-u32>
```

The parser accepts the initial compatibility form without `generation` and
interprets it as generation 1. The encoder always emits the explicit field.
Parsing is ASCII-only, whitespace-free, fixed-order, duplicate-free, and
unknown-field-free. The key is a valid 32-byte x-only secp256k1 coordinate; it
is not an `hs1...` witness-program address or a 33-byte SEC1 key. More than one
candidate `hnschat` TXT record is ambiguous and fails closed.

The current owner proof reconstructs both `02 || x` and `03 || x`, validates
both curve points, derives each canonical Handshake version-zero
BLAKE2b-160 single-key witness program, and compares raw program bytes with the
current owner output. Exactly one original compressed key must match. The code
does not assume even Y and does not use a BIP-340-normalized point to prove the
Handshake owner address.

The resulting original compressed key supplies the owner-bound profile's
authority adapter and `hnschat.generation` supplies its authority epoch for the
HIP-compliant HNSA service name `chat`. The x coordinate remains the Nostr
identity. Downstream wallet code remains responsible for established BIP-340
signing, exact NIP-44 v2, NIP-17, and NIP-59 behavior while keeping all private
scalars and conversation keys inside the wallet boundary.

## HNSA and HIP-78

The generated HNSR service-profile registry allocates:

| Profile | ID |
| --- | ---: |
| `hns.node` v1 | 1 |
| `hns.web` v1 | 2 |
| `hns.chat` v1 | 3 |

`hns.chat` is the registry/profile-layer label. It is never placed in an HNSA
`service_name`, whose version-1 grammar forbids periods; that field is `chat`.

The registry has fingerprint
`36614e9dd0c47a2c59886406909a9b1e23ed6bd539376d2f553b62e1ca79351b`.
It is separate from the immutable Denuo V1/V2 packet registries, whose
fingerprints and negotiation behavior do not change.

`verify_owner_bound_chat_route` first proves the current owner binding, then
synthesizes the profile-local `AuthorityRecord` adapter and invokes the complete
`ServiceAuthorizationV1` → `EndpointDelegationV1` → `NamedRouteRecordV2`
verification chain. Generic `hsa1` roots and other service profiles retain
their existing behavior.

The HIP-78 mailbox values are intentionally opaque. Version 1 bounds a NIP-59
gift wrap to 8 KiB, requires a nonzero message ID and recipient x-only key,
requires expiration after creation, and limits retention to seven days. An
encrypted acknowledgement is separately bounded to 2 KiB. Acceptance of an
envelope by a mailbox is not a received acknowledgement.

The canonical wire version is 1. The largest reachable canonical envelope is
8,276 bytes and the largest acknowledgement is 2,092 bytes, including their
three-byte CompactSize prefixes at the maximum payload. Decoders reject larger
outer values before allocation, non-minimal CompactSize lengths, truncation,
trailing bytes, invalid x-only recipient keys, zero identifiers/timestamps,
empty ciphertexts, and retention windows beyond seven days.

## Security invariants and caller obligations

- The `Resource` and owner output supplied to this crate must come from the
  same authenticated, canonical NameState at the caller's accepted chain tip.
  `verify_current_owner_binding` proves control of the supplied output; it does
  not independently query a chain or prove that an arbitrary output is current.
- Both compressed-key parities are derived and compared to the raw version-zero
  20-byte owner program. A stale owner, version-zero 32-byte script program,
  nonzero witness version, invalid point, ambiguous result, zero generation,
  or unsupported owner construction fails closed.
- A `VerifiedOwnerBindingV1` cannot be constructed outside the crate. HNSA
  authority derivation rechecks its verified trust, generation, and exact
  original compressed key before exposing an authority record.
- Mailbox values contain opaque ciphertext only. This crate does not validate
  NIP-44/NIP-59 cryptography, sender authenticity, plaintext semantics,
  delivery, durable replay state, rate limits, peer authorization, or erasure;
  those remain mandatory product and deployment controls.
- Versioned release vectors cover canonical encoding and both owner parities,
  plus malformed fields, overflow/noncanonical generations, stale and
  script-controlled owners, noncanonical lengths, bad versions, zero fields,
  empty payloads, oversized declarations, truncation, and trailing data.

## Deliberate tradeoffs and unsupported owners

The design creates no additional recovery secret or long-term chat key. For
HD-derived software keys, the existing wallet mnemonic controls both name
ownership and the chat identity. This also means cross-protocol use of the
owner key, increased impact from a wallet chat-cryptography compromise, no
forward secrecy for historical messages under one identity key, and identity
rotation whenever the current name-owner key changes.

Version 1 explicitly does not support P2WSH/script-controlled owners,
multisignature owners, watch-only names, Ledger/hardware owners without typed
BIP-340 and NIP-44 device operations, or imported names whose encrypted wallet
does not possess the controlling private key.

No source in this crate authorizes mainnet use, publishes a package, exposes a
private key, creates a NIP-06 identity, or introduces a transport beside
HIP-78.

## Qualification status

The focused external-consumer integration target passed at exact source commit
`87c26b21e971d45de47d08cb0a154ac28ec83d00`:

```text
CARGO_TARGET_DIR=/home/den/.codex/targets/hns-rs-chat-aug3 TMPDIR=/home/den/.codex/tmp/hns-rs-chat-aug3 cargo +1.89.0 test --locked --offline -p hns-chat-protocol --test release_source -- --test-threads=1
```

Result: 4 passed; 0 failed, ignored, measured, or filtered. This proves only
the checked-in public-API resource/parser, owner-parity/false-authority, exact
wire-bound/rejection, and fixture-sidecar cases in `tests/release_source.rs`.
The crate's other unit tests were not selected by that command.

The later converged feature head
`b33b346780c8f6a9bb18a54390019486cdab0221` passed the normalized archive
checks, repository full locked gate, dependency policy, and RustSec jobs in CI
run `31369025777`. Undated release-preparation commit
`abf11ff3b16920c08f3c0b6d32d2e1af7cbe37b2` then passed locked CI run
`31385655990` and the manual 17-package Cargo preflight run `31386373480`. Its
CodeQL run `31385656053` was incomplete because JavaScript/TypeScript analysis
remained queued. Before upload, the release procedure requires exact-head CI,
complete CodeQL, and a new manual release preflight for the exact dated source.
Publication, tagging, and post-publication archive/VCS identity checks are
separate actions and are not evidence supplied by this source. A deployed
mailbox is not evidence supplied by this source; downstream persistence and
restart, canonical-chain and reorg handling, authenticated transport, abuse,
installed-client, adversarial, performance, and independent security
qualification remain product responsibilities.
