# Owner-bound HNS Chat protocol

Status: source-implemented protocol boundary for software-controlled standard
single-key owner outputs. Installed-device, full Nostr-vector, regtest,
publication, release, and mainnet qualification remain separate gates.

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

The resulting original compressed key becomes the existing HNSA root key and
`hnschat.generation` becomes its authority epoch for the canonical service
name `hns.chat`. The x coordinate remains the Nostr identity. Downstream wallet
code remains responsible for established BIP-340 signing, exact NIP-44 v2,
NIP-17, and NIP-59 behavior while keeping all private scalars and conversation
keys inside the wallet boundary.

## HNSA and HIP-78

The generated HNSR service-profile registry allocates:

| Profile | ID |
| --- | ---: |
| `hns.node` v1 | 1 |
| `hns.web` v1 | 2 |
| `hns.chat` v1 | 3 |

The registry has fingerprint
`36614e9dd0c47a2c59886406909a9b1e23ed6bd539376d2f553b62e1ca79351b`.
It is separate from the immutable Denuo V1/V2 packet registries, whose
fingerprints and negotiation behavior do not change.

`verify_owner_bound_chat_route` first proves the current owner binding, then
synthesizes an ordinary `AuthorityRecord` and invokes the existing complete
`ServiceAuthorizationV1` → `EndpointDelegationV1` → `NamedRouteRecordV2`
verification chain. Generic `hsa1` roots and other service profiles retain
their existing behavior.

The HIP-78 mailbox values are intentionally opaque. Version 1 bounds a NIP-59
gift wrap to 8 KiB, requires a nonzero message ID and recipient x-only key,
requires expiration after creation, and limits retention to seven days. An
encrypted acknowledgement is separately bounded to 2 KiB. Acceptance of an
envelope by a mailbox is not a received acknowledgement.

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
