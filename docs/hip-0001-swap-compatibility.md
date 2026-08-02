# HIP-0001 and Shakedex compatibility

`hns-swap` implements the non-custodial HIP-0001 name-swap construction and the
current Shakedex v2 semantic proof fields. The compatibility source is
`kurumiimari/shakedex@ab5687b04cb61d2548937b8cee3c056c1c75bbdc`,
especially `src/script.js`, `src/swapProof.js`, and `src/auction.js`.

The canonical locking script is exactly:

```text
OP_TYPE OP_9 OP_EQUAL OP_IF
  PUSH33 <seller compressed public key> OP_CHECKSIG
OP_ELSE
  OP_TYPE OP_10 OP_EQUAL
OP_ENDIF
```

Seller presigns use `SIGHASH_SINGLEREVERSE | SIGHASH_ANYONECANPAY` (`0x84`).
Verification reconstructs the presign, checks the active FINALIZE coin and name,
checks SHA3-256 of the script against its version-0 locking address, requires a
canonical low-S compact secp256k1 signature, and preserves the seller payment as
the last output. Optional fee output semantics match Shakedex v2.

`fulfillment_transaction` constructs the complete buyer-funded layout while
keeping the locked-name input at index zero, the canonical `TRANSFER` output at
index zero, any marketplace fee in its fixed position, and the seller payment
last. `seller_signature_hash`, `verify_fulfillment`, and `classify_spend`
authenticate the exact seller commitment without exposing a caller-selected
hash mode.

Cancellation is the Shakedex two-stage recovery path, not a direct `FINALIZE`:
the seller first signs a `TRANSFER` to an explicitly selected recovery address
with `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY` (`0x83`), then finalizes that
transfer after the consensus lock. `recovery_transaction`,
`recovery_signature_hash`, `recovery_witness`, and `verify_recovery` enforce
this layout. Classification never infers a recovery destination from listing
metadata; the caller must supply the independently selected expected address.
Recovery authenticates its own seller signature and therefore does not depend
on retaining or publishing a separate `0x84` offer presign.

Handshake time locktimes are not literal Unix timestamps on wire. Proofs retain
the Shakedex seconds value, while transaction reconstruction encodes
`0x80000000 | floor(seconds / 512)`. Executability uses HSD's strict comparison:
the encoded threshold multiplied by 512 must be less than parent median time.

Reverse-Dutch bundles enforce:

- bounded proof, step, and bundle sizes;
- a common network, genesis, outpoint, name, seller key, payment address, and
  fee address;
- strictly increasing encoded locktimes;
- non-increasing integer prices;
- independent verification of every seller signature;
- selection of only the lowest currently executable price.

The Rust canonical binary envelope adds explicit network magic and genesis
binding around the Shakedex fields. This prevents cross-network offer IDs while
preserving a direct mapping to Shakedex v2 JSON at the service boundary.

## Differential authority

Signature hashes are checked against all selected HSD oracle modes from
`handshake-org/hsd@698e252ebc7b5c1dd0a9587e342fdd153d020ae4`.
Tests also pin the Shakedex script bytes, mutate signed prices and coins, reject
trailing proof data, and permanently assert that a lower Dutch price cannot
execute before its advertised locktime.

The source-independent `fixtures/protocol-v1/hns-swap-v1.txt` oracle
additionally pins the proof bytes and offer ID, seller digest, presigned
transaction, canonical fulfillment, cancellation transfer, all transaction
IDs, and the explicit transfer recipients. The generator cross-checks its
RFC6979 signer against a pre-existing fixed-price listing signature before
writing fixtures.
