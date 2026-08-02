# Native Handshake HTLC

`hns-swap::HnsHtlc` describes a native-HNS witness-script HTLC bound to the
Handshake network magic and genesis, exact dollarydoo value, SHA-256 hashlock,
compressed receiver/refund keys, and absolute refund locktime.
Zero values and all-zero hashlocks are rejected.

The redeem branch requires the receiver signature and an exact 32-byte
preimage. The refund branch requires the refund-owner signature and
`OP_CHECKLOCKTIMEVERIFY`. The keys must differ. The helper derives the exact
script, SHA3-256 witness address, funding output, descriptor hash,
`SIGHASH_ALL` signature hash, and canonical redeem/refund witnesses.
`HNS_HTLC_SIGHASH` exports that sole permitted mode. Digest creation does not
accept a caller-selected hash type, and witness validation rejects `NONE`,
`SINGLE`, `ANYONECANPAY`, and every other non-`ALL` combination.

Verification checks the funding output or transaction index, amount, address,
empty covenant, spent outpoint, signature hash type, witness layout, consensus
script result, and selected branch. Preimage extraction accepts only the exact
canonical redeem witness and verifies the SHA-256 commitment. The classified
redeem result wraps the preimage in a non-`Copy`, redacted-debug type;
settlement code must call the explicit `preimage_for_settlement` accessor. This
prevents routine diagnostics from formatting the raw secret.

Confirmation depth, fee/dust policy, and the asymmetric cross-chain timeout
relationship are wallet/settlement policy and are intentionally not invented
by this protocol crate.
