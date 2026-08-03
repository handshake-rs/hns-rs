# Exact protocol V1 fixtures

These documents are the source-independent wire oracle for the production
marketplace and settlement boundary introduced in the 0.2 release line.

- `hns-swap-v1.txt` covers the complete signed fixed-price listing and listing
  cancellation envelopes, Shakedex proof and seller presign, canonical buyer
  fulfillment, explicit-recipient recovery transfer, the later one-item
  FINALIZE witness and complete FINALIZE transaction, native HNS HTLC
  descriptor/script/address, funding, redeem/refund digests, complete
  transactions, and transaction IDs.
- `hns-marketplace-v1.txt` covers signed intents and cancellations, price
  observations and rounds, match/grant/reject objects, bilateral session hello,
  native-HNS descriptor binding, settlement statuses, and complete Denuo
  envelopes.

Each line after the comments is `name=lowercase_hex`. Tests parse these files
directly. The adjacent `.sha256` authenticates the complete document bytes.

Regenerate or compare without invoking Rust code:

```bash
python3 generators/generate-marketplace-v1-fixtures.py --write
python3 generators/generate-marketplace-v1-fixtures.py --check
```

The standard-library generator implements canonical encodings and RFC6979
secp256k1 signing independently. Before producing output it reproduces the
pre-existing fixed-price listing and cancellation signatures pinned in the
Rust source. Those two envelopes are hns-rs protocol values rather than HSD or
upstream Shakedex wire objects, so their fixtures are source-independent
implementations of the documented domains and encodings, not a third-party
differential oracle.
