# Exact protocol V1 fixtures

These source-independent settlement fixtures authenticate the canonical
settlement encodings.

- `hns-swap-v1.txt` covers the complete signed fixed-price listing and listing
  cancellation envelopes, Shakedex proof and seller presign, canonical buyer
  fulfillment, explicit-recipient recovery transfer, the later one-item
  FINALIZE witness and complete FINALIZE transaction, native HNS HTLC
  descriptor/script/address, funding, redeem/refund digests, complete
  transactions, and transaction IDs.
Each line after the comments is `name=lowercase_hex`. Tests parse these files
directly. The adjacent `.sha256` authenticates the complete document bytes.

Fixed-term offer, take, cancellation, bilateral-session, registry-retirement,
and relay-acceptance encodings are covered by bounded Rust protocol tests.
