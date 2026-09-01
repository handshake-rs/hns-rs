# Exact protocol V1 fixtures

This document describes the retained source-independent settlement oracle from
the 0.2 release line.

- `hns-swap-v1.txt` covers the complete signed fixed-price listing and listing
  cancellation envelopes, Shakedex proof and seller presign, canonical buyer
  fulfillment, explicit-recipient recovery transfer, the later one-item
  FINALIZE witness and complete FINALIZE transaction, native HNS HTLC
  descriptor/script/address, funding, redeem/refund digests, complete
  transactions, and transaction IDs.
Each line after the comments is `name=lowercase_hex`. Tests parse these files
directly. The adjacent `.sha256` authenticates the complete document bytes.

The retained fixture freezes the legacy fixed-price listing and cancellation
compatibility boundary. The `0.3.1` direct-offer protocol deliberately removes
the oracle-priced marketplace message family and its obsolete vector document;
the direct offer, take, cancellation, bilateral-session, retired-registry, and relay
acceptance encodings are exercised by their bounded Rust protocol tests.
