# Changelog

## 0.4.0 - Unreleased

- Break the direct-offer wire format deliberately: every signed offer now
  contains the maker-selected swap session identifier, and a take or session
  proposal must repeat that exact identifier. This prevents a taker-selected
  session from being incompatible with the per-offer settlement key.
- Advance the signed marketplace object version to 2 for the incompatible
  direct-offer encoding.

This crate uses the shared `hns-rs` workspace version. Complete release notes
for every public crate are maintained in the repository-level
[`CHANGELOG.md`](https://github.com/handshake-rs/hns-rs/blob/v0.3.1/CHANGELOG.md).

## 0.3.1 - 2026-08-23

See the canonical workspace changelog for the complete shared release notes,
publication procedure, and qualification scope. A source archive alone is not
evidence that every shared package or any downstream product has been released.
