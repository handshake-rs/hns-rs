# Releasing

The `hns-rs` libraries use a shared version and are published to crates.io.
Crates.io releases are permanent: a published version cannot be overwritten or
deleted.

## Public package allowlist

The release script publishes only these packages, in dependency order:

1. `hns-encoding`
2. `hns-primitives`
3. `hns-covenants`
4. `hns-dns-relay-protocol`
5. `hns-header-consensus`
6. `hns-service-authority`
7. `hns-odoh-protocol`
8. `hns-p2p-experimental`
9. `hns-urkel-proof`
10. `hns-transaction`
11. `hns-chat-protocol`
12. `hns-hnsr-protocol`
13. `hns-script`
14. `hns-mining`
15. `hns-swap`
16. `hns-marketplace-protocol`
17. `hns-p2p-wire`

Internal dependencies carry both a workspace path and the shared crates.io
version. Cargo removes each path when it creates the published package.

## 0.1.0 publication record

The original 14 allowlisted crates were published to crates.io on 2026-07-29 and are
non-yanked. Every published package embeds release-source commit
`0ea5994c336642ea7d01c51c0e22df2008985426` in its Cargo VCS metadata.

`hns-marketplace-protocol` and `hns-chat-protocol` were added after that
publication and have no 0.1.0 publication record in this repository.

The annotated local and `origin` `v0.1.0` tag object
`354b286ff623424d24376f20885fb05407561d70` points to the follow-up publication
record commit `f6f46e1ecf9b31ca6592a6350c254a6effb9c9d0`, whose parent is the release
source above. The published archives therefore identify the parent release
source, not the tag target. The remote tag-object identity was confirmed with
`git ls-remote --tags origin v0.1.0` on 2026-08-02.

## 0.2.0 release candidate

The marketplace/Denuo V2 source advances the shared workspace and every
internal dependency requirement to `0.2.0`. This is necessary because the new
marketplace crate consumes `hns-swap` and `hns-p2p-experimental` APIs that do
not exist in their permanent crates.io `0.1.0` packages. Local publication
patches are verification aids only and must never be used to present the old
version as satisfying those dependencies.

No `0.2.0` package or tag has been published by the preparation commit. The
full gate, source review, intentional commit, authenticated upload, tag, and
post-publication verification remain separate release actions.

The release candidate includes HNSA named-service authority objects, the
versioned HNSA-to-HNSR named-route adapter, owner-bound HNS Chat resource and
opaque mailbox values, a generated HNSR service-profile assignment, and
bounded live HNSR reservation and route-service state machines. The live
service boundary remains transport- and persistence-independent; it does not
qualify a deployed relay. The candidate also includes exact protocol-V1
marketplace/settlement fixtures, independent
maker settlement delegation, native-HNS hello binding,
Shakedex fulfillment and cancellation APIs, exact Denuo version/flag handling,
post-deadline recovery-status validation, and resumable publication identity
checks. It also includes the exact HSD NameState/resource codec, shared
owner-outpoint semantics, sigop-adjusted fee-policy arithmetic with explicit
units, strict TRANSFER/FINALIZE construction, listing-independent Shakedex
recovery, canonical empty offer-inventory responses, and pinned
source-verified HSD vectors. The chat crate now carries an explicit normalized
source-package inventory, SHA-256-authenticated valid/invalid vectors, an
external-consumer integration test, and public canonical wire bounds so a
downstream node does not require a sibling checkout or copied types. These
post-vector source additions and the
converged HNSR/chat dependency graph have not yet passed this document's full
locked gate. No downstream release may claim the API until that gate passes
and the shared `0.2.0` packages are published.

## Private packages

The following development packages must retain `publish = false`:

- `hns-conformance`;
- `hns-registry-gen`;
- `hns-rs-fuzz` in the independent `fuzz` workspace.

The release preflight fails if Cargo permits any of those packages to be
published.

## Release procedure

1. Update the shared version in the root `Cargo.toml`, every internal dependency
   version in `[workspace.dependencies]`, and this changelog.
2. Inspect the changes and commit the exact release source. The execution mode
   refuses a dirty worktree.
3. Qualify that exact commit once with the full locked gate, either in CI after
   an explicitly authorized push or in a clean local checkout:

   ```bash
   ./scripts/check.sh
   ```

   Do not repeat the same full gate locally and in CI when the source commit,
   toolchain, and gate are identical.
4. Authenticate without placing a token in the repository:

   ```bash
   cargo login
   ```

5. Run the package-only preflight only if it was not already part of the
   qualifying gate:

   ```bash
   ./scripts/publish.sh --dry-run
   ```

   The preflight temporarily patches unpublished workspace dependencies to
   their local paths so Cargo can verify every normalized package before the
   first dependency exists on crates.io. Those patches are not used for the
   real upload. The preflight additionally inspects the normalized
   `hns-chat-protocol` archive for its complete public source/test/vector
   inventory, absence of path dependencies, and a valid vector sidecar. To
   inspect only that package while preparing downstream source, use:

   ```bash
   ./scripts/publish.sh --dry-run hns-chat-protocol
   ```

   Partial selection is deliberately unavailable in execution mode.

6. Publish the allowlist:

   ```bash
   ./scripts/publish.sh --execute
   ```

The execution mode is restartable, but it never skips solely because an API
record exists. For an already-published package/version it recreates the
normalized `.crate`, downloads the crates.io archive, requires byte-for-byte
SHA-256 identity, and requires both archives' `.cargo_vcs_info.json` to name the
current release commit. Any mismatch aborts the release. This permits a
partially completed release to resume without accepting an unrelated artifact
under the same version.

After publication, push an annotated `vX.Y.Z` tag and, if it was qualified
locally, the release commit; then confirm every package page and docs.rs build.
