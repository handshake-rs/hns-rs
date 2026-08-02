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
6. `hns-hnsr-protocol`
7. `hns-odoh-protocol`
8. `hns-p2p-experimental`
9. `hns-urkel-proof`
10. `hns-transaction`
11. `hns-script`
12. `hns-mining`
13. `hns-swap`
14. `hns-marketplace-protocol`
15. `hns-p2p-wire`

Internal dependencies carry both a workspace path and the shared crates.io
version. Cargo removes each path when it creates the published package.

## 0.1.0 publication record

The original 14 allowlisted crates were published to crates.io on 2026-07-29 and are
non-yanked. Every published package embeds release-source commit
`0ea5994c336642ea7d01c51c0e22df2008985426` in its Cargo VCS metadata.

`hns-marketplace-protocol` was added after that publication and has no 0.1.0
publication record in this repository.

Registry publication is complete, but no `v0.1.0` Git tag exists locally or on
`origin`. Treat the commit above as the published source; do not describe
`0.1.0` as Git-tagged unless that tag is later created and pushed.

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

The release candidate includes exact protocol-V1 marketplace/settlement
fixtures, independent maker settlement delegation, native-HNS hello binding,
Shakedex fulfillment and cancellation APIs, exact Denuo version/flag handling,
post-deadline recovery-status validation, and resumable publication identity
checks. These are supported release surfaces, not provisional APIs.

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
2. Run the full locked qualification gate:

   ```bash
   ./scripts/check.sh
   ```

3. Inspect the staged changes and commit the exact release source. The execution
   mode refuses a dirty worktree.
4. Authenticate without placing a token in the repository:

   ```bash
   cargo login
   ```

5. Re-run the package-only preflight if desired:

   ```bash
   ./scripts/publish.sh --dry-run
   ```

   The preflight temporarily patches unpublished workspace dependencies to
   their local paths so Cargo can verify every normalized package before the
   first dependency exists on crates.io. Those patches are not used for the
   real upload.

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

After publication, push the release commit and an annotated `vX.Y.Z` tag, then
confirm every package page and docs.rs build.
