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
14. `hns-p2p-wire`

Internal dependencies carry both a workspace path and the shared crates.io
version. Cargo removes each path when it creates the published package.

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

The execution mode is restartable. It checks the crates.io API and skips a
package version that is already present, allowing a partially completed release
to continue safely.

After publication, push the release commit and an annotated `vX.Y.Z` tag, then
confirm every package page and docs.rs build.
