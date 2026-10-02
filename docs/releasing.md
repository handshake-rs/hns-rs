# Releasing

The `hns-rs` libraries use a shared version and are published to crates.io.
Crates.io releases are permanent: a published version cannot be overwritten or
deleted.

## Public package allowlist

The release script publishes only these packages, in dependency order:

1. `hns-encoding`
2. `hns-rollback-journal`
3. `hns-hrm`
4. `hns-primitives`
5. `hns-covenants`
6. `hns-dns-relay-protocol`
7. `hns-header-consensus`
8. `hns-service-authority`
9. `hns-odoh-protocol`
10. `hns-p2p-experimental`
11. `hns-urkel-proof`
12. `hns-transaction`
13. `hns-chat-protocol`
14. `hns-hnsr-protocol`
15. `hns-script`
16. `hns-mining`
17. `hns-swap`
18. `hns-marketplace-protocol`
19. `hns-p2p-wire`

`release/public-crates.txt` is the machine-readable authority for this list.
The cheap release validator fails if this document, the workspace's
publishable package set, or the dependency order diverges from that file.

Internal dependencies carry both a workspace path and the shared crates.io
version. Cargo removes each path when it creates the published package.

Every public package carries its own README, exact workspace license copies,
and a package-local changelog that points to the canonical shared release
notes. `scripts/verify-release.py` checks those files, all required crates.io
metadata, the shared version and internal version requirements, private
packages, and dependency order without compiling source. Routine qualification
creates every normalized archive without compiling it and checks that the
required files are present and no dependency path survives normalization. A
separate, explicitly requested release preflight performs Cargo's real publish
dry-run for all 19 packages.

## 0.5.0 release source

Version `0.5.0` changes direct-offer maker and responder roles across the
marketplace and experimental peer protocols. The shared nineteen-crate cohort
advances together so consumers cannot assemble incompatible protocol types or
wire messages from different generations. Wallet and browser products consume
the exact protocol versions and archive checksums selected by their release
source guards.

## Private packages

The following development packages must retain `publish = false`:

- `hns-conformance`;
- `hns-registry-gen`;
- `hns-rs-fuzz` in the independent `fuzz` workspace.

The release preflight fails if Cargo permits any of those packages to be
published.

## Release procedure

1. Update the shared version in the root `Cargo.toml`, every internal dependency
   version in `[workspace.dependencies]`, `CHANGELOG.md`,
   and `release/CRATE-CHANGELOG.md`, then synchronize the package copies with
   `./scripts/sync-release-changelogs.sh`. Before an actual upload, replace
   `unreleased` with the release date in both changelog authorities and
   synchronize again. The validator rejects an execution attempt whose heading
   is still `unreleased`.
2. Run the cheap metadata and dependency-order check while preparing source:

   ```bash
   python3 scripts/verify-release.py --toolchain 1.89.0
   ```

3. Inspect the changes and commit the exact release source. The execution mode
   refuses a dirty worktree.
4. Qualify that exact commit once with the full locked gate, either in CI after
   an explicitly authorized push or in a clean local checkout:

   ```bash
   ./scripts/check.sh
   ```

   Do not repeat the same full gate locally and in CI when the source commit,
   toolchain, and gate are identical.
   Routine qualification performs archive-only packaging and custom inventory
   validation after the workspace build; it does not repeat 19 crate builds.
5. Run Cargo's full package dry-runs for the exact qualified commit. Prefer the
   explicit `Release preflight` workflow so the additional compilation stays
   separate from routine CI:

   ```bash
   gh workflow run release-preflight.yml \
     --ref main \
     -f expected_commit="$(git rev-parse HEAD)"
   ```

   The equivalent local command is:

   ```bash
   ./scripts/publish.sh --dry-run
   ```

   The preflight temporarily patches unpublished workspace dependencies to
   their local paths so Cargo can verify every normalized package before the
   first dependency exists on crates.io. Those patches are not used for the
   real upload. It also requires every normalized archive to carry README,
   license, changelog, manifest, and exact source-commit metadata, with no
   retained dependency paths. The HNS Chat, HRM, HNSA, and HNSA/HNSR packages
   receive additional public source/test/vector inventory and vector-sidecar
   checks. To inspect one package while preparing downstream source, use for
   example:

   ```bash
   ./scripts/publish.sh --dry-run hns-chat-protocol
   ./scripts/publish.sh --archive-check hns-hrm
   ./scripts/publish.sh --archive-check hns-service-authority
   ./scripts/publish.sh --archive-check hns-hnsr-protocol
   ```

   Partial selection is deliberately unavailable in execution mode.

6. Stop and obtain explicit human authorization for the irreversible crates.io
   upload. Authentication, publication, and tagging are never CI steps and are
   not implied by a successful dry-run. Authenticate without placing a token in
   the repository:

   ```bash
   cargo login
   ```

7. After checking the exact version again, perform the explicitly confirmed
   upload. The confirmation version must equal the workspace version:

   ```bash
   ./scripts/publish.sh --execute --confirm-publish 0.5.0
   ```

The execution mode is restartable, but it never skips solely because an API
record exists. Before each possible upload it creates and applies the custom
inventory checks to the exact normalized `.crate`. For an already-published
package/version it reuses that archive, downloads the crates.io archive,
requires byte-for-byte SHA-256 identity, and requires both archives'
`.cargo_vcs_info.json` to name the current release commit. Any mismatch aborts
the release. This permits a partially completed release to resume without
accepting an unrelated artifact under the same version.

Before uploading, the script checks whether the crate name already exists.
A new crate name uses a 605-second cooldown; a new version of an existing name
uses a 65-second cooldown. The command waits only after a successful upload and
only when another crate remains; verified resume skips and the final upload do
not sleep. Override either non-negative interval only when crates.io
communicates a different limit:

```bash
PUBLISH_NEW_INTERVAL_SECONDS=605 \
PUBLISH_UPDATE_INTERVAL_SECONDS=65 \
  ./scripts/publish.sh --execute --confirm-publish 0.5.0
```

After the cooldown, the script downloads the newly uploaded archive and
requires the same exact checksum and source-commit identity as a resume skip
before it attempts the next crate. It checks the final upload immediately so
it does not impose a pointless final cooldown. If that archive is not visible
yet, the command exits safely; rerunning the same command after propagation
verifies the existing version and resumes without publishing it again.

After publication, push an annotated `vX.Y.Z` tag and, if it was qualified
locally, the release commit; then confirm every package page and docs.rs build.
Publication cannot be rolled back: yanking can discourage new resolution, but
it cannot delete or replace an uploaded crate version.
