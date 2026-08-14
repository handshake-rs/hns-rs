# External anti-rollback journal contract

`hns-rollback-journal` supplies the platform-neutral record and recovery state
machine needed by HRM/HNSA authority aggregates, HNSR requester and rendezvous
state, and publisher sequence reservations. It is intentionally inert until an
embedding supplies a separately qualified journal broker.

One canonical record is indexed externally for each exact authority namespace.
Its immutable binding covers the installation lineage, Handshake network,
protocol role and version, physical storage namespace, logical key, AEAD suite,
key version, key identifier, and reported rollback-protection class. Absence is
a terminal runtime error. Only a privileged control plane may create the
explicit `NeverInitialized` marker and enroll an exact existing database
snapshot. Retirement has no transition back to an active state.

## Ordered transition

The embedding acquires the external journal fenced lease first and the
protocol database fenced lease second. It rereads both exact states under the
leases, stores `Prepared` durably in the independent journal, performs the
exact database CAS, stores `Stable` durably, and only then exposes a result.
Every journal write atomically checks the binding, exact record fingerprint,
journal revision, and current fencing token. The protocol write independently
checks its exact old state and current protocol fencing token.

The canonical v1 revision sequence is structural: `NeverInitialized` is zero,
`Stable` is odd, and both `Prepared` and terminal `Retired` are even and at
least two. A prepare reserves the following finalization revision, so a
checksum-valid record with any other state/revision parity is rejected.

An ambiguous journal outcome is resolved by exact reload: an exact proposal is
committed, an exact old state is retried unchanged, and anything else fails
closed. `Prepared` has no ordinary abort. It retains the complete authenticated
old and new snapshot images so data-volume rollback can be recovered without
inventing state. Restore actions always decrypt and authenticate the snapshot,
verify its exact plaintext-byte fingerprint and protocol semantics, use an
exact fenced database CAS, reread, and run the recovery planner again.

## Trust boundary

The canonical BLAKE2b checksum and fingerprints are corruption/equality tools,
not authentication. Version 1 assigns AEAD suite 1 to AES-256-GCM with a
32-byte key and sealed bytes encoded as
`nonce[12] || ciphertext || tag[16]`. A native backend must protect the
complete record and key and guarantee that a nonce never repeats under the same
actual AEAD key across any metadata key version, namespace, or sealing purpose.
Each new key version must resolve to fresh key material for each sealing
purpose. If actual key material is reused across versions, nonce allocation and
invocation accounting must continue without reset across those versions; the
binding's key version and identifier are not evidence of rotation. Use durable
nonce allocation or a qualified uniform 96-bit random construction with an
enforced conservative per-key invocation bound and rotation policy. Snapshot
and outer-record sealing must derive domain-separated subkeys; otherwise they
share one nonce-allocation domain. An exact retry reuses the identical already
sealed bytes and never re-encrypts the pending mutation. The backend
must use the exported binding/state associated data, reject
symlinks and ownership/mode/link-count surprises, update through an
fsync/rename/parent-fsync sequence, and verify that its journal and protected
database really occupy the claimed rollback domains.

On the current Linux host, a root-owned journal on the system NVMe can protect
the separately backed-up 1 TB data volume and an unprivileged node process, but
does not protect whole-host or root rollback. No qualified TPM is currently
available. A hardware monotonic anchor or independent remote witness is needed
for that stronger threat model.

Ordinary IndexedDB, extension storage, and mobile application databases are
replayable or evictable with the state they protect. Browser and mobile
adapters therefore require a trusted sole broker plus a qualified platform
primitive or remote witness; otherwise authority-changing roles remain
disabled. All `u64` values cross JavaScript boundaries as `BigInt` or exact
bytes, never `Number`.

Untrusted pages, content scripts, UI/webview contexts, and ordinary application
callers never receive `JournalLeaseContext`, fencing tokens, raw CAS access,
nonce/key operations, decrypted snapshots, or unpromoted results. Those are
broker-internal. A caller receives only a fence-tagged result or broker-owned
session promotion after `Stable` is durable, while the broker retains or
equivalently serializes every required live lease through dependent use.
