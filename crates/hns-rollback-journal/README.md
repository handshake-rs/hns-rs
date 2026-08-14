# hns-rollback-journal

Platform-neutral state and recovery contract for an authenticated external
anti-rollback journal used by durable HRM, HNSA, HNSR requester, rendezvous,
and publisher state.

The crate deliberately performs no filesystem, database, key-management, or
AEAD operation. It defines the canonical bounded record, exact fenced
compare-and-swap expectations, crash-safe `Stable`/`Prepared` state machine,
and deterministic recovery decisions that a native, extension, or mobile
broker must implement. A checksum and the exported fingerprints detect
corruption and identify exact bytes; they are not authentication and do not
make replayable storage rollback-resistant.

Each protocol authority namespace has one record bound to an installation
lineage, Handshake network, role, physical storage namespace, logical key,
protocol/version, AEAD suite, key version, and key identifier. An absent record
is `Missing`, never `NeverInitialized`. A privileged control plane provisions
the explicit `NeverInitialized` marker and separately enrolls an exact current
database snapshot. Runtime code must fail closed on missing or unenrolled
state. `Retired` is terminal.

The required commit order is:

1. acquire the external journal namespace's live fenced lease;
2. acquire the protocol database namespace's live fenced lease;
3. re-read both exact states under those leases;
4. atomically persist and durably acknowledge `Prepared` in the external
   journal;
5. perform the exact protocol-database compare-and-swap;
6. atomically persist and durably acknowledge `Stable` in the external
   journal; and
7. only then expose the protocol result, while retaining every operation lease
   required by that protocol through dependent use.

`Prepared` retains both the old and new sealed complete snapshots. There is no
ordinary abort transition. Recovery retries the exact proposal when the
database is at the old state, finalizes when it is at the new state, and
restores an externally retained state before rereading when the data volume is
older or missing. Same-revision forks, database-ahead states, corrupted or
misbound records, missing enrollment, and unexpected intermediate states fail
closed.

The v1 sealed format uses AES-256-GCM (`aead_suite = 1`): a 32-byte key, the
exported associated data, and `nonce[12] || ciphertext || tag[16]` in the
sealed-snapshot field. The backend performs the cryptography. It must
authenticate the complete journal record and guarantee that a nonce never
repeats under the same actual AEAD key across any metadata key version,
namespace, or sealing purpose. Each new key version must resolve to fresh key
material for each sealing purpose. If actual key material is reused across
versions, nonce allocation and invocation accounting must continue without
reset across those versions; the binding's key version and identifier are not
evidence of rotation. That requires either durable nonce allocation or a
qualified uniform 96-bit random scheme with an enforced conservative per-key
invocation bound and rotation policy. Snapshot and outer-record sealing must
use domain-separated subkeys; otherwise they share one nonce-allocation domain.
An exact retry reuses the identical already sealed image and must never
re-encrypt or choose another nonce. The backend must also bind the exported
snapshot associated data, decrypt before restoration, verify the
exact plaintext-byte fingerprint, validate the protocol snapshot itself, and
atomically enforce the supplied namespace, record fingerprint, journal
revision, and fencing token. Success means the exact proposed bytes and parent
directory metadata are durable; an ambiguous outcome must be resolved with
`JournalMutation::reconcile` and an exact retry.

`IntegrityOnlySameRollbackDomain` is not production anti-rollback protection.
`IndependentLocalRoot` can protect a separately backed-up data volume and
unprivileged node process only while the root-owned journal domain and its key
remain trusted; it does not protect whole-host or root rollback. Hardware and
remote-witness classifications likewise require independently qualified
backends and must not be inferred from the enum alone.

IndexedDB, extension storage, ordinary mobile databases, and a journal stored
beside the protected snapshot are normally replayable or evictable together.
Browser and mobile products need one trusted sole broker plus a qualified
platform rollback primitive or remote witness. JavaScript adapters must carry
every `u64` as `BigInt` or exact bytes, never `Number`.

Untrusted pages, content scripts, UI/webview contexts, and ordinary application
callers must never receive a `JournalLeaseContext` or fencing token, raw journal
or database CAS access, nonce/key operations, decrypted snapshots, or an
unpromoted result. Those remain broker-internal. The broker may return only a
fence-tagged result or broker-owned session promotion after `Stable` is durably
acknowledged, and it must retain or equivalently serialize every required live
lease through the complete dependent operation.

Licensed under either Apache-2.0 or MIT.
