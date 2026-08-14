//! Leased durable boundary for the finite HRM-backed rendezvous ledger.
//!
//! Live route bytes remain a volatile cache. Only the finite V3 replay ledger
//! crosses this boundary, under an embedding-owned sole-writer lease and an
//! exact namespace/fencing-token compare-and-swap contract.

use std::fmt;
use std::future::Future;
use std::num::NonZeroU64;

use hns_service_authority::{
    authority_state::CurrentCommittedNamedService, hrm::NamedServiceIdentity,
};

use crate::body::{GetRouteBody, PutResultBody, PutRouteBody, RoutesBody};
use crate::{
    HnsrOpcode, HnsrPacket, HnsrProtocolError, HrmNamedRoutePolicy, MAX_CONTACTS, MAX_PACKET_SIZE,
    NamedRouteV3LedgerSnapshot, RouteStore, RouteStoreLimits,
};

const ROUTES_BODY_FIXED_SIZE: usize = 1;
const ROUTES_BODY_RECORD_PREFIX_SIZE: usize = 2;
const ROUTES_BODY_MAX_SIZE: usize = MAX_PACKET_SIZE - 12;

/// Exact storage namespace and route-store configuration protected by a lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedRouteV3StorageNamespace {
    storage_namespace_id: [u8; 32],
    network_magic: u32,
    allow_private_routes: bool,
    limits: RouteStoreLimits,
}

impl NamedRouteV3StorageNamespace {
    /// Define a nonzero embedding-owned durable-storage namespace.
    pub fn new(
        storage_namespace_id: [u8; 32],
        network_magic: u32,
        allow_private_routes: bool,
        limits: RouteStoreLimits,
    ) -> Result<Self, HnsrProtocolError> {
        if storage_namespace_id == [0; 32] {
            return Err(HnsrProtocolError::Invalid(
                "zero HNSR V3 storage namespace identifier",
            ));
        }
        Ok(Self {
            storage_namespace_id,
            network_magic,
            allow_private_routes,
            limits,
        })
    }

    /// Embedding-defined durable namespace identifier.
    pub const fn storage_namespace_id(&self) -> &[u8; 32] {
        &self.storage_namespace_id
    }

    /// Handshake network magic bound to this namespace.
    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }

    /// Whether this namespace admits private route addresses.
    pub const fn allow_private_routes(&self) -> bool {
        self.allow_private_routes
    }

    /// Exact finite-store limits bound to this namespace.
    pub const fn limits(&self) -> RouteStoreLimits {
        self.limits
    }
}

/// Exact broker context held while loading, committing, and emitting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedRouteV3LeaseContext {
    namespace: NamedRouteV3StorageNamespace,
    fencing_token: NonZeroU64,
}

impl NamedRouteV3LeaseContext {
    /// Exact storage namespace and route configuration.
    pub const fn namespace(&self) -> NamedRouteV3StorageNamespace {
        self.namespace
    }

    /// Monotonic, nonzero fencing token for this acquisition.
    pub const fn fencing_token(&self) -> NonZeroU64 {
        self.fencing_token
    }

    const fn absent_expectation(self) -> NamedRouteV3LedgerExpectation {
        NamedRouteV3LedgerExpectation::Absent {
            namespace: self.namespace,
            fencing_token: self.fencing_token,
        }
    }

    fn exact_expectation(
        self,
        snapshot: &NamedRouteV3LedgerSnapshot,
    ) -> NamedRouteV3LedgerExpectation {
        NamedRouteV3LedgerExpectation::Exact {
            namespace: self.namespace,
            fencing_token: self.fencing_token,
            revision: snapshot.revision(),
            fingerprint: snapshot.fingerprint(),
        }
    }
}

/// Exact durable precondition for a V3 admission-ledger proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamedRouteV3LedgerExpectation {
    /// Create the initialized ledger only if no value exists.
    Absent {
        /// Exact durable namespace and route configuration.
        namespace: NamedRouteV3StorageNamespace,
        /// Current broker fencing token.
        fencing_token: NonZeroU64,
    },
    /// Replace only the exact previously acknowledged snapshot.
    Exact {
        /// Exact durable namespace and route configuration.
        namespace: NamedRouteV3StorageNamespace,
        /// Current broker fencing token.
        fencing_token: NonZeroU64,
        /// Exact acknowledged revision.
        revision: u64,
        /// Exact acknowledged snapshot fingerprint.
        fingerprint: [u8; 32],
    },
}

impl NamedRouteV3LedgerExpectation {
    /// Exact namespace/configuration covered by this CAS.
    pub const fn namespace(&self) -> NamedRouteV3StorageNamespace {
        match self {
            Self::Absent { namespace, .. } | Self::Exact { namespace, .. } => *namespace,
        }
    }

    /// Current broker fencing token which storage must atomically validate.
    pub const fn fencing_token(&self) -> NonZeroU64 {
        match self {
            Self::Absent { fencing_token, .. } | Self::Exact { fencing_token, .. } => {
                *fencing_token
            }
        }
    }
}

/// Authenticated external storage state returned by the post-acquisition loader.
///
/// `Absent` is an authenticated never-initialized marker, not a fallback for
/// lookup failure. An initialized namespace must retain its minimum accepted
/// revision in authenticated anti-rollback state. Rust cannot prove external
/// I/O freshness: the loader is trusted to perform or reconfirm its read inside
/// the callback while atomically validating the supplied namespace and fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamedRouteV3LedgerStorageState {
    /// Authenticated storage proves that no ledger was ever initialized.
    Absent,
    /// Authenticated storage returned the initialized snapshot.
    Initialized {
        snapshot: NamedRouteV3LedgerSnapshot,
        minimum_revision: u64,
    },
}

/// A trusted embedding's RAII proof of sole ownership of one namespace.
///
/// From acquisition until drop, an implementation must exclude every other
/// writer for [`Self::namespace`], including other tabs, workers, processes,
/// and devices. Its token must increase on every acquisition. Every durable
/// callback must atomically compare the expectation's namespace and token with
/// the broker's current values. [`Self::ensure_held`] is additional loss
/// notification; it never replaces the callback's atomic fencing check.
///
/// Web Locks plus an extension background broker, an OS lock plus a durable
/// epoch, or a mobile single-owner service can implement this contract. The
/// rendezvous service takes the guard by value and cannot be cloned.
pub trait NamedRouteV3SoleOwnerLease: fmt::Debug {
    /// Namespace/configuration exclusively owned by this guard.
    fn namespace(&self) -> NamedRouteV3StorageNamespace;

    /// Monotonic token established by the lease broker.
    fn fencing_token(&self) -> NonZeroU64;

    /// Confirm that this guard is still the broker's sole owner.
    fn ensure_held(&mut self) -> Result<(), NamedRouteV3LeaseLost>;
}

/// The broker no longer recognizes the owned lease as current.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedRouteV3LeaseLost;

impl fmt::Display for NamedRouteV3LeaseLost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HNSR V3 storage lease was lost")
    }
}

impl std::error::Error for NamedRouteV3LeaseLost {}

/// Error reported by storage/load/emission while inside the lease boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamedRouteV3GuardedCallbackError<E> {
    /// The callback atomically rejected the namespace or fencing token.
    LeaseLost,
    /// A backend error unrelated to ownership.
    Other(E),
}

impl<E: fmt::Display> fmt::Display for NamedRouteV3GuardedCallbackError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaseLost => NamedRouteV3LeaseLost.fmt(formatter),
            Self::Other(error) => error.fmt(formatter),
        }
    }
}

impl<E> std::error::Error for NamedRouteV3GuardedCallbackError<E> where
    E: std::error::Error + 'static
{
}

/// Failure while acquiring the lease and loading authenticated storage.
#[derive(Debug)]
pub enum NamedRouteV3OpenError<A, L> {
    /// The embedding's broker could not acquire sole ownership.
    Acquisition(A),
    /// The acquired guard did not match the requested namespace.
    LeaseBinding,
    /// Ownership was lost before loading completed.
    LeaseLost,
    /// The authenticated post-acquisition loader failed.
    Load(L),
    /// The loaded ledger or route configuration was invalid.
    Protocol(HnsrProtocolError),
}

impl<A: fmt::Display, L: fmt::Display> fmt::Display for NamedRouteV3OpenError<A, L> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acquisition(error) => write!(formatter, "V3 lease acquisition failed: {error}"),
            Self::LeaseBinding => formatter.write_str("V3 lease binding mismatch"),
            Self::LeaseLost => NamedRouteV3LeaseLost.fmt(formatter),
            Self::Load(error) => write!(formatter, "V3 ledger load failed: {error}"),
            Self::Protocol(error) => error.fmt(formatter),
        }
    }
}

impl<A, L> std::error::Error for NamedRouteV3OpenError<A, L>
where
    A: std::error::Error + 'static,
    L: std::error::Error + 'static,
{
}

/// A wire result delivered to the embedding while the lease is held.
#[derive(Debug)]
pub enum NamedRouteV3Emission {
    /// Successful protocol response.
    Response(HnsrPacket),
    /// Protocol rejection, durably ordered behind any ledger transition.
    ProtocolError(HnsrProtocolError),
}

/// Infrastructure failure from a leased handle-and-emit operation.
#[derive(Debug)]
pub enum LeasedPersistentRendezvousError<P, E> {
    /// This service was previously poisoned; reopen under a new acquisition.
    Poisoned,
    /// Sole ownership was lost and volatile bytes were discarded.
    LeaseLost,
    /// Durable storage failed without proving lease loss.
    Persistence(P),
    /// Emission failed; delivery is ambiguous and the service was poisoned.
    Emission(E),
}

/// Failure from a leased current-authority route operation.
#[derive(Debug)]
pub enum LeasedPersistentRouteMutationError<P> {
    /// This service was previously poisoned; reopen under a new acquisition.
    Poisoned,
    /// Sole ownership was lost and volatile bytes were discarded.
    LeaseLost,
    /// The committed HNSA authority's operation lease was lost.
    AuthorityLeaseLost,
    /// Durable storage failed without proving lease loss.
    Persistence(P),
    /// The requested current-authority operation was invalid.
    Protocol(HnsrProtocolError),
}

impl<P: fmt::Display> fmt::Display for LeasedPersistentRouteMutationError<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned => formatter.write_str("leased V3 rendezvous service is poisoned"),
            Self::LeaseLost => NamedRouteV3LeaseLost.fmt(formatter),
            Self::AuthorityLeaseLost => {
                formatter.write_str("committed HNSA authority lease was lost")
            }
            Self::Persistence(error) => write!(formatter, "V3 ledger persistence failed: {error}"),
            Self::Protocol(error) => error.fmt(formatter),
        }
    }
}

impl<P> std::error::Error for LeasedPersistentRouteMutationError<P> where
    P: std::error::Error + 'static
{
}

impl<P: fmt::Display, E: fmt::Display> fmt::Display for LeasedPersistentRendezvousError<P, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned => formatter.write_str("leased V3 rendezvous service is poisoned"),
            Self::LeaseLost => NamedRouteV3LeaseLost.fmt(formatter),
            Self::Persistence(error) => write!(formatter, "V3 ledger persistence failed: {error}"),
            Self::Emission(error) => write!(formatter, "V3 response emission failed: {error}"),
        }
    }
}

impl<P, E> std::error::Error for LeasedPersistentRendezvousError<P, E>
where
    P: std::error::Error + 'static,
    E: std::error::Error + 'static,
{
}

#[derive(Debug)]
enum LocalCommitError<E> {
    Protocol(HnsrProtocolError),
    Persistence(E),
}

impl<E> From<HnsrProtocolError> for LocalCommitError<E> {
    fn from(error: HnsrProtocolError) -> Self {
        Self::Protocol(error)
    }
}

#[derive(Debug)]
struct PendingLedgerCas {
    expectation: NamedRouteV3LedgerExpectation,
    proposed: NamedRouteV3LedgerSnapshot,
}

/// Crate-private, uncommitted mechanism. The public leased service is the
/// production boundary and never exposes this mutable lineage directly.
#[derive(Debug)]
struct LocalPersistentRouteStore {
    lease_context: NamedRouteV3LeaseContext,
    volatile: RouteStore,
    acknowledged: Option<NamedRouteV3LedgerSnapshot>,
    pending: Option<PendingLedgerCas>,
}

#[allow(dead_code)]
impl LocalPersistentRouteStore {
    fn open(
        lease_context: NamedRouteV3LeaseContext,
        trusted_now: u64,
        storage: NamedRouteV3LedgerStorageState,
    ) -> Result<Self, HnsrProtocolError> {
        let namespace = lease_context.namespace();
        let mut volatile = RouteStore::new(
            namespace.network_magic(),
            namespace.allow_private_routes(),
            namespace.limits(),
        )?;
        match storage {
            NamedRouteV3LedgerStorageState::Absent => {
                let proposed = volatile.named_v3_ledger_snapshot(trusted_now)?;
                Ok(Self {
                    lease_context,
                    volatile,
                    acknowledged: None,
                    pending: Some(PendingLedgerCas {
                        expectation: lease_context.absent_expectation(),
                        proposed,
                    }),
                })
            }
            NamedRouteV3LedgerStorageState::Initialized {
                snapshot,
                minimum_revision,
            } => {
                let acknowledged = snapshot.clone();
                volatile.restore_named_v3_ledger(snapshot, trusted_now, minimum_revision)?;
                let current = volatile.named_v3_ledger_snapshot(trusted_now)?;
                let pending = (current != acknowledged).then(|| PendingLedgerCas {
                    expectation: lease_context.exact_expectation(&acknowledged),
                    proposed: current,
                });
                Ok(Self {
                    lease_context,
                    volatile,
                    acknowledged: Some(acknowledged),
                    pending,
                })
            }
        }
    }

    const fn route_count(&self) -> usize {
        self.volatile.len()
    }

    fn persist_pending<E, F>(&mut self, persist: &mut F) -> Result<(), LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, &NamedRouteV3LedgerSnapshot) -> Result<(), E>,
    {
        let Some(pending) = self.pending.as_ref() else {
            return Ok(());
        };
        persist(pending.expectation, &pending.proposed).map_err(LocalCommitError::Persistence)?;
        self.acknowledged = Some(pending.proposed.clone());
        self.pending = None;
        Ok(())
    }

    async fn persist_pending_async<E, F, Fut>(
        &mut self,
        persist: &mut F,
    ) -> Result<(), LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let Some(pending) = self.pending.as_ref() else {
            return Ok(());
        };
        let expectation = pending.expectation;
        let proposed = pending.proposed.clone();
        persist(expectation, proposed.clone())
            .await
            .map_err(LocalCommitError::Persistence)?;
        self.acknowledged = Some(proposed);
        self.pending = None;
        Ok(())
    }

    fn run_persisted<E, F, T, M>(
        &mut self,
        now: u64,
        persist: &mut F,
        mutate: M,
    ) -> Result<T, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, &NamedRouteV3LedgerSnapshot) -> Result<(), E>,
        M: FnOnce(&mut RouteStore) -> Result<T, HnsrProtocolError>,
    {
        self.persist_pending(persist)?;
        let result = mutate(&mut self.volatile);
        self.capture_current(now)?;
        self.persist_pending(persist)?;
        result.map_err(LocalCommitError::Protocol)
    }

    async fn run_persisted_async<E, F, Fut, T, M>(
        &mut self,
        now: u64,
        persist: &mut F,
        mutate: M,
    ) -> Result<T, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
        M: FnOnce(&mut RouteStore) -> Result<T, HnsrProtocolError>,
    {
        self.persist_pending_async(persist).await?;
        let result = mutate(&mut self.volatile);
        self.capture_current(now)?;
        self.persist_pending_async(persist).await?;
        result.map_err(LocalCommitError::Protocol)
    }

    fn capture_current(&mut self, now: u64) -> Result<(), HnsrProtocolError> {
        debug_assert!(self.pending.is_none());
        let acknowledged = self
            .acknowledged
            .as_ref()
            .ok_or(HnsrProtocolError::Invalid(
                "persistent V3 route ledger is not initialized",
            ))?;
        let proposed = self.volatile.named_v3_ledger_snapshot(now)?;
        if proposed != *acknowledged {
            self.pending = Some(PendingLedgerCas {
                expectation: self.lease_context.exact_expectation(acknowledged),
                proposed,
            });
        }
        Ok(())
    }

    fn put_unnamed<E, F>(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        now: u64,
        source: String,
        persist: &mut F,
    ) -> Result<u64, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, &NamedRouteV3LedgerSnapshot) -> Result<(), E>,
    {
        self.run_persisted(now, persist, move |store| store.put(key, raw, now, source))
    }

    fn put_named_v2_for_admission<E, F>(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        now: u64,
        source: String,
        persist: &mut F,
    ) -> Result<u64, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, &NamedRouteV3LedgerSnapshot) -> Result<(), E>,
    {
        self.run_persisted(now, persist, move |store| {
            store.put_named_v2_for_admission(key, raw, now, source)
        })
    }

    fn put_named_v3_for_admission<E, F>(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        now: u64,
        source: String,
        persist: &mut F,
    ) -> Result<u64, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, &NamedRouteV3LedgerSnapshot) -> Result<(), E>,
    {
        self.run_persisted(now, persist, move |store| {
            store.put_named_v3_for_admission(key, raw, now, source)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn put_named_v3<E, F>(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        committed_service: &CurrentCommittedNamedService<'_>,
        policy: HrmNamedRoutePolicy,
        now: u64,
        source: String,
        persist: &mut F,
    ) -> Result<u64, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, &NamedRouteV3LedgerSnapshot) -> Result<(), E>,
    {
        self.run_persisted(now, persist, move |store| {
            store.put_named_v3(key, raw, committed_service, policy, now, source)
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn put_named_v3_async<E, F, Fut>(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        committed_service: &CurrentCommittedNamedService<'_>,
        policy: HrmNamedRoutePolicy,
        now: u64,
        source: String,
        persist: &mut F,
    ) -> Result<u64, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.run_persisted_async(now, persist, move |store| {
            store.put_named_v3(key, raw, committed_service, policy, now, source)
        })
        .await
    }

    fn revalidate_named_v3_current<E, F>(
        &mut self,
        identity: &NamedServiceIdentity,
        committed_service: &CurrentCommittedNamedService<'_>,
        policy: HrmNamedRoutePolicy,
        now: u64,
        persist: &mut F,
    ) -> Result<usize, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, &NamedRouteV3LedgerSnapshot) -> Result<(), E>,
    {
        self.run_persisted(now, persist, |store| {
            store.revalidate_named_v3_current(identity, committed_service, policy, now)
        })
    }

    async fn revalidate_named_v3_current_async<E, F, Fut>(
        &mut self,
        identity: &NamedServiceIdentity,
        committed_service: &CurrentCommittedNamedService<'_>,
        policy: HrmNamedRoutePolicy,
        now: u64,
        persist: &mut F,
    ) -> Result<usize, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.run_persisted_async(now, persist, |store| {
            store.revalidate_named_v3_current(identity, committed_service, policy, now)
        })
        .await
    }

    fn invalidate_named_v3_withdrawal<E, F>(
        &mut self,
        identity: &NamedServiceIdentity,
        committed_service: &CurrentCommittedNamedService<'_>,
        now: u64,
        persist: &mut F,
    ) -> Result<usize, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, &NamedRouteV3LedgerSnapshot) -> Result<(), E>,
    {
        self.run_persisted(now, persist, |store| {
            store.invalidate_named_v3_withdrawal(identity, committed_service, now)
        })
    }

    async fn invalidate_named_v3_withdrawal_async<E, F, Fut>(
        &mut self,
        identity: &NamedServiceIdentity,
        committed_service: &CurrentCommittedNamedService<'_>,
        now: u64,
        persist: &mut F,
    ) -> Result<usize, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.run_persisted_async(now, persist, |store| {
            store.invalidate_named_v3_withdrawal(identity, committed_service, now)
        })
        .await
    }

    fn get_named_v3<E, F>(
        &mut self,
        key: &[u8; 32],
        maximum: usize,
        now: u64,
        persist: &mut F,
    ) -> Result<Vec<Vec<u8>>, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, &NamedRouteV3LedgerSnapshot) -> Result<(), E>,
    {
        self.run_persisted(now, persist, |store| {
            Ok(store.get_named_v3(key, maximum, now))
        })
    }

    fn get_unnamed_v1<E, F>(
        &mut self,
        key: &[u8; 32],
        maximum: usize,
        now: u64,
        persist: &mut F,
    ) -> Result<Vec<Vec<u8>>, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, &NamedRouteV3LedgerSnapshot) -> Result<(), E>,
    {
        self.run_persisted(now, persist, |store| {
            Ok(store.get_unnamed_v1(key, maximum, now))
        })
    }

    async fn put_unnamed_async<E, F, Fut>(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        now: u64,
        source: String,
        persist: &mut F,
    ) -> Result<u64, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.run_persisted_async(now, persist, move |store| store.put(key, raw, now, source))
            .await
    }

    async fn put_named_v2_for_admission_async<E, F, Fut>(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        now: u64,
        source: String,
        persist: &mut F,
    ) -> Result<u64, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.run_persisted_async(now, persist, move |store| {
            store.put_named_v2_for_admission(key, raw, now, source)
        })
        .await
    }

    async fn put_named_v3_for_admission_async<E, F, Fut>(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        now: u64,
        source: String,
        persist: &mut F,
    ) -> Result<u64, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.run_persisted_async(now, persist, move |store| {
            store.put_named_v3_for_admission(key, raw, now, source)
        })
        .await
    }

    async fn get_named_v3_async<E, F, Fut>(
        &mut self,
        key: &[u8; 32],
        maximum: usize,
        now: u64,
        persist: &mut F,
    ) -> Result<Vec<Vec<u8>>, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.run_persisted_async(now, persist, |store| {
            Ok(store.get_named_v3(key, maximum, now))
        })
        .await
    }

    async fn get_unnamed_v1_async<E, F, Fut>(
        &mut self,
        key: &[u8; 32],
        maximum: usize,
        now: u64,
        persist: &mut F,
    ) -> Result<Vec<Vec<u8>>, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.run_persisted_async(now, persist, |store| {
            Ok(store.get_unnamed_v1(key, maximum, now))
        })
        .await
    }
}

#[derive(Debug)]
struct LocalPersistentRendezvousService {
    routes: LocalPersistentRouteStore,
    allow_legacy_named_v2_publication: bool,
}

impl LocalPersistentRendezvousService {
    fn open(
        context: NamedRouteV3LeaseContext,
        trusted_now: u64,
        storage: NamedRouteV3LedgerStorageState,
        allow_legacy_named_v2_publication: bool,
    ) -> Result<Self, HnsrProtocolError> {
        Ok(Self {
            routes: LocalPersistentRouteStore::open(context, trusted_now, storage)?,
            allow_legacy_named_v2_publication,
        })
    }

    fn handle<E, F>(
        &mut self,
        packet: &HnsrPacket,
        source: &str,
        now: u64,
        persist: &mut F,
    ) -> Result<Option<HnsrPacket>, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, &NamedRouteV3LedgerSnapshot) -> Result<(), E>,
    {
        self.routes.persist_pending(persist)?;
        match packet.opcode {
            HnsrOpcode::PutRoute => {
                let put = PutRouteBody::decode(&packet.body)?;
                let stored_until = match put.record.get(..2) {
                    Some([1, 0]) => self.routes.put_unnamed(
                        put.route_key,
                        put.record,
                        now,
                        source.to_owned(),
                        persist,
                    )?,
                    Some([2, 1]) if self.allow_legacy_named_v2_publication => {
                        self.routes.put_named_v2_for_admission(
                            put.route_key,
                            put.record,
                            now,
                            source.to_owned(),
                            persist,
                        )?
                    }
                    Some([3, 2]) => self.routes.put_named_v3_for_admission(
                        put.route_key,
                        put.record,
                        now,
                        source.to_owned(),
                        persist,
                    )?,
                    _ => {
                        return Err(HnsrProtocolError::Invalid(
                            "unsupported HNSR route record version",
                        )
                        .into());
                    }
                };
                Ok(Some(HnsrPacket::new(
                    HnsrOpcode::PutResult,
                    packet.context_id,
                    PutResultBody {
                        status: 0,
                        stored_until,
                    }
                    .encode(),
                )?))
            }
            HnsrOpcode::GetRoute => {
                let get = GetRouteBody::decode(&packet.body)?;
                let maximum = usize::from(get.maximum_records).min(MAX_CONTACTS);
                let mut records =
                    self.routes
                        .get_named_v3(&get.route_key, maximum, now, persist)?;
                let remaining = maximum.saturating_sub(records.len());
                records.extend(self.routes.get_unnamed_v1(
                    &get.route_key,
                    remaining,
                    now,
                    persist,
                )?);
                truncate_route_response(&mut records);
                Ok(Some(HnsrPacket::new(
                    HnsrOpcode::Routes,
                    packet.context_id,
                    RoutesBody { records }.encode()?,
                )?))
            }
            _ => Err(HnsrProtocolError::Invalid("unsupported HNSR rendezvous operation").into()),
        }
    }

    async fn handle_async<E, F, Fut>(
        &mut self,
        packet: &HnsrPacket,
        source: &str,
        now: u64,
        persist: &mut F,
    ) -> Result<Option<HnsrPacket>, LocalCommitError<E>>
    where
        F: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.routes.persist_pending_async(persist).await?;
        match packet.opcode {
            HnsrOpcode::PutRoute => {
                let put = PutRouteBody::decode(&packet.body)?;
                let stored_until = match put.record.get(..2) {
                    Some([1, 0]) => {
                        self.routes
                            .put_unnamed_async(
                                put.route_key,
                                put.record,
                                now,
                                source.to_owned(),
                                persist,
                            )
                            .await?
                    }
                    Some([2, 1]) if self.allow_legacy_named_v2_publication => {
                        self.routes
                            .put_named_v2_for_admission_async(
                                put.route_key,
                                put.record,
                                now,
                                source.to_owned(),
                                persist,
                            )
                            .await?
                    }
                    Some([3, 2]) => {
                        self.routes
                            .put_named_v3_for_admission_async(
                                put.route_key,
                                put.record,
                                now,
                                source.to_owned(),
                                persist,
                            )
                            .await?
                    }
                    _ => {
                        return Err(HnsrProtocolError::Invalid(
                            "unsupported HNSR route record version",
                        )
                        .into());
                    }
                };
                Ok(Some(HnsrPacket::new(
                    HnsrOpcode::PutResult,
                    packet.context_id,
                    PutResultBody {
                        status: 0,
                        stored_until,
                    }
                    .encode(),
                )?))
            }
            HnsrOpcode::GetRoute => {
                let get = GetRouteBody::decode(&packet.body)?;
                let maximum = usize::from(get.maximum_records).min(MAX_CONTACTS);
                let mut records = self
                    .routes
                    .get_named_v3_async(&get.route_key, maximum, now, persist)
                    .await?;
                let remaining = maximum.saturating_sub(records.len());
                records.extend(
                    self.routes
                        .get_unnamed_v1_async(&get.route_key, remaining, now, persist)
                        .await?,
                );
                truncate_route_response(&mut records);
                Ok(Some(HnsrPacket::new(
                    HnsrOpcode::Routes,
                    packet.context_id,
                    RoutesBody { records }.encode()?,
                )?))
            }
            _ => Err(HnsrProtocolError::Invalid("unsupported HNSR rendezvous operation").into()),
        }
    }

    const fn route_count(&self) -> usize {
        self.routes.route_count()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundaryFailure {
    Poisoned,
    LeaseLost,
}

/// Non-cloneable production rendezvous stage owning the sole-writer lease.
///
/// Construction invokes the storage loader only after acquiring the lease.
/// The loader remains part of the trusted computing base and must perform or
/// reconfirm its actual read inside that callback under the supplied fence.
/// Packet outcomes are delivered only through [`Self::handle_and_emit`] or
/// [`Self::handle_and_emit_async`], while the guard is owned. Lease loss,
/// canceled async work, unwind, and ambiguous emission poison the stage and
/// discard all volatile route bytes. Drop it and call `open` again to reacquire
/// and reload.
///
/// ```compile_fail
/// use hns_hnsr_protocol::LeasedPersistentRendezvousService;
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<LeasedPersistentRendezvousService<MyLease>>();
/// # struct MyLease;
/// ```
#[derive(Debug)]
pub struct LeasedPersistentRendezvousService<L> {
    lease: L,
    context: NamedRouteV3LeaseContext,
    inner: Option<LocalPersistentRendezvousService>,
    poisoned: bool,
    operation_in_flight: bool,
}

impl<L> LeasedPersistentRendezvousService<L>
where
    L: NamedRouteV3SoleOwnerLease,
{
    /// Acquire sole ownership, then load authenticated storage while held.
    ///
    /// The loader is invoked only after acquisition and receives the exact
    /// acquired context. It is a trusted external-I/O boundary: it must perform
    /// or reconfirm the authenticated read inside this callback and atomically
    /// reject a stale namespace/fence. Capturing an earlier read is invalid.
    pub fn open<A, Load, AcquireError, LoadError>(
        namespace: NamedRouteV3StorageNamespace,
        trusted_now: u64,
        allow_legacy_named_v2_publication: bool,
        acquire: A,
        load: Load,
    ) -> Result<Self, NamedRouteV3OpenError<AcquireError, LoadError>>
    where
        A: FnOnce(NamedRouteV3StorageNamespace) -> Result<L, AcquireError>,
        Load: FnOnce(
            NamedRouteV3LeaseContext,
        ) -> Result<
            NamedRouteV3LedgerStorageState,
            NamedRouteV3GuardedCallbackError<LoadError>,
        >,
    {
        let mut lease = acquire(namespace).map_err(NamedRouteV3OpenError::Acquisition)?;
        let context = Self::validate_acquisition(namespace, &mut lease)?;
        let storage = match load(context) {
            Ok(storage) => storage,
            Err(NamedRouteV3GuardedCallbackError::LeaseLost) => {
                return Err(NamedRouteV3OpenError::LeaseLost);
            }
            Err(NamedRouteV3GuardedCallbackError::Other(error)) => {
                return Err(NamedRouteV3OpenError::Load(error));
            }
        };
        lease
            .ensure_held()
            .map_err(|_| NamedRouteV3OpenError::LeaseLost)?;
        let inner = LocalPersistentRendezvousService::open(
            context,
            trusted_now,
            storage,
            allow_legacy_named_v2_publication,
        )
        .map_err(NamedRouteV3OpenError::Protocol)?;
        Ok(Self {
            lease,
            context,
            inner: Some(inner),
            poisoned: false,
            operation_in_flight: false,
        })
    }

    /// Async acquisition and post-acquisition loading for browser/mobile stores.
    ///
    /// Cancellation while loading drops the acquired guard and cannot create a
    /// service from partially loaded state. As with synchronous loading, the
    /// callback must read or reconfirm external state under the supplied fence.
    pub async fn open_async<A, AcquireFuture, Load, LoadFuture, AcquireError, LoadError>(
        namespace: NamedRouteV3StorageNamespace,
        trusted_now: u64,
        allow_legacy_named_v2_publication: bool,
        acquire: A,
        load: Load,
    ) -> Result<Self, NamedRouteV3OpenError<AcquireError, LoadError>>
    where
        A: FnOnce(NamedRouteV3StorageNamespace) -> AcquireFuture,
        AcquireFuture: Future<Output = Result<L, AcquireError>>,
        Load: FnOnce(NamedRouteV3LeaseContext) -> LoadFuture,
        LoadFuture: Future<
            Output = Result<
                NamedRouteV3LedgerStorageState,
                NamedRouteV3GuardedCallbackError<LoadError>,
            >,
        >,
    {
        let mut lease = acquire(namespace)
            .await
            .map_err(NamedRouteV3OpenError::Acquisition)?;
        let context = Self::validate_acquisition(namespace, &mut lease)?;
        let storage = match load(context).await {
            Ok(storage) => storage,
            Err(NamedRouteV3GuardedCallbackError::LeaseLost) => {
                return Err(NamedRouteV3OpenError::LeaseLost);
            }
            Err(NamedRouteV3GuardedCallbackError::Other(error)) => {
                return Err(NamedRouteV3OpenError::Load(error));
            }
        };
        lease
            .ensure_held()
            .map_err(|_| NamedRouteV3OpenError::LeaseLost)?;
        let inner = LocalPersistentRendezvousService::open(
            context,
            trusted_now,
            storage,
            allow_legacy_named_v2_publication,
        )
        .map_err(NamedRouteV3OpenError::Protocol)?;
        Ok(Self {
            lease,
            context,
            inner: Some(inner),
            poisoned: false,
            operation_in_flight: false,
        })
    }

    fn validate_acquisition<AcquireError, LoadError>(
        namespace: NamedRouteV3StorageNamespace,
        lease: &mut L,
    ) -> Result<NamedRouteV3LeaseContext, NamedRouteV3OpenError<AcquireError, LoadError>> {
        if lease.namespace() != namespace {
            return Err(NamedRouteV3OpenError::LeaseBinding);
        }
        lease
            .ensure_held()
            .map_err(|_| NamedRouteV3OpenError::LeaseLost)?;
        Ok(NamedRouteV3LeaseContext {
            namespace,
            fencing_token: lease.fencing_token(),
        })
    }

    /// Exact acquisition context used by every storage callback.
    pub const fn lease_context(&self) -> NamedRouteV3LeaseContext {
        self.context
    }

    /// Whether volatile state has been discarded and reopening is required.
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Diagnostic count of volatile live routes; zero after poisoning/reopen.
    pub fn volatile_route_count(&self) -> usize {
        self.inner
            .as_ref()
            .map_or(0, LocalPersistentRendezvousService::route_count)
    }

    /// Admit one V3 route against exact-current, durably committed authority.
    ///
    /// The returned expiry is a diagnostic released only after any resulting
    /// replay-ledger CAS is acknowledged under the current fencing token.
    #[allow(clippy::too_many_arguments)]
    pub fn put_named_v3_current<Persist, PersistenceError>(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        committed_service: &CurrentCommittedNamedService<'_>,
        policy: HrmNamedRoutePolicy,
        now: u64,
        source: String,
        persist: &mut Persist,
    ) -> Result<u64, LeasedPersistentRouteMutationError<PersistenceError>>
    where
        Persist: FnMut(
            NamedRouteV3LedgerExpectation,
            &NamedRouteV3LedgerSnapshot,
        ) -> Result<(), NamedRouteV3GuardedCallbackError<PersistenceError>>,
    {
        self.ensure_authority_held(committed_service)?;
        let mut inner = self.take_inner_for_guarded_mutation()?;
        let result =
            inner
                .routes
                .put_named_v3(key, raw, committed_service, policy, now, source, persist);
        if committed_service.ensure_lease_held().is_err() {
            self.poison();
            return Err(LeasedPersistentRouteMutationError::AuthorityLeaseLost);
        }
        self.finish_owned_mutation(inner, result)
    }

    /// Await current-authority admission under the owned lease.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_named_v3_current_async<Persist, PersistFuture, PersistenceError>(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        committed_service: &CurrentCommittedNamedService<'_>,
        policy: HrmNamedRoutePolicy,
        now: u64,
        source: String,
        persist: &mut Persist,
    ) -> Result<u64, LeasedPersistentRouteMutationError<PersistenceError>>
    where
        Persist: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> PersistFuture,
        PersistFuture:
            Future<Output = Result<(), NamedRouteV3GuardedCallbackError<PersistenceError>>>,
    {
        self.ensure_authority_held(committed_service)?;
        let mut inner = self.take_inner_for_guarded_mutation()?;
        let result = inner
            .routes
            .put_named_v3_async(key, raw, committed_service, policy, now, source, persist)
            .await;
        if committed_service.ensure_lease_held().is_err() {
            self.poison();
            return Err(LeasedPersistentRouteMutationError::AuthorityLeaseLost);
        }
        self.finish_owned_mutation(inner, result)
    }

    /// Revalidate volatile bytes against exact-current committed authority.
    pub fn revalidate_named_v3_current<Persist, PersistenceError>(
        &mut self,
        identity: &NamedServiceIdentity,
        committed_service: &CurrentCommittedNamedService<'_>,
        policy: HrmNamedRoutePolicy,
        now: u64,
        persist: &mut Persist,
    ) -> Result<usize, LeasedPersistentRouteMutationError<PersistenceError>>
    where
        Persist: FnMut(
            NamedRouteV3LedgerExpectation,
            &NamedRouteV3LedgerSnapshot,
        ) -> Result<(), NamedRouteV3GuardedCallbackError<PersistenceError>>,
    {
        self.ensure_authority_held(committed_service)?;
        let mut inner = self.take_inner_for_guarded_mutation()?;
        let result = inner.routes.revalidate_named_v3_current(
            identity,
            committed_service,
            policy,
            now,
            persist,
        );
        if committed_service.ensure_lease_held().is_err() {
            self.poison();
            return Err(LeasedPersistentRouteMutationError::AuthorityLeaseLost);
        }
        self.finish_owned_mutation(inner, result)
    }

    /// Await current-authority revalidation under the owned lease.
    pub async fn revalidate_named_v3_current_async<Persist, PersistFuture, PersistenceError>(
        &mut self,
        identity: &NamedServiceIdentity,
        committed_service: &CurrentCommittedNamedService<'_>,
        policy: HrmNamedRoutePolicy,
        now: u64,
        persist: &mut Persist,
    ) -> Result<usize, LeasedPersistentRouteMutationError<PersistenceError>>
    where
        Persist: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> PersistFuture,
        PersistFuture:
            Future<Output = Result<(), NamedRouteV3GuardedCallbackError<PersistenceError>>>,
    {
        self.ensure_authority_held(committed_service)?;
        let mut inner = self.take_inner_for_guarded_mutation()?;
        let result = inner
            .routes
            .revalidate_named_v3_current_async(identity, committed_service, policy, now, persist)
            .await;
        if committed_service.ensure_lease_held().is_err() {
            self.poison();
            return Err(LeasedPersistentRouteMutationError::AuthorityLeaseLost);
        }
        self.finish_owned_mutation(inner, result)
    }

    /// Apply an exact-current committed withdrawal at the supplied trusted time.
    pub fn invalidate_named_v3_withdrawal<Persist, PersistenceError>(
        &mut self,
        identity: &NamedServiceIdentity,
        committed_service: &CurrentCommittedNamedService<'_>,
        now: u64,
        persist: &mut Persist,
    ) -> Result<usize, LeasedPersistentRouteMutationError<PersistenceError>>
    where
        Persist: FnMut(
            NamedRouteV3LedgerExpectation,
            &NamedRouteV3LedgerSnapshot,
        ) -> Result<(), NamedRouteV3GuardedCallbackError<PersistenceError>>,
    {
        self.ensure_authority_held(committed_service)?;
        let mut inner = self.take_inner_for_guarded_mutation()?;
        let result =
            inner
                .routes
                .invalidate_named_v3_withdrawal(identity, committed_service, now, persist);
        if committed_service.ensure_lease_held().is_err() {
            self.poison();
            return Err(LeasedPersistentRouteMutationError::AuthorityLeaseLost);
        }
        self.finish_owned_mutation(inner, result)
    }

    /// Await exact-time committed withdrawal invalidation under the lease.
    pub async fn invalidate_named_v3_withdrawal_async<Persist, PersistFuture, PersistenceError>(
        &mut self,
        identity: &NamedServiceIdentity,
        committed_service: &CurrentCommittedNamedService<'_>,
        now: u64,
        persist: &mut Persist,
    ) -> Result<usize, LeasedPersistentRouteMutationError<PersistenceError>>
    where
        Persist: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> PersistFuture,
        PersistFuture:
            Future<Output = Result<(), NamedRouteV3GuardedCallbackError<PersistenceError>>>,
    {
        self.ensure_authority_held(committed_service)?;
        let mut inner = self.take_inner_for_guarded_mutation()?;
        let result = inner
            .routes
            .invalidate_named_v3_withdrawal_async(identity, committed_service, now, persist)
            .await;
        if committed_service.ensure_lease_held().is_err() {
            self.poison();
            return Err(LeasedPersistentRouteMutationError::AuthorityLeaseLost);
        }
        self.finish_owned_mutation(inner, result)
    }

    /// Durably handle one packet and emit its response or protocol error while
    /// sole ownership is still held.
    ///
    /// `persist` must atomically reject a namespace/token mismatch with
    /// [`NamedRouteV3GuardedCallbackError::LeaseLost`]. A normal return means
    /// the exact proposed bytes are durable (or were already installed by an
    /// outcome-ambiguous retry). No owned packet or protocol error is returned.
    ///
    /// `emit` may return success only after delivery actually completes while
    /// the lease is held, or after a broker-owned, fence-tagged atomic promotion
    /// which rejects stale consumers. Merely scheduling, queueing, or calling
    /// `postMessage` is not successful emission. Any retained outcome must stay
    /// broker-owned and be discarded if this context's fence becomes stale.
    pub fn handle_and_emit<Persist, Emit, PersistenceError, EmissionError>(
        &mut self,
        packet: &HnsrPacket,
        source: &str,
        now: u64,
        persist: &mut Persist,
        emit: Emit,
    ) -> Result<(), LeasedPersistentRendezvousError<PersistenceError, EmissionError>>
    where
        Persist: FnMut(
            NamedRouteV3LedgerExpectation,
            &NamedRouteV3LedgerSnapshot,
        ) -> Result<(), NamedRouteV3GuardedCallbackError<PersistenceError>>,
        Emit: FnOnce(
            NamedRouteV3LeaseContext,
            NamedRouteV3Emission,
        ) -> Result<(), NamedRouteV3GuardedCallbackError<EmissionError>>,
    {
        self.begin_operation().map_err(Self::map_boundary)?;
        let mut inner = self.inner.take().expect("checked live leased service");
        // If a storage or emission callback unwinds, `inner` is dropped and
        // the public object remains poisoned rather than retaining live bytes.
        self.poisoned = true;
        let handled = inner.handle(packet, source, now, persist);
        let emission = match handled {
            Ok(Some(response)) => NamedRouteV3Emission::Response(response),
            Ok(None) => {
                return self.restore_inner(inner).map_err(Self::map_boundary);
            }
            Err(LocalCommitError::Protocol(error)) => NamedRouteV3Emission::ProtocolError(error),
            Err(LocalCommitError::Persistence(NamedRouteV3GuardedCallbackError::LeaseLost)) => {
                self.poison();
                return Err(LeasedPersistentRendezvousError::LeaseLost);
            }
            Err(LocalCommitError::Persistence(NamedRouteV3GuardedCallbackError::Other(error))) => {
                self.restore_inner(inner).map_err(Self::map_boundary)?;
                return Err(LeasedPersistentRendezvousError::Persistence(error));
            }
        };
        if self.lease.ensure_held().is_err() {
            self.poison();
            return Err(LeasedPersistentRendezvousError::LeaseLost);
        }
        match emit(self.context, emission) {
            Ok(()) => self.restore_inner(inner).map_err(Self::map_boundary),
            Err(NamedRouteV3GuardedCallbackError::LeaseLost) => {
                self.poison();
                Err(LeasedPersistentRendezvousError::LeaseLost)
            }
            Err(NamedRouteV3GuardedCallbackError::Other(error)) => {
                self.poison();
                Err(LeasedPersistentRendezvousError::Emission(error))
            }
        }
    }

    /// Await durable handling and guarded emission under the owned lease.
    ///
    /// The in-flight marker is cleared only after the same completed-delivery or
    /// fenced-promotion contract documented on [`Self::handle_and_emit`].
    /// Dropping this future while storage or emission is pending immediately
    /// leaves the service poisoned and drops its volatile inner state.
    pub async fn handle_and_emit_async<
        Persist,
        PersistFuture,
        Emit,
        EmitFuture,
        PersistenceError,
        EmissionError,
    >(
        &mut self,
        packet: &HnsrPacket,
        source: &str,
        now: u64,
        persist: &mut Persist,
        emit: Emit,
    ) -> Result<(), LeasedPersistentRendezvousError<PersistenceError, EmissionError>>
    where
        Persist: FnMut(NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot) -> PersistFuture,
        PersistFuture:
            Future<Output = Result<(), NamedRouteV3GuardedCallbackError<PersistenceError>>>,
        Emit: FnOnce(NamedRouteV3LeaseContext, NamedRouteV3Emission) -> EmitFuture,
        EmitFuture: Future<Output = Result<(), NamedRouteV3GuardedCallbackError<EmissionError>>>,
    {
        self.begin_operation().map_err(Self::map_boundary)?;
        let mut inner = self.inner.take().expect("checked live leased service");
        // Cancellation from this point drops `inner`; the public object stays
        // poisoned and cannot release any of those volatile bytes.
        self.poisoned = true;
        let handled = inner.handle_async(packet, source, now, persist).await;
        let emission = match handled {
            Ok(Some(response)) => NamedRouteV3Emission::Response(response),
            Ok(None) => {
                return self.restore_inner(inner).map_err(Self::map_boundary);
            }
            Err(LocalCommitError::Protocol(error)) => NamedRouteV3Emission::ProtocolError(error),
            Err(LocalCommitError::Persistence(NamedRouteV3GuardedCallbackError::LeaseLost)) => {
                self.poison();
                return Err(LeasedPersistentRendezvousError::LeaseLost);
            }
            Err(LocalCommitError::Persistence(NamedRouteV3GuardedCallbackError::Other(error))) => {
                self.restore_inner(inner).map_err(Self::map_boundary)?;
                return Err(LeasedPersistentRendezvousError::Persistence(error));
            }
        };
        if self.lease.ensure_held().is_err() {
            self.poison();
            return Err(LeasedPersistentRendezvousError::LeaseLost);
        }
        match emit(self.context, emission).await {
            Ok(()) => self.restore_inner(inner).map_err(Self::map_boundary),
            Err(NamedRouteV3GuardedCallbackError::LeaseLost) => {
                self.poison();
                Err(LeasedPersistentRendezvousError::LeaseLost)
            }
            Err(NamedRouteV3GuardedCallbackError::Other(error)) => {
                self.poison();
                Err(LeasedPersistentRendezvousError::Emission(error))
            }
        }
    }

    fn ensure_authority_held<P>(
        &mut self,
        committed_service: &CurrentCommittedNamedService<'_>,
    ) -> Result<(), LeasedPersistentRouteMutationError<P>> {
        if committed_service.ensure_lease_held().is_err() {
            self.poison();
            Err(LeasedPersistentRouteMutationError::AuthorityLeaseLost)
        } else {
            Ok(())
        }
    }

    fn take_inner_for_guarded_mutation<P>(
        &mut self,
    ) -> Result<LocalPersistentRendezvousService, LeasedPersistentRouteMutationError<P>> {
        self.begin_operation()
            .map_err(Self::map_mutation_boundary)?;
        let inner = self.inner.take().expect("checked live leased service");
        self.poisoned = true;
        Ok(inner)
    }

    fn finish_owned_mutation<T, P>(
        &mut self,
        inner: LocalPersistentRendezvousService,
        result: Result<T, LocalCommitError<NamedRouteV3GuardedCallbackError<P>>>,
    ) -> Result<T, LeasedPersistentRouteMutationError<P>> {
        if matches!(
            result,
            Err(LocalCommitError::Persistence(
                NamedRouteV3GuardedCallbackError::LeaseLost
            ))
        ) {
            self.poison();
            return Err(LeasedPersistentRouteMutationError::LeaseLost);
        }
        self.restore_inner(inner)
            .map_err(Self::map_mutation_boundary)?;
        match result {
            Ok(value) => Ok(value),
            Err(LocalCommitError::Protocol(error)) => {
                Err(LeasedPersistentRouteMutationError::Protocol(error))
            }
            Err(LocalCommitError::Persistence(NamedRouteV3GuardedCallbackError::Other(error))) => {
                Err(LeasedPersistentRouteMutationError::Persistence(error))
            }
            Err(LocalCommitError::Persistence(NamedRouteV3GuardedCallbackError::LeaseLost)) => {
                unreachable!("handled before restoring the async inner service")
            }
        }
    }

    fn restore_inner(
        &mut self,
        inner: LocalPersistentRendezvousService,
    ) -> Result<(), BoundaryFailure> {
        if self.lease.ensure_held().is_err() {
            self.poison();
            return Err(BoundaryFailure::LeaseLost);
        }
        self.inner = Some(inner);
        self.poisoned = false;
        self.operation_in_flight = false;
        Ok(())
    }

    fn begin_operation(&mut self) -> Result<(), BoundaryFailure> {
        if self.poisoned || self.inner.is_none() {
            return Err(BoundaryFailure::Poisoned);
        }
        if self.operation_in_flight {
            self.poison();
            return Err(BoundaryFailure::Poisoned);
        }
        self.operation_in_flight = true;
        if self.lease.ensure_held().is_err() {
            self.poison();
            return Err(BoundaryFailure::LeaseLost);
        }
        Ok(())
    }

    fn poison(&mut self) {
        self.inner = None;
        self.poisoned = true;
        self.operation_in_flight = false;
    }

    fn map_boundary<P, E>(failure: BoundaryFailure) -> LeasedPersistentRendezvousError<P, E> {
        match failure {
            BoundaryFailure::Poisoned => LeasedPersistentRendezvousError::Poisoned,
            BoundaryFailure::LeaseLost => LeasedPersistentRendezvousError::LeaseLost,
        }
    }

    fn map_mutation_boundary<P>(failure: BoundaryFailure) -> LeasedPersistentRouteMutationError<P> {
        match failure {
            BoundaryFailure::Poisoned => LeasedPersistentRouteMutationError::Poisoned,
            BoundaryFailure::LeaseLost => LeasedPersistentRouteMutationError::LeaseLost,
        }
    }
}

fn truncate_route_response(records: &mut Vec<Vec<u8>>) {
    let mut response_size = ROUTES_BODY_FIXED_SIZE;
    records.truncate(
        records
            .iter()
            .take_while(|record| {
                let next = response_size
                    .saturating_add(ROUTES_BODY_RECORD_PREFIX_SIZE)
                    .saturating_add(record.len());
                if next > ROUTES_BODY_MAX_SIZE {
                    return false;
                }
                response_size = next;
                true
            })
            .count(),
    );
}
