//! Durable subject-wide HNSA rollback and service-generation authority.
//!
//! This module is the production boundary around HRM validation and HNSA
//! observation. It keeps one bounded aggregate for an exact `(network,
//! subject)`, advances a trusted-time high-water mark, and releases a durable
//! result only after the aggregate's exact compare-and-swap has been
//! acknowledged by storage. Operational use additionally requires rebinding
//! that result as the exact current borrowed guard.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_encoding::{DecodeError, Decoder, Encoder};
use hns_hrm::model::MAX_RESOURCES;
use hns_hrm::validation::{
    ResolvedManifest, RollbackObservations, RollbackState, ValidationError, ValidationLimits,
    validate_current_manifest,
};
use thiserror::Error;

use crate::hrm::{
    HnsaError, NamedServiceIdentity, NamedServicePolicy, ObservedNamedService,
    SERVICE_GENERATION_OBSERVATION_SIZE, ServiceGenerationObservation, VerifiedNamedService,
    observe_named_service,
};
use crate::lease::{AuthorityLeaseWitness, FencingToken, LeaseError, StorageNamespaceId};

/// Durable authority snapshot format version.
pub const NAMED_SERVICE_AUTHORITY_SNAPSHOT_VERSION: u8 = 1;
/// Hard upper bound on service observations or withdrawal tombstones per subject.
pub const MAX_NAMED_SERVICE_AUTHORITY_ENTRIES: usize = MAX_RESOURCES;

const SNAPSHOT_MAGIC: &[u8; 8] = b"HNSAAST\0";
const SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"HNS-HRM-HNSA-AUTHORITY-SNAPSHOT-CHECKSUM-V1\0";
const SNAPSHOT_FINGERPRINT_DOMAIN: &[u8] = b"HNS-HRM-HNSA-AUTHORITY-SNAPSHOT-FINGERPRINT-V1\0";
const CHECKSUM_SIZE: usize = 32;
const ROLLBACK_BODY_SIZE: usize = 8 + 32 + 4 + 32 + 32;
const SNAPSHOT_HEADER_SIZE: usize = 8 + 1 + 4 + 32 + 4 + 8 + 8 + 1 + ROLLBACK_BODY_SIZE + 4;
const MIN_SNAPSHOT_SIZE: usize = SNAPSHOT_HEADER_SIZE + CHECKSUM_SIZE;
const MAX_SNAPSHOT_SIZE: usize = SNAPSHOT_HEADER_SIZE
    + MAX_NAMED_SERVICE_AUTHORITY_ENTRIES * SERVICE_GENERATION_OBSERVATION_SIZE
    + CHECKSUM_SIZE;

/// Fenced storage precondition for a pending durable authority snapshot.
///
/// The storage adapter must validate the namespace identity and fencing token
/// in the same atomic transaction as the snapshot compare-and-swap. Checking a
/// lease immediately before an unfenced write is not equivalent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamedServiceAuthorityExpectation {
    /// Create the aggregate only if no value exists for the exact subject key.
    Absent {
        storage_namespace_id: StorageNamespaceId,
        fencing_token: FencingToken,
    },
    /// Replace only the exact previously acknowledged aggregate.
    Exact {
        storage_namespace_id: StorageNamespaceId,
        fencing_token: FencingToken,
        revision: u64,
        fingerprint: [u8; 32],
    },
}

impl NamedServiceAuthorityExpectation {
    pub const fn storage_namespace_id(self) -> StorageNamespaceId {
        match self {
            Self::Absent {
                storage_namespace_id,
                ..
            }
            | Self::Exact {
                storage_namespace_id,
                ..
            } => storage_namespace_id,
        }
    }

    pub const fn fencing_token(self) -> FencingToken {
        match self {
            Self::Absent { fencing_token, .. } | Self::Exact { fencing_token, .. } => fencing_token,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityPersistenceExpectation {
    Absent,
    Exact {
        revision: u64,
        fingerprint: [u8; 32],
    },
}

impl AuthorityPersistenceExpectation {
    fn fenced(self, lease: &AuthorityLeaseWitness<'_>) -> NamedServiceAuthorityExpectation {
        let storage_namespace_id = lease.key().storage_namespace_id();
        let fencing_token = lease.fencing_token();
        match self {
            Self::Absent => NamedServiceAuthorityExpectation::Absent {
                storage_namespace_id,
                fencing_token,
            },
            Self::Exact {
                revision,
                fingerprint,
            } => NamedServiceAuthorityExpectation::Exact {
                storage_namespace_id,
                fencing_token,
                revision,
                fingerprint,
            },
        }
    }
}

/// Authenticated durable value returned by an authority loader while leased.
///
/// The loader is part of the trusted embedding boundary. `Present` bytes must
/// come from the exact subject key in the witness's physical storage namespace,
/// and `minimum_revision` must be the embedding's authenticated rollback floor.
#[derive(Debug)]
pub enum NamedServiceAuthorityStorageState {
    Absent,
    Present {
        encoded: Vec<u8>,
        minimum_revision: u64,
    },
}

/// A bounded, opaque, canonical authority aggregate for one HNS subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedServiceAuthoritySnapshot {
    network_magic: u32,
    subject: [u8; 32],
    capacity: usize,
    revision: u64,
    trusted_time_high_water: u64,
    rollback_state: Option<RollbackState>,
    observations: BTreeMap<[u8; 32], ServiceGenerationObservation>,
}

impl NamedServiceAuthoritySnapshot {
    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }

    pub const fn subject(&self) -> [u8; 32] {
        self.subject
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn trusted_time_high_water(&self) -> u64 {
        self.trusted_time_high_water
    }

    pub const fn rollback_state(&self) -> Option<RollbackState> {
        self.rollback_state
    }

    pub fn len(&self) -> usize {
        self.observations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    pub fn observation(&self, resource_id: &[u8; 32]) -> Option<&ServiceGenerationObservation> {
        self.observations.get(resource_id)
    }

    pub fn observations(
        &self,
    ) -> impl ExactSizeIterator<Item = &ServiceGenerationObservation> + DoubleEndedIterator {
        self.observations.values()
    }

    /// Encode the canonical bounded representation with an unkeyed corruption checksum.
    ///
    /// The checksum is not storage authentication. Persist these bytes through
    /// authenticated local storage using [`NamedServiceAuthorityExpectation`].
    pub fn encode(&self) -> Result<Vec<u8>, NamedServiceAuthorityError> {
        self.validate()?;
        let entry_bytes = self
            .observations
            .len()
            .checked_mul(SERVICE_GENERATION_OBSERVATION_SIZE)
            .ok_or(NamedServiceAuthorityError::InvalidSnapshot(
                "authority snapshot size overflow",
            ))?;
        let encoded_size = SNAPSHOT_HEADER_SIZE
            .checked_add(entry_bytes)
            .and_then(|size| size.checked_add(CHECKSUM_SIZE))
            .ok_or(NamedServiceAuthorityError::InvalidSnapshot(
                "authority snapshot size overflow",
            ))?;
        let mut encoder = Encoder::with_capacity(encoded_size);
        encoder.put_bytes(SNAPSHOT_MAGIC);
        encoder.put_u8(NAMED_SERVICE_AUTHORITY_SNAPSHOT_VERSION);
        encoder.put_u32_le(self.network_magic);
        encoder.put_bytes(&self.subject);
        encoder.put_u32_le(u32::try_from(self.capacity).map_err(|_| {
            NamedServiceAuthorityError::InvalidSnapshot("authority capacity is not encodable")
        })?);
        encoder.put_u64_le(self.revision);
        encoder.put_u64_le(self.trusted_time_high_water);
        encoder.put_u8(u8::from(self.rollback_state.is_some()));
        if let Some(rollback) = self.rollback_state {
            encode_rollback_body(&mut encoder, rollback);
        } else {
            encoder.put_bytes(&[0; ROLLBACK_BODY_SIZE]);
        }
        encoder.put_u32_le(u32::try_from(self.observations.len()).map_err(|_| {
            NamedServiceAuthorityError::InvalidSnapshot("authority entry count is not encodable")
        })?);
        for observation in self.observations.values() {
            encoder.put_bytes(&observation.encode()?);
        }
        let mut encoded = encoder.into_bytes();
        if encoded.len() + CHECKSUM_SIZE != encoded_size {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "authority snapshot encoded size mismatch",
            ));
        }
        encoded.extend_from_slice(&snapshot_checksum(&encoded));
        Ok(encoded)
    }

    /// Decode and fully validate an exact canonical bounded representation.
    pub fn decode(input: &[u8]) -> Result<Self, NamedServiceAuthorityError> {
        if !(MIN_SNAPSHOT_SIZE..=MAX_SNAPSHOT_SIZE).contains(&input.len()) {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "invalid authority snapshot size",
            ));
        }
        let payload_size = input.len() - CHECKSUM_SIZE;
        let (payload, supplied_checksum) = input.split_at(payload_size);
        if supplied_checksum != snapshot_checksum(payload) {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "authority snapshot checksum mismatch",
            ));
        }

        let mut decoder = Decoder::new(payload);
        if decoder.read_array::<8>()? != *SNAPSHOT_MAGIC {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "invalid authority snapshot magic",
            ));
        }
        if decoder.read_u8()? != NAMED_SERVICE_AUTHORITY_SNAPSHOT_VERSION {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "unsupported authority snapshot version",
            ));
        }
        let network_magic = decoder.read_u32_le()?;
        let subject = decoder.read_array()?;
        let capacity = usize::try_from(decoder.read_u32_le()?).map_err(|_| {
            NamedServiceAuthorityError::InvalidSnapshot("invalid authority capacity")
        })?;
        validate_capacity(capacity)?;
        let revision = decoder.read_u64_le()?;
        let trusted_time_high_water = decoder.read_u64_le()?;
        let has_rollback = decoder.read_u8()?;
        let rollback_body = decoder.read_slice(ROLLBACK_BODY_SIZE)?;
        let rollback_state = match has_rollback {
            0 => {
                if rollback_body != [0; ROLLBACK_BODY_SIZE] {
                    return Err(NamedServiceAuthorityError::InvalidSnapshot(
                        "noncanonical absent rollback state",
                    ));
                }
                None
            }
            1 => Some(decode_rollback_body(rollback_body, network_magic, subject)?),
            _ => {
                return Err(NamedServiceAuthorityError::InvalidSnapshot(
                    "invalid authority rollback-state marker",
                ));
            }
        };
        let count = usize::try_from(decoder.read_u32_le()?).map_err(|_| {
            NamedServiceAuthorityError::InvalidSnapshot("invalid authority entry count")
        })?;
        if count > capacity {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "authority entry count exceeds capacity",
            ));
        }
        let expected_remaining = count
            .checked_mul(SERVICE_GENERATION_OBSERVATION_SIZE)
            .ok_or(NamedServiceAuthorityError::InvalidSnapshot(
                "authority entry size overflow",
            ))?;
        if decoder.remaining() != expected_remaining {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "authority snapshot entry length mismatch",
            ));
        }

        let mut observations = BTreeMap::new();
        let mut previous_resource = None;
        for _ in 0..count {
            let encoded = decoder.read_slice(SERVICE_GENERATION_OBSERVATION_SIZE)?;
            let observation = ServiceGenerationObservation::decode(encoded)?;
            let resource_id = observation.resource_id();
            if observation.network_magic() != network_magic || observation.subject() != subject {
                return Err(NamedServiceAuthorityError::InvalidSnapshot(
                    "authority service observation binding mismatch",
                ));
            }
            if previous_resource.is_some_and(|previous| resource_id <= previous) {
                return Err(NamedServiceAuthorityError::InvalidSnapshot(
                    "authority service observations are not strictly sorted",
                ));
            }
            previous_resource = Some(resource_id);
            if observations.insert(resource_id, observation).is_some() {
                return Err(NamedServiceAuthorityError::InvalidSnapshot(
                    "duplicate authority service observation",
                ));
            }
        }
        decoder.finish()?;

        let snapshot = Self {
            network_magic,
            subject,
            capacity,
            revision,
            trusted_time_high_water,
            rollback_state,
            observations,
        };
        snapshot.validate()?;
        if snapshot.encode()?.as_slice() != input {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "noncanonical authority snapshot",
            ));
        }
        Ok(snapshot)
    }

    /// Fingerprint the complete canonical snapshot for exact CAS.
    pub fn fingerprint(&self) -> Result<[u8; 32], NamedServiceAuthorityError> {
        Ok(blake2b_256(&[SNAPSHOT_FINGERPRINT_DOMAIN, &self.encode()?]))
    }

    fn exact_expectation(
        &self,
    ) -> Result<AuthorityPersistenceExpectation, NamedServiceAuthorityError> {
        Ok(AuthorityPersistenceExpectation::Exact {
            revision: self.revision,
            fingerprint: self.fingerprint()?,
        })
    }

    fn validate(&self) -> Result<(), NamedServiceAuthorityError> {
        validate_capacity(self.capacity)?;
        if self.revision == u64::MAX {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "authority revision u64::MAX is reserved",
            ));
        }
        let entry_count = u64::try_from(self.observations.len()).map_err(|_| {
            NamedServiceAuthorityError::InvalidSnapshot(
                "authority entry count is not representable as a revision",
            )
        })?;
        if entry_count > self.revision {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "authority entry count exceeds reachable revision lineage",
            ));
        }
        if self.observations.len() > self.capacity {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "authority entry count exceeds capacity",
            ));
        }
        let Some(global) = self.rollback_state else {
            if !self.observations.is_empty() {
                return Err(NamedServiceAuthorityError::InvalidSnapshot(
                    "service observations exist without a subject rollback state",
                ));
            }
            return Ok(());
        };
        if self.revision == 0 {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "revision zero cannot contain authority observations",
            ));
        }
        if global.network_magic != self.network_magic || global.subject != self.subject {
            return Err(NamedServiceAuthorityError::InvalidSnapshot(
                "subject rollback-state binding mismatch",
            ));
        }
        // HRM commitment sequence zero is valid. The checks below still reject
        // any retained per-service observation that is ahead of or conflicts
        // with that exact subject root.
        for (resource_id, observation) in &self.observations {
            if observation.network_magic() != self.network_magic
                || observation.subject() != self.subject
                || observation.resource_id() != *resource_id
            {
                return Err(NamedServiceAuthorityError::InvalidSnapshot(
                    "service observation binding mismatch",
                ));
            }
            // Accepted rollback events clear all earlier service observations,
            // so no retained observation may be ahead of the aggregate root.
            let service_root = observation.rollback_state();
            if service_root.sequence > global.sequence
                || service_root.chain_work > global.chain_work
                || (service_root.sequence == global.sequence
                    && service_root.envelope_hash != global.envelope_hash)
            {
                return Err(NamedServiceAuthorityError::InvalidSnapshot(
                    "service observation is ahead of subject rollback state",
                ));
            }
        }
        Ok(())
    }
}

/// Errors in authority snapshot validation or an authority decision.
#[derive(Debug, Error)]
pub enum NamedServiceAuthorityError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Hnsa(#[from] HnsaError),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Lease(#[from] LeaseError),
    #[error("invalid named-service authority snapshot: {0}")]
    InvalidSnapshot(&'static str),
    #[error("named-service authority state belongs to a different network, subject, or capacity")]
    BindingMismatch,
    #[error("trusted time rolled back below the persisted high-water mark")]
    TrustedTimeRollback,
    #[error("named-service authority revision is below the required minimum")]
    RevisionRollback,
    #[error("named-service authority revision is exhausted")]
    RevisionExhausted,
    #[error("named-service authority entry capacity is exhausted")]
    Capacity,
    #[error("named-service authority has an unacknowledged persistence proposal")]
    PendingPersistence,
    #[error("committed named-service result is not current for this authority state")]
    CommittedResultNotCurrent,
    #[error("named-service authority guard is not bound to the exact operation time")]
    OperationTimeMismatch,
    #[error("named-service authority durable state was not reconfirmed under the held lease")]
    DurableStateMismatch,
    #[error("named-service authority capability belongs to a different operation lease")]
    OperationLeaseMismatch,
}

/// An authority error or a caller-owned durable-storage failure.
#[derive(Debug)]
pub enum NamedServiceAuthorityCommitError<E> {
    Authority(NamedServiceAuthorityError),
    Persistence(E),
}

impl<E> From<NamedServiceAuthorityError> for NamedServiceAuthorityCommitError<E> {
    fn from(error: NamedServiceAuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl<E> From<LeaseError> for NamedServiceAuthorityCommitError<E> {
    fn from(error: LeaseError) -> Self {
        Self::Authority(error.into())
    }
}

impl<E: fmt::Display> fmt::Display for NamedServiceAuthorityCommitError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => error.fmt(formatter),
            Self::Persistence(error) => {
                write!(formatter, "authority snapshot persistence failed: {error}")
            }
        }
    }
}

impl<E> std::error::Error for NamedServiceAuthorityCommitError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Authority(error) => Some(error),
            Self::Persistence(error) => Some(error),
        }
    }
}

/// A retrieval, authority-decision, or durable-storage failure from the
/// ordered production operation.
///
/// Retrieval has its own type because it happens only after the exact trusted
/// operation time is durable. Persistence failures happen both before
/// retrieval (pending replay or the time transition) and after validation (the
/// HRM/HNSA transition), while authority failures cover lease, rollback,
/// validation, and HNSA decisions.
#[derive(Debug)]
pub enum NamedServiceAuthorityOperationError<R, P> {
    Retrieval(R),
    Authority(NamedServiceAuthorityError),
    Persistence(P),
}

impl<R, P> From<NamedServiceAuthorityError> for NamedServiceAuthorityOperationError<R, P> {
    fn from(error: NamedServiceAuthorityError) -> Self {
        Self::Authority(error)
    }
}

impl<R, P> From<LeaseError> for NamedServiceAuthorityOperationError<R, P> {
    fn from(error: LeaseError) -> Self {
        Self::Authority(error.into())
    }
}

impl<R, P> From<NamedServiceAuthorityCommitError<P>> for NamedServiceAuthorityOperationError<R, P> {
    fn from(error: NamedServiceAuthorityCommitError<P>) -> Self {
        match error {
            NamedServiceAuthorityCommitError::Authority(error) => Self::Authority(error),
            NamedServiceAuthorityCommitError::Persistence(error) => Self::Persistence(error),
        }
    }
}

impl<R: fmt::Display, P: fmt::Display> fmt::Display for NamedServiceAuthorityOperationError<R, P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retrieval(error) => write!(formatter, "authority retrieval failed: {error}"),
            Self::Authority(error) => error.fmt(formatter),
            Self::Persistence(error) => {
                write!(formatter, "authority snapshot persistence failed: {error}")
            }
        }
    }
}

impl<R, P> std::error::Error for NamedServiceAuthorityOperationError<R, P>
where
    R: std::error::Error + 'static,
    P: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Retrieval(error) => Some(error),
            Self::Authority(error) => Some(error),
            Self::Persistence(error) => Some(error),
        }
    }
}

/// Durable HNSA result whose aggregate CAS was acknowledged at one revision.
///
/// This owned value is historical evidence, not a permanently current
/// operational capability. Time advances, unrelated service observations,
/// withdrawals, replacements, and accepted reorganizations all advance the
/// subject-wide authority revision. Before every operational use, callers must
/// rebind this result through
/// [`ReconfirmedNamedServiceAuthorityState::bind_current_at`] and pass the
/// resulting [`CurrentCommittedNamedService`] guard downstream.
#[derive(Debug, Eq, PartialEq)]
pub struct CommittedNamedService {
    authority_revision: u64,
    observed: ObservedNamedService,
}

impl CommittedNamedService {
    pub const fn authority_revision(&self) -> u64 {
        self.authority_revision
    }

    /// Return the observation acknowledged at [`Self::authority_revision`].
    ///
    /// This does not prove the observation is still current. Operational code
    /// uses [`CurrentCommittedNamedService::observation`] after rebinding.
    pub const fn observation(&self) -> &ServiceGenerationObservation {
        self.observed.observation()
    }

    /// Whether the result was a withdrawal when its revision was committed.
    ///
    /// This does not prove the withdrawal is still current. Operational code
    /// uses [`CurrentCommittedNamedService::is_withdrawn`] after rebinding.
    pub const fn is_withdrawn(&self) -> bool {
        self.observation().is_withdrawn()
    }

    /// Return the active service acknowledged at this result's revision.
    ///
    /// The returned value is unbound historical data. Operational code must
    /// instead use [`CurrentCommittedNamedService::active`] after rebinding.
    pub fn active(&self) -> Option<&VerifiedNamedService> {
        match &self.observed {
            ObservedNamedService::Active(service) => Some(service),
            ObservedNamedService::Withdrawn(_) => None,
        }
    }

    /// Consume this historical result without proving it remains current.
    ///
    /// This is a low-level escape hatch for offline inspection and tests. It
    /// must not be used as a production authority boundary.
    pub fn into_active(self) -> Result<VerifiedNamedService, HnsaError> {
        self.observed.into_active()
    }
}

/// Non-cloneable borrowed proof that a committed service is still the exact
/// current result of one settled subject-wide authority aggregate.
///
/// The guard borrows both the mutable authority lineage and its owned durable
/// result. While it exists Rust prevents that authority state from advancing.
/// It can be constructed for production use only by
/// [`ReconfirmedNamedServiceAuthorityState::bind_current_at`], after the
/// durable aggregate has been reloaded under its exact namespace lease. The
/// guard borrows that opaque lease witness and therefore cannot escape the
/// broker scope. Production requester, rendezvous, browser, extension, and
/// mobile adapters should accept this guard rather than a bare
/// [`VerifiedNamedService`] or [`ServiceGenerationObservation`]. Expiring
/// leases require scoped, abortable dependent operations and broker-owned
/// fenced result promotion.
///
/// The current binding is intentionally non-cloneable:
///
/// ```compile_fail
/// use hns_service_authority::authority_state::CurrentCommittedNamedService;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<CurrentCommittedNamedService<'static>>();
/// ```
///
/// Its active service cannot be cloned into a detached owned capability:
///
/// ```compile_fail
/// use hns_service_authority::authority_state::CurrentCommittedNamedService;
/// use hns_service_authority::hrm::VerifiedNamedService;
///
/// fn detach(guard: CurrentCommittedNamedService<'_>) -> VerifiedNamedService {
///     guard.active().expect("active service").clone()
/// }
/// ```
#[derive(Debug)]
pub struct CurrentCommittedNamedService<'a> {
    authority: &'a NamedServiceAuthorityState,
    committed: &'a CommittedNamedService,
    lease: &'a AuthorityLeaseWitness<'a>,
}

impl CurrentCommittedNamedService<'_> {
    /// Recheck the embedding-owned lease before a dependent use.
    pub fn ensure_lease_held(&self) -> Result<(), NamedServiceAuthorityError> {
        self.lease.ensure_held().map_err(Into::into)
    }

    /// Verify that a composite downstream operation carries this exact witness.
    pub fn ensure_bound_to(
        &self,
        lease: &AuthorityLeaseWitness<'_>,
    ) -> Result<(), NamedServiceAuthorityError> {
        if !std::ptr::eq(self.lease, lease) {
            return Err(NamedServiceAuthorityError::OperationLeaseMismatch);
        }
        self.ensure_lease_held()
    }

    pub const fn storage_namespace_id(&self) -> StorageNamespaceId {
        self.lease.key().storage_namespace_id()
    }

    pub const fn fencing_token(&self) -> FencingToken {
        self.lease.fencing_token()
    }

    /// Exact settled authority revision to which this borrow is bound.
    pub const fn authority_revision(&self) -> u64 {
        self.authority.revision()
    }

    /// Exact settled authority trusted time to which this borrow is bound.
    pub const fn trusted_time_high_water(&self) -> u64 {
        self.authority.trusted_time_high_water()
    }

    /// Exact current per-resource observation in the settled aggregate.
    pub fn observation(&self) -> &ServiceGenerationObservation {
        self.committed.observation()
    }

    /// Whether the exact current observation is a withdrawal tombstone.
    pub fn is_withdrawn(&self) -> bool {
        self.committed.is_withdrawn()
    }

    /// Return the exact current withdrawal tombstone, if withdrawn.
    pub fn withdrawal(&self) -> Option<&ServiceGenerationObservation> {
        self.is_withdrawn().then(|| self.observation())
    }

    /// Return the exact current active service, if active.
    pub fn active(&self) -> Option<&VerifiedNamedService> {
        self.committed.active()
    }
}

/// Mutable, non-cloneable authority state. Every mutation becomes a retryable
/// CAS proposal on one linear in-memory lineage.
///
/// Non-cloneability serializes only this Rust value. Embeddings with multiple
/// tabs, workers, or processes must place construction/restoration, mutation,
/// acknowledgement, current binding, and dependent use under the same external
/// namespace-wide exclusive/fenced broker lease.
///
/// ```compile_fail
/// use hns_service_authority::authority_state::NamedServiceAuthorityState;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<NamedServiceAuthorityState>();
/// ```
#[derive(Debug)]
pub struct NamedServiceAuthorityState {
    snapshot: NamedServiceAuthoritySnapshot,
    pending: Option<AuthorityPersistenceExpectation>,
    storage_namespace_id: Option<StorageNamespaceId>,
}

impl NamedServiceAuthorityState {
    /// Create a new exact-subject aggregate with a create-if-absent proposal.
    pub fn new(
        network_magic: u32,
        subject: [u8; 32],
        capacity: usize,
        trusted_now: u64,
    ) -> Result<Self, NamedServiceAuthorityError> {
        validate_capacity(capacity)?;
        Ok(Self {
            snapshot: NamedServiceAuthoritySnapshot {
                network_magic,
                subject,
                capacity,
                revision: 0,
                trusted_time_high_water: trusted_now,
                rollback_state: None,
                observations: BTreeMap::new(),
            },
            pending: Some(AuthorityPersistenceExpectation::Absent),
            storage_namespace_id: None,
        })
    }

    /// Restore authenticated bytes against exact configuration and rollback floors.
    pub fn restore(
        encoded: &[u8],
        expected_network_magic: u32,
        expected_subject: [u8; 32],
        expected_capacity: usize,
        minimum_revision: u64,
        trusted_now: u64,
    ) -> Result<Self, NamedServiceAuthorityError> {
        let snapshot = NamedServiceAuthoritySnapshot::decode(encoded)?;
        if snapshot.network_magic != expected_network_magic
            || snapshot.subject != expected_subject
            || snapshot.capacity != expected_capacity
        {
            return Err(NamedServiceAuthorityError::BindingMismatch);
        }
        if snapshot.revision < minimum_revision {
            return Err(NamedServiceAuthorityError::RevisionRollback);
        }
        if trusted_now < snapshot.trusted_time_high_water {
            return Err(NamedServiceAuthorityError::TrustedTimeRollback);
        }
        let mut state = Self {
            snapshot,
            pending: None,
            storage_namespace_id: None,
        };
        if trusted_now > state.snapshot.trusted_time_high_water {
            let expected = state.snapshot.exact_expectation()?;
            let mut candidate = state.snapshot.clone();
            candidate.revision = next_revision(candidate.revision)?;
            candidate.trusted_time_high_water = trusted_now;
            candidate.validate()?;
            state.snapshot = candidate;
            state.pending = Some(expected);
        }
        Ok(state)
    }

    /// Return the current in-memory proposal.
    ///
    /// When [`Self::has_pending_persistence`] is true this snapshot has not
    /// been acknowledged and must not be treated as operationally committed.
    pub const fn snapshot(&self) -> &NamedServiceAuthoritySnapshot {
        &self.snapshot
    }

    /// Return the snapshot only when no durable CAS acknowledgment is pending.
    pub const fn committed_snapshot(&self) -> Option<&NamedServiceAuthoritySnapshot> {
        if self.pending.is_none() {
            Some(&self.snapshot)
        } else {
            None
        }
    }

    pub const fn revision(&self) -> u64 {
        self.snapshot.revision
    }

    pub const fn trusted_time_high_water(&self) -> u64 {
        self.snapshot.trusted_time_high_water
    }

    pub const fn has_pending_persistence(&self) -> bool {
        self.pending.is_some()
    }

    /// Namespace pinned by the first successful leased reconfirmation.
    pub const fn storage_namespace_id(&self) -> Option<StorageNamespaceId> {
        self.storage_namespace_id
    }

    /// Reload and authenticate the exact durable authority value after its
    /// namespace lease has been acquired.
    ///
    /// This step is mandatory even for a state restored immediately before
    /// acquisition: another context may have advanced the lineage in that
    /// interval. The returned wrapper is the only production mutation and
    /// current-binding surface.
    pub fn reconfirm<'a, E, F>(
        &'a mut self,
        lease: &'a AuthorityLeaseWitness<'a>,
        load: F,
    ) -> Result<ReconfirmedNamedServiceAuthorityState<'a>, NamedServiceAuthorityCommitError<E>>
    where
        F: FnOnce(&AuthorityLeaseWitness<'a>) -> Result<NamedServiceAuthorityStorageState, E>,
    {
        self.validate_lease(lease)?;
        let loaded = load(lease).map_err(NamedServiceAuthorityCommitError::Persistence)?;
        lease.ensure_held()?;
        self.reconcile_loaded(lease, loaded)?;
        Ok(ReconfirmedNamedServiceAuthorityState { state: self, lease })
    }

    /// Task-local asynchronous durable reconfirmation for browser, extension,
    /// and mobile storage adapters. No `Send` bound is imposed.
    pub async fn reconfirm_async<'a, E, F, Fut>(
        &'a mut self,
        lease: &'a AuthorityLeaseWitness<'a>,
        load: F,
    ) -> Result<ReconfirmedNamedServiceAuthorityState<'a>, NamedServiceAuthorityCommitError<E>>
    where
        F: FnOnce(&'a AuthorityLeaseWitness<'a>) -> Fut,
        Fut: Future<Output = Result<NamedServiceAuthorityStorageState, E>>,
    {
        self.validate_lease(lease)?;
        let loaded = load(lease)
            .await
            .map_err(NamedServiceAuthorityCommitError::Persistence)?;
        lease.ensure_held()?;
        self.reconcile_loaded(lease, loaded)?;
        Ok(ReconfirmedNamedServiceAuthorityState { state: self, lease })
    }

    fn validate_lease(
        &self,
        lease: &AuthorityLeaseWitness<'_>,
    ) -> Result<(), NamedServiceAuthorityError> {
        lease.ensure_held()?;
        let key = lease.key();
        if key.network_magic() != self.snapshot.network_magic
            || key.subject() != &self.snapshot.subject
            || self
                .storage_namespace_id
                .is_some_and(|namespace| namespace != key.storage_namespace_id())
        {
            return Err(NamedServiceAuthorityError::BindingMismatch);
        }
        Ok(())
    }

    fn reconcile_loaded(
        &mut self,
        lease: &AuthorityLeaseWitness<'_>,
        loaded: NamedServiceAuthorityStorageState,
    ) -> Result<(), NamedServiceAuthorityError> {
        let pending_after = match loaded {
            NamedServiceAuthorityStorageState::Absent => match self.pending {
                Some(AuthorityPersistenceExpectation::Absent) => self.pending,
                _ => return Err(NamedServiceAuthorityError::DurableStateMismatch),
            },
            NamedServiceAuthorityStorageState::Present {
                encoded,
                minimum_revision,
            } => {
                let durable = NamedServiceAuthoritySnapshot::decode(&encoded)?;
                if durable.network_magic != self.snapshot.network_magic
                    || durable.subject != self.snapshot.subject
                    || durable.capacity != self.snapshot.capacity
                {
                    return Err(NamedServiceAuthorityError::BindingMismatch);
                }
                if durable.revision < minimum_revision {
                    return Err(NamedServiceAuthorityError::RevisionRollback);
                }
                let proposed_installed = durable == self.snapshot;
                match self.pending {
                    None if proposed_installed => None,
                    Some(AuthorityPersistenceExpectation::Absent) if proposed_installed => None,
                    Some(expectation @ AuthorityPersistenceExpectation::Exact { .. }) => {
                        if proposed_installed {
                            None
                        } else if snapshot_matches_expectation(&durable, expectation)? {
                            Some(expectation)
                        } else {
                            return Err(NamedServiceAuthorityError::DurableStateMismatch);
                        }
                    }
                    _ => return Err(NamedServiceAuthorityError::DurableStateMismatch),
                }
            }
        };
        lease.ensure_held()?;
        self.pending = pending_after;
        self.storage_namespace_id = Some(lease.key().storage_namespace_id());
        Ok(())
    }

    fn bind_current_at<'a>(
        &'a self,
        committed: &'a CommittedNamedService,
        trusted_now: u64,
        lease: &'a AuthorityLeaseWitness<'a>,
    ) -> Result<CurrentCommittedNamedService<'a>, NamedServiceAuthorityError> {
        self.validate_lease(lease)?;
        let current = self.bind_current_revision(committed, lease)?;
        if trusted_now != self.snapshot.trusted_time_high_water
            || current.active().is_some_and(|active| {
                trusted_now < active.validated_at() || trusted_now >= active.cache_until()
            })
        {
            return Err(NamedServiceAuthorityError::OperationTimeMismatch);
        }
        Ok(current)
    }

    fn bind_current_revision<'a>(
        &'a self,
        committed: &'a CommittedNamedService,
        lease: &'a AuthorityLeaseWitness<'a>,
    ) -> Result<CurrentCommittedNamedService<'a>, NamedServiceAuthorityError> {
        if self.pending.is_some() {
            return Err(NamedServiceAuthorityError::PendingPersistence);
        }
        if committed.authority_revision != self.snapshot.revision {
            return Err(NamedServiceAuthorityError::CommittedResultNotCurrent);
        }
        let observation = committed.observation();
        if observation.network_magic() != self.snapshot.network_magic
            || observation.subject() != self.snapshot.subject
            || self.snapshot.observations.get(&observation.resource_id()) != Some(observation)
        {
            return Err(NamedServiceAuthorityError::CommittedResultNotCurrent);
        }
        Ok(CurrentCommittedNamedService {
            authority: self,
            committed,
            lease,
        })
    }

    /// Retry the exact pending CAS. `Ok(())` must mean the proposed snapshot is durable.
    ///
    /// A storage adapter should also return `Ok(())` when an earlier ambiguous
    /// attempt already installed these exact bytes. It must reject both a
    /// non-absent create and any mismatch of revision or fingerprint.
    fn persist_pending<E, F>(
        &mut self,
        lease: &AuthorityLeaseWitness<'_>,
        persist: &mut F,
    ) -> Result<(), NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, &NamedServiceAuthoritySnapshot) -> Result<(), E>,
    {
        self.validate_lease(lease)?;
        let Some(expectation) = self.pending else {
            return Ok(());
        };
        persist(expectation.fenced(lease), &self.snapshot)
            .map_err(NamedServiceAuthorityCommitError::Persistence)?;
        lease.ensure_held()?;
        self.pending = None;
        Ok(())
    }

    /// Async retry of the exact pending CAS, suitable for browser/extension stores.
    ///
    /// The callback receives an owned snapshot so its future need not borrow
    /// this state across an `await`.
    async fn persist_pending_async<E, F, Fut>(
        &mut self,
        lease: &AuthorityLeaseWitness<'_>,
        persist: &mut F,
    ) -> Result<(), NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.validate_lease(lease)?;
        let Some(expectation) = self.pending else {
            return Ok(());
        };
        persist(expectation.fenced(lease), self.snapshot.clone())
            .await
            .map_err(NamedServiceAuthorityCommitError::Persistence)?;
        lease.ensure_held()?;
        self.pending = None;
        Ok(())
    }

    /// Persist a trusted-time advance when resolution/retrieval failed before
    /// a [`ResolvedManifest`] could be produced.
    ///
    /// Callers must invoke this on resolver unavailability and other
    /// pre-validation failures; otherwise repeated failures could permit a
    /// restart to reuse an older clock. The exact pending CAS is always retried
    /// before preparing a new time transition.
    fn advance_trusted_time_persisted<E, F>(
        &mut self,
        lease: &AuthorityLeaseWitness<'_>,
        trusted_now: u64,
        persist: &mut F,
    ) -> Result<u64, NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, &NamedServiceAuthoritySnapshot) -> Result<(), E>,
    {
        self.persist_pending(lease, persist)?;
        if trusted_now < self.snapshot.trusted_time_high_water {
            return Err(NamedServiceAuthorityError::TrustedTimeRollback.into());
        }
        self.prepare_transition(
            trusted_now,
            self.snapshot.rollback_state,
            self.snapshot.observations.clone(),
        )?;
        self.persist_pending(lease, persist)?;
        Ok(self.snapshot.revision)
    }

    /// Async trusted-time persistence for browser, extension, and mobile stores.
    async fn advance_trusted_time_persisted_async<E, F, Fut>(
        &mut self,
        lease: &AuthorityLeaseWitness<'_>,
        trusted_now: u64,
        persist: &mut F,
    ) -> Result<u64, NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.persist_pending_async(lease, persist).await?;
        if trusted_now < self.snapshot.trusted_time_high_water {
            return Err(NamedServiceAuthorityError::TrustedTimeRollback.into());
        }
        self.prepare_transition(
            trusted_now,
            self.snapshot.rollback_state,
            self.snapshot.observations.clone(),
        )?;
        self.persist_pending_async(lease, persist).await?;
        Ok(self.snapshot.revision)
    }

    /// Complete pending persistence, durably acknowledge exact operation time,
    /// then invoke retrieval and commit the resulting HRM/HNSA decision.
    #[allow(clippy::too_many_arguments)]
    fn retrieve_validate_and_observe<R, P, Retrieve, Persist>(
        &mut self,
        lease: &AuthorityLeaseWitness<'_>,
        trusted_now: u64,
        retrieve: Retrieve,
        identity: &NamedServiceIdentity,
        policy: &NamedServicePolicy,
        limits: ValidationLimits,
        persist: &mut Persist,
    ) -> Result<CommittedNamedService, NamedServiceAuthorityOperationError<R, P>>
    where
        Retrieve: FnOnce(u64) -> Result<ResolvedManifest, R>,
        Persist: FnMut(
            NamedServiceAuthorityExpectation,
            &NamedServiceAuthoritySnapshot,
        ) -> Result<(), P>,
    {
        self.advance_trusted_time_persisted(lease, trusted_now, persist)?;
        let retrieved = retrieve(trusted_now);
        self.validate_lease(lease)?;
        let root = retrieved.map_err(NamedServiceAuthorityOperationError::Retrieval)?;
        self.validate_and_observe_resolved(
            lease,
            root,
            identity,
            policy,
            trusted_now,
            limits,
            persist,
        )
        .map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_and_observe_resolved<P, Persist>(
        &mut self,
        lease: &AuthorityLeaseWitness<'_>,
        root: ResolvedManifest,
        identity: &NamedServiceIdentity,
        policy: &NamedServicePolicy,
        trusted_now: u64,
        limits: ValidationLimits,
        persist: &mut Persist,
    ) -> Result<CommittedNamedService, NamedServiceAuthorityCommitError<P>>
    where
        Persist: FnMut(
            NamedServiceAuthorityExpectation,
            &NamedServiceAuthoritySnapshot,
        ) -> Result<(), P>,
    {
        self.validate_lease(lease)?;
        if self.pending.is_some() {
            return Err(NamedServiceAuthorityError::PendingPersistence.into());
        }
        if trusted_now != self.snapshot.trusted_time_high_water {
            return Err(NamedServiceAuthorityError::OperationTimeMismatch.into());
        }
        let prepared =
            self.prepare_validate_and_observe(root, identity, policy, trusted_now, limits);
        self.persist_pending(lease, persist)?;
        prepared
            .map(|observed| CommittedNamedService {
                authority_revision: self.snapshot.revision,
                observed,
            })
            .map_err(NamedServiceAuthorityCommitError::Authority)
    }

    /// Task-local async equivalent of [`Self::retrieve_validate_and_observe`].
    #[allow(clippy::too_many_arguments)]
    async fn retrieve_validate_and_observe_async<
        R,
        P,
        Retrieve,
        RetrieveFuture,
        Persist,
        PersistFuture,
    >(
        &mut self,
        lease: &AuthorityLeaseWitness<'_>,
        trusted_now: u64,
        retrieve: Retrieve,
        identity: &NamedServiceIdentity,
        policy: &NamedServicePolicy,
        limits: ValidationLimits,
        persist: &mut Persist,
    ) -> Result<CommittedNamedService, NamedServiceAuthorityOperationError<R, P>>
    where
        Retrieve: FnOnce(u64) -> RetrieveFuture,
        RetrieveFuture: Future<Output = Result<ResolvedManifest, R>>,
        Persist:
            FnMut(NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot) -> PersistFuture,
        PersistFuture: Future<Output = Result<(), P>>,
    {
        self.advance_trusted_time_persisted_async(lease, trusted_now, persist)
            .await?;
        let retrieved = retrieve(trusted_now).await;
        self.validate_lease(lease)?;
        let root = retrieved.map_err(NamedServiceAuthorityOperationError::Retrieval)?;
        self.validate_and_observe_resolved_async(
            lease,
            root,
            identity,
            policy,
            trusted_now,
            limits,
            persist,
        )
        .await
        .map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    async fn validate_and_observe_resolved_async<P, Persist, PersistFuture>(
        &mut self,
        lease: &AuthorityLeaseWitness<'_>,
        root: ResolvedManifest,
        identity: &NamedServiceIdentity,
        policy: &NamedServicePolicy,
        trusted_now: u64,
        limits: ValidationLimits,
        persist: &mut Persist,
    ) -> Result<CommittedNamedService, NamedServiceAuthorityCommitError<P>>
    where
        Persist:
            FnMut(NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot) -> PersistFuture,
        PersistFuture: Future<Output = Result<(), P>>,
    {
        self.validate_lease(lease)?;
        if self.pending.is_some() {
            return Err(NamedServiceAuthorityError::PendingPersistence.into());
        }
        if trusted_now != self.snapshot.trusted_time_high_water {
            return Err(NamedServiceAuthorityError::OperationTimeMismatch.into());
        }
        let prepared =
            self.prepare_validate_and_observe(root, identity, policy, trusted_now, limits);
        self.persist_pending_async(lease, persist).await?;
        prepared
            .map(|observed| CommittedNamedService {
                authority_revision: self.snapshot.revision,
                observed,
            })
            .map_err(NamedServiceAuthorityCommitError::Authority)
    }

    fn prepare_validate_and_observe(
        &mut self,
        root: ResolvedManifest,
        identity: &NamedServiceIdentity,
        policy: &NamedServicePolicy,
        trusted_now: u64,
        limits: ValidationLimits,
    ) -> Result<ObservedNamedService, NamedServiceAuthorityError> {
        if self.pending.is_some() {
            return Err(NamedServiceAuthorityError::PendingPersistence);
        }
        if identity.network_magic != self.snapshot.network_magic
            || identity.name_hash != self.snapshot.subject
        {
            return Err(NamedServiceAuthorityError::BindingMismatch);
        }
        if trusted_now != self.snapshot.trusted_time_high_water {
            return Err(NamedServiceAuthorityError::OperationTimeMismatch);
        }

        let mut previous_roots = RollbackObservations::new();
        if let Some(previous) = self.snapshot.rollback_state {
            previous_roots.insert(
                (self.snapshot.network_magic, self.snapshot.subject),
                previous,
            );
        }
        let validated = match validate_current_manifest(
            root,
            self.snapshot.network_magic,
            self.snapshot.subject,
            trusted_now,
            limits,
            &previous_roots,
        ) {
            Ok(validated) => validated,
            Err(error) => {
                self.prepare_transition(
                    trusted_now,
                    self.snapshot.rollback_state,
                    self.snapshot.observations.clone(),
                )?;
                return Err(error.into());
            }
        };

        let current_root = validated.rollback_observation();
        let accepted_reorganization = self.snapshot.rollback_state.is_some_and(|previous| {
            actually_rolls_back(previous, current_root)
                && validated
                    .current_snapshot()
                    .accepted_reorganization()
                    .is_some_and(|evidence| evidence.matches(previous, current_root))
        });
        let resource_id = identity.resource_id();
        let mut observations = if accepted_reorganization {
            // The accepted event authorizes one subject-wide reset. Do not let
            // unrelated services retain generation floors from the old root.
            BTreeMap::new()
        } else {
            self.snapshot.observations.clone()
        };
        let observed = match resource_id {
            Ok(resource_id) => {
                let previous = if accepted_reorganization {
                    None
                } else {
                    self.snapshot.observations.get(&resource_id)
                };
                observe_named_service(&validated, identity, policy, previous)
            }
            Err(error) => Err(error),
        };

        let decision = match observed {
            Ok(observed) => {
                let observation = observed.observation().clone();
                let is_new = !observations.contains_key(&observation.resource_id());
                if is_new && observations.len() >= self.snapshot.capacity {
                    Err(NamedServiceAuthorityError::Capacity)
                } else {
                    observations.insert(observation.resource_id(), observation);
                    Ok(observed)
                }
            }
            Err(error) => Err(error.into()),
        };

        // This transition deliberately occurs for HNSA/capacity errors too:
        // successful HRM validation is itself a subject-global observation.
        self.prepare_transition(trusted_now, Some(current_root), observations)?;
        decision
    }

    fn prepare_transition(
        &mut self,
        trusted_time_high_water: u64,
        rollback_state: Option<RollbackState>,
        observations: BTreeMap<[u8; 32], ServiceGenerationObservation>,
    ) -> Result<(), NamedServiceAuthorityError> {
        debug_assert!(self.pending.is_none());
        if trusted_time_high_water == self.snapshot.trusted_time_high_water
            && rollback_state == self.snapshot.rollback_state
            && observations == self.snapshot.observations
        {
            return Ok(());
        }
        let expectation = self.snapshot.exact_expectation()?;
        let revision = next_revision(self.snapshot.revision)?;
        let mut candidate = self.snapshot.clone();
        candidate.trusted_time_high_water = trusted_time_high_water;
        candidate.rollback_state = rollback_state;
        candidate.observations = observations;
        candidate.revision = revision;
        candidate.validate()?;
        self.snapshot = candidate;
        self.pending = Some(expectation);
        Ok(())
    }
}

/// Authority state authenticated against durable storage under one exact
/// namespace lease.
///
/// This wrapper has no public constructor and is non-cloneable. It borrows the
/// opaque witness issued by [`crate::lease::HeldAuthorityLease::run`], so it and
/// every current capability derived from it are confined to that lease scope.
#[derive(Debug)]
pub struct ReconfirmedNamedServiceAuthorityState<'a> {
    state: &'a mut NamedServiceAuthorityState,
    lease: &'a AuthorityLeaseWitness<'a>,
}

impl ReconfirmedNamedServiceAuthorityState<'_> {
    pub fn ensure_lease_held(&self) -> Result<(), NamedServiceAuthorityError> {
        self.state.validate_lease(self.lease)
    }

    pub const fn snapshot(&self) -> &NamedServiceAuthoritySnapshot {
        self.state.snapshot()
    }

    pub const fn committed_snapshot(&self) -> Option<&NamedServiceAuthoritySnapshot> {
        self.state.committed_snapshot()
    }

    pub const fn revision(&self) -> u64 {
        self.state.revision()
    }

    pub const fn trusted_time_high_water(&self) -> u64 {
        self.state.trusted_time_high_water()
    }

    pub const fn has_pending_persistence(&self) -> bool {
        self.state.has_pending_persistence()
    }

    pub fn pending_expectation(&self) -> Option<NamedServiceAuthorityExpectation> {
        self.state
            .pending
            .map(|expectation| expectation.fenced(self.lease))
    }

    /// Bind historical evidence to the exact reconfirmed revision, trusted
    /// time, and opaque lease witness.
    pub fn bind_current_at<'a>(
        &'a self,
        committed: &'a CommittedNamedService,
        trusted_now: u64,
    ) -> Result<CurrentCommittedNamedService<'a>, NamedServiceAuthorityError> {
        self.state
            .bind_current_at(committed, trusted_now, self.lease)
    }

    /// Retry the exact fenced CAS. The adapter must reject namespace or fence
    /// mismatch atomically with the revision/fingerprint precondition.
    pub fn persist_pending<E, F>(
        &mut self,
        persist: &mut F,
    ) -> Result<(), NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, &NamedServiceAuthoritySnapshot) -> Result<(), E>,
    {
        self.state.persist_pending(self.lease, persist)
    }

    pub async fn persist_pending_async<E, F, Fut>(
        &mut self,
        persist: &mut F,
    ) -> Result<(), NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.state.persist_pending_async(self.lease, persist).await
    }

    pub fn advance_trusted_time_persisted<E, F>(
        &mut self,
        trusted_now: u64,
        persist: &mut F,
    ) -> Result<u64, NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, &NamedServiceAuthoritySnapshot) -> Result<(), E>,
    {
        self.state
            .advance_trusted_time_persisted(self.lease, trusted_now, persist)
    }

    pub async fn advance_trusted_time_persisted_async<E, F, Fut>(
        &mut self,
        trusted_now: u64,
        persist: &mut F,
    ) -> Result<u64, NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.state
            .advance_trusted_time_persisted_async(self.lease, trusted_now, persist)
            .await
    }

    /// Retrieve, validate, and observe current HRM/HNSA authority in the
    /// protocol-mandated order.
    ///
    /// This first retries any exact pending transition and durably advances the
    /// aggregate to `trusted_now`. Only after both acknowledgements does it
    /// invoke `retrieve`, passing that same exact operation time. It then
    /// validates the returned current manifest, observes the named service,
    /// and durably commits the resulting subject-wide transition before
    /// releasing a result.
    ///
    /// `retrieve` is part of the trusted embedding boundary for this ordering:
    /// it must begin all fallible namestate, commitment, and envelope I/O when
    /// invoked. Capturing a preloaded result, a previously started request, or
    /// other I/O performed before this call violates the contract and can move
    /// retrieval ahead of the trusted-time acknowledgement.
    #[allow(clippy::too_many_arguments)]
    pub fn retrieve_validate_and_observe<R, P, Retrieve, Persist>(
        &mut self,
        trusted_now: u64,
        retrieve: Retrieve,
        identity: &NamedServiceIdentity,
        policy: &NamedServicePolicy,
        limits: ValidationLimits,
        persist: &mut Persist,
    ) -> Result<CommittedNamedService, NamedServiceAuthorityOperationError<R, P>>
    where
        Retrieve: FnOnce(u64) -> Result<ResolvedManifest, R>,
        Persist: FnMut(
            NamedServiceAuthorityExpectation,
            &NamedServiceAuthoritySnapshot,
        ) -> Result<(), P>,
    {
        self.state.retrieve_validate_and_observe(
            self.lease,
            trusted_now,
            retrieve,
            identity,
            policy,
            limits,
            persist,
        )
    }

    /// Task-local asynchronous ordered retrieval and authority transition.
    ///
    /// Neither the retrieval nor persistence future must be `Send`, supporting
    /// browser, extension, and mobile stores. The retrieval closure is invoked
    /// only after the exact time CAS is awaited. It must construct and start
    /// its I/O then; capturing preloaded data or a previously started future
    /// violates the same trusted-boundary contract as the synchronous method.
    #[allow(clippy::too_many_arguments)]
    pub async fn retrieve_validate_and_observe_async<
        R,
        P,
        Retrieve,
        RetrieveFuture,
        Persist,
        PersistFuture,
    >(
        &mut self,
        trusted_now: u64,
        retrieve: Retrieve,
        identity: &NamedServiceIdentity,
        policy: &NamedServicePolicy,
        limits: ValidationLimits,
        persist: &mut Persist,
    ) -> Result<CommittedNamedService, NamedServiceAuthorityOperationError<R, P>>
    where
        Retrieve: FnOnce(u64) -> RetrieveFuture,
        RetrieveFuture: Future<Output = Result<ResolvedManifest, R>>,
        Persist:
            FnMut(NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot) -> PersistFuture,
        PersistFuture: Future<Output = Result<(), P>>,
    {
        self.state
            .retrieve_validate_and_observe_async(
                self.lease,
                trusted_now,
                retrieve,
                identity,
                policy,
                limits,
                persist,
            )
            .await
    }
}

fn snapshot_matches_expectation(
    snapshot: &NamedServiceAuthoritySnapshot,
    expectation: AuthorityPersistenceExpectation,
) -> Result<bool, NamedServiceAuthorityError> {
    match expectation {
        AuthorityPersistenceExpectation::Absent => Ok(false),
        AuthorityPersistenceExpectation::Exact {
            revision,
            fingerprint,
        } => Ok(snapshot.revision == revision && snapshot.fingerprint()? == fingerprint),
    }
}

fn validate_capacity(capacity: usize) -> Result<(), NamedServiceAuthorityError> {
    if !(1..=MAX_NAMED_SERVICE_AUTHORITY_ENTRIES).contains(&capacity) {
        return Err(NamedServiceAuthorityError::InvalidSnapshot(
            "authority capacity must be in 1..=1024",
        ));
    }
    Ok(())
}

fn next_revision(current: u64) -> Result<u64, NamedServiceAuthorityError> {
    let next = current
        .checked_add(1)
        .ok_or(NamedServiceAuthorityError::RevisionExhausted)?;
    if next == u64::MAX {
        return Err(NamedServiceAuthorityError::RevisionExhausted);
    }
    Ok(next)
}

fn encode_rollback_body(encoder: &mut Encoder, rollback: RollbackState) {
    encoder.put_u64_le(rollback.sequence);
    encoder.put_bytes(&rollback.envelope_hash);
    encoder.put_u32_le(rollback.chain_height);
    encoder.put_bytes(&rollback.chain_work);
    encoder.put_bytes(&rollback.chain_anchor);
}

fn decode_rollback_body(
    input: &[u8],
    network_magic: u32,
    subject: [u8; 32],
) -> Result<RollbackState, NamedServiceAuthorityError> {
    let mut decoder = Decoder::new(input);
    let rollback = RollbackState {
        network_magic,
        subject,
        sequence: decoder.read_u64_le()?,
        envelope_hash: decoder.read_array()?,
        chain_height: decoder.read_u32_le()?,
        chain_work: decoder.read_array()?,
        chain_anchor: decoder.read_array()?,
    };
    decoder.finish()?;
    Ok(rollback)
}

fn actually_rolls_back(previous: RollbackState, current: RollbackState) -> bool {
    current.sequence < previous.sequence
        || (current.sequence == previous.sequence
            && current.envelope_hash != previous.envelope_hash)
        || current.chain_work < previous.chain_work
}

fn snapshot_checksum(payload: &[u8]) -> [u8; 32] {
    blake2b_256(&[SNAPSHOT_CHECKSUM_DOMAIN, payload])
}

fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

#[cfg(test)]
mod lease_tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use crate::lease::{
        AuthorityLeaseKey, FencedLeaseGuard, FencingToken, HeldAuthorityLease, LeaseError,
        LeaseScopeError, StorageNamespaceId,
    };

    use super::*;

    const NETWORK: u32 = 0x1234_5678;
    const SUBJECT: [u8; 32] = [6; 32];

    #[derive(Debug)]
    struct TestGuard {
        key: AuthorityLeaseKey,
        fence: FencingToken,
        held: Rc<Cell<bool>>,
    }

    impl FencedLeaseGuard<AuthorityLeaseKey> for TestGuard {
        fn key(&self) -> &AuthorityLeaseKey {
            &self.key
        }

        fn fencing_token(&self) -> FencingToken {
            self.fence
        }

        fn ensure_held(&self) -> Result<(), LeaseError> {
            self.held.get().then_some(()).ok_or(LeaseError::Lost)
        }
    }

    fn key(namespace: u8) -> AuthorityLeaseKey {
        AuthorityLeaseKey::new(
            StorageNamespaceId::new([namespace; 32]).expect("namespace"),
            NETWORK,
            SUBJECT,
        )
    }

    fn lease(
        key: AuthorityLeaseKey,
        fence: u64,
        held: Rc<Cell<bool>>,
    ) -> HeldAuthorityLease<TestGuard> {
        HeldAuthorityLease::acquire(key, |_| {
            Ok::<_, ()>(TestGuard {
                key,
                fence: FencingToken::new(fence).expect("fence"),
                held,
            })
        })
        .expect("lease")
    }

    #[test]
    fn fenced_expectation_is_exact_and_loss_keeps_proposal_pending() {
        let authority_key = key(1);
        let held = Rc::new(Cell::new(true));
        let mut state =
            NamedServiceAuthorityState::new(NETWORK, SUBJECT, 4, 10).expect("authority");
        let result = lease(authority_key, 17, Rc::clone(&held)).run(|witness| {
            let mut state = state
                .reconfirm(witness, |_| {
                    Ok::<_, ()>(NamedServiceAuthorityStorageState::Absent)
                })
                .expect("reconfirmed");
            let result = state.persist_pending(&mut |expectation, _| {
                assert_eq!(
                    expectation.storage_namespace_id(),
                    authority_key.storage_namespace_id()
                );
                assert_eq!(expectation.fencing_token().get(), 17);
                assert!(matches!(
                    expectation,
                    NamedServiceAuthorityExpectation::Absent { .. }
                ));
                held.set(false);
                Ok::<_, ()>(())
            });
            assert!(matches!(
                result,
                Err(NamedServiceAuthorityCommitError::Authority(
                    NamedServiceAuthorityError::Lease(LeaseError::Lost)
                ))
            ));
            Ok::<_, ()>(())
        });
        assert!(matches!(
            result,
            Err(LeaseScopeError::Lease(LeaseError::Lost))
        ));
        assert!(state.has_pending_persistence());
    }

    #[test]
    fn independently_restored_context_is_rejected_after_other_context_advances() {
        let authority_key = key(1);
        let durable = Rc::new(RefCell::new(None::<Vec<u8>>));
        let mut current =
            NamedServiceAuthorityState::new(NETWORK, SUBJECT, 4, 10).expect("authority");
        lease(authority_key, 1, Rc::new(Cell::new(true)))
            .run(|witness| {
                let mut current = current
                    .reconfirm(witness, |_| {
                        Ok::<_, ()>(NamedServiceAuthorityStorageState::Absent)
                    })
                    .expect("reconfirm create");
                current
                    .persist_pending(&mut |_, snapshot| {
                        *durable.borrow_mut() = Some(snapshot.encode().expect("encode"));
                        Ok::<_, ()>(())
                    })
                    .expect("persist create");
                Ok::<_, ()>(())
            })
            .expect("create scope");

        let initial = durable.borrow().clone().expect("initial durable");
        let mut stale = NamedServiceAuthorityState::restore(&initial, NETWORK, SUBJECT, 4, 0, 10)
            .expect("stale context");

        lease(authority_key, 2, Rc::new(Cell::new(true)))
            .run(|witness| {
                let loaded = durable.borrow().clone().expect("durable");
                let mut current = current
                    .reconfirm(witness, |_| {
                        Ok::<_, ()>(NamedServiceAuthorityStorageState::Present {
                            encoded: loaded,
                            minimum_revision: 0,
                        })
                    })
                    .expect("reconfirm current");
                current
                    .advance_trusted_time_persisted(11, &mut |_, snapshot| {
                        *durable.borrow_mut() = Some(snapshot.encode().expect("encode"));
                        Ok::<_, ()>(())
                    })
                    .expect("advance");
                Ok::<_, ()>(())
            })
            .expect("advance scope");

        lease(authority_key, 3, Rc::new(Cell::new(true)))
            .run(|witness| {
                let loaded = durable.borrow().clone().expect("advanced durable");
                let result = stale.reconfirm(witness, |_| {
                    Ok::<_, ()>(NamedServiceAuthorityStorageState::Present {
                        encoded: loaded,
                        minimum_revision: 0,
                    })
                });
                assert!(matches!(
                    result,
                    Err(NamedServiceAuthorityCommitError::Authority(
                        NamedServiceAuthorityError::DurableStateMismatch
                    ))
                ));
                Ok::<_, ()>(())
            })
            .expect("stale scope");
    }

    #[test]
    fn authority_lineage_pins_namespace_before_loader_runs() {
        let first_key = key(1);
        let mut state =
            NamedServiceAuthorityState::new(NETWORK, SUBJECT, 4, 10).expect("authority");
        let durable = Rc::new(RefCell::new(None::<Vec<u8>>));
        lease(first_key, 1, Rc::new(Cell::new(true)))
            .run(|witness| {
                let mut state = state
                    .reconfirm(witness, |_| {
                        Ok::<_, ()>(NamedServiceAuthorityStorageState::Absent)
                    })
                    .expect("reconfirm");
                state
                    .persist_pending(&mut |_, snapshot| {
                        *durable.borrow_mut() = Some(snapshot.encode().expect("encode"));
                        Ok::<_, ()>(())
                    })
                    .expect("persist");
                Ok::<_, ()>(())
            })
            .expect("scope");

        let loader_called = Rc::new(Cell::new(false));
        lease(key(2), 1, Rc::new(Cell::new(true)))
            .run(|witness| {
                let result = state.reconfirm(witness, |_| {
                    loader_called.set(true);
                    Ok::<_, ()>(NamedServiceAuthorityStorageState::Present {
                        encoded: durable.borrow().clone().expect("durable"),
                        minimum_revision: 0,
                    })
                });
                assert!(matches!(
                    result,
                    Err(NamedServiceAuthorityCommitError::Authority(
                        NamedServiceAuthorityError::BindingMismatch
                    ))
                ));
                Ok::<_, ()>(())
            })
            .expect("scope");
        assert!(!loader_called.get());
    }
}
