//! Durable requester-side downgrade and equivocation observations for current
//! HRM/HNSA-backed named routes.
//!
//! Rendezvous storage is an untrusted, finite admission cache. A requester
//! which has accepted a current-authority route needs a separate permanent
//! high-water mark so omission of the newer route cannot make a lower sequence
//! acceptable after restart. This module owns that state and makes persistence
//! precede the return of newly trusted route results.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::ops::AsyncFnOnce;

use hns_encoding::Decoder;
use hns_service_authority::authority_state::CurrentCommittedNamedService;
use hns_service_authority::hrm::{MAX_SERVICE_NAME, NamedServiceIdentity, VerifiedNamedService};
use hns_service_authority::lease::{
    AuthorityLeaseKey, AuthorityLeaseWitness, FencedLeaseGuard, FencingToken, HeldAuthorityLease,
    HeldFencedLease, LeaseAcquireError, LeaseError, LeaseScopeError, LeaseWitness,
    StorageNamespaceId,
};

use crate::named_hrm::{HrmNamedRoutePolicy, NamedRouteRecordV3, VerifiedNamedRouteV3};
use crate::record::{blake2b_256, validate_public_key};
use crate::{HnsrProtocolError, MAX_RECORDS_PER_KEY, MAX_STORED_RECORDS, named_route_key_v3};

const SNAPSHOT_MAGIC: &[u8; 8] = b"HNSRV3Q\0";
const SNAPSHOT_SCHEMA: u8 = 1;
const SNAPSHOT_HEADER_SIZE: usize = 40;
const SNAPSHOT_ENTRY_SIZE: usize = 277;
const SNAPSHOT_CHECKSUM_SIZE: usize = 32;
const SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"HNSR-NAMED-V3-REQUESTER-SNAPSHOT-V1\0";
const SNAPSHOT_FINGERPRINT_DOMAIN: &[u8] = b"HNSR-NAMED-V3-REQUESTER-CAS-V1\0";
const CANONICAL_HASH_DOMAIN: &[u8] = b"HNSR-NAMED-V3-CANONICAL-RECORD-V1\0";

/// Key for the one requester aggregate shared by every HNSA origin in a
/// physical client storage namespace.
///
/// This key deliberately contains no HNSA `name_hash`, serving origin, or
/// resource ID. A browser profile, extension installation, mobile application,
/// or native client must map every origin that can reach the same requester
/// snapshot to this one lease. Per-origin locks are unsound because the encoded
/// snapshot is a multi-origin aggregate and every write replaces it wholesale.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NamedRouteV3RequesterLeaseKey {
    storage_namespace_id: StorageNamespaceId,
    network_magic: u32,
}

impl NamedRouteV3RequesterLeaseKey {
    pub const fn new(storage_namespace_id: StorageNamespaceId, network_magic: u32) -> Self {
        Self {
            storage_namespace_id,
            network_magic,
        }
    }

    pub const fn storage_namespace_id(&self) -> StorageNamespaceId {
        self.storage_namespace_id
    }

    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }
}

pub type NamedRouteV3RequesterLeaseWitness<'a> = LeaseWitness<'a, NamedRouteV3RequesterLeaseKey>;
pub type HeldNamedRouteV3RequesterLease<G> = HeldFencedLease<NamedRouteV3RequesterLeaseKey, G>;

/// Exact ordered authority-plus-requester lease capability for one operation.
///
/// Fields and construction are private. The witness is non-cloneable and is
/// issued only by [`HeldNamedRouteV3OperationLeases::run`] or its task-local
/// async counterpart.
#[derive(Debug)]
pub struct NamedRouteV3OperationLeaseWitness<'a> {
    authority: &'a AuthorityLeaseWitness<'a>,
    requester: &'a NamedRouteV3RequesterLeaseWitness<'a>,
}

impl NamedRouteV3OperationLeaseWitness<'_> {
    pub const fn authority(&self) -> &AuthorityLeaseWitness<'_> {
        self.authority
    }

    pub const fn requester(&self) -> &NamedRouteV3RequesterLeaseWitness<'_> {
        self.requester
    }

    pub fn ensure_held(&self) -> Result<(), LeaseError> {
        // Order is security-significant and mirrors acquisition.
        self.authority.ensure_held()?;
        self.requester.ensure_held()?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum NamedRouteV3LeaseAcquireError<AuthorityError, RequesterError> {
    BindingMismatch,
    Authority(LeaseAcquireError<AuthorityError>),
    Requester(LeaseAcquireError<RequesterError>),
    AuthorityLost(LeaseError),
}

impl<AuthorityError: fmt::Display, RequesterError: fmt::Display> fmt::Display
    for NamedRouteV3LeaseAcquireError<AuthorityError, RequesterError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BindingMismatch => {
                formatter.write_str("authority and requester leases belong to different networks")
            }
            Self::Authority(error) => error.fmt(formatter),
            Self::Requester(error) => error.fmt(formatter),
            Self::AuthorityLost(error) => error.fmt(formatter),
        }
    }
}

impl<AuthorityError, RequesterError> std::error::Error
    for NamedRouteV3LeaseAcquireError<AuthorityError, RequesterError>
where
    AuthorityError: std::error::Error + 'static,
    RequesterError: std::error::Error + 'static,
{
}

#[derive(Debug)]
pub enum NamedRouteV3LeaseScopeError<E> {
    Operation(E),
    Authority(LeaseError),
    Requester(LeaseError),
}

impl<E: fmt::Display> fmt::Display for NamedRouteV3LeaseScopeError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation(error) => error.fmt(formatter),
            Self::Authority(error) | Self::Requester(error) => error.fmt(formatter),
        }
    }
}

impl<E> std::error::Error for NamedRouteV3LeaseScopeError<E> where E: std::error::Error + 'static {}

/// Retrieval or requester/protocol failure from the ordered production route
/// operation.
///
/// Retrieval has a caller-owned error type because transport and browser or
/// mobile platform failures occur only after requester trusted time is
/// durable. Every other failure includes persistence, authority binding,
/// canonical decoding, verification, replay reduction, and lease loss.
#[derive(Debug)]
pub enum NamedRouteV3RequesterOperationError<R> {
    Retrieval(R),
    Requester(HnsrProtocolError),
}

impl<R> From<HnsrProtocolError> for NamedRouteV3RequesterOperationError<R> {
    fn from(error: HnsrProtocolError) -> Self {
        Self::Requester(error)
    }
}

impl<R: fmt::Display> fmt::Display for NamedRouteV3RequesterOperationError<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retrieval(error) => write!(formatter, "named-route retrieval failed: {error}"),
            Self::Requester(error) => error.fmt(formatter),
        }
    }
}

impl<R> std::error::Error for NamedRouteV3RequesterOperationError<R>
where
    R: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Retrieval(error) => Some(error),
            Self::Requester(error) => Some(error),
        }
    }
}

/// Owned ordered operation leases. Acquisition is always authority first,
/// requester second, with the authority rechecked after requester acquisition.
#[derive(Debug)]
pub struct HeldNamedRouteV3OperationLeases<AuthorityGuard, RequesterGuard> {
    authority: HeldAuthorityLease<AuthorityGuard>,
    requester: HeldNamedRouteV3RequesterLease<RequesterGuard>,
}

impl<AuthorityGuard, RequesterGuard> HeldNamedRouteV3OperationLeases<AuthorityGuard, RequesterGuard>
where
    AuthorityGuard: FencedLeaseGuard<AuthorityLeaseKey>,
    RequesterGuard: FencedLeaseGuard<NamedRouteV3RequesterLeaseKey>,
{
    pub fn acquire<AuthorityError, RequesterError, AcquireAuthority, AcquireRequester>(
        authority_key: AuthorityLeaseKey,
        requester_key: NamedRouteV3RequesterLeaseKey,
        acquire_authority: AcquireAuthority,
        acquire_requester: AcquireRequester,
    ) -> Result<Self, NamedRouteV3LeaseAcquireError<AuthorityError, RequesterError>>
    where
        AcquireAuthority: FnOnce(&AuthorityLeaseKey) -> Result<AuthorityGuard, AuthorityError>,
        AcquireRequester:
            FnOnce(&NamedRouteV3RequesterLeaseKey) -> Result<RequesterGuard, RequesterError>,
    {
        // Authority and requester are separate durable lineages and normally
        // have distinct storage namespace IDs and fencing-token sequences.
        if authority_key.network_magic() != requester_key.network_magic() {
            return Err(NamedRouteV3LeaseAcquireError::BindingMismatch);
        }
        let authority = HeldAuthorityLease::acquire(authority_key, acquire_authority)
            .map_err(NamedRouteV3LeaseAcquireError::Authority)?;
        let requester = HeldNamedRouteV3RequesterLease::acquire(requester_key, acquire_requester)
            .map_err(NamedRouteV3LeaseAcquireError::Requester)?;
        authority
            .ensure_held()
            .map_err(NamedRouteV3LeaseAcquireError::AuthorityLost)?;
        Ok(Self {
            authority,
            requester,
        })
    }

    /// Task-local ordered acquisition for Web Locks, extension stores, and
    /// mobile database brokers. The authority guard remains owned while the
    /// requester acquisition is awaited and is rechecked afterward. Neither
    /// acquisition future nor guard is required to be `Send`.
    pub async fn acquire_async<
        AuthorityError,
        RequesterError,
        AcquireAuthority,
        AuthorityFuture,
        AcquireRequester,
        RequesterFuture,
    >(
        authority_key: AuthorityLeaseKey,
        requester_key: NamedRouteV3RequesterLeaseKey,
        acquire_authority: AcquireAuthority,
        acquire_requester: AcquireRequester,
    ) -> Result<Self, NamedRouteV3LeaseAcquireError<AuthorityError, RequesterError>>
    where
        AcquireAuthority: FnOnce(AuthorityLeaseKey) -> AuthorityFuture,
        AuthorityFuture: Future<Output = Result<AuthorityGuard, AuthorityError>>,
        AcquireRequester: FnOnce(NamedRouteV3RequesterLeaseKey) -> RequesterFuture,
        RequesterFuture: Future<Output = Result<RequesterGuard, RequesterError>>,
    {
        if authority_key.network_magic() != requester_key.network_magic() {
            return Err(NamedRouteV3LeaseAcquireError::BindingMismatch);
        }
        let authority = HeldAuthorityLease::acquire_async(authority_key, acquire_authority)
            .await
            .map_err(NamedRouteV3LeaseAcquireError::Authority)?;
        let requester =
            HeldNamedRouteV3RequesterLease::acquire_async(requester_key, acquire_requester)
                .await
                .map_err(NamedRouteV3LeaseAcquireError::Requester)?;
        authority
            .ensure_held()
            .map_err(NamedRouteV3LeaseAcquireError::AuthorityLost)?;
        Ok(Self {
            authority,
            requester,
        })
    }

    /// Run a scoped operation whose owned result cannot borrow either witness.
    ///
    /// ```compile_fail
    /// use hns_hnsr_protocol::requester_hrm::HeldNamedRouteV3OperationLeases;
    /// use hns_service_authority::lease::{
    ///     AuthorityLeaseKey, FencedLeaseGuard,
    /// };
    /// use hns_hnsr_protocol::requester_hrm::NamedRouteV3RequesterLeaseKey;
    ///
    /// fn escape<A, R>(held: HeldNamedRouteV3OperationLeases<A, R>)
    /// where
    ///     A: FencedLeaseGuard<AuthorityLeaseKey>,
    ///     R: FencedLeaseGuard<NamedRouteV3RequesterLeaseKey>,
    /// {
    ///     let _escaped = held.run(|witness| Ok::<_, ()>(witness)).unwrap();
    /// }
    /// ```
    pub fn run<R, E, F>(self, operation: F) -> Result<R, NamedRouteV3LeaseScopeError<E>>
    where
        F: for<'op> FnOnce(&'op NamedRouteV3OperationLeaseWitness<'op>) -> Result<R, E>,
    {
        let Self {
            authority,
            requester,
        } = self;
        let outer = authority.run(|authority_witness| {
            let inner = requester.run(|requester_witness| {
                let witness = NamedRouteV3OperationLeaseWitness {
                    authority: authority_witness,
                    requester: requester_witness,
                };
                operation(&witness)
            });
            match inner {
                Ok(result) => Ok(result),
                Err(LeaseScopeError::Operation(error)) => {
                    Err(NamedRouteV3LeaseScopeError::Operation(error))
                }
                Err(LeaseScopeError::Lease(error)) => {
                    Err(NamedRouteV3LeaseScopeError::Requester(error))
                }
            }
        });
        match outer {
            Ok(result) => Ok(result),
            Err(LeaseScopeError::Operation(error)) => Err(error),
            Err(LeaseScopeError::Lease(error)) => {
                Err(NamedRouteV3LeaseScopeError::Authority(error))
            }
        }
    }

    /// Task-local async scope. No `Send` bound is imposed for browser/mobile
    /// adapters; cancellation drops both owned guards.
    pub async fn run_async<R, E, F>(self, operation: F) -> Result<R, NamedRouteV3LeaseScopeError<E>>
    where
        F: for<'op> AsyncFnOnce(&'op NamedRouteV3OperationLeaseWitness<'op>) -> Result<R, E>,
    {
        let Self {
            authority,
            requester,
        } = self;
        let outer = authority
            .run_async(async move |authority_witness| {
                let inner = requester
                    .run_async(async move |requester_witness| {
                        let witness = NamedRouteV3OperationLeaseWitness {
                            authority: authority_witness,
                            requester: requester_witness,
                        };
                        operation(&witness).await
                    })
                    .await;
                match inner {
                    Ok(result) => Ok(result),
                    Err(LeaseScopeError::Operation(error)) => {
                        Err(NamedRouteV3LeaseScopeError::Operation(error))
                    }
                    Err(LeaseScopeError::Lease(error)) => {
                        Err(NamedRouteV3LeaseScopeError::Requester(error))
                    }
                }
            })
            .await;
        match outer {
            Ok(result) => Ok(result),
            Err(LeaseScopeError::Operation(error)) => Err(error),
            Err(LeaseScopeError::Lease(error)) => {
                Err(NamedRouteV3LeaseScopeError::Authority(error))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct RequesterScope {
    name_hash: [u8; 32],
    service_name: String,
    application_profile_id: u16,
    resource_id: [u8; 32],
    route_key: [u8; 32],
    endpoint_key: [u8; 33],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequesterObservation {
    endpoint_high_water: u64,
    endpoint_conflicted: bool,
    endpoint_canonical_id: [u8; 32],
    route_high_water: u64,
    route_conflicted: bool,
    route_canonical_hash: [u8; 32],
}

/// Opaque deterministic persistence image for requester downgrade state.
///
/// The checksum detects accidental corruption only. It is not authentication
/// or rollback protection. Store the bytes atomically in authenticated local
/// storage and retain the last committed revision outside the snapshot so
/// [`NamedRouteV3RequesterState::restore`] can enforce it.
///
/// This is the first released draft `V1` image. Earlier development-only
/// requester images were never released and have no migration guarantee; an
/// embedding encountering one must fail closed rather than reinterpret it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedRouteV3RequesterSnapshot {
    network_magic: u32,
    capacity: usize,
    revision: u64,
    trusted_time_high_water: u64,
    entries: Vec<(RequesterScope, RequesterObservation)>,
}

impl NamedRouteV3RequesterSnapshot {
    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }

    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Greatest trusted time committed into this snapshot.
    pub const fn trusted_time_high_water(&self) -> u64 {
        self.trusted_time_high_water
    }

    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Stable digest of the entire canonical image for persistence CAS.
    ///
    /// This digest is an identity token, not authentication. The surrounding
    /// persistence layer still has to authenticate snapshots and prevent
    /// rollback.
    pub fn fingerprint(&self) -> [u8; 32] {
        blake2b_256(&[SNAPSHOT_FINGERPRINT_DOMAIN, &self.encode()])
    }

    pub fn encode(&self) -> Vec<u8> {
        let payload_size = SNAPSHOT_HEADER_SIZE
            .saturating_add(self.entries.len().saturating_mul(SNAPSHOT_ENTRY_SIZE));
        let mut bytes = Vec::with_capacity(payload_size.saturating_add(SNAPSHOT_CHECKSUM_SIZE));
        bytes.extend_from_slice(SNAPSHOT_MAGIC);
        bytes.push(SNAPSHOT_SCHEMA);
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&self.network_magic.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.capacity)
                .expect("validated requester capacity fits u32")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.revision.to_le_bytes());
        bytes.extend_from_slice(&self.trusted_time_high_water.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.entries.len())
                .expect("validated requester length fits u32")
                .to_le_bytes(),
        );
        for (scope, observation) in &self.entries {
            bytes.extend_from_slice(&scope.name_hash);
            bytes.push(scope.service_name.len() as u8);
            bytes.extend_from_slice(scope.service_name.as_bytes());
            bytes.resize(bytes.len() + MAX_SERVICE_NAME - scope.service_name.len(), 0);
            bytes.extend_from_slice(&scope.application_profile_id.to_le_bytes());
            bytes.extend_from_slice(&scope.resource_id);
            bytes.extend_from_slice(&scope.route_key);
            bytes.extend_from_slice(&scope.endpoint_key);
            bytes.extend_from_slice(&observation.endpoint_high_water.to_le_bytes());
            bytes.push(u8::from(observation.endpoint_conflicted));
            bytes.extend_from_slice(&observation.endpoint_canonical_id);
            bytes.extend_from_slice(&observation.route_high_water.to_le_bytes());
            bytes.push(u8::from(observation.route_conflicted));
            bytes.extend_from_slice(&observation.route_canonical_hash);
        }
        let checksum = snapshot_checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let minimum_size = SNAPSHOT_HEADER_SIZE + SNAPSHOT_CHECKSUM_SIZE;
        let maximum_size = SNAPSHOT_HEADER_SIZE
            + MAX_STORED_RECORDS * SNAPSHOT_ENTRY_SIZE
            + SNAPSHOT_CHECKSUM_SIZE;
        if input.len() < minimum_size || input.len() > maximum_size {
            return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot);
        }
        let payload_size = input.len() - SNAPSHOT_CHECKSUM_SIZE;
        let (payload, supplied_checksum) = input.split_at(payload_size);
        if supplied_checksum != snapshot_checksum(payload) {
            return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot);
        }
        let corrupt = |_| HnsrProtocolError::CorruptNamedRouteRequesterSnapshot;
        let mut decoder = Decoder::new(payload);
        if decoder.read_slice(SNAPSHOT_MAGIC.len()).map_err(corrupt)? != SNAPSHOT_MAGIC
            || decoder.read_u8().map_err(corrupt)? != SNAPSHOT_SCHEMA
            || decoder.read_array::<3>().map_err(corrupt)? != [0; 3]
        {
            return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot);
        }
        let network_magic = decoder.read_u32_le().map_err(corrupt)?;
        let capacity = usize::try_from(decoder.read_u32_le().map_err(corrupt)?)
            .map_err(|_| HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)?;
        let revision = decoder.read_u64_le().map_err(corrupt)?;
        let trusted_time_high_water = decoder.read_u64_le().map_err(corrupt)?;
        let entry_count = usize::try_from(decoder.read_u32_le().map_err(corrupt)?)
            .map_err(|_| HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)?;
        let entry_count_u64 = u64::try_from(entry_count)
            .map_err(|_| HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)?;
        if capacity == 0
            || capacity > MAX_STORED_RECORDS
            || entry_count > capacity
            || entry_count_u64 > revision
            || revision == u64::MAX
            || (entry_count != 0 && revision == 0)
            || payload.len()
                != SNAPSHOT_HEADER_SIZE
                    .checked_add(
                        entry_count
                            .checked_mul(SNAPSHOT_ENTRY_SIZE)
                            .ok_or(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)?,
                    )
                    .ok_or(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)?
        {
            return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot);
        }

        let mut entries = Vec::with_capacity(entry_count);
        let mut route_counts = HashMap::<[u8; 32], usize>::new();
        let mut previous_scope = None;
        for _ in 0..entry_count {
            let name_hash = decoder.read_array().map_err(corrupt)?;
            let service_name_length = decoder.read_u8().map_err(corrupt)? as usize;
            if !(1..=MAX_SERVICE_NAME).contains(&service_name_length) {
                return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot);
            }
            let service_name =
                std::str::from_utf8(decoder.read_slice(service_name_length).map_err(corrupt)?)
                    .map_err(|_| HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)?
                    .to_owned();
            if decoder
                .read_slice(MAX_SERVICE_NAME - service_name_length)
                .map_err(corrupt)?
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot);
            }
            let application_profile_id = decoder.read_u16_le().map_err(corrupt)?;
            let resource_id = decoder.read_array().map_err(corrupt)?;
            let route_key = decoder.read_array().map_err(corrupt)?;
            let endpoint_key = decoder.read_array().map_err(corrupt)?;
            validate_public_key(&endpoint_key)
                .map_err(|_| HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)?;
            let identity = NamedServiceIdentity::new(
                network_magic,
                name_hash,
                service_name.clone(),
                application_profile_id,
            )
            .map_err(|_| HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)?;
            if identity
                .resource_id()
                .map_err(|_| HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)?
                != resource_id
                || named_route_key_v3(&identity)
                    .map_err(|_| HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)?
                    != route_key
            {
                return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot);
            }
            let scope = RequesterScope {
                name_hash,
                service_name,
                application_profile_id,
                resource_id,
                route_key,
                endpoint_key,
            };
            if previous_scope
                .as_ref()
                .is_some_and(|previous| previous >= &scope)
            {
                return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot);
            }
            let route_count = route_counts.entry(route_key).or_default();
            *route_count = route_count.saturating_add(1);
            if *route_count > MAX_RECORDS_PER_KEY {
                return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot);
            }
            let endpoint_high_water = decoder.read_u64_le().map_err(corrupt)?;
            let endpoint_conflicted = match decoder.read_u8().map_err(corrupt)? {
                0 => false,
                1 => true,
                _ => return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot),
            };
            let endpoint_canonical_id = decoder.read_array().map_err(corrupt)?;
            let route_high_water = decoder.read_u64_le().map_err(corrupt)?;
            let route_conflicted = match decoder.read_u8().map_err(corrupt)? {
                0 => false,
                1 => true,
                _ => return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot),
            };
            let route_canonical_hash = decoder.read_array().map_err(corrupt)?;
            if endpoint_high_water == 0
                || route_high_water == 0
                || (endpoint_conflicted && endpoint_canonical_id != [0; 32])
                || (route_conflicted && route_canonical_hash != [0; 32])
            {
                return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot);
            }
            entries.push((
                scope.clone(),
                RequesterObservation {
                    endpoint_high_water,
                    endpoint_conflicted,
                    endpoint_canonical_id,
                    route_high_water,
                    route_conflicted,
                    route_canonical_hash,
                },
            ));
            previous_scope = Some(scope);
        }
        decoder.finish().map_err(corrupt)?;
        let snapshot = Self {
            network_magic,
            capacity,
            revision,
            trusted_time_high_water,
            entries,
        };
        if snapshot.encode() != input {
            return Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot);
        }
        Ok(snapshot)
    }
}

/// Fenced storage precondition for the multi-origin requester aggregate.
///
/// The namespace and token must be checked atomically with the snapshot CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamedRouteV3RequesterExpectation {
    Absent {
        storage_namespace_id: StorageNamespaceId,
        fencing_token: FencingToken,
    },
    Exact {
        storage_namespace_id: StorageNamespaceId,
        fencing_token: FencingToken,
        revision: u64,
        fingerprint: [u8; 32],
    },
}

impl NamedRouteV3RequesterExpectation {
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

/// Authenticated requester value loaded after both ordered leases are held.
///
/// `Present` must come from the one whole requester-aggregate key for the
/// witness namespace—not from a per-HNSA-origin partition.
#[derive(Debug)]
pub enum NamedRouteV3RequesterStorageState {
    Absent,
    Present {
        encoded: Vec<u8>,
        minimum_revision: u64,
    },
}

/// Permanent requester observations for fully current-authority V3 routes.
///
/// Unlike the rendezvous admission ledger, these entries do not expire or
/// reset on service-controller rotation, HNSA withdrawal, route expiry, or
/// restart. The logical endpoint is one exact endpoint public key; key
/// rotation creates a concurrent/new logical endpoint. Within that scope,
/// endpoint-delegation and route sequences are independent product dimensions:
/// every fully current record updates both, and a route is usable only when
/// that exact record realizes both final nonconflicted high-waters. Only a
/// fully current greater endpoint/route observation clears its corresponding
/// conflict.
/// Entries are never silently evicted. If the configured bound is reached, a
/// user must export/archive the snapshot and explicitly authorize creation of
/// a fresh state, understanding that doing so discards the old replay
/// protection and requires re-establishing every route from current authority.
///
/// Production use requires one namespace-wide exclusive/fenced requester
/// broker lease, acquired only after the corresponding authority lease and
/// held from before authenticated restore through CAS acknowledgement and the
/// complete dependent use. Persistence callbacks must implement compare-and-
/// swap using the supplied expected `(revision, fingerprint)`, and
/// accept success only when storage contains that exact prior image (which it
/// replaces atomically) or already contains the exact proposed image from an
/// outcome-ambiguous retry. `None` means atomic create-if-absent for a fresh
/// state. Same-revision divergent writers must fail the callback. CAS alone is
/// not exclusion: it cannot stop another tab, worker, or process from
/// committing immediately after a local currentness check.
#[derive(Debug)]
pub struct NamedRouteV3RequesterState {
    network_magic: u32,
    capacity: usize,
    revision: u64,
    trusted_time_high_water: u64,
    entries: HashMap<RequesterScope, RequesterObservation>,
    pending_cas: Option<PersistenceExpectation>,
    storage_namespace_id: Option<StorageNamespaceId>,
}

/// Non-cloneable proof that one named route is bound to the exact current
/// authority aggregate and exact durable requester observation.
///
/// The guard immutably borrows both state machines. Neither authority nor
/// requester replay state can advance while it is held, so applications should
/// keep it through profile-specific authenticated session establishment. Its
/// route and service accessors deliberately borrow `self`; references obtained
/// from them cannot outlive or be detached from this guard.
///
/// Those borrows protect only the two local Rust lineages. The embedding must
/// retain the ordered authority-then-requester exclusive/fenced broker leases
/// for the full authenticated session establishment. An expiring lease needs
/// a scoped abortable operation or broker-owned session promotion; a final
/// revision/lease check is raceable.
///
/// The guard is intentionally not [`Clone`].
///
/// ```compile_fail
/// use hns_hnsr_protocol::requester_hrm::CurrentNamedRouteV3;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<CurrentNamedRouteV3<'static>>();
/// ```
///
/// The underlying record reference also cannot be leaked after consuming the
/// guard.
///
/// ```compile_fail
/// use hns_hnsr_protocol::{NamedRouteRecordV3, requester_hrm::CurrentNamedRouteV3};
///
/// fn leak_record<'a>(guard: CurrentNamedRouteV3<'a>) -> &'a NamedRouteRecordV3 {
///     guard.record()
/// }
/// ```
///
/// The active service also cannot be cloned away from the route guard:
///
/// ```compile_fail
/// use hns_hnsr_protocol::CurrentNamedRouteV3;
/// use hns_service_authority::hrm::VerifiedNamedService;
///
/// fn detach(guard: CurrentNamedRouteV3<'_>) -> VerifiedNamedService {
///     guard.service().clone()
/// }
/// ```
#[derive(Debug)]
pub struct CurrentNamedRouteV3<'a> {
    requester: &'a NamedRouteV3RequesterState,
    authority: &'a CurrentCommittedNamedService<'a>,
    service: &'a VerifiedNamedService,
    record: NamedRouteRecordV3,
    cache_until: u64,
    requester_revision: u64,
    scope: RequesterScope,
    observation: RequesterObservation,
    operation_lease: &'a NamedRouteV3OperationLeaseWitness<'a>,
}

impl CurrentNamedRouteV3<'_> {
    /// Recheck authority first and requester second at a dependent-use boundary.
    pub fn ensure_leases_held(&self) -> Result<(), HnsrProtocolError> {
        self.operation_lease
            .ensure_held()
            .map_err(|_| HnsrProtocolError::Invalid("named-route operation lease was lost"))?;
        self.authority
            .ensure_bound_to(self.operation_lease.authority())
            .map_err(|_| {
                HnsrProtocolError::Invalid(
                    "named-route authority belongs to a different operation lease",
                )
            })
    }

    pub const fn storage_namespace_id(&self) -> StorageNamespaceId {
        self.operation_lease
            .requester()
            .key()
            .storage_namespace_id()
    }

    pub const fn requester_fencing_token(&self) -> FencingToken {
        self.operation_lease.requester().fencing_token()
    }

    /// Route evidence, borrowed only for the lifetime of this guard borrow.
    pub fn record(&self) -> &NamedRouteRecordV3 {
        &self.record
    }

    /// Exact active service, borrowed only for the lifetime of this guard
    /// borrow.
    pub fn service(&self) -> &VerifiedNamedService {
        self.service
    }

    /// Fail-closed cache bound reduced across service, endpoint, route, and
    /// relay-ticket validity.
    pub const fn cache_until(&self) -> u64 {
        self.cache_until
    }

    /// Exact requester CAS revision held by this guard.
    pub fn requester_revision(&self) -> u64 {
        debug_assert_eq!(self.requester.revision(), self.requester_revision);
        self.requester_revision
    }

    /// Exact authority CAS revision held by this guard.
    pub fn authority_revision(&self) -> u64 {
        self.authority.authority_revision()
    }

    /// Exact authority operation time held by this guard.
    pub fn authority_trusted_time(&self) -> u64 {
        self.authority.trusted_time_high_water()
    }

    pub const fn name_hash(&self) -> &[u8; 32] {
        &self.scope.name_hash
    }

    pub fn service_name(&self) -> &str {
        &self.scope.service_name
    }

    pub const fn application_profile_id(&self) -> u16 {
        self.scope.application_profile_id
    }

    pub const fn resource_id(&self) -> &[u8; 32] {
        &self.scope.resource_id
    }

    pub const fn route_key(&self) -> &[u8; 32] {
        &self.scope.route_key
    }

    pub const fn endpoint_key(&self) -> &[u8; 33] {
        &self.scope.endpoint_key
    }

    pub const fn endpoint_sequence(&self) -> u64 {
        self.observation.endpoint_high_water
    }

    pub const fn endpoint_delegation_id(&self) -> &[u8; 32] {
        &self.observation.endpoint_canonical_id
    }

    pub const fn route_sequence(&self) -> u64 {
        self.observation.route_high_water
    }

    pub const fn route_canonical_hash(&self) -> &[u8; 32] {
        &self.observation.route_canonical_hash
    }
}

impl NamedRouteV3RequesterState {
    pub fn new(
        network_magic: u32,
        capacity: usize,
        trusted_now: u64,
    ) -> Result<Self, HnsrProtocolError> {
        if capacity == 0 || capacity > MAX_STORED_RECORDS {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSR V3 requester-state configuration",
            ));
        }
        Ok(Self {
            network_magic,
            capacity,
            revision: 0,
            trusted_time_high_water: trusted_now,
            entries: HashMap::new(),
            pending_cas: Some(PersistenceExpectation::Absent),
            storage_namespace_id: None,
        })
    }

    /// Restore an authenticated snapshot with external revision rollback and
    /// trusted-time rollback protection.
    ///
    /// If `trusted_now` is greater than the snapshot's time high-water, restore
    /// advances both time and revision and leaves a pending CAS transition.
    /// Reconfirm under ordered leases and call
    /// [`ReconfirmedNamedRouteV3RequesterState::persist_pending`] (or a safe
    /// observation method) before using any trusted route result.
    pub fn restore(
        network_magic: u32,
        capacity: usize,
        snapshot: NamedRouteV3RequesterSnapshot,
        minimum_revision: u64,
        trusted_now: u64,
    ) -> Result<Self, HnsrProtocolError> {
        if snapshot.network_magic != network_magic
            || snapshot.capacity != capacity
            || snapshot.revision < minimum_revision
        {
            return Err(HnsrProtocolError::IncompatibleNamedRouteRequesterSnapshot);
        }
        if trusted_now < snapshot.trusted_time_high_water {
            return Err(HnsrProtocolError::ClockRollback);
        }
        let mut state = Self {
            network_magic,
            capacity,
            revision: snapshot.revision,
            trusted_time_high_water: snapshot.trusted_time_high_water,
            entries: snapshot.entries.into_iter().collect(),
            pending_cas: None,
            storage_namespace_id: None,
        };
        if trusted_now > state.trusted_time_high_water {
            let expectation = state.persistence_expectation();
            let next_revision = state.next_revision()?;
            state.trusted_time_high_water = trusted_now;
            state.revision = next_revision;
            state.pending_cas = Some(expectation);
        }
        Ok(state)
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn trusted_time_high_water(&self) -> u64 {
        self.trusted_time_high_water
    }

    /// Whether a previous callback may have committed a transition but did
    /// not report success, or restore advanced trusted time.
    pub const fn has_pending_persistence(&self) -> bool {
        self.pending_cas.is_some()
    }

    pub const fn storage_namespace_id(&self) -> Option<StorageNamespaceId> {
        self.storage_namespace_id
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn snapshot(&self) -> NamedRouteV3RequesterSnapshot {
        let mut entries = self
            .entries
            .iter()
            .map(|(scope, observation)| (scope.clone(), *observation))
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        NamedRouteV3RequesterSnapshot {
            network_magic: self.network_magic,
            capacity: self.capacity,
            revision: self.revision,
            trusted_time_high_water: self.trusted_time_high_water,
            entries,
        }
    }

    /// Reconfirm this entire multi-origin aggregate from authenticated durable
    /// storage after both ordered leases have been acquired.
    pub fn reconfirm<'a, F>(
        &'a mut self,
        operation_lease: &'a NamedRouteV3OperationLeaseWitness<'a>,
        load: F,
    ) -> Result<ReconfirmedNamedRouteV3RequesterState<'a>, HnsrProtocolError>
    where
        F: FnOnce(
            &NamedRouteV3OperationLeaseWitness<'a>,
        ) -> Result<NamedRouteV3RequesterStorageState, HnsrProtocolError>,
    {
        self.validate_operation_lease(operation_lease)?;
        let loaded = load(operation_lease)?;
        ensure_operation_lease(operation_lease)?;
        self.reconcile_loaded(operation_lease, loaded)?;
        Ok(ReconfirmedNamedRouteV3RequesterState {
            state: self,
            operation_lease,
        })
    }

    /// Task-local asynchronous reconfirmation. The loader is invoked only
    /// after both leases are held and may use non-`Send` browser/mobile APIs.
    pub async fn reconfirm_async<'a, F, Fut>(
        &'a mut self,
        operation_lease: &'a NamedRouteV3OperationLeaseWitness<'a>,
        load: F,
    ) -> Result<ReconfirmedNamedRouteV3RequesterState<'a>, HnsrProtocolError>
    where
        F: FnOnce(&'a NamedRouteV3OperationLeaseWitness<'a>) -> Fut,
        Fut: Future<Output = Result<NamedRouteV3RequesterStorageState, HnsrProtocolError>>,
    {
        self.validate_operation_lease(operation_lease)?;
        let loaded = load(operation_lease).await?;
        ensure_operation_lease(operation_lease)?;
        self.reconcile_loaded(operation_lease, loaded)?;
        Ok(ReconfirmedNamedRouteV3RequesterState {
            state: self,
            operation_lease,
        })
    }

    fn validate_operation_lease(
        &self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
    ) -> Result<(), HnsrProtocolError> {
        ensure_operation_lease(operation_lease)?;
        let requester_key = operation_lease.requester().key();
        if requester_key.network_magic() != self.network_magic
            || operation_lease.authority().key().network_magic() != self.network_magic
            || self
                .storage_namespace_id
                .is_some_and(|namespace| namespace != requester_key.storage_namespace_id())
        {
            return Err(HnsrProtocolError::Invalid(
                "HNSR V3 requester operation-lease binding mismatch",
            ));
        }
        Ok(())
    }

    fn reconcile_loaded(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        loaded: NamedRouteV3RequesterStorageState,
    ) -> Result<(), HnsrProtocolError> {
        let pending_after = match loaded {
            NamedRouteV3RequesterStorageState::Absent => match self.pending_cas {
                Some(PersistenceExpectation::Absent) => self.pending_cas,
                _ => {
                    return Err(HnsrProtocolError::Invalid(
                        "HNSR V3 requester durable-state mismatch",
                    ));
                }
            },
            NamedRouteV3RequesterStorageState::Present {
                encoded,
                minimum_revision,
            } => {
                let durable = NamedRouteV3RequesterSnapshot::decode(&encoded)?;
                if durable.network_magic != self.network_magic || durable.capacity != self.capacity
                {
                    return Err(HnsrProtocolError::IncompatibleNamedRouteRequesterSnapshot);
                }
                if durable.revision < minimum_revision {
                    return Err(HnsrProtocolError::IncompatibleNamedRouteRequesterSnapshot);
                }
                let proposed_installed = durable == self.snapshot();
                match self.pending_cas {
                    None if proposed_installed => None,
                    Some(PersistenceExpectation::Absent) if proposed_installed => None,
                    Some(expectation @ PersistenceExpectation::Exact { .. }) => {
                        if proposed_installed {
                            None
                        } else if expectation.matches_snapshot(&durable) {
                            Some(expectation)
                        } else {
                            return Err(HnsrProtocolError::Invalid(
                                "HNSR V3 requester durable-state mismatch",
                            ));
                        }
                    }
                    _ => {
                        return Err(HnsrProtocolError::Invalid(
                            "HNSR V3 requester durable-state mismatch",
                        ));
                    }
                }
            }
        };
        ensure_operation_lease(operation_lease)?;
        self.pending_cas = pending_after;
        self.storage_namespace_id = Some(operation_lease.requester().key().storage_namespace_id());
        Ok(())
    }

    /// Retry an outcome-ambiguous transition without changing requester state.
    ///
    /// The callback receives `(expected_state, proposed_snapshot)` and must
    /// obey the CAS contract on this type. `expected_state` is `None` only for
    /// atomic creation of a fresh state. It is not called when no persistence
    /// is pending.
    fn persist_pending<F>(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        mut persist: F,
    ) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.flush_pending(operation_lease, &mut persist)
    }

    /// Async/mobile equivalent of
    /// [`ReconfirmedNamedRouteV3RequesterState::persist_pending`].
    ///
    /// The proposed snapshot is owned so IndexedDB, extension storage, and
    /// mobile database adapters can retain it across `await`. A successful
    /// callback must mean the exact CAS is durably acknowledged, not merely
    /// scheduled.
    async fn persist_pending_async<F, Fut>(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        mut persist: F,
    ) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        self.flush_pending_async(operation_lease, &mut persist)
            .await
    }

    /// Durably advance the trusted-time high-water without observing a route.
    ///
    /// Applications should call this with their trusted clock even when a
    /// route is expired or absent. That prevents a later clock rollback from
    /// reviving a formerly expired, high-sequence route.
    fn advance_trusted_time_persisted<F>(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        now: u64,
        mut persist: F,
    ) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.validate_operation_lease(operation_lease)?;
        self.reject_clock_rollback(now)?;
        self.flush_pending(operation_lease, &mut persist)?;
        if now == self.trusted_time_high_water {
            return Ok(());
        }
        let expectation = self.persistence_expectation();
        let next_revision = self.next_revision()?;
        self.trusted_time_high_water = now;
        self.revision = next_revision;
        self.pending_cas = Some(expectation);
        self.flush_pending(operation_lease, &mut persist)
    }

    /// Awaited, owned-snapshot variant of
    /// [`ReconfirmedNamedRouteV3RequesterState::advance_trusted_time_persisted`].
    async fn advance_trusted_time_persisted_async<F, Fut>(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        now: u64,
        mut persist: F,
    ) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        self.validate_operation_lease(operation_lease)?;
        self.reject_clock_rollback(now)?;
        self.flush_pending_async(operation_lease, &mut persist)
            .await?;
        if now == self.trusted_time_high_water {
            return Ok(());
        }
        let mut handoff = None;
        let result =
            self.advance_trusted_time_persisted(operation_lease, now, |expected, proposed| {
                handoff = Some((expected, proposed.clone()));
                Err(HnsrProtocolError::Invalid(
                    "async requester persistence handoff",
                ))
            });
        let Some((expected, proposed)) = handoff else {
            return result;
        };
        persist(expected, proposed.clone()).await?;
        self.acknowledge_pending(operation_lease, expected, &proposed)
    }

    /// Fully verify and durably observe one already-selected current route.
    ///
    /// This low-level method does not know whether a caller ignored a greater
    /// route in the same response batch. Production batch processing should
    /// use [`ReconfirmedNamedRouteV3RequesterState::retrieve_select_and_observe_current_persisted`]. Raw
    /// `VerifiedNamedService` values do not prove the HNSA authority aggregate
    /// crossed its CAS boundary or that their revision is still current. This
    /// method is therefore an explicitly uncommitted validator/test escape
    /// hatch. The callback follows the CAS contract documented on this type.
    /// Any pending callback failure is retried before another mutation or
    /// trusted success is returned.
    /// Trusted `now` is committed before binding, capacity, and cryptographic
    /// errors are returned, preventing a later rollback from reviving an
    /// expired candidate even on this single-record path.
    #[doc(hidden)]
    fn observe_current_persisted_uncommitted<'a, F>(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        record: &'a NamedRouteRecordV3,
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        mut persist: F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.validate_operation_lease(operation_lease)?;
        self.reject_clock_rollback(now)?;
        self.advance_trusted_time_persisted(operation_lease, now, &mut persist)?;
        if service.identity().network_magic != self.network_magic {
            return Err(HnsrProtocolError::Invalid(
                "HNSR V3 requester-state network mismatch",
            ));
        }
        let scope = self.scope_for(service, record.endpoint_delegation.endpoint_key)?;
        self.check_capacity_for_scope(&scope)?;
        let verified = record.verify_current_uncommitted(service, policy, now)?;
        self.check_capacity_for_scope(&scope)?;
        let endpoint_canonical_id = record
            .endpoint_delegation
            .id()
            .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation ID"))?;
        let canonical = record.encode()?;
        let canonical_hash = blake2b_256(&[CANONICAL_HASH_DOMAIN, &canonical]);
        self.apply_observation(
            operation_lease,
            Some(verified),
            scope,
            CandidateObservation {
                endpoint_sequence: record.endpoint_delegation.endpoint_sequence,
                endpoint_canonical_id,
                route_sequence: record.record_sequence,
                route_canonical_hash: canonical_hash,
                force_endpoint_conflict: false,
                force_route_conflict: false,
                now,
            },
            &mut persist,
        )
    }

    /// Awaited, owned-snapshot variant of
    /// [`Self::observe_current_persisted_uncommitted`].
    ///
    /// The verified route is withheld until every pending and newly prepared
    /// CAS transition has completed successfully.
    #[doc(hidden)]
    async fn observe_current_persisted_uncommitted_async<'a, F, Fut>(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        record: &'a NamedRouteRecordV3,
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        mut persist: F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        self.advance_trusted_time_persisted_async(operation_lease, now, &mut persist)
            .await?;
        if service.identity().network_magic != self.network_magic {
            return Err(HnsrProtocolError::Invalid(
                "HNSR V3 requester-state network mismatch",
            ));
        }
        loop {
            let mut handoff = None;
            let result = self.observe_current_persisted_uncommitted(
                operation_lease,
                record,
                service,
                policy,
                now,
                |expected, proposed| {
                    handoff = Some((expected, proposed.clone()));
                    Err(HnsrProtocolError::Invalid(
                        "async requester persistence handoff",
                    ))
                },
            );
            let Some((expected, proposed)) = handoff else {
                return result;
            };
            persist(expected, proposed.clone()).await?;
            self.acknowledge_pending(operation_lease, expected, &proposed)?;
        }
    }

    /// Select the greatest current route in one bounded response batch and
    /// durably apply permanent replay/equivocation state before returning it.
    ///
    /// The batch independently reduces greatest endpoint-delegation and route
    /// observations. Equal-sequence distinct values produce deterministic
    /// tombstones. If the two nonconflicted maxima belong to different records,
    /// both are persisted and no route is released. Candidate verification is
    /// bounded by
    /// [`MAX_RECORDS_PER_KEY`]. Trusted time is committed before every
    /// processed result, including empty, oversized, all-invalid, all-expired,
    /// stale, conflict, and capacity errors, so an expired route cannot revive
    /// after restart and clock rollback. Production callers should prefer
    /// [`ReconfirmedNamedRouteV3RequesterState::retrieve_select_and_observe_current_persisted`]; passing raw validator
    /// output here bypasses both the HNSA authority-state commit boundary and
    /// its current-revision binding.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    fn select_and_observe_current_persisted_uncommitted<'a, I, F>(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        candidates: I,
        endpoint_key: &[u8; 33],
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        mut persist: F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        I: IntoIterator<Item = &'a NamedRouteRecordV3>,
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.validate_operation_lease(operation_lease)?;
        self.reject_clock_rollback(now)?;
        self.advance_trusted_time_persisted(operation_lease, now, &mut persist)?;
        if service.identity().network_magic != self.network_magic {
            return Err(HnsrProtocolError::Invalid(
                "HNSR V3 requester-state network mismatch",
            ));
        }
        validate_public_key(endpoint_key)?;
        let scope = self.scope_for(service, *endpoint_key)?;
        self.check_capacity_for_scope(&scope)?;

        let candidates = candidates
            .into_iter()
            .take(MAX_RECORDS_PER_KEY.saturating_add(1))
            .collect::<Vec<_>>();
        if candidates.len() > MAX_RECORDS_PER_KEY {
            return Err(HnsrProtocolError::TooLarge {
                actual: candidates.len(),
                maximum: MAX_RECORDS_PER_KEY,
            });
        }
        let mut valid = Vec::new();
        for candidate in candidates {
            if candidate.route_key != scope.route_key
                || candidate.endpoint_delegation.endpoint_key != *endpoint_key
            {
                continue;
            }
            let Ok(verified) = candidate.verify_current_uncommitted(service, policy, now) else {
                continue;
            };
            let endpoint_canonical_id = candidate
                .endpoint_delegation
                .id()
                .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation ID"))?;
            valid.push((verified, endpoint_canonical_id, candidate.encode()?));
        }
        let greatest_endpoint = valid
            .iter()
            .map(|(verified, _, _)| verified.record().endpoint_delegation.endpoint_sequence)
            .max()
            .ok_or(HnsrProtocolError::Invalid(
                "no current HRM-backed named route",
            ))?;
        let mut greatest_endpoints = valid.iter().filter(|(verified, _, _)| {
            verified.record().endpoint_delegation.endpoint_sequence == greatest_endpoint
        });
        let (_, endpoint_canonical_id, _) = greatest_endpoints.next().ok_or(
            HnsrProtocolError::Invalid("no current HRM-backed named route"),
        )?;
        let force_endpoint_conflict =
            greatest_endpoints.any(|(_, other_id, _)| other_id != endpoint_canonical_id);
        let greatest_route = valid
            .iter()
            .map(|(verified, _, _)| verified.record().record_sequence)
            .max()
            .ok_or(HnsrProtocolError::Invalid(
                "no current HRM-backed named route",
            ))?;
        let mut greatest_routes = valid
            .iter()
            .filter(|(verified, _, _)| verified.record().record_sequence == greatest_route);
        let (_, _, canonical) = greatest_routes.next().ok_or(HnsrProtocolError::Invalid(
            "no current HRM-backed named route",
        ))?;
        let force_route_conflict = greatest_routes.any(|(_, _, other)| other != canonical);
        let canonical_hash = blake2b_256(&[CANONICAL_HASH_DOMAIN, canonical]);
        let selected = (!force_endpoint_conflict && !force_route_conflict)
            .then(|| {
                valid
                    .iter()
                    .find(|(verified, candidate_endpoint_id, candidate_bytes)| {
                        verified.record().endpoint_delegation.endpoint_sequence == greatest_endpoint
                            && candidate_endpoint_id == endpoint_canonical_id
                            && verified.record().record_sequence == greatest_route
                            && candidate_bytes == canonical
                    })
                    .map(|(verified, _, _)| *verified)
            })
            .flatten();
        self.check_capacity_for_scope(&scope)?;
        self.apply_observation(
            operation_lease,
            selected,
            scope,
            CandidateObservation {
                endpoint_sequence: greatest_endpoint,
                endpoint_canonical_id: *endpoint_canonical_id,
                route_sequence: greatest_route,
                route_canonical_hash: canonical_hash,
                force_endpoint_conflict,
                force_route_conflict,
                now,
            },
            &mut persist,
        )
    }

    /// Ordered production retrieval and selection boundary.
    #[allow(clippy::too_many_arguments)]
    fn retrieve_select_and_observe_current_persisted<'a, R, I, B, Retrieve, F>(
        &'a mut self,
        operation_lease: &'a NamedRouteV3OperationLeaseWitness<'a>,
        now: u64,
        retrieve: Retrieve,
        endpoint_key: &[u8; 33],
        committed_service: &'a CurrentCommittedNamedService<'a>,
        policy: HrmNamedRoutePolicy,
        mut persist: F,
    ) -> Result<CurrentNamedRouteV3<'a>, NamedRouteV3RequesterOperationError<R>>
    where
        Retrieve: FnOnce(u64) -> Result<I, R>,
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.advance_trusted_time_persisted(operation_lease, now, &mut persist)?;
        let retrieved = retrieve(now);
        // Retrieval may outlive or replace either broker guard. Recheck the
        // composite in its security-significant authority/requester order
        // before interpreting even a retrieval failure or touching the batch.
        self.validate_operation_lease(operation_lease)?;
        let candidates = retrieved.map_err(NamedRouteV3RequesterOperationError::Retrieval)?;
        self.select_and_observe_current_persisted(
            operation_lease,
            candidates,
            endpoint_key,
            committed_service,
            policy,
            now,
            persist,
        )
        .map_err(Into::into)
    }

    /// Internal direct-raw selector. Production callers enter through the
    /// retrieval closure above so unavailable transport cannot precede the
    /// requester trusted-time CAS.
    #[allow(clippy::too_many_arguments)]
    fn select_and_observe_current_persisted<'a, I, B, F>(
        &'a mut self,
        operation_lease: &'a NamedRouteV3OperationLeaseWitness<'a>,
        candidates: I,
        endpoint_key: &[u8; 33],
        committed_service: &'a CurrentCommittedNamedService<'a>,
        policy: HrmNamedRoutePolicy,
        now: u64,
        mut persist: F,
    ) -> Result<CurrentNamedRouteV3<'a>, HnsrProtocolError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        // Advance and durably acknowledge requester time before rejecting a
        // mismatched authority guard. Otherwise an expired route could be
        // revived by repeatedly presenting an older authority-time guard.
        self.advance_trusted_time_persisted(operation_lease, now, &mut persist)?;
        committed_service
            .ensure_bound_to(operation_lease.authority())
            .map_err(|_| {
                HnsrProtocolError::Invalid(
                    "committed HNSA authority belongs to a different operation lease",
                )
            })?;
        if committed_service.trusted_time_high_water() != now {
            return Err(HnsrProtocolError::Invalid(
                "committed HNSA authority operation-time mismatch",
            ));
        }
        let service = committed_service
            .active()
            .ok_or(HnsrProtocolError::Invalid(
                "committed HNSA service is withdrawn",
            ))?;
        let candidates = decode_bounded_raw_route_batch(candidates)?;
        let verified = self.select_and_observe_current_persisted_uncommitted(
            operation_lease,
            candidates.iter(),
            endpoint_key,
            service,
            policy,
            now,
            persist,
        )?;
        if !std::ptr::eq(service, verified.service()) {
            return Err(HnsrProtocolError::Invalid(
                "selected route belongs to a different HNSA service",
            ));
        }
        let record = verified.record().clone();
        let cache_until = verified.cache_until();
        self.bind_current_route(
            operation_lease,
            committed_service,
            service,
            record,
            cache_until,
        )
    }

    /// Async/mobile production selector with owned snapshots and awaited CAS
    /// acknowledgement before any verified route is released.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    async fn select_and_observe_current_persisted_uncommitted_async<'a, I, F, Fut>(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        candidates: I,
        endpoint_key: &[u8; 33],
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        mut persist: F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        I: IntoIterator<Item = &'a NamedRouteRecordV3>,
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        // Preserve the same fail-closed ordering as the synchronous path:
        // requester time crosses its CAS before an old authority guard fails.
        self.advance_trusted_time_persisted_async(operation_lease, now, &mut persist)
            .await?;
        if service.identity().network_magic != self.network_magic {
            return Err(HnsrProtocolError::Invalid(
                "HNSR V3 requester-state network mismatch",
            ));
        }
        let candidates = candidates
            .into_iter()
            .take(MAX_RECORDS_PER_KEY.saturating_add(1))
            .collect::<Vec<_>>();
        loop {
            let mut handoff = None;
            let result = self.select_and_observe_current_persisted_uncommitted(
                operation_lease,
                candidates.iter().copied(),
                endpoint_key,
                service,
                policy,
                now,
                |expected, proposed| {
                    handoff = Some((expected, proposed.clone()));
                    Err(HnsrProtocolError::Invalid(
                        "async requester persistence handoff",
                    ))
                },
            );
            let Some((expected, proposed)) = handoff else {
                return result;
            };
            persist(expected, proposed.clone()).await?;
            self.acknowledge_pending(operation_lease, expected, &proposed)?;
        }
    }

    /// Ordered task-local async retrieval and selection boundary.
    #[allow(clippy::too_many_arguments)]
    async fn retrieve_select_and_observe_current_persisted_async<
        'a,
        R,
        I,
        B,
        Retrieve,
        RetrieveFuture,
        F,
        Fut,
    >(
        &'a mut self,
        operation_lease: &'a NamedRouteV3OperationLeaseWitness<'a>,
        now: u64,
        retrieve: Retrieve,
        endpoint_key: &[u8; 33],
        committed_service: &'a CurrentCommittedNamedService<'a>,
        policy: HrmNamedRoutePolicy,
        mut persist: F,
    ) -> Result<CurrentNamedRouteV3<'a>, NamedRouteV3RequesterOperationError<R>>
    where
        Retrieve: FnOnce(u64) -> RetrieveFuture,
        RetrieveFuture: Future<Output = Result<I, R>>,
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        self.advance_trusted_time_persisted_async(operation_lease, now, &mut persist)
            .await?;
        let retrieved = retrieve(now).await;
        self.validate_operation_lease(operation_lease)?;
        let candidates = retrieved.map_err(NamedRouteV3RequesterOperationError::Retrieval)?;
        self.select_and_observe_current_persisted_async(
            operation_lease,
            candidates,
            endpoint_key,
            committed_service,
            policy,
            now,
            persist,
        )
        .await
        .map_err(Into::into)
    }

    /// Internal direct-raw async selector used only after ordered retrieval.
    #[allow(clippy::too_many_arguments)]
    async fn select_and_observe_current_persisted_async<'a, I, B, F, Fut>(
        &'a mut self,
        operation_lease: &'a NamedRouteV3OperationLeaseWitness<'a>,
        candidates: I,
        endpoint_key: &[u8; 33],
        committed_service: &'a CurrentCommittedNamedService<'a>,
        policy: HrmNamedRoutePolicy,
        now: u64,
        mut persist: F,
    ) -> Result<CurrentNamedRouteV3<'a>, HnsrProtocolError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        self.advance_trusted_time_persisted_async(operation_lease, now, &mut persist)
            .await?;
        committed_service
            .ensure_bound_to(operation_lease.authority())
            .map_err(|_| {
                HnsrProtocolError::Invalid(
                    "committed HNSA authority belongs to a different operation lease",
                )
            })?;
        if committed_service.trusted_time_high_water() != now {
            return Err(HnsrProtocolError::Invalid(
                "committed HNSA authority operation-time mismatch",
            ));
        }
        let service = committed_service
            .active()
            .ok_or(HnsrProtocolError::Invalid(
                "committed HNSA service is withdrawn",
            ))?;
        let candidates = decode_bounded_raw_route_batch(candidates)?;
        let verified = self
            .select_and_observe_current_persisted_uncommitted_async(
                operation_lease,
                candidates.iter(),
                endpoint_key,
                service,
                policy,
                now,
                persist,
            )
            .await?;
        if !std::ptr::eq(service, verified.service()) {
            return Err(HnsrProtocolError::Invalid(
                "selected route belongs to a different HNSA service",
            ));
        }
        let record = verified.record().clone();
        let cache_until = verified.cache_until();
        self.bind_current_route(
            operation_lease,
            committed_service,
            service,
            record,
            cache_until,
        )
    }

    fn apply_observation<'a, F>(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        return_candidate: Option<VerifiedNamedRouteV3<'a>>,
        scope: RequesterScope,
        candidate: CandidateObservation,
        persist: &mut F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.validate_operation_lease(operation_lease)?;
        self.flush_pending(operation_lease, persist)?;
        let endpoint_disposition = self.classify_endpoint(
            &scope,
            candidate.endpoint_sequence,
            candidate.endpoint_canonical_id,
            candidate.force_endpoint_conflict,
        );
        let route_disposition = self.classify_route(
            &scope,
            candidate.route_sequence,
            candidate.route_canonical_hash,
            candidate.force_route_conflict,
        );

        let endpoint_changes = endpoint_disposition.changes_observation();
        let route_changes = route_disposition.changes_observation();
        let observation_changes = endpoint_changes || route_changes;
        let observation_was_processed = observation_changes
            || endpoint_disposition.is_conflict()
            || route_disposition.is_conflict()
            || (endpoint_disposition == ObservationDisposition::Exact
                && route_disposition == ObservationDisposition::Exact);
        let time_changes =
            observation_was_processed && candidate.now > self.trusted_time_high_water;
        if observation_changes || time_changes {
            self.check_capacity_for_scope(&scope)?;
            let expectation = self.persistence_expectation();
            let next_revision = self.next_revision()?;
            if let Some(observation) = self.entries.get_mut(&scope) {
                apply_endpoint_disposition(
                    observation,
                    endpoint_disposition,
                    candidate.endpoint_sequence,
                    candidate.endpoint_canonical_id,
                );
                apply_route_disposition(
                    observation,
                    route_disposition,
                    candidate.route_sequence,
                    candidate.route_canonical_hash,
                );
            } else {
                let endpoint_conflicted = endpoint_disposition.is_conflict();
                self.entries.insert(
                    scope.clone(),
                    RequesterObservation {
                        endpoint_high_water: candidate.endpoint_sequence,
                        endpoint_conflicted,
                        endpoint_canonical_id: if endpoint_conflicted {
                            [0; 32]
                        } else {
                            candidate.endpoint_canonical_id
                        },
                        route_high_water: candidate.route_sequence,
                        route_conflicted: route_disposition.is_conflict(),
                        route_canonical_hash: if !route_disposition.is_conflict() {
                            candidate.route_canonical_hash
                        } else {
                            [0; 32]
                        },
                    },
                );
            }
            if time_changes {
                self.trusted_time_high_water = candidate.now;
            }
            self.revision = next_revision;
            self.pending_cas = Some(expectation);
            self.flush_pending(operation_lease, persist)?;
        }

        let observation = self.entries.get(&scope).ok_or(HnsrProtocolError::Invalid(
            "HNSR V3 requester observation changed",
        ))?;
        if observation.endpoint_conflicted || observation.route_conflicted {
            Err(HnsrProtocolError::ConflictingSequence)
        } else if observation.endpoint_high_water == candidate.endpoint_sequence
            && observation.endpoint_canonical_id == candidate.endpoint_canonical_id
            && observation.route_high_water == candidate.route_sequence
            && observation.route_canonical_hash == candidate.route_canonical_hash
        {
            return_candidate.ok_or(HnsrProtocolError::StaleSequence)
        } else {
            Err(HnsrProtocolError::StaleSequence)
        }
    }

    fn classify_endpoint(
        &self,
        scope: &RequesterScope,
        sequence: u64,
        canonical_id: [u8; 32],
        force_conflict: bool,
    ) -> ObservationDisposition {
        let Some(observation) = self.entries.get(scope) else {
            return if force_conflict {
                ObservationDisposition::NewConflict
            } else {
                ObservationDisposition::New
            };
        };
        if sequence < observation.endpoint_high_water {
            return ObservationDisposition::Stale;
        }
        if sequence > observation.endpoint_high_water {
            return if force_conflict {
                ObservationDisposition::AdvanceConflict
            } else {
                ObservationDisposition::Advance
            };
        }
        if observation.endpoint_conflicted {
            return ObservationDisposition::ExistingConflict;
        }
        if force_conflict || observation.endpoint_canonical_id != canonical_id {
            return ObservationDisposition::Conflict;
        }
        ObservationDisposition::Exact
    }

    fn classify_route(
        &self,
        scope: &RequesterScope,
        sequence: u64,
        canonical_hash: [u8; 32],
        force_conflict: bool,
    ) -> ObservationDisposition {
        let Some(observation) = self.entries.get(scope) else {
            return if force_conflict {
                ObservationDisposition::NewConflict
            } else {
                ObservationDisposition::New
            };
        };
        if sequence < observation.route_high_water {
            return ObservationDisposition::Stale;
        }
        if sequence > observation.route_high_water {
            return if force_conflict {
                ObservationDisposition::AdvanceConflict
            } else {
                ObservationDisposition::Advance
            };
        }
        if observation.route_conflicted {
            return ObservationDisposition::ExistingConflict;
        }
        if force_conflict || observation.route_canonical_hash != canonical_hash {
            return ObservationDisposition::Conflict;
        }
        ObservationDisposition::Exact
    }

    fn bind_current_route<'a>(
        &'a self,
        operation_lease: &'a NamedRouteV3OperationLeaseWitness<'a>,
        authority: &'a CurrentCommittedNamedService<'a>,
        service: &'a VerifiedNamedService,
        record: NamedRouteRecordV3,
        cache_until: u64,
    ) -> Result<CurrentNamedRouteV3<'a>, HnsrProtocolError> {
        self.validate_operation_lease(operation_lease)?;
        authority
            .ensure_bound_to(operation_lease.authority())
            .map_err(|_| {
                HnsrProtocolError::Invalid(
                    "named-route authority belongs to a different operation lease",
                )
            })?;
        if self.pending_cas.is_some()
            || !authority
                .active()
                .is_some_and(|active| std::ptr::eq(active, service))
        {
            return Err(HnsrProtocolError::Invalid(
                "named route is not bound to settled current state",
            ));
        }
        let scope = self.scope_for(service, record.endpoint_delegation.endpoint_key)?;
        let observation = *self.entries.get(&scope).ok_or(HnsrProtocolError::Invalid(
            "missing current HNSR V3 requester observation",
        ))?;
        let endpoint_canonical_id = record
            .endpoint_delegation
            .id()
            .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation ID"))?;
        let canonical = record.encode()?;
        let route_canonical_hash = blake2b_256(&[CANONICAL_HASH_DOMAIN, &canonical]);
        if observation.endpoint_conflicted
            || observation.route_conflicted
            || observation.endpoint_high_water != record.endpoint_delegation.endpoint_sequence
            || observation.endpoint_canonical_id != endpoint_canonical_id
            || observation.route_high_water != record.record_sequence
            || observation.route_canonical_hash != route_canonical_hash
        {
            return Err(HnsrProtocolError::Invalid(
                "named route is not the exact current requester observation",
            ));
        }
        Ok(CurrentNamedRouteV3 {
            requester: self,
            authority,
            service,
            record,
            cache_until,
            requester_revision: self.revision,
            scope,
            observation,
            operation_lease,
        })
    }

    fn scope_for(
        &self,
        service: &VerifiedNamedService,
        endpoint_key: [u8; 33],
    ) -> Result<RequesterScope, HnsrProtocolError> {
        Ok(RequesterScope {
            name_hash: service.identity().name_hash,
            service_name: service.identity().service_name.clone(),
            application_profile_id: service.identity().application_profile_id,
            resource_id: service.resource_id(),
            route_key: named_route_key_v3(service.identity())?,
            endpoint_key,
        })
    }

    fn check_capacity_for_scope(&self, scope: &RequesterScope) -> Result<(), HnsrProtocolError> {
        if self.entries.contains_key(scope) {
            return Ok(());
        }
        if self.entries.len() >= self.capacity
            || self
                .entries
                .keys()
                .filter(|existing| existing.route_key == scope.route_key)
                .count()
                >= MAX_RECORDS_PER_KEY
        {
            return Err(HnsrProtocolError::Capacity);
        }
        Ok(())
    }

    fn reject_clock_rollback(&self, now: u64) -> Result<(), HnsrProtocolError> {
        if now < self.trusted_time_high_water {
            return Err(HnsrProtocolError::ClockRollback);
        }
        Ok(())
    }

    fn persistence_expectation(&self) -> PersistenceExpectation {
        let snapshot = self.snapshot();
        PersistenceExpectation::Exact {
            revision: snapshot.revision(),
            fingerprint: snapshot.fingerprint(),
        }
    }

    fn flush_pending<F>(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        persist: &mut F,
    ) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.validate_operation_lease(operation_lease)?;
        let Some(expectation) = self.pending_cas else {
            return Ok(());
        };
        let snapshot = self.snapshot();
        persist(expectation.fenced(operation_lease.requester()), &snapshot)?;
        ensure_operation_lease(operation_lease)?;
        self.pending_cas = None;
        Ok(())
    }

    async fn flush_pending_async<F, Fut>(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        persist: &mut F,
    ) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        self.validate_operation_lease(operation_lease)?;
        let Some(expectation) = self.pending_cas else {
            return Ok(());
        };
        let snapshot = self.snapshot();
        persist(expectation.fenced(operation_lease.requester()), snapshot).await?;
        ensure_operation_lease(operation_lease)?;
        self.pending_cas = None;
        Ok(())
    }

    fn acknowledge_pending(
        &mut self,
        operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
        expected: NamedRouteV3RequesterExpectation,
        proposed: &NamedRouteV3RequesterSnapshot,
    ) -> Result<(), HnsrProtocolError> {
        self.validate_operation_lease(operation_lease)?;
        if self
            .pending_cas
            .map(|pending| pending.fenced(operation_lease.requester()))
            != Some(expected)
            || self.snapshot() != *proposed
        {
            return Err(HnsrProtocolError::Invalid(
                "async requester persistence acknowledgement mismatch",
            ));
        }
        ensure_operation_lease(operation_lease)?;
        self.pending_cas = None;
        Ok(())
    }

    fn next_revision(&self) -> Result<u64, HnsrProtocolError> {
        self.revision
            .checked_add(1)
            .filter(|next| *next != u64::MAX)
            .ok_or(HnsrProtocolError::NamedRouteRequesterRevisionExhausted)
    }
}

/// Whole-aggregate requester state reconfirmed under the exact ordered
/// authority-plus-requester operation leases.
///
/// There is no public constructor. The wrapper borrows the opaque composite
/// witness and cannot escape its HRTB scope.
#[derive(Debug)]
pub struct ReconfirmedNamedRouteV3RequesterState<'a> {
    state: &'a mut NamedRouteV3RequesterState,
    operation_lease: &'a NamedRouteV3OperationLeaseWitness<'a>,
}

impl ReconfirmedNamedRouteV3RequesterState<'_> {
    pub fn ensure_leases_held(&self) -> Result<(), HnsrProtocolError> {
        self.state.validate_operation_lease(self.operation_lease)
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

    pub fn len(&self) -> usize {
        self.state.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }

    pub fn snapshot(&self) -> NamedRouteV3RequesterSnapshot {
        self.state.snapshot()
    }

    pub fn pending_expectation(&self) -> Option<NamedRouteV3RequesterExpectation> {
        self.state
            .pending_cas
            .map(|expectation| expectation.fenced(self.operation_lease.requester()))
    }

    pub fn persist_pending<F>(&mut self, persist: F) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.state.persist_pending(self.operation_lease, persist)
    }

    pub async fn persist_pending_async<F, Fut>(
        &mut self,
        persist: F,
    ) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        self.state
            .persist_pending_async(self.operation_lease, persist)
            .await
    }

    pub fn advance_trusted_time_persisted<F>(
        &mut self,
        now: u64,
        persist: F,
    ) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.state
            .advance_trusted_time_persisted(self.operation_lease, now, persist)
    }

    pub async fn advance_trusted_time_persisted_async<F, Fut>(
        &mut self,
        now: u64,
        persist: F,
    ) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        self.state
            .advance_trusted_time_persisted_async(self.operation_lease, now, persist)
            .await
    }

    /// Historical/uncommitted validator path. It remains visibly distinct and
    /// cannot construct [`CurrentNamedRouteV3`].
    #[doc(hidden)]
    pub fn observe_current_persisted_uncommitted<'a, F>(
        &mut self,
        record: &'a NamedRouteRecordV3,
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        persist: F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.state.observe_current_persisted_uncommitted(
            self.operation_lease,
            record,
            service,
            policy,
            now,
            persist,
        )
    }

    #[doc(hidden)]
    pub async fn observe_current_persisted_uncommitted_async<'a, F, Fut>(
        &mut self,
        record: &'a NamedRouteRecordV3,
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        persist: F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        self.state
            .observe_current_persisted_uncommitted_async(
                self.operation_lease,
                record,
                service,
                policy,
                now,
                persist,
            )
            .await
    }

    /// Historical/uncommitted batch validator. Production session setup must
    /// use [`Self::retrieve_select_and_observe_current_persisted`].
    #[doc(hidden)]
    pub fn select_and_observe_current_persisted_uncommitted<'a, I, F>(
        &mut self,
        candidates: I,
        endpoint_key: &[u8; 33],
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        persist: F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        I: IntoIterator<Item = &'a NamedRouteRecordV3>,
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.state.select_and_observe_current_persisted_uncommitted(
            self.operation_lease,
            candidates,
            endpoint_key,
            service,
            policy,
            now,
            persist,
        )
    }

    #[doc(hidden)]
    pub async fn select_and_observe_current_persisted_uncommitted_async<'a, I, F, Fut>(
        &mut self,
        candidates: I,
        endpoint_key: &[u8; 33],
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        persist: F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        I: IntoIterator<Item = &'a NamedRouteRecordV3>,
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        self.state
            .select_and_observe_current_persisted_uncommitted_async(
                self.operation_lease,
                candidates,
                endpoint_key,
                service,
                policy,
                now,
                persist,
            )
            .await
    }

    /// Retrieve and select one current route in protocol-mandated order.
    ///
    /// Pending persistence is retried and requester trusted time is durably
    /// acknowledged before `retrieve` is invoked. The closure receives that
    /// exact operation time and must begin all transport, lookup, and response
    /// acquisition when invoked, returning the complete raw response batch.
    /// Capturing a preloaded batch or previously started request violates this
    /// boundary and can move an unavailable/malformed result ahead of the time
    /// CAS. The batch is lease-rechecked, bounded, canonically decoded, fully
    /// product-reduced, and durably observed before a current route is
    /// released. Already-decoded routes are never production input.
    #[allow(clippy::too_many_arguments)]
    pub fn retrieve_select_and_observe_current_persisted<'a, R, I, B, Retrieve, F>(
        &'a mut self,
        now: u64,
        retrieve: Retrieve,
        endpoint_key: &[u8; 33],
        committed_service: &'a CurrentCommittedNamedService<'a>,
        policy: HrmNamedRoutePolicy,
        persist: F,
    ) -> Result<CurrentNamedRouteV3<'a>, NamedRouteV3RequesterOperationError<R>>
    where
        Retrieve: FnOnce(u64) -> Result<I, R>,
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
        F: FnMut(
            NamedRouteV3RequesterExpectation,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        self.state.retrieve_select_and_observe_current_persisted(
            self.operation_lease,
            now,
            retrieve,
            endpoint_key,
            committed_service,
            policy,
            persist,
        )
    }

    /// Task-local async/mobile ordered retrieval and selection.
    ///
    /// The trusted-time CAS is awaited before `retrieve` is invoked, and the
    /// returned batch is withheld until all observation CAS operations finish.
    /// `retrieve` must create and start its future when called; capturing a
    /// previously started future or preloaded result violates the boundary.
    /// No callback or future needs to be `Send`, supporting browser, extension,
    /// and mobile task-local transports and stores.
    #[allow(clippy::too_many_arguments)]
    pub async fn retrieve_select_and_observe_current_persisted_async<
        'a,
        R,
        I,
        B,
        Retrieve,
        RetrieveFuture,
        F,
        Fut,
    >(
        &'a mut self,
        now: u64,
        retrieve: Retrieve,
        endpoint_key: &[u8; 33],
        committed_service: &'a CurrentCommittedNamedService<'a>,
        policy: HrmNamedRoutePolicy,
        persist: F,
    ) -> Result<CurrentNamedRouteV3<'a>, NamedRouteV3RequesterOperationError<R>>
    where
        Retrieve: FnOnce(u64) -> RetrieveFuture,
        RetrieveFuture: Future<Output = Result<I, R>>,
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
        F: FnMut(NamedRouteV3RequesterExpectation, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        self.state
            .retrieve_select_and_observe_current_persisted_async(
                self.operation_lease,
                now,
                retrieve,
                endpoint_key,
                committed_service,
                policy,
                persist,
            )
            .await
    }
}

fn decode_bounded_raw_route_batch<I, B>(
    candidates: I,
) -> Result<Vec<NamedRouteRecordV3>, HnsrProtocolError>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let candidates = candidates
        .into_iter()
        .take(MAX_RECORDS_PER_KEY.saturating_add(1))
        .collect::<Vec<_>>();
    if candidates.len() > MAX_RECORDS_PER_KEY {
        return Err(HnsrProtocolError::TooLarge {
            actual: candidates.len(),
            maximum: MAX_RECORDS_PER_KEY,
        });
    }
    candidates
        .into_iter()
        .map(|candidate| NamedRouteRecordV3::decode(candidate.as_ref()))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistenceExpectation {
    Absent,
    Exact {
        revision: u64,
        fingerprint: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateObservation {
    endpoint_sequence: u64,
    endpoint_canonical_id: [u8; 32],
    route_sequence: u64,
    route_canonical_hash: [u8; 32],
    force_endpoint_conflict: bool,
    force_route_conflict: bool,
    now: u64,
}

impl PersistenceExpectation {
    fn fenced(
        self,
        lease: &NamedRouteV3RequesterLeaseWitness<'_>,
    ) -> NamedRouteV3RequesterExpectation {
        let storage_namespace_id = lease.key().storage_namespace_id();
        let fencing_token = lease.fencing_token();
        match self {
            Self::Absent => NamedRouteV3RequesterExpectation::Absent {
                storage_namespace_id,
                fencing_token,
            },
            Self::Exact {
                revision,
                fingerprint,
            } => NamedRouteV3RequesterExpectation::Exact {
                storage_namespace_id,
                fencing_token,
                revision,
                fingerprint,
            },
        }
    }

    fn matches_snapshot(self, snapshot: &NamedRouteV3RequesterSnapshot) -> bool {
        match self {
            Self::Absent => false,
            Self::Exact {
                revision,
                fingerprint,
            } => snapshot.revision() == revision && snapshot.fingerprint() == fingerprint,
        }
    }
}

fn ensure_operation_lease(
    operation_lease: &NamedRouteV3OperationLeaseWitness<'_>,
) -> Result<(), HnsrProtocolError> {
    operation_lease
        .ensure_held()
        .map_err(|_| HnsrProtocolError::Invalid("named-route operation lease was lost"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservationDisposition {
    New,
    Advance,
    NewConflict,
    AdvanceConflict,
    Exact,
    Conflict,
    ExistingConflict,
    Stale,
}

impl ObservationDisposition {
    const fn is_conflict(self) -> bool {
        matches!(
            self,
            Self::NewConflict | Self::AdvanceConflict | Self::Conflict | Self::ExistingConflict
        )
    }

    const fn changes_observation(self) -> bool {
        matches!(
            self,
            Self::New | Self::Advance | Self::NewConflict | Self::AdvanceConflict | Self::Conflict
        )
    }
}

fn apply_endpoint_disposition(
    observation: &mut RequesterObservation,
    disposition: ObservationDisposition,
    sequence: u64,
    canonical_id: [u8; 32],
) {
    match disposition {
        ObservationDisposition::Advance => {
            observation.endpoint_high_water = sequence;
            observation.endpoint_conflicted = false;
            observation.endpoint_canonical_id = canonical_id;
        }
        ObservationDisposition::AdvanceConflict => {
            observation.endpoint_high_water = sequence;
            observation.endpoint_conflicted = true;
            observation.endpoint_canonical_id = [0; 32];
        }
        ObservationDisposition::Conflict => {
            observation.endpoint_conflicted = true;
            observation.endpoint_canonical_id = [0; 32];
        }
        ObservationDisposition::New
        | ObservationDisposition::NewConflict
        | ObservationDisposition::Exact
        | ObservationDisposition::ExistingConflict
        | ObservationDisposition::Stale => {}
    }
}

fn apply_route_disposition(
    observation: &mut RequesterObservation,
    disposition: ObservationDisposition,
    sequence: u64,
    canonical_hash: [u8; 32],
) {
    match disposition {
        ObservationDisposition::New | ObservationDisposition::Advance => {
            observation.route_high_water = sequence;
            observation.route_conflicted = false;
            observation.route_canonical_hash = canonical_hash;
        }
        ObservationDisposition::NewConflict | ObservationDisposition::AdvanceConflict => {
            observation.route_high_water = sequence;
            observation.route_conflicted = true;
            observation.route_canonical_hash = [0; 32];
        }
        ObservationDisposition::Conflict => {
            observation.route_conflicted = true;
            observation.route_canonical_hash = [0; 32];
        }
        ObservationDisposition::Exact
        | ObservationDisposition::ExistingConflict
        | ObservationDisposition::Stale => {}
    }
}

fn snapshot_checksum(payload: &[u8]) -> [u8; 32] {
    blake2b_256(&[SNAPSHOT_CHECKSUM_DOMAIN, payload])
}

#[cfg(test)]
mod lease_tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    use hns_service_authority::authority_state::{
        NamedServiceAuthorityState, NamedServiceAuthorityStorageState,
    };

    use super::*;

    #[derive(Debug)]
    struct AuthorityGuard {
        key: AuthorityLeaseKey,
        fence: FencingToken,
        held: Rc<Cell<bool>>,
        drops: Rc<RefCell<Vec<&'static str>>>,
    }

    impl Drop for AuthorityGuard {
        fn drop(&mut self) {
            self.drops.borrow_mut().push("drop_authority");
        }
    }

    impl FencedLeaseGuard<AuthorityLeaseKey> for AuthorityGuard {
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

    #[derive(Debug)]
    struct RequesterGuard {
        key: NamedRouteV3RequesterLeaseKey,
        fence: FencingToken,
        held: Rc<Cell<bool>>,
        drops: Rc<RefCell<Vec<&'static str>>>,
    }

    impl Drop for RequesterGuard {
        fn drop(&mut self) {
            self.drops.borrow_mut().push("drop_requester");
        }
    }

    impl FencedLeaseGuard<NamedRouteV3RequesterLeaseKey> for RequesterGuard {
        fn key(&self) -> &NamedRouteV3RequesterLeaseKey {
            &self.key
        }

        fn fencing_token(&self) -> FencingToken {
            self.fence
        }

        fn ensure_held(&self) -> Result<(), LeaseError> {
            self.held.get().then_some(()).ok_or(LeaseError::Lost)
        }
    }

    fn keys() -> (AuthorityLeaseKey, NamedRouteV3RequesterLeaseKey) {
        // The two physical durable lineages intentionally use different IDs.
        let authority_namespace = StorageNamespaceId::new([1; 32]).expect("namespace");
        let requester_namespace = StorageNamespaceId::new([2; 32]).expect("namespace");
        (
            AuthorityLeaseKey::new(authority_namespace, 0x1234_5678, [7; 32]),
            NamedRouteV3RequesterLeaseKey::new(requester_namespace, 0x1234_5678),
        )
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        struct Noop;
        impl Wake for Noop {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(Noop));
        let mut context = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn test_leases(
        authority_fence: u64,
        requester_fence: u64,
    ) -> HeldNamedRouteV3OperationLeases<AuthorityGuard, RequesterGuard> {
        let (authority_key, requester_key) = keys();
        let drops = Rc::new(RefCell::new(Vec::new()));
        HeldNamedRouteV3OperationLeases::acquire(
            authority_key,
            requester_key,
            {
                let drops = Rc::clone(&drops);
                move |key| {
                    Ok::<_, ()>(AuthorityGuard {
                        key: *key,
                        fence: FencingToken::new(authority_fence).expect("fence"),
                        held: Rc::new(Cell::new(true)),
                        drops,
                    })
                }
            },
            {
                let drops = Rc::clone(&drops);
                move |key| {
                    Ok::<_, ()>(RequesterGuard {
                        key: *key,
                        fence: FencingToken::new(requester_fence).expect("fence"),
                        held: Rc::new(Cell::new(true)),
                        drops,
                    })
                }
            },
        )
        .expect("leases")
    }

    #[test]
    fn distinct_lineages_acquire_authority_then_requester_then_load_in_order() {
        let (authority_key, requester_key) = keys();
        let order = Rc::new(RefCell::new(Vec::new()));
        let drops = Rc::new(RefCell::new(Vec::new()));
        let authority_held = Rc::new(Cell::new(true));
        let requester_held = Rc::new(Cell::new(true));
        let leases = HeldNamedRouteV3OperationLeases::acquire(
            authority_key,
            requester_key,
            {
                let order = Rc::clone(&order);
                let drops = Rc::clone(&drops);
                let held = Rc::clone(&authority_held);
                move |key| {
                    order.borrow_mut().push("acquire_authority");
                    Ok::<_, ()>(AuthorityGuard {
                        key: *key,
                        fence: FencingToken::new(11).expect("fence"),
                        held,
                        drops,
                    })
                }
            },
            {
                let order = Rc::clone(&order);
                let drops = Rc::clone(&drops);
                let held = Rc::clone(&requester_held);
                move |key| {
                    order.borrow_mut().push("acquire_requester");
                    Ok::<_, ()>(RequesterGuard {
                        key: *key,
                        fence: FencingToken::new(29).expect("fence"),
                        held,
                        drops,
                    })
                }
            },
        )
        .expect("ordered leases");

        let mut authority =
            NamedServiceAuthorityState::new(0x1234_5678, [7; 32], 4, 10).expect("authority");
        let mut requester = NamedRouteV3RequesterState::new(0x1234_5678, 4, 10).expect("requester");
        leases
            .run(|operation| {
                let _authority = authority
                    .reconfirm(operation.authority(), |_| {
                        order.borrow_mut().push("load_authority");
                        Ok::<_, HnsrProtocolError>(NamedServiceAuthorityStorageState::Absent)
                    })
                    .map_err(|_| HnsrProtocolError::Invalid("authority reconfirmation"))?;
                let _requester = requester.reconfirm(operation, |_| {
                    order.borrow_mut().push("load_requester");
                    Ok(NamedRouteV3RequesterStorageState::Absent)
                })?;
                Ok::<_, HnsrProtocolError>(())
            })
            .expect("operation");
        assert_eq!(
            order.borrow().as_slice(),
            [
                "acquire_authority",
                "acquire_requester",
                "load_authority",
                "load_requester"
            ]
        );
    }

    #[test]
    fn async_acquisition_is_ordered_non_send_and_drops_authority_on_requester_failure() {
        let (authority_key, requester_key) = keys();
        let order = Rc::new(RefCell::new(Vec::new()));
        let drops = Rc::new(RefCell::new(Vec::new()));
        let result = block_on(HeldNamedRouteV3OperationLeases::acquire_async(
            authority_key,
            requester_key,
            {
                let order = Rc::clone(&order);
                let drops = Rc::clone(&drops);
                move |key| {
                    order.borrow_mut().push("authority_future_created");
                    async move {
                        order.borrow_mut().push("authority_acquired");
                        Ok::<_, &'static str>(AuthorityGuard {
                            key,
                            fence: FencingToken::new(11).expect("fence"),
                            held: Rc::new(Cell::new(true)),
                            drops,
                        })
                    }
                }
            },
            {
                let order = Rc::clone(&order);
                move |_key| {
                    order.borrow_mut().push("requester_future_created");
                    async move {
                        order.borrow_mut().push("requester_failed");
                        Err::<RequesterGuard, _>("requester unavailable")
                    }
                }
            },
        ));
        assert!(matches!(
            result,
            Err(NamedRouteV3LeaseAcquireError::Requester(
                LeaseAcquireError::Backend("requester unavailable")
            ))
        ));
        assert_eq!(
            order.borrow().as_slice(),
            [
                "authority_future_created",
                "authority_acquired",
                "requester_future_created",
                "requester_failed"
            ]
        );
        assert_eq!(drops.borrow().as_slice(), ["drop_authority"]);
    }

    #[test]
    fn requester_commit_loss_keeps_pending_proposal() {
        let (authority_key, requester_key) = keys();
        let drops = Rc::new(RefCell::new(Vec::new()));
        let requester_held = Rc::new(Cell::new(true));
        let leases = HeldNamedRouteV3OperationLeases::acquire(
            authority_key,
            requester_key,
            {
                let drops = Rc::clone(&drops);
                move |key| {
                    Ok::<_, ()>(AuthorityGuard {
                        key: *key,
                        fence: FencingToken::new(11).expect("fence"),
                        held: Rc::new(Cell::new(true)),
                        drops,
                    })
                }
            },
            {
                let drops = Rc::clone(&drops);
                let held = Rc::clone(&requester_held);
                move |key| {
                    Ok::<_, ()>(RequesterGuard {
                        key: *key,
                        fence: FencingToken::new(29).expect("fence"),
                        held,
                        drops,
                    })
                }
            },
        )
        .expect("leases");
        let mut requester = NamedRouteV3RequesterState::new(0x1234_5678, 4, 10).expect("requester");
        let result = leases.run(|operation| {
            let mut requester = requester
                .reconfirm(operation, |_| Ok(NamedRouteV3RequesterStorageState::Absent))?;
            requester.persist_pending(|expectation, _| {
                assert_eq!(
                    expectation.storage_namespace_id(),
                    requester_key.storage_namespace_id()
                );
                assert_eq!(expectation.fencing_token().get(), 29);
                requester_held.set(false);
                Ok(())
            })
        });
        assert!(result.is_err());
        assert!(requester.has_pending_persistence());
    }

    #[test]
    fn independently_restored_requester_context_fails_after_newer_fenced_commit() {
        let durable = Rc::new(RefCell::new(None::<Vec<u8>>));
        let mut current = NamedRouteV3RequesterState::new(0x1234_5678, 4, 10).expect("requester");
        test_leases(1, 1)
            .run(|operation| {
                let mut current = current
                    .reconfirm(operation, |_| Ok(NamedRouteV3RequesterStorageState::Absent))?;
                current.persist_pending(|_, snapshot| {
                    *durable.borrow_mut() = Some(snapshot.encode());
                    Ok(())
                })
            })
            .expect("initial commit");

        let initial = NamedRouteV3RequesterSnapshot::decode(
            durable.borrow().as_deref().expect("initial durable"),
        )
        .expect("snapshot");
        let mut stale = NamedRouteV3RequesterState::restore(0x1234_5678, 4, initial, 0, 10)
            .expect("stale context");

        test_leases(2, 2)
            .run(|operation| {
                let loaded = durable.borrow().clone().expect("durable");
                let mut current = current.reconfirm(operation, |_| {
                    Ok(NamedRouteV3RequesterStorageState::Present {
                        encoded: loaded,
                        minimum_revision: 0,
                    })
                })?;
                current.advance_trusted_time_persisted(11, |expectation, snapshot| {
                    assert_eq!(expectation.fencing_token().get(), 2);
                    *durable.borrow_mut() = Some(snapshot.encode());
                    Ok(())
                })
            })
            .expect("newer commit");

        test_leases(3, 3)
            .run(|operation| {
                let loaded = durable.borrow().clone().expect("newer durable");
                let result = stale.reconfirm(operation, |_| {
                    Ok(NamedRouteV3RequesterStorageState::Present {
                        encoded: loaded,
                        minimum_revision: 0,
                    })
                });
                assert!(matches!(result, Err(HnsrProtocolError::Invalid(_))));
                Ok::<_, HnsrProtocolError>(())
            })
            .expect("stale check scope");
    }
}
