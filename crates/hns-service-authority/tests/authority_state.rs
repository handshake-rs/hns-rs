use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_hrm::Envelope;
use hns_hrm::validation::{
    AcceptedReorganization, AuthenticatedNameState, ResolvedManifest, ValidationLimits,
};
use hns_service_authority::authority_state::{
    CommittedNamedService, CurrentCommittedNamedService, MAX_NAMED_SERVICE_AUTHORITY_ENTRIES,
    NamedServiceAuthorityCommitError, NamedServiceAuthorityError, NamedServiceAuthorityExpectation,
    NamedServiceAuthorityOperationError, NamedServiceAuthoritySnapshot,
    NamedServiceAuthorityState as RawNamedServiceAuthorityState, NamedServiceAuthorityStorageState,
    ReconfirmedNamedServiceAuthorityState,
};
use hns_service_authority::hrm::{
    NamedServiceIdentity, NamedServicePolicy, SERVICE_GENERATION_OBSERVATION_SIZE,
};
use hns_service_authority::lease::{
    AuthorityLeaseKey, FencedLeaseGuard, FencingToken, HeldAuthorityLease, LeaseError,
    LeaseScopeError, StorageNamespaceId,
};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_700_000_300;
const SNAPSHOT_HEADER_SIZE: usize = 178;
const SNAPSHOT_CHECKSUM_DOMAIN: &[u8] = b"HNS-HRM-HNSA-AUTHORITY-SNAPSHOT-CHECKSUM-V1\0";

fn fixtures() -> BTreeMap<&'static str, &'static str> {
    include_str!("../fixtures/hnsa-hnsr-v3/hnsa-hnsr-v3.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once('=').expect("fixture key/value"))
        .collect()
}

fn bytes(fixtures: &BTreeMap<&str, &str>, key: &str) -> Vec<u8> {
    hex::decode(fixtures.get(key).expect("fixture field")).expect("fixture hex")
}

fn array<const N: usize>(fixtures: &BTreeMap<&str, &str>, key: &str) -> [u8; N] {
    bytes(fixtures, key).try_into().expect("fixture array")
}

fn integer<T>(fixtures: &BTreeMap<&str, &str>, key: &str) -> T
where
    T: std::str::FromStr,
    T::Err: fmt::Debug,
{
    fixtures[key].parse().expect("fixture integer")
}

fn identity(fixtures: &BTreeMap<&str, &str>) -> NamedServiceIdentity {
    NamedServiceIdentity::new(
        integer(fixtures, "network_magic"),
        array(fixtures, "name_hash"),
        fixtures["service_name"],
        integer(fixtures, "application_profile_id"),
    )
    .expect("fixture identity")
}

fn other_identity(fixtures: &BTreeMap<&str, &str>) -> NamedServiceIdentity {
    NamedServiceIdentity::new(
        integer(fixtures, "network_magic"),
        array(fixtures, "name_hash"),
        "other-service",
        integer(fixtures, "application_profile_id"),
    )
    .expect("second identity")
}

fn policy(fixtures: &BTreeMap<&str, &str>) -> NamedServicePolicy {
    NamedServicePolicy {
        application_profile_id: integer(fixtures, "application_profile_id"),
        allowed_profile_flags: 0,
        required_profile_flags: 0,
        expected_profile_constraints_hash: [0; 32],
        allowed_endpoint_capabilities: integer(fixtures, "allowed_endpoint_capabilities"),
        required_endpoint_capabilities: integer(fixtures, "allowed_endpoint_capabilities"),
        expected_endpoint_constraints_hash: [0; 32],
        maximum_endpoint_lifetime: integer(fixtures, "max_endpoint_lifetime"),
    }
}

fn base64url(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(input.len().saturating_mul(4).div_ceil(3));
    for chunk in input.chunks(3) {
        let word = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        output.push(TABLE[((word >> 18) & 63) as usize] as char);
        output.push(TABLE[((word >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            output.push(TABLE[((word >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(TABLE[(word & 63) as usize] as char);
        }
    }
    output
}

fn chain_state(sequence: u64) -> (u32, [u8; 32], [u8; 32]) {
    let mut work = [0; 32];
    work[24..].copy_from_slice(&sequence.to_be_bytes());
    let mut anchor = Sha256::new();
    Digest::update(&mut anchor, b"test-chain-anchor");
    Digest::update(&mut anchor, sequence.to_le_bytes());
    (
        u32::try_from(sequence).expect("fixture sequence") + 100,
        work,
        anchor.finalize().into(),
    )
}

fn resolved_manifest_with_reorganization(
    fixtures: &BTreeMap<&str, &str>,
    envelope_key: &str,
    accepted_reorganization: Option<AcceptedReorganization>,
) -> ResolvedManifest {
    let encoded = bytes(fixtures, envelope_key);
    let envelope = Envelope::decode(&encoded).expect("fixture HRM envelope");
    let sequence = envelope.payload.sequence;
    let subject = envelope.payload.subject;
    let (chain_height, chain_work, chain_anchor) = chain_state(sequence);
    let envelope_hash: [u8; 32] = Sha256::digest(&encoded).into();
    ResolvedManifest {
        name_state: AuthenticatedNameState {
            network_magic: integer(fixtures, "network_magic"),
            subject,
            has_current_owner: true,
            revoked: false,
            expired: false,
            finality_accepted: true,
            chain_height,
            chain_work,
            chain_anchor,
            accepted_reorganization,
            commitment_records: vec![vec![
                "hrm1".to_owned(),
                format!("seq={sequence}"),
                format!("hash=sha256:{}", base64url(&envelope_hash)),
                "uri=https://example.test/hrm".to_owned(),
            ]],
        },
        envelope: encoded,
    }
}

fn resolved_manifest(fixtures: &BTreeMap<&str, &str>, envelope_key: &str) -> ResolvedManifest {
    resolved_manifest_with_reorganization(fixtures, envelope_key, None)
}

fn resolved_manifest_at_sequence(
    fixtures: &BTreeMap<&str, &str>,
    envelope_key: &str,
    sequence: u64,
) -> ResolvedManifest {
    let mut payload = Envelope::decode(&bytes(fixtures, envelope_key))
        .expect("fixture HRM envelope")
        .payload;
    payload.sequence = sequence;
    let network_magic = integer(fixtures, "network_magic");
    let envelope = Envelope::sign(payload, network_magic, &array(fixtures, "hrm_private_key"))
        .expect("sign sequence-specific HRM envelope");
    let encoded = envelope.encode().expect("encode sequence-specific HRM");
    let subject = envelope.payload.subject;
    let (chain_height, chain_work, chain_anchor) = chain_state(sequence);
    let envelope_hash: [u8; 32] = Sha256::digest(&encoded).into();
    ResolvedManifest {
        name_state: AuthenticatedNameState {
            network_magic,
            subject,
            has_current_owner: true,
            revoked: false,
            expired: false,
            finality_accepted: true,
            chain_height,
            chain_work,
            chain_anchor,
            accepted_reorganization: None,
            commitment_records: vec![vec![
                "hrm1".to_owned(),
                format!("seq={sequence}"),
                format!("hash=sha256:{}", base64url(&envelope_hash)),
                "uri=https://example.test/hrm".to_owned(),
            ]],
        },
        envelope: encoded,
    }
}

fn accepted_reorganization(fixtures: &BTreeMap<&str, &str>) -> AcceptedReorganization {
    AcceptedReorganization {
        previous_chain_height: integer(fixtures, "reorg_previous_chain_height"),
        previous_chain_work: array(fixtures, "reorg_previous_chain_work"),
        previous_chain_anchor: array(fixtures, "reorg_previous_chain_anchor"),
        current_chain_height: integer(fixtures, "reorg_current_chain_height"),
        current_chain_work: array(fixtures, "reorg_current_chain_work"),
        current_chain_anchor: array(fixtures, "reorg_current_chain_anchor"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoreError(&'static str);

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for StoreError {}

#[derive(Default)]
struct CasStore {
    encoded: Option<Vec<u8>>,
    writes: usize,
}

impl CasStore {
    fn persist(
        &mut self,
        expectation: NamedServiceAuthorityExpectation,
        proposed: &NamedServiceAuthoritySnapshot,
    ) -> Result<(), StoreError> {
        let proposed_bytes = proposed.encode().map_err(|_| StoreError("encode"))?;
        if self.encoded.as_deref() == Some(proposed_bytes.as_slice()) {
            return Ok(());
        }
        match expectation {
            NamedServiceAuthorityExpectation::Absent { .. } => {
                if self.encoded.is_some() {
                    return Err(StoreError("create conflict"));
                }
            }
            NamedServiceAuthorityExpectation::Exact {
                revision,
                fingerprint,
                ..
            } => {
                let current = self.encoded.as_deref().ok_or(StoreError("missing"))?;
                let current = NamedServiceAuthoritySnapshot::decode(current)
                    .map_err(|_| StoreError("corrupt"))?;
                if current.revision() != revision
                    || current
                        .fingerprint()
                        .map_err(|_| StoreError("fingerprint"))?
                        != fingerprint
                {
                    return Err(StoreError("cas conflict"));
                }
            }
        }
        self.encoded = Some(proposed_bytes);
        self.writes += 1;
        Ok(())
    }

    fn snapshot(&self) -> NamedServiceAuthoritySnapshot {
        NamedServiceAuthoritySnapshot::decode(self.encoded.as_ref().expect("stored snapshot"))
            .expect("valid stored snapshot")
    }
}

#[derive(Debug)]
struct TestLeaseGuard {
    key: AuthorityLeaseKey,
    fencing_token: FencingToken,
}

impl FencedLeaseGuard<AuthorityLeaseKey> for TestLeaseGuard {
    fn key(&self) -> &AuthorityLeaseKey {
        &self.key
    }

    fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    fn ensure_held(&self) -> Result<(), LeaseError> {
        Ok(())
    }
}

type AcknowledgedDurableWrite = Rc<RefCell<Option<(Vec<u8>, u64)>>>;

/// Test-local embedding boundary: every production operation acquires a real
/// scoped lease, reloads authenticated durable bytes, and reconfirms the raw
/// authority state before invoking the public leased surface.
struct TestAuthorityState {
    inner: RawNamedServiceAuthorityState,
    durable: Option<Vec<u8>>,
    minimum_revision: u64,
    storage_namespace_id: StorageNamespaceId,
    next_fencing_token: u64,
}

impl TestAuthorityState {
    fn new(
        network_magic: u32,
        subject: [u8; 32],
        capacity: usize,
        trusted_now: u64,
    ) -> Result<Self, NamedServiceAuthorityError> {
        RawNamedServiceAuthorityState::new(network_magic, subject, capacity, trusted_now)
            .map(|inner| Self::from_parts(inner, None, 0))
    }

    fn restore(
        encoded: &[u8],
        expected_network_magic: u32,
        expected_subject: [u8; 32],
        expected_capacity: usize,
        minimum_revision: u64,
        trusted_now: u64,
    ) -> Result<Self, NamedServiceAuthorityError> {
        RawNamedServiceAuthorityState::restore(
            encoded,
            expected_network_magic,
            expected_subject,
            expected_capacity,
            minimum_revision,
            trusted_now,
        )
        .map(|inner| Self::from_parts(inner, Some(encoded.to_vec()), minimum_revision))
    }

    fn from_parts(
        inner: RawNamedServiceAuthorityState,
        durable: Option<Vec<u8>>,
        minimum_revision: u64,
    ) -> Self {
        Self {
            inner,
            durable,
            minimum_revision,
            storage_namespace_id: StorageNamespaceId::new([0xa5; 32])
                .expect("nonzero test storage namespace"),
            next_fencing_token: 1,
        }
    }

    fn acquire(&mut self) -> HeldAuthorityLease<TestLeaseGuard> {
        let key = AuthorityLeaseKey::new(
            self.storage_namespace_id,
            self.inner.snapshot().network_magic(),
            self.inner.snapshot().subject(),
        );
        let fencing_token =
            FencingToken::new(self.next_fencing_token).expect("nonzero test fencing token");
        self.next_fencing_token = self
            .next_fencing_token
            .checked_add(1)
            .expect("test fencing token space");
        HeldAuthorityLease::acquire(key, |_| {
            Ok::<_, Infallible>(TestLeaseGuard { key, fencing_token })
        })
        .expect("acquire test authority lease")
    }

    fn run_reconfirmed<R, P, O, F>(&mut self, operation: F) -> Result<R, O>
    where
        O: From<NamedServiceAuthorityCommitError<P>> + From<LeaseError>,
        F: for<'lease> FnOnce(
            &mut ReconfirmedNamedServiceAuthorityState<'lease>,
            StorageNamespaceId,
            FencingToken,
            &AcknowledgedDurableWrite,
        ) -> Result<R, O>,
    {
        let held = self.acquire();
        let loaded = self.durable.clone();
        let minimum_revision = self.minimum_revision;
        let acknowledged = Rc::new(RefCell::new(None));
        let acknowledged_in_scope = Rc::clone(&acknowledged);
        let result = held.run(|lease| {
            let storage = match loaded {
                Some(encoded) => NamedServiceAuthorityStorageState::Present {
                    encoded,
                    minimum_revision,
                },
                None => NamedServiceAuthorityStorageState::Absent,
            };
            let mut reconfirmed = self
                .inner
                .reconfirm(lease, |_| Ok::<_, P>(storage))
                .map_err(O::from)?;
            operation(
                &mut reconfirmed,
                lease.key().storage_namespace_id(),
                lease.fencing_token(),
                &acknowledged_in_scope,
            )
        });
        if let Some((encoded, revision)) = acknowledged.borrow_mut().take() {
            self.durable = Some(encoded);
            self.minimum_revision = self.minimum_revision.max(revision);
        }
        match result {
            Ok(value) => Ok(value),
            Err(LeaseScopeError::Operation(error)) => Err(error),
            Err(LeaseScopeError::Lease(error)) => Err(O::from(error)),
        }
    }

    fn pending_expectation(&mut self) -> Option<NamedServiceAuthorityExpectation> {
        let result: Result<_, NamedServiceAuthorityCommitError<Infallible>> =
            self.run_reconfirmed(|reconfirmed, _, _, _| Ok(reconfirmed.pending_expectation()));
        result
            .map_err(collapse_infallible_commit_error)
            .expect("reconfirm authority state")
    }

    fn persist_pending<E, F>(
        &mut self,
        persist: &mut F,
    ) -> Result<(), NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, &NamedServiceAuthoritySnapshot) -> Result<(), E>,
    {
        self.run_reconfirmed(|reconfirmed, namespace, fence, acknowledged| {
            let mut persist_fenced = |expectation, snapshot: &NamedServiceAuthoritySnapshot| {
                assert_fenced(expectation, namespace, fence);
                let result = persist(expectation, snapshot);
                if result.is_ok() {
                    record_acknowledged(acknowledged, snapshot);
                }
                result
            };
            reconfirmed.persist_pending(&mut persist_fenced)
        })
    }

    fn advance_trusted_time_persisted<E, F>(
        &mut self,
        trusted_now: u64,
        persist: &mut F,
    ) -> Result<u64, NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, &NamedServiceAuthoritySnapshot) -> Result<(), E>,
    {
        self.run_reconfirmed(|reconfirmed, namespace, fence, acknowledged| {
            let mut persist_fenced = |expectation, snapshot: &NamedServiceAuthoritySnapshot| {
                assert_fenced(expectation, namespace, fence);
                let result = persist(expectation, snapshot);
                if result.is_ok() {
                    record_acknowledged(acknowledged, snapshot);
                }
                result
            };
            reconfirmed.advance_trusted_time_persisted(trusted_now, &mut persist_fenced)
        })
    }

    fn validate_and_observe<E, F>(
        &mut self,
        root: ResolvedManifest,
        identity: &NamedServiceIdentity,
        policy: &NamedServicePolicy,
        trusted_now: u64,
        limits: ValidationLimits,
        persist: &mut F,
    ) -> Result<CommittedNamedService, NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, &NamedServiceAuthoritySnapshot) -> Result<(), E>,
    {
        self.retrieve_validate_and_observe(
            trusted_now,
            |_| Ok::<_, Infallible>(root),
            identity,
            policy,
            limits,
            persist,
        )
        .map_err(collapse_infallible_operation_error)
    }

    fn retrieve_validate_and_observe<R, P, Retrieve, Persist>(
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
        self.run_reconfirmed(|reconfirmed, namespace, fence, acknowledged| {
            let mut persist_fenced = |expectation, snapshot: &NamedServiceAuthoritySnapshot| {
                assert_fenced(expectation, namespace, fence);
                let result = persist(expectation, snapshot);
                if result.is_ok() {
                    record_acknowledged(acknowledged, snapshot);
                }
                result
            };
            reconfirmed.retrieve_validate_and_observe(
                trusted_now,
                retrieve,
                identity,
                policy,
                limits,
                &mut persist_fenced,
            )
        })
    }

    async fn persist_pending_async<E, F, Fut>(
        &mut self,
        persist: &mut F,
    ) -> Result<(), NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.run_reconfirmed(|reconfirmed, namespace, fence, acknowledged| {
            let acknowledged = Rc::clone(acknowledged);
            let mut persist_fenced = |expectation, snapshot: NamedServiceAuthoritySnapshot| {
                assert_fenced(expectation, namespace, fence);
                let encoded = snapshot
                    .encode()
                    .expect("encode acknowledged test snapshot");
                let revision = snapshot.revision();
                let acknowledged = Rc::clone(&acknowledged);
                let future = persist(expectation, snapshot);
                async move {
                    let result = future.await;
                    if result.is_ok() {
                        *acknowledged.borrow_mut() = Some((encoded, revision));
                    }
                    result
                }
            };
            block_on(reconfirmed.persist_pending_async(&mut persist_fenced))
        })
    }

    async fn advance_trusted_time_persisted_async<E, F, Fut>(
        &mut self,
        trusted_now: u64,
        persist: &mut F,
    ) -> Result<u64, NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.run_reconfirmed(|reconfirmed, namespace, fence, acknowledged| {
            let acknowledged = Rc::clone(acknowledged);
            let mut persist_fenced = |expectation, snapshot: NamedServiceAuthoritySnapshot| {
                assert_fenced(expectation, namespace, fence);
                let encoded = snapshot
                    .encode()
                    .expect("encode acknowledged test snapshot");
                let revision = snapshot.revision();
                let acknowledged = Rc::clone(&acknowledged);
                let future = persist(expectation, snapshot);
                async move {
                    let result = future.await;
                    if result.is_ok() {
                        *acknowledged.borrow_mut() = Some((encoded, revision));
                    }
                    result
                }
            };
            block_on(
                reconfirmed.advance_trusted_time_persisted_async(trusted_now, &mut persist_fenced),
            )
        })
    }

    async fn validate_and_observe_async<E, F, Fut>(
        &mut self,
        root: ResolvedManifest,
        identity: &NamedServiceIdentity,
        policy: &NamedServicePolicy,
        trusted_now: u64,
        limits: ValidationLimits,
        persist: &mut F,
    ) -> Result<CommittedNamedService, NamedServiceAuthorityCommitError<E>>
    where
        F: FnMut(NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        self.retrieve_validate_and_observe_async(
            trusted_now,
            |_| std::future::ready(Ok::<_, Infallible>(root)),
            identity,
            policy,
            limits,
            persist,
        )
        .await
        .map_err(collapse_infallible_operation_error)
    }

    async fn retrieve_validate_and_observe_async<
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
        self.run_reconfirmed(|reconfirmed, namespace, fence, acknowledged| {
            let acknowledged = Rc::clone(acknowledged);
            let mut persist_fenced = |expectation, snapshot: NamedServiceAuthoritySnapshot| {
                assert_fenced(expectation, namespace, fence);
                let encoded = snapshot
                    .encode()
                    .expect("encode acknowledged test snapshot");
                let revision = snapshot.revision();
                let acknowledged = Rc::clone(&acknowledged);
                let future = persist(expectation, snapshot);
                async move {
                    let result = future.await;
                    if result.is_ok() {
                        *acknowledged.borrow_mut() = Some((encoded, revision));
                    }
                    result
                }
            };
            block_on(reconfirmed.retrieve_validate_and_observe_async(
                trusted_now,
                retrieve,
                identity,
                policy,
                limits,
                &mut persist_fenced,
            ))
        })
    }

    fn with_current_at<R, F>(
        &mut self,
        committed: &CommittedNamedService,
        trusted_now: u64,
        use_current: F,
    ) -> Result<R, NamedServiceAuthorityError>
    where
        F: for<'lease> FnOnce(&CurrentCommittedNamedService<'lease>) -> R,
    {
        let held = self.acquire();
        let loaded = self.durable.clone();
        let minimum_revision = self.minimum_revision;
        let result = held.run(|lease| {
            let storage = match loaded {
                Some(encoded) => NamedServiceAuthorityStorageState::Present {
                    encoded,
                    minimum_revision,
                },
                None => NamedServiceAuthorityStorageState::Absent,
            };
            let reconfirmed = self
                .inner
                .reconfirm(lease, |_| Ok::<_, Infallible>(storage))
                .map_err(collapse_infallible_commit_error)?;
            let current = reconfirmed.bind_current_at(committed, trusted_now)?;
            Ok(use_current(&current))
        });
        match result {
            Ok(value) => Ok(value),
            Err(LeaseScopeError::Operation(error)) => Err(error),
            Err(LeaseScopeError::Lease(error)) => Err(error.into()),
        }
    }

    fn install_ambiguous_durable_write(&mut self, encoded: &[u8]) {
        let snapshot = NamedServiceAuthoritySnapshot::decode(encoded)
            .expect("authenticated ambiguous test write");
        self.minimum_revision = self.minimum_revision.max(snapshot.revision());
        self.durable = Some(encoded.to_vec());
    }
}

impl Deref for TestAuthorityState {
    type Target = RawNamedServiceAuthorityState;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

fn assert_fenced(
    expectation: NamedServiceAuthorityExpectation,
    namespace: StorageNamespaceId,
    fence: FencingToken,
) {
    assert_eq!(expectation.storage_namespace_id(), namespace);
    assert_eq!(expectation.fencing_token(), fence);
}

fn record_acknowledged(
    acknowledged: &AcknowledgedDurableWrite,
    snapshot: &NamedServiceAuthoritySnapshot,
) {
    *acknowledged.borrow_mut() = Some((
        snapshot
            .encode()
            .expect("encode acknowledged test snapshot"),
        snapshot.revision(),
    ));
}

fn collapse_infallible_commit_error(
    error: NamedServiceAuthorityCommitError<Infallible>,
) -> NamedServiceAuthorityError {
    match error {
        NamedServiceAuthorityCommitError::Authority(error) => error,
        NamedServiceAuthorityCommitError::Persistence(error) => match error {},
    }
}

fn collapse_infallible_operation_error<E>(
    error: NamedServiceAuthorityOperationError<Infallible, E>,
) -> NamedServiceAuthorityCommitError<E> {
    match error {
        NamedServiceAuthorityOperationError::Retrieval(error) => match error {},
        NamedServiceAuthorityOperationError::Authority(error) => {
            NamedServiceAuthorityCommitError::Authority(error)
        }
        NamedServiceAuthorityOperationError::Persistence(error) => {
            NamedServiceAuthorityCommitError::Persistence(error)
        }
    }
}

fn new_state(fixtures: &BTreeMap<&str, &str>, capacity: usize) -> TestAuthorityState {
    TestAuthorityState::new(
        integer(fixtures, "network_magic"),
        array(fixtures, "name_hash"),
        capacity,
        NOW,
    )
    .expect("new authority state")
}

fn persist_new(state: &mut TestAuthorityState, store: &mut CasStore) {
    state
        .persist_pending(&mut |expectation, snapshot| store.persist(expectation, snapshot))
        .expect("persist initial state");
}

fn rewrite_checksum(encoded: &mut [u8]) {
    let payload_len = encoded.len() - 32;
    let checksum = blake2b_256(&[SNAPSHOT_CHECKSUM_DOMAIN, &encoded[..payload_len]]);
    encoded[payload_len..].copy_from_slice(&checksum);
}

fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("BLAKE2b output length");
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("BLAKE2b output buffer");
    output
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

#[test]
fn canonical_snapshot_detects_corruption_and_restore_rollbacks() {
    let values = fixtures();
    let mut state = new_state(&values, 2);
    assert_eq!(state.revision(), 0);
    assert!(matches!(
        state.pending_expectation(),
        Some(NamedServiceAuthorityExpectation::Absent { .. })
    ));
    assert!(state.committed_snapshot().is_none());
    let encoded = state.snapshot().encode().expect("encode initial snapshot");
    let decoded = NamedServiceAuthoritySnapshot::decode(&encoded).expect("decode snapshot");
    assert_eq!(decoded, *state.snapshot());
    assert_eq!(
        decoded.fingerprint().expect("decoded fingerprint"),
        state.snapshot().fingerprint().expect("state fingerprint")
    );

    for offset in [0, encoded.len() - 1] {
        let mut corrupted = encoded.clone();
        corrupted[offset] ^= 1;
        assert!(NamedServiceAuthoritySnapshot::decode(&corrupted).is_err());
    }
    let mut noncanonical_absent_root = encoded.clone();
    noncanonical_absent_root[66] = 1;
    rewrite_checksum(&mut noncanonical_absent_root);
    assert!(NamedServiceAuthoritySnapshot::decode(&noncanonical_absent_root).is_err());

    let mut store = CasStore::default();
    persist_new(&mut state, &mut store);
    assert!(!state.has_pending_persistence());
    assert!(state.committed_snapshot().is_some());
    assert!(matches!(
        TestAuthorityState::restore(
            &encoded,
            integer(&values, "network_magic"),
            array(&values, "name_hash"),
            2,
            1,
            NOW,
        ),
        Err(NamedServiceAuthorityError::RevisionRollback)
    ));
    assert!(matches!(
        TestAuthorityState::restore(
            &encoded,
            integer(&values, "network_magic"),
            array(&values, "name_hash"),
            2,
            0,
            NOW - 1,
        ),
        Err(NamedServiceAuthorityError::TrustedTimeRollback)
    ));
    assert!(matches!(
        TestAuthorityState::restore(
            &encoded,
            integer(&values, "network_magic"),
            array(&values, "name_hash"),
            1,
            0,
            NOW,
        ),
        Err(NamedServiceAuthorityError::BindingMismatch)
    ));

    let mut restored = TestAuthorityState::restore(
        &encoded,
        integer(&values, "network_magic"),
        array(&values, "name_hash"),
        2,
        0,
        NOW + 1,
    )
    .expect("restore and advance trusted time");
    assert_eq!(restored.revision(), 1);
    assert!(matches!(
        restored.pending_expectation(),
        Some(NamedServiceAuthorityExpectation::Exact { revision: 0, .. })
    ));
    let mut restored_store = CasStore {
        encoded: Some(encoded),
        writes: 0,
    };
    restored
        .persist_pending(&mut |expectation, snapshot| restored_store.persist(expectation, snapshot))
        .expect("persist trusted-time advance");
    let time_only = restored_store.snapshot();
    assert_eq!(time_only.revision(), 1);
    assert_eq!(time_only.trusted_time_high_water(), NOW + 1);
    assert!(time_only.is_empty());
    assert!(time_only.rollback_state().is_none());
}

#[test]
fn decode_rejects_capacity_revision_and_noncanonical_entry_attacks() {
    let values = fixtures();
    let mut oversized = new_state(&values, 2).snapshot().encode().expect("snapshot");
    oversized[45..49].copy_from_slice(
        &u32::try_from(MAX_NAMED_SERVICE_AUTHORITY_ENTRIES + 1)
            .unwrap()
            .to_le_bytes(),
    );
    rewrite_checksum(&mut oversized);
    assert!(NamedServiceAuthoritySnapshot::decode(&oversized).is_err());

    let mut exhausted = new_state(&values, 2).snapshot().encode().expect("snapshot");
    exhausted[49..57].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    rewrite_checksum(&mut exhausted);
    let restored = TestAuthorityState::restore(
        &exhausted,
        integer(&values, "network_magic"),
        array(&values, "name_hash"),
        2,
        u64::MAX - 1,
        NOW + 1,
    );
    assert!(matches!(
        restored,
        Err(NamedServiceAuthorityError::RevisionExhausted)
    ));

    let mut state = new_state(&values, 2);
    let mut store = CasStore::default();
    let first = identity(&values);
    let second = other_identity(&values);
    let trusted_policy = policy(&values);
    state
        .validate_and_observe(
            resolved_manifest(&values, "hrm_envelope"),
            &first,
            &trusted_policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("first service");
    state
        .validate_and_observe(
            resolved_manifest(&values, "replacement_hrm_envelope"),
            &second,
            &trusted_policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("second withdrawal tombstone");

    let mut impossible_lineage = state.snapshot().encode().expect("two-entry snapshot");
    impossible_lineage[49..57].copy_from_slice(&1_u64.to_le_bytes());
    rewrite_checksum(&mut impossible_lineage);
    assert!(NamedServiceAuthoritySnapshot::decode(&impossible_lineage).is_err());

    let mut reordered = state.snapshot().encode().expect("two-entry snapshot");
    let entry = SERVICE_GENERATION_OBSERVATION_SIZE;
    let first_entry = reordered[SNAPSHOT_HEADER_SIZE..SNAPSHOT_HEADER_SIZE + entry].to_vec();
    let second_entry =
        reordered[SNAPSHOT_HEADER_SIZE + entry..SNAPSHOT_HEADER_SIZE + 2 * entry].to_vec();
    reordered[SNAPSHOT_HEADER_SIZE..SNAPSHOT_HEADER_SIZE + entry].copy_from_slice(&second_entry);
    reordered[SNAPSHOT_HEADER_SIZE + entry..SNAPSHOT_HEADER_SIZE + 2 * entry]
        .copy_from_slice(&first_entry);
    rewrite_checksum(&mut reordered);
    assert!(NamedServiceAuthoritySnapshot::decode(&reordered).is_err());

    let mut duplicate = state.snapshot().encode().expect("two-entry snapshot");
    duplicate[SNAPSHOT_HEADER_SIZE + entry..SNAPSHOT_HEADER_SIZE + 2 * entry]
        .copy_from_slice(&first_entry);
    rewrite_checksum(&mut duplicate);
    assert!(NamedServiceAuthoritySnapshot::decode(&duplicate).is_err());

    let mut cross_network = state.snapshot().encode().expect("two-entry snapshot");
    cross_network[9..13]
        .copy_from_slice(&(integer::<u32>(&values, "network_magic") + 1).to_le_bytes());
    rewrite_checksum(&mut cross_network);
    assert!(NamedServiceAuthoritySnapshot::decode(&cross_network).is_err());

    let mut root_behind_service = state.snapshot().encode().expect("two-entry snapshot");
    let root_sequence = u64::from_le_bytes(root_behind_service[66..74].try_into().unwrap());
    root_behind_service[66..74].copy_from_slice(&(root_sequence - 1).to_le_bytes());
    rewrite_checksum(&mut root_behind_service);
    assert!(NamedServiceAuthoritySnapshot::decode(&root_behind_service).is_err());
}

#[test]
fn active_and_withdrawal_results_are_released_only_after_exact_cas() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 2);
    let mut store = CasStore::default();
    let committed = state
        .validate_and_observe(
            resolved_manifest(&values, "hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("committed active service");
    assert!(committed.active().is_some());
    assert_eq!(committed.authority_revision(), state.revision());
    assert_eq!(store.writes, 2, "create and exact service CAS");
    assert_eq!(store.snapshot(), *state.snapshot());

    let replacement = state
        .validate_and_observe(
            resolved_manifest(&values, "replacement_hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("committed replacement");
    assert!(replacement.active().is_some());
    let withheld_withdrawal = state.validate_and_observe(
        resolved_manifest(&values, "removal_hrm_envelope"),
        &identity,
        &policy,
        NOW,
        ValidationLimits::default(),
        &mut |_expectation, _snapshot| Err(StoreError("withdrawal CAS failed")),
    );
    assert!(matches!(
        withheld_withdrawal,
        Err(NamedServiceAuthorityCommitError::Persistence(StoreError(
            "withdrawal CAS failed"
        )))
    ));
    assert!(state.has_pending_persistence());
    assert!(state.committed_snapshot().is_none());
    state
        .persist_pending(&mut |expectation, snapshot| store.persist(expectation, snapshot))
        .expect("retry withdrawal CAS");
    let withdrawn = state
        .validate_and_observe(
            resolved_manifest(&values, "removal_hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("committed withdrawal");
    assert!(withdrawn.is_withdrawn());
    assert!(withdrawn.observation().is_withdrawn());
    assert!(
        store
            .snapshot()
            .observation(&identity.resource_id().expect("resource ID"))
            .expect("stored tombstone")
            .is_withdrawn()
    );
}

#[test]
fn current_guard_exposes_active_result_and_rejects_time_staleness() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    let committed = state
        .validate_and_observe(
            resolved_manifest(&values, "hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("committed active service");

    let expected_revision = state.revision();
    state
        .with_current_at(&committed, NOW, |current| {
            assert_eq!(current.authority_revision(), expected_revision);
            assert_eq!(current.trusted_time_high_water(), NOW);
            assert_eq!(current.observation(), committed.observation());
            assert!(!current.is_withdrawn());
            assert!(current.withdrawal().is_none());
            let active = current.active().expect("current active service");
            assert_eq!(active.identity(), &identity);
            assert_eq!(active.generation_observation(), current.observation());
        })
        .expect("current active guard");
    assert!(matches!(
        state.with_current_at(&committed, NOW + 1, |_| ()),
        Err(NamedServiceAuthorityError::OperationTimeMismatch)
    ));

    state
        .advance_trusted_time_persisted(NOW + 1, &mut |expectation, snapshot| {
            store.persist(expectation, snapshot)
        })
        .expect("commit trusted-time advance");
    assert!(matches!(
        state.with_current_at(&committed, NOW + 1, |_| ()),
        Err(NamedServiceAuthorityError::CommittedResultNotCurrent)
    ));
}

#[test]
fn current_guard_rejects_root_and_service_revision_staleness() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);

    let mut root_state = new_state(&values, 1);
    let mut root_store = CasStore::default();
    let before_root_advance = root_state
        .validate_and_observe(
            resolved_manifest(&values, "hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| root_store.persist(expectation, snapshot),
        )
        .expect("service before root advance");
    let mut wrong_policy = policy;
    wrong_policy.application_profile_id += 1;
    let root_only = root_state.validate_and_observe(
        resolved_manifest(&values, "replacement_hrm_envelope"),
        &identity,
        &wrong_policy,
        NOW,
        ValidationLimits::default(),
        &mut |expectation, snapshot| root_store.persist(expectation, snapshot),
    );
    assert!(matches!(
        root_only,
        Err(NamedServiceAuthorityCommitError::Authority(
            NamedServiceAuthorityError::Hnsa(_)
        ))
    ));
    assert!(matches!(
        root_state.with_current_at(&before_root_advance, NOW, |_| ()),
        Err(NamedServiceAuthorityError::CommittedResultNotCurrent)
    ));

    let mut service_state = new_state(&values, 1);
    let mut service_store = CasStore::default();
    let original = service_state
        .validate_and_observe(
            resolved_manifest(&values, "hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| service_store.persist(expectation, snapshot),
        )
        .expect("original service");
    let replacement = service_state
        .validate_and_observe(
            resolved_manifest(&values, "replacement_hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| service_store.persist(expectation, snapshot),
        )
        .expect("replacement service");
    assert!(matches!(
        service_state.with_current_at(&original, NOW, |_| ()),
        Err(NamedServiceAuthorityError::CommittedResultNotCurrent)
    ));
    let current_generation = service_state
        .with_current_at(&replacement, NOW, |current| {
            current
                .active()
                .expect("replacement remains active")
                .service_generation()
        })
        .expect("current replacement");
    assert_eq!(
        current_generation,
        replacement
            .active()
            .expect("historical replacement")
            .service_generation()
    );
}

#[test]
fn current_guard_exposes_withdrawal_and_invalidates_replacement() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    let replacement = state
        .validate_and_observe(
            resolved_manifest(&values, "replacement_hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("replacement service");
    let withdrawn = state
        .validate_and_observe(
            resolved_manifest(&values, "removal_hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("withdrawal tombstone");

    assert!(matches!(
        state.with_current_at(&replacement, NOW, |_| ()),
        Err(NamedServiceAuthorityError::CommittedResultNotCurrent)
    ));
    state
        .with_current_at(&withdrawn, NOW, |current| {
            assert_eq!(current.authority_revision(), withdrawn.authority_revision());
            assert!(current.is_withdrawn());
            assert!(current.active().is_none());
            assert_eq!(current.withdrawal(), Some(withdrawn.observation()));
        })
        .expect("current withdrawal guard");
    assert!(matches!(
        state.with_current_at(&withdrawn, NOW + 1, |_| ()),
        Err(NamedServiceAuthorityError::OperationTimeMismatch)
    ));
}

#[test]
fn current_guard_rejects_pending_and_cross_resource_handles() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);

    let mut pending_state = new_state(&values, 1);
    let mut pending_store = CasStore::default();
    let committed = pending_state
        .validate_and_observe(
            resolved_manifest(&values, "hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| pending_store.persist(expectation, snapshot),
        )
        .expect("committed service");
    let failed_advance = pending_state
        .advance_trusted_time_persisted(NOW + 1, &mut |_expectation, _snapshot| {
            Err(StoreError("time CAS failed"))
        });
    assert!(matches!(
        failed_advance,
        Err(NamedServiceAuthorityCommitError::Persistence(StoreError(
            "time CAS failed"
        )))
    ));
    assert!(matches!(
        pending_state.with_current_at(&committed, NOW + 1, |_| ()),
        Err(NamedServiceAuthorityError::PendingPersistence)
    ));

    let mut first_state = new_state(&values, 1);
    let mut first_store = CasStore::default();
    let first = first_state
        .validate_and_observe(
            resolved_manifest(&values, "hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| first_store.persist(expectation, snapshot),
        )
        .expect("first resource handle");

    let other = other_identity(&values);
    let mut second_state = new_state(&values, 1);
    let mut second_store = CasStore::default();
    let second = second_state
        .validate_and_observe(
            resolved_manifest(&values, "replacement_hrm_envelope"),
            &other,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| second_store.persist(expectation, snapshot),
        )
        .expect("second resource handle");
    assert_eq!(first.authority_revision(), second.authority_revision());
    assert!(matches!(
        first_state.with_current_at(&second, NOW, |_| ()),
        Err(NamedServiceAuthorityError::CommittedResultNotCurrent)
    ));
    assert!(matches!(
        second_state.with_current_at(&first, NOW, |_| ()),
        Err(NamedServiceAuthorityError::CommittedResultNotCurrent)
    ));
}

#[test]
fn failed_and_ambiguous_cas_keeps_exact_proposal_pending() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    let mut calls = 0;
    let result = state.validate_and_observe(
        resolved_manifest(&values, "hrm_envelope"),
        &identity,
        &policy,
        NOW,
        ValidationLimits::default(),
        &mut |expectation, snapshot| {
            calls += 1;
            if calls == 1 {
                store.persist(expectation, snapshot)
            } else {
                Err(StoreError("offline after proposal"))
            }
        },
    );
    assert!(matches!(
        result,
        Err(NamedServiceAuthorityCommitError::Persistence(StoreError(
            "offline after proposal"
        )))
    ));
    assert!(state.has_pending_persistence());
    assert!(state.committed_snapshot().is_none());
    let pending_revision = state.revision();
    let pending_bytes = state.snapshot().encode().expect("pending exact bytes");

    // Model an ambiguous first attempt that did install the proposal. The
    // idempotent adapter accepts exact proposed bytes on retry.
    store.encoded = Some(pending_bytes.clone());
    state.install_ambiguous_durable_write(&pending_bytes);
    state
        .persist_pending(&mut |expectation, snapshot| store.persist(expectation, snapshot))
        .expect("acknowledge already-installed exact proposal");
    assert!(!state.has_pending_persistence());
    assert!(state.committed_snapshot().is_some());
    assert_eq!(state.revision(), pending_revision);

    let committed = state
        .validate_and_observe(
            resolved_manifest(&values, "hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("release only after retry acknowledgment");
    assert!(committed.active().is_some());
    assert_eq!(state.revision(), pending_revision);
}

#[test]
fn validation_error_still_commits_trusted_time() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    persist_new(&mut state, &mut store);
    let mut invalid = resolved_manifest(&values, "hrm_envelope");
    invalid.envelope[0] ^= 1;
    let result = state.validate_and_observe(
        invalid,
        &identity,
        &policy,
        NOW + 10,
        ValidationLimits::default(),
        &mut |expectation, snapshot| store.persist(expectation, snapshot),
    );
    assert!(matches!(
        result,
        Err(NamedServiceAuthorityCommitError::Authority(
            NamedServiceAuthorityError::Validation(_)
        ))
    ));
    assert_eq!(state.trusted_time_high_water(), NOW + 10);
    assert_eq!(store.snapshot().trusted_time_high_water(), NOW + 10);
    assert!(store.snapshot().rollback_state().is_none());

    let expired_now = integer::<u64>(&values, "hrm_expires_at") + 1;
    let expired = state.validate_and_observe(
        resolved_manifest(&values, "hrm_envelope"),
        &identity,
        &policy,
        expired_now,
        ValidationLimits::default(),
        &mut |expectation, snapshot| store.persist(expectation, snapshot),
    );
    assert!(matches!(
        expired,
        Err(NamedServiceAuthorityCommitError::Authority(
            NamedServiceAuthorityError::Validation(_)
        ))
    ));
    assert_eq!(state.trusted_time_high_water(), expired_now);
    assert_eq!(store.snapshot().trusted_time_high_water(), expired_now);
}

#[test]
fn resolver_failure_paths_can_advance_time_synchronously_and_asynchronously() {
    let values = fixtures();
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    let revision = state
        .advance_trusted_time_persisted(NOW + 5, &mut |expectation, snapshot| {
            store.persist(expectation, snapshot)
        })
        .expect("sync resolver-failure time advance");
    assert_eq!(revision, 1);
    assert_eq!(store.writes, 2, "initial create plus time CAS");
    assert_eq!(store.snapshot().trusted_time_high_water(), NOW + 5);

    let writes = store.writes;
    assert_eq!(
        state
            .advance_trusted_time_persisted(NOW + 5, &mut |expectation, snapshot| {
                store.persist(expectation, snapshot)
            })
            .expect("same time is an acknowledged no-op"),
        revision
    );
    assert_eq!(store.writes, writes);
    assert!(matches!(
        state.advance_trusted_time_persisted(NOW + 4, &mut |expectation, snapshot| store
            .persist(expectation, snapshot),),
        Err(NamedServiceAuthorityCommitError::Authority(
            NamedServiceAuthorityError::TrustedTimeRollback
        ))
    ));

    let async_revision = block_on(
        state.advance_trusted_time_persisted_async(NOW + 6, &mut |expectation, snapshot| {
            std::future::ready(store.persist(expectation, &snapshot))
        }),
    )
    .expect("async resolver-failure time advance");
    assert_eq!(async_revision, revision + 1);
    assert_eq!(store.snapshot().trusted_time_high_water(), NOW + 6);
}

#[test]
fn successful_hrm_root_commits_even_when_hnsa_or_capacity_fails() {
    let values = fixtures();
    let identity = identity(&values);
    let mut wrong_policy = policy(&values);
    wrong_policy.application_profile_id += 1;
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    let result = state.validate_and_observe(
        resolved_manifest(&values, "hrm_envelope"),
        &identity,
        &wrong_policy,
        NOW,
        ValidationLimits::default(),
        &mut |expectation, snapshot| store.persist(expectation, snapshot),
    );
    assert!(matches!(
        result,
        Err(NamedServiceAuthorityCommitError::Authority(
            NamedServiceAuthorityError::Hnsa(_)
        ))
    ));
    let first_root = state
        .snapshot()
        .rollback_state()
        .expect("persisted HRM root");
    assert_eq!(store.snapshot().rollback_state(), Some(first_root));
    assert!(state.snapshot().is_empty());

    let trusted_policy = policy(&values);
    state
        .validate_and_observe(
            resolved_manifest(&values, "hrm_envelope"),
            &identity,
            &trusted_policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("fill one-entry capacity");
    let second = other_identity(&values);
    let result = state.validate_and_observe(
        resolved_manifest(&values, "replacement_hrm_envelope"),
        &second,
        &trusted_policy,
        NOW,
        ValidationLimits::default(),
        &mut |expectation, snapshot| store.persist(expectation, snapshot),
    );
    assert!(matches!(
        result,
        Err(NamedServiceAuthorityCommitError::Authority(
            NamedServiceAuthorityError::Capacity
        ))
    ));
    let advanced_root = state
        .snapshot()
        .rollback_state()
        .expect("advanced HRM root");
    assert!(advanced_root.sequence > first_root.sequence);
    assert_eq!(store.snapshot().rollback_state(), Some(advanced_root));
    assert_eq!(store.snapshot().len(), 1);
}

#[test]
fn sequence_zero_active_authority_commits_binds_and_survives_restart() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    let committed = state
        .retrieve_validate_and_observe(
            NOW,
            |_| Ok::<_, Infallible>(resolved_manifest_at_sequence(&values, "hrm_envelope", 0)),
            &identity,
            &policy,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("commit active sequence-zero authority");

    assert!(committed.active().is_some());
    assert_eq!(committed.observation().hrm_sequence(), 0);
    assert_eq!(
        state
            .snapshot()
            .rollback_state()
            .expect("sequence-zero subject root")
            .sequence,
        0
    );
    assert_eq!(store.snapshot(), *state.snapshot());
    let revision = state.revision();
    state
        .with_current_at(&committed, NOW, |current| {
            assert_eq!(current.authority_revision(), revision);
            assert_eq!(current.observation().hrm_sequence(), 0);
            assert_eq!(
                current
                    .active()
                    .expect("active sequence zero")
                    .hrm_sequence(),
                0
            );
        })
        .expect("bind current active sequence-zero authority");

    let encoded = state
        .snapshot()
        .encode()
        .expect("canonical sequence-zero snapshot");
    let decoded = NamedServiceAuthoritySnapshot::decode(&encoded)
        .expect("decode canonical sequence-zero snapshot");
    assert_eq!(decoded, *state.snapshot());
    let mut restored = TestAuthorityState::restore(
        &encoded,
        integer(&values, "network_magic"),
        array(&values, "name_hash"),
        1,
        revision,
        NOW,
    )
    .expect("restore sequence-zero authority");
    assert_eq!(restored.snapshot(), state.snapshot());
    restored
        .with_current_at(&committed, NOW, |current| {
            assert_eq!(current.authority_revision(), revision);
            assert_eq!(current.observation().hrm_sequence(), 0);
        })
        .expect("rebind sequence-zero authority after restart");
}

#[test]
fn sequence_zero_complete_snapshot_absence_commits_withdrawal() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    let withdrawn = state
        .retrieve_validate_and_observe(
            NOW,
            |_| {
                Ok::<_, Infallible>(resolved_manifest_at_sequence(
                    &values,
                    "removal_hrm_envelope",
                    0,
                ))
            },
            &identity,
            &policy,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("commit sequence-zero withdrawal");

    assert!(withdrawn.is_withdrawn());
    assert_eq!(withdrawn.observation().hrm_sequence(), 0);
    assert_eq!(
        state
            .snapshot()
            .rollback_state()
            .expect("sequence-zero withdrawal root")
            .sequence,
        0
    );
    assert_eq!(store.snapshot(), *state.snapshot());
    state
        .with_current_at(&withdrawn, NOW, |current| {
            assert!(current.is_withdrawn());
            assert_eq!(current.withdrawal().expect("withdrawal").hrm_sequence(), 0);
        })
        .expect("bind current sequence-zero withdrawal");
    let encoded = state
        .snapshot()
        .encode()
        .expect("canonical sequence-zero withdrawal snapshot");
    assert_eq!(
        NamedServiceAuthoritySnapshot::decode(&encoded)
            .expect("decode sequence-zero withdrawal snapshot"),
        *state.snapshot()
    );
}

#[test]
fn snapshots_forbid_revision_boundaries_and_inconsistent_zero_sequence() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    state
        .validate_and_observe(
            resolved_manifest(&values, "hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("authority observation");
    let encoded = state.snapshot().encode().expect("observed snapshot");

    let mut zero_revision = encoded.clone();
    zero_revision[49..57].copy_from_slice(&0_u64.to_le_bytes());
    rewrite_checksum(&mut zero_revision);
    assert!(NamedServiceAuthoritySnapshot::decode(&zero_revision).is_err());

    let mut exhausted_revision = encoded.clone();
    exhausted_revision[49..57].copy_from_slice(&u64::MAX.to_le_bytes());
    rewrite_checksum(&mut exhausted_revision);
    assert!(NamedServiceAuthoritySnapshot::decode(&exhausted_revision).is_err());

    // Sequence zero itself is valid. Rewriting only the subject root to zero
    // while retaining a service observation from sequence nine is not: the
    // retained observation would be ahead of its aggregate root.
    let mut zero_sequence = encoded;
    zero_sequence[66..74].copy_from_slice(&0_u64.to_le_bytes());
    rewrite_checksum(&mut zero_sequence);
    assert!(NamedServiceAuthoritySnapshot::decode(&zero_sequence).is_err());
}

#[test]
fn accepted_reorganization_atomically_invalidates_all_subject_services() {
    let values = fixtures();
    let first = identity(&values);
    let second = other_identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 2);
    let mut store = CasStore::default();
    state
        .validate_and_observe(
            resolved_manifest(&values, "replacement_hrm_envelope"),
            &first,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("first service at pre-reorg root");
    state
        .validate_and_observe(
            resolved_manifest(&values, "replacement_hrm_envelope"),
            &second,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("second service tombstone at pre-reorg root");
    assert_eq!(state.snapshot().len(), 2);
    let old_revision = state.revision();
    let second_resource = second.resource_id().expect("second resource ID");

    let mut wrong_policy = policy;
    wrong_policy.application_profile_id += 1;
    let failed_observation = state.validate_and_observe(
        resolved_manifest_with_reorganization(
            &values,
            "hrm_envelope",
            Some(accepted_reorganization(&values)),
        ),
        &first,
        &wrong_policy,
        NOW,
        ValidationLimits::default(),
        &mut |expectation, snapshot| store.persist(expectation, snapshot),
    );
    assert!(matches!(
        failed_observation,
        Err(NamedServiceAuthorityCommitError::Authority(
            NamedServiceAuthorityError::Hnsa(_)
        ))
    ));
    assert!(state.revision() > old_revision);
    assert!(state.snapshot().is_empty());
    assert_eq!(store.snapshot(), *state.snapshot());

    let post_reset_revision = state.revision();
    let committed = state
        .validate_and_observe(
            resolved_manifest(&values, "hrm_envelope"),
            &first,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("revalidate selected service after committed reset");
    assert!(committed.active().is_some());
    assert!(committed.authority_revision() > post_reset_revision);
    assert_eq!(state.snapshot().len(), 1);
    assert!(state.snapshot().observation(&second_resource).is_none());
    assert_eq!(store.snapshot(), *state.snapshot());
}

#[test]
fn unaccepted_rollback_keeps_root_but_commits_time() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    state
        .validate_and_observe(
            resolved_manifest(&values, "replacement_hrm_envelope"),
            &identity,
            &policy,
            NOW,
            ValidationLimits::default(),
            &mut |expectation, snapshot| store.persist(expectation, snapshot),
        )
        .expect("pre-rollback service");
    let prior_root = state.snapshot().rollback_state();
    let result = state.validate_and_observe(
        resolved_manifest(&values, "rollback_hrm_envelope"),
        &identity,
        &policy,
        NOW + 1,
        ValidationLimits::default(),
        &mut |expectation, snapshot| store.persist(expectation, snapshot),
    );
    assert!(matches!(
        result,
        Err(NamedServiceAuthorityCommitError::Authority(
            NamedServiceAuthorityError::Validation(_)
        ))
    ));
    assert_eq!(state.snapshot().rollback_state(), prior_root);
    assert_eq!(state.trusted_time_high_water(), NOW + 1);
    assert_eq!(store.snapshot(), *state.snapshot());
}

#[test]
fn async_path_withholds_result_until_owned_snapshot_is_acknowledged() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    let mut calls = 0;
    let result = block_on(state.validate_and_observe_async(
        resolved_manifest(&values, "hrm_envelope"),
        &identity,
        &policy,
        NOW,
        ValidationLimits::default(),
        &mut |expectation, snapshot| {
            calls += 1;
            std::future::ready(if calls == 1 {
                store.persist(expectation, &snapshot)
            } else {
                Err(StoreError("async durable write failed"))
            })
        },
    ));
    assert!(matches!(
        result,
        Err(NamedServiceAuthorityCommitError::Persistence(StoreError(
            "async durable write failed"
        )))
    ));
    assert!(state.has_pending_persistence());

    block_on(state.persist_pending_async(&mut |expectation, snapshot| {
        std::future::ready(store.persist(expectation, &snapshot))
    }))
    .expect("async retry exact proposal");
    let committed = block_on(state.validate_and_observe_async(
        resolved_manifest(&values, "hrm_envelope"),
        &identity,
        &policy,
        NOW,
        ValidationLimits::default(),
        &mut |expectation, snapshot| std::future::ready(store.persist(expectation, &snapshot)),
    ))
    .expect("async committed result");
    assert!(committed.active().is_some());
}

#[test]
fn time_persistence_failure_prevents_retrieval_invocation() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    persist_new(&mut state, &mut store);
    let retrieval_calls = Cell::new(0);

    let result = state.retrieve_validate_and_observe(
        NOW + 1,
        |_| {
            retrieval_calls.set(retrieval_calls.get() + 1);
            Ok::<_, StoreError>(resolved_manifest(&values, "hrm_envelope"))
        },
        &identity,
        &policy,
        ValidationLimits::default(),
        &mut |_expectation, _snapshot| Err(StoreError("time CAS failed")),
    );

    assert!(matches!(
        result,
        Err(NamedServiceAuthorityOperationError::Persistence(
            StoreError("time CAS failed")
        ))
    ));
    assert_eq!(retrieval_calls.get(), 0);
    assert!(state.has_pending_persistence());
    assert_eq!(store.snapshot().trusted_time_high_water(), NOW);
}

#[test]
fn retrieval_failure_leaves_exact_operation_time_durable() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    persist_new(&mut state, &mut store);
    let operation_time = NOW + 10;

    let result = state.retrieve_validate_and_observe(
        operation_time,
        |trusted_now| {
            assert_eq!(trusted_now, operation_time);
            Err::<ResolvedManifest, _>(StoreError("retrieval unavailable"))
        },
        &identity,
        &policy,
        ValidationLimits::default(),
        &mut |expectation, snapshot| store.persist(expectation, snapshot),
    );

    assert!(matches!(
        result,
        Err(NamedServiceAuthorityOperationError::Retrieval(StoreError(
            "retrieval unavailable"
        )))
    ));
    assert_eq!(state.trusted_time_high_water(), operation_time);
    assert_eq!(store.snapshot().trusted_time_high_water(), operation_time);
    assert!(!state.has_pending_persistence());
}

#[test]
fn validation_begins_only_after_time_acknowledgement() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    persist_new(&mut state, &mut store);
    let operation_time = NOW + 1;
    let events = Rc::new(RefCell::new(Vec::new()));
    let retrieve_events = Rc::clone(&events);
    let persist_events = Rc::clone(&events);

    let result = state.retrieve_validate_and_observe(
        operation_time,
        move |trusted_now| {
            assert_eq!(trusted_now, operation_time);
            assert_eq!(retrieve_events.borrow().as_slice(), ["time-ack"]);
            retrieve_events.borrow_mut().push("retrieve");
            let mut invalid = resolved_manifest(&values, "hrm_envelope");
            invalid.envelope[0] ^= 1;
            Ok::<_, StoreError>(invalid)
        },
        &identity,
        &policy,
        ValidationLimits::default(),
        &mut |expectation, snapshot| {
            store.persist(expectation, snapshot)?;
            assert_eq!(snapshot.trusted_time_high_water(), operation_time);
            persist_events.borrow_mut().push("time-ack");
            Ok::<(), StoreError>(())
        },
    );

    assert!(matches!(
        result,
        Err(NamedServiceAuthorityOperationError::Authority(
            NamedServiceAuthorityError::Validation(_)
        ))
    ));
    assert_eq!(events.borrow().as_slice(), ["time-ack", "retrieve"]);
    assert_eq!(store.snapshot().trusted_time_high_water(), operation_time);
}

#[test]
fn outcome_ambiguous_pending_transition_retries_before_time_and_retrieval() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut state = new_state(&values, 1);
    let mut store = CasStore::default();
    let mut first_calls = 0;
    let first = state.validate_and_observe(
        resolved_manifest(&values, "hrm_envelope"),
        &identity,
        &policy,
        NOW,
        ValidationLimits::default(),
        &mut |expectation, snapshot| {
            first_calls += 1;
            if first_calls == 1 {
                store.persist(expectation, snapshot)
            } else {
                // The adapter cannot tell whether the exact write landed. This
                // branch models the valid "not installed" ambiguous outcome.
                Err(StoreError("ambiguous root CAS"))
            }
        },
    );
    assert!(matches!(
        first,
        Err(NamedServiceAuthorityCommitError::Persistence(StoreError(
            "ambiguous root CAS"
        )))
    ));
    assert!(state.has_pending_persistence());
    let pending_revision = state.revision();
    let operation_time = NOW + 1;
    let events = Rc::new(RefCell::new(Vec::new()));
    let retrieve_events = Rc::clone(&events);
    let persist_events = Rc::clone(&events);

    let committed = state
        .retrieve_validate_and_observe(
            operation_time,
            move |_| {
                assert_eq!(
                    retrieve_events.borrow().as_slice(),
                    ["pending-retry", "time-ack"]
                );
                retrieve_events.borrow_mut().push("retrieve");
                Ok::<_, StoreError>(resolved_manifest(&values, "hrm_envelope"))
            },
            &identity,
            &policy,
            ValidationLimits::default(),
            &mut |expectation, snapshot| {
                store.persist(expectation, snapshot)?;
                if snapshot.revision() == pending_revision {
                    persist_events.borrow_mut().push("pending-retry");
                } else {
                    assert_eq!(snapshot.trusted_time_high_water(), operation_time);
                    persist_events.borrow_mut().push("time-ack");
                }
                Ok::<(), StoreError>(())
            },
        )
        .expect("retry pending, commit time, then retrieve");

    assert!(committed.active().is_some());
    assert_eq!(
        events.borrow().as_slice(),
        ["pending-retry", "time-ack", "retrieve"]
    );
    assert_eq!(store.snapshot().trusted_time_high_water(), operation_time);
}

#[test]
fn task_local_async_order_matches_sync_without_send_bounds() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let mut sync_state = new_state(&values, 1);
    let mut sync_store = CasStore::default();
    persist_new(&mut sync_state, &mut sync_store);
    let initial = sync_store
        .encoded
        .clone()
        .expect("initial durable snapshot");
    let mut async_state = TestAuthorityState::restore(
        &initial,
        integer(&values, "network_magic"),
        array(&values, "name_hash"),
        1,
        0,
        NOW,
    )
    .expect("parallel async authority state");
    let async_store = Rc::new(RefCell::new(CasStore {
        encoded: Some(initial),
        writes: 0,
    }));
    let operation_time = NOW + 1;

    let sync_events = Rc::new(RefCell::new(Vec::new()));
    let sync_retrieve_events = Rc::clone(&sync_events);
    let sync_persist_events = Rc::clone(&sync_events);
    let sync_values = &values;
    let sync_committed = sync_state
        .retrieve_validate_and_observe(
            operation_time,
            move |_| {
                sync_retrieve_events.borrow_mut().push("retrieve");
                Ok::<_, Infallible>(resolved_manifest(sync_values, "hrm_envelope"))
            },
            &identity,
            &policy,
            ValidationLimits::default(),
            &mut |expectation, snapshot| {
                sync_store.persist(expectation, snapshot)?;
                sync_persist_events.borrow_mut().push("persist");
                Ok::<(), StoreError>(())
            },
        )
        .expect("ordered synchronous operation");

    let async_events = Rc::new(RefCell::new(Vec::new()));
    let async_retrieve_events = Rc::clone(&async_events);
    let async_persist_events = Rc::clone(&async_events);
    let async_persist_store = Rc::clone(&async_store);
    let async_values = &values;
    let async_committed = block_on(async_state.retrieve_validate_and_observe_async(
        operation_time,
        move |_| {
            async_retrieve_events.borrow_mut().push("retrieve");
            let events = Rc::clone(&async_retrieve_events);
            async move {
                // Capturing `Rc<RefCell<_>>` makes this future non-Send. The
                // public task-local boundary deliberately accepts it.
                assert_eq!(events.borrow().last(), Some(&"retrieve"));
                Ok::<_, Infallible>(resolved_manifest(async_values, "hrm_envelope"))
            }
        },
        &identity,
        &policy,
        ValidationLimits::default(),
        &mut move |expectation, snapshot| {
            let events = Rc::clone(&async_persist_events);
            let store = Rc::clone(&async_persist_store);
            async move {
                store.borrow_mut().persist(expectation, &snapshot)?;
                events.borrow_mut().push("persist");
                Ok::<(), StoreError>(())
            }
        },
    ))
    .expect("ordered task-local asynchronous operation");

    assert_eq!(
        sync_events.borrow().as_slice(),
        ["persist", "retrieve", "persist"]
    );
    assert_eq!(
        async_events.borrow().as_slice(),
        sync_events.borrow().as_slice()
    );
    assert_eq!(async_state.snapshot(), sync_state.snapshot());
    assert_eq!(async_store.borrow().snapshot(), sync_store.snapshot());
    assert_eq!(async_committed.observation(), sync_committed.observation());
}
