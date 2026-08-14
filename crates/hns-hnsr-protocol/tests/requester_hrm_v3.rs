use std::cell::{Cell, RefCell};
use std::convert::Infallible;
use std::future::Future;
use std::ops::AsyncFnOnce;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_hnsr_protocol::named_hrm::VerifiedNamedRouteV3;
use hns_hnsr_protocol::requester_hrm::{
    CurrentNamedRouteV3, HeldNamedRouteV3OperationLeases, NamedRouteV3RequesterExpectation,
    NamedRouteV3RequesterLeaseKey, NamedRouteV3RequesterOperationError,
    NamedRouteV3RequesterStorageState, ReconfirmedNamedRouteV3RequesterState,
};
use hns_hnsr_protocol::{
    HnsrProtocolError, HrmNamedRoutePolicy, MAX_RECORD_SIZE, MAX_RECORDS_PER_KEY,
    NamedRouteRecordV3, NamedRouteV3RequesterSnapshot,
    NamedRouteV3RequesterState as ProductionRequesterState, named_route_key_v3, public_key,
    select_named_route_v3_uncommitted,
};
use hns_hrm::validation::{
    AuthenticatedNameState, ResolvedManifest, RollbackObservations, ValidatedCurrentManifest,
    ValidationLimits, validate_current_manifest,
};
use hns_service_authority::authority_state::{
    CommittedNamedService, CurrentCommittedNamedService, NamedServiceAuthorityError,
    NamedServiceAuthorityExpectation, NamedServiceAuthorityOperationError,
    NamedServiceAuthoritySnapshot, NamedServiceAuthorityState as ProductionAuthorityState,
    NamedServiceAuthorityStorageState,
};
use hns_service_authority::hrm::{
    NamedServiceIdentity, NamedServicePolicy, VerifiedNamedService, observe_named_service,
};
use hns_service_authority::lease::{
    AuthorityLeaseKey, FencedLeaseGuard, FencingToken, HeldAuthorityLease, LeaseError,
    LeaseScopeError, StorageNamespaceId,
};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_700_000_300;
const MAGIC: u32 = 2_922_943_951;
const PROFILE: u16 = 0xff00;
const SNAPSHOT_HEADER_SIZE: usize = 40;
const SNAPSHOT_ENTRY_SIZE: usize = 277;
const AUTHORITY_NAMESPACE: [u8; 32] = [21; 32];
const REQUESTER_NAMESPACE: [u8; 32] = [22; 32];

fn fixture(name: &str) -> &str {
    include_str!("../fixtures/hnsa-hnsr-v3/hnsa-hnsr-v3.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
        .unwrap_or_else(|| panic!("missing fixture field {name}"))
}

fn bytes(name: &str) -> Vec<u8> {
    hex::decode(fixture(name)).unwrap_or_else(|_| panic!("invalid fixture hex {name}"))
}

fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("BLAKE2b-256");
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("BLAKE2b output");
    output
}

fn rechecksum_snapshot(encoded: &mut [u8]) {
    let payload_len = encoded.len() - 32;
    let checksum = blake2b_256(&[
        b"HNSR-NAMED-V3-REQUESTER-SNAPSHOT-V1\0",
        &encoded[..payload_len],
    ]);
    encoded[payload_len..].copy_from_slice(&checksum);
}

fn normalized_snapshot(snapshot: &NamedRouteV3RequesterSnapshot) -> Vec<u8> {
    let mut encoded = snapshot.encode();
    encoded[20..28].fill(0);
    rechecksum_snapshot(&mut encoded);
    encoded
}

fn identity(service_name: &str) -> NamedServiceIdentity {
    NamedServiceIdentity::new(MAGIC, [15; 32], service_name, PROFILE).expect("identity")
}

fn service_policy() -> NamedServicePolicy {
    NamedServicePolicy {
        application_profile_id: PROFILE,
        allowed_profile_flags: 0,
        required_profile_flags: 0,
        expected_profile_constraints_hash: [0; 32],
        allowed_endpoint_capabilities: 1,
        required_endpoint_capabilities: 1,
        expected_endpoint_constraints_hash: [0; 32],
        maximum_endpoint_lifetime: 3_600,
    }
}

fn route_policy() -> HrmNamedRoutePolicy {
    HrmNamedRoutePolicy {
        maximum_route_lifetime: 900,
        allowed_service_flags: 0,
        required_service_flags: 0,
        expected_service_constraints_hash: [0; 32],
        allowed_endpoint_capabilities: 1,
        required_endpoint_capabilities: 1,
        expected_endpoint_constraints_hash: [0; 32],
        allow_private_relays: true,
    }
}

fn current_manifest(
    identity: &NamedServiceIdentity,
    envelope_name: &str,
    sequence: u64,
) -> ValidatedCurrentManifest {
    let envelope = bytes(envelope_name);
    let digest = Sha256::digest(&envelope);
    validate_current_manifest(
        ResolvedManifest {
            name_state: AuthenticatedNameState {
                network_magic: MAGIC,
                subject: identity.name_hash,
                has_current_owner: true,
                revoked: false,
                expired: false,
                finality_accepted: true,
                chain_height: 100,
                chain_work: [3; 32],
                chain_anchor: [4; 32],
                accepted_reorganization: None,
                commitment_records: vec![vec![
                    "hrm1".to_owned(),
                    format!("seq={sequence}"),
                    format!("hash=sha256:{}", URL_SAFE_NO_PAD.encode(digest)),
                    "uri=https://example.test/hrm".to_owned(),
                ]],
            },
            envelope,
        },
        MAGIC,
        identity.name_hash,
        NOW,
        ValidationLimits::default(),
        &RollbackObservations::new(),
    )
    .expect("current HRM manifest")
}

fn authority_manifest(
    identity: &NamedServiceIdentity,
    envelope_name: &str,
    sequence: u64,
) -> ResolvedManifest {
    let envelope = bytes(envelope_name);
    let digest = Sha256::digest(&envelope);
    let mut chain_work = [0; 32];
    chain_work[24..].copy_from_slice(&sequence.to_be_bytes());
    let mut chain_anchor = Sha256::new();
    Digest::update(
        &mut chain_anchor,
        b"requester-committed-wrapper-test-anchor",
    );
    Digest::update(&mut chain_anchor, sequence.to_le_bytes());
    ResolvedManifest {
        name_state: AuthenticatedNameState {
            network_magic: MAGIC,
            subject: identity.name_hash,
            has_current_owner: true,
            revoked: false,
            expired: false,
            finality_accepted: true,
            chain_height: u32::try_from(sequence).expect("test sequence") + 100,
            chain_work,
            chain_anchor: chain_anchor.finalize().into(),
            accepted_reorganization: None,
            commitment_records: vec![vec![
                "hrm1".to_owned(),
                format!("seq={sequence}"),
                format!("hash=sha256:{}", URL_SAFE_NO_PAD.encode(digest)),
                "uri=https://example.test/hrm".to_owned(),
            ]],
        },
        envelope,
    }
}

fn acknowledge_authority_snapshot(
    _expected: NamedServiceAuthorityExpectation,
    _proposed: &NamedServiceAuthoritySnapshot,
) -> Result<(), HnsrProtocolError> {
    Ok(())
}

#[derive(Debug)]
struct AuthorityTestGuard {
    key: AuthorityLeaseKey,
    fence: FencingToken,
}

impl FencedLeaseGuard<AuthorityLeaseKey> for AuthorityTestGuard {
    fn key(&self) -> &AuthorityLeaseKey {
        &self.key
    }

    fn fencing_token(&self) -> FencingToken {
        self.fence
    }

    fn ensure_held(&self) -> Result<(), LeaseError> {
        Ok(())
    }
}

#[derive(Debug)]
struct RequesterTestGuard {
    key: NamedRouteV3RequesterLeaseKey,
    fence: FencingToken,
}

impl FencedLeaseGuard<NamedRouteV3RequesterLeaseKey> for RequesterTestGuard {
    fn key(&self) -> &NamedRouteV3RequesterLeaseKey {
        &self.key
    }

    fn fencing_token(&self) -> FencingToken {
        self.fence
    }

    fn ensure_held(&self) -> Result<(), LeaseError> {
        Ok(())
    }
}

#[derive(Debug)]
struct NamedServiceAuthorityState {
    inner: ProductionAuthorityState,
    durable: Option<Vec<u8>>,
    next_fence: u64,
}

impl std::ops::Deref for NamedServiceAuthorityState {
    type Target = ProductionAuthorityState;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl NamedServiceAuthorityState {
    fn new(
        network_magic: u32,
        subject: [u8; 32],
        capacity: usize,
        trusted_now: u64,
    ) -> Result<Self, NamedServiceAuthorityError> {
        Ok(Self {
            inner: ProductionAuthorityState::new(network_magic, subject, capacity, trusted_now)?,
            durable: None,
            next_fence: 1,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn retrieve_validate_and_observe<R, E, Retrieve, F>(
        &mut self,
        trusted_now: u64,
        retrieve: Retrieve,
        identity: &NamedServiceIdentity,
        policy: &NamedServicePolicy,
        limits: ValidationLimits,
        persist: &mut F,
    ) -> Result<CommittedNamedService, NamedServiceAuthorityOperationError<R, E>>
    where
        Retrieve: FnOnce(u64) -> Result<ResolvedManifest, R>,
        F: FnMut(NamedServiceAuthorityExpectation, &NamedServiceAuthoritySnapshot) -> Result<(), E>,
    {
        let key = AuthorityLeaseKey::new(
            StorageNamespaceId::new(AUTHORITY_NAMESPACE).expect("authority namespace"),
            self.inner.snapshot().network_magic(),
            self.inner.snapshot().subject(),
        );
        let fence = FencingToken::new(self.next_fence).expect("fence");
        self.next_fence += 1;
        let held =
            HeldAuthorityLease::acquire(key, |_| Ok::<_, ()>(AuthorityTestGuard { key, fence }))
                .expect("authority lease");
        let loaded = self.durable.clone();
        let acknowledged = Rc::new(RefCell::new(None::<Vec<u8>>));
        let acknowledged_in_scope = Rc::clone(&acknowledged);
        let result = held.run(|witness| {
            let storage = loaded.map_or(NamedServiceAuthorityStorageState::Absent, |encoded| {
                NamedServiceAuthorityStorageState::Present {
                    encoded,
                    minimum_revision: 0,
                }
            });
            let mut state = self.inner.reconfirm(witness, |_| Ok::<_, E>(storage))?;
            state.retrieve_validate_and_observe(
                trusted_now,
                retrieve,
                identity,
                policy,
                limits,
                &mut |expectation, snapshot| {
                    let result = persist(expectation, snapshot);
                    if result.is_ok() {
                        *acknowledged_in_scope.borrow_mut() =
                            Some(snapshot.encode().expect("authority snapshot"));
                    }
                    result
                },
            )
        });
        if let Some(encoded) = acknowledged.borrow_mut().take() {
            self.durable = Some(encoded);
        }
        match result {
            Ok(result) => Ok(result),
            Err(LeaseScopeError::Operation(error)) => Err(error),
            Err(LeaseScopeError::Lease(error)) => {
                Err(NamedServiceAuthorityOperationError::Authority(
                    NamedServiceAuthorityError::Lease(error),
                ))
            }
        }
    }
}

fn legacy_requester_expectation(
    expectation: NamedRouteV3RequesterExpectation,
) -> Option<(u64, [u8; 32])> {
    match expectation {
        NamedRouteV3RequesterExpectation::Absent { .. } => None,
        NamedRouteV3RequesterExpectation::Exact {
            revision,
            fingerprint,
            ..
        } => Some((revision, fingerprint)),
    }
}

fn infallible_requester_operation<T>(
    result: Result<T, NamedRouteV3RequesterOperationError<Infallible>>,
) -> Result<T, HnsrProtocolError> {
    match result {
        Ok(value) => Ok(value),
        Err(NamedRouteV3RequesterOperationError::Requester(error)) => Err(error),
        Err(NamedRouteV3RequesterOperationError::Retrieval(never)) => match never {},
    }
}

macro_rules! retrieve_current {
    ($state:expr, $now:expr, $batch:expr, $endpoint:expr, $current:expr, $policy:expr, $persist:expr) => {
        infallible_requester_operation($state.retrieve_select_and_observe_current_persisted(
            $now,
            |_| Ok::<_, Infallible>($batch),
            $endpoint,
            $current,
            $policy,
            $persist,
        ))
    };
}

macro_rules! retrieve_current_async {
    ($state:expr, $now:expr, $batch:expr, $endpoint:expr, $current:expr, $policy:expr, $persist:expr) => {
        infallible_requester_operation(block_on(
            $state.retrieve_select_and_observe_current_persisted_async(
                $now,
                |_| std::future::ready(Ok::<_, Infallible>($batch)),
                $endpoint,
                $current,
                $policy,
                $persist,
            ),
        ))
    };
}

#[derive(Debug)]
struct NamedRouteV3RequesterState {
    inner: ProductionRequesterState,
    durable: Option<Vec<u8>>,
    next_fence: u64,
}

impl std::ops::Deref for NamedRouteV3RequesterState {
    type Target = ProductionRequesterState;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl NamedRouteV3RequesterState {
    fn new(
        network_magic: u32,
        capacity: usize,
        trusted_now: u64,
    ) -> Result<Self, HnsrProtocolError> {
        Ok(Self {
            inner: ProductionRequesterState::new(network_magic, capacity, trusted_now)?,
            durable: None,
            next_fence: 1,
        })
    }

    fn restore(
        network_magic: u32,
        capacity: usize,
        snapshot: NamedRouteV3RequesterSnapshot,
        minimum_revision: u64,
        trusted_now: u64,
    ) -> Result<Self, HnsrProtocolError> {
        let durable = Some(snapshot.encode());
        Ok(Self {
            inner: ProductionRequesterState::restore(
                network_magic,
                capacity,
                snapshot,
                minimum_revision,
                trusted_now,
            )?,
            durable,
            next_fence: 1,
        })
    }

    fn with_reconfirmed<R, F>(&mut self, operation: F) -> R
    where
        F: for<'op> FnOnce(&mut ReconfirmedNamedRouteV3RequesterState<'op>) -> R,
    {
        let authority_key = AuthorityLeaseKey::new(
            StorageNamespaceId::new(AUTHORITY_NAMESPACE).expect("authority namespace"),
            self.inner.snapshot().network_magic(),
            [15; 32],
        );
        let requester_key = NamedRouteV3RequesterLeaseKey::new(
            StorageNamespaceId::new(REQUESTER_NAMESPACE).expect("requester namespace"),
            self.inner.snapshot().network_magic(),
        );
        let fence = FencingToken::new(self.next_fence).expect("fence");
        self.next_fence += 1;
        let leases = HeldNamedRouteV3OperationLeases::acquire(
            authority_key,
            requester_key,
            |key| Ok::<_, ()>(AuthorityTestGuard { key: *key, fence }),
            |key| Ok::<_, ()>(RequesterTestGuard { key: *key, fence }),
        )
        .expect("operation leases");
        let loaded = self.durable.clone();
        leases
            .run(|witness| {
                let storage = loaded.map_or(NamedRouteV3RequesterStorageState::Absent, |encoded| {
                    NamedRouteV3RequesterStorageState::Present {
                        encoded,
                        minimum_revision: 0,
                    }
                });
                let mut state = self.inner.reconfirm(witness, |_| Ok(storage))?;
                Ok::<_, HnsrProtocolError>(operation(&mut state))
            })
            .expect("reconfirmed requester scope")
    }

    async fn with_reconfirmed_async<R, F>(&mut self, operation: F) -> R
    where
        F: for<'op> AsyncFnOnce(&'op mut ReconfirmedNamedRouteV3RequesterState<'op>) -> R,
    {
        let authority_key = AuthorityLeaseKey::new(
            StorageNamespaceId::new(AUTHORITY_NAMESPACE).expect("authority namespace"),
            self.inner.snapshot().network_magic(),
            [15; 32],
        );
        let requester_key = NamedRouteV3RequesterLeaseKey::new(
            StorageNamespaceId::new(REQUESTER_NAMESPACE).expect("requester namespace"),
            self.inner.snapshot().network_magic(),
        );
        let fence = FencingToken::new(self.next_fence).expect("fence");
        self.next_fence += 1;
        let leases = HeldNamedRouteV3OperationLeases::acquire(
            authority_key,
            requester_key,
            |key| Ok::<_, ()>(AuthorityTestGuard { key: *key, fence }),
            |key| Ok::<_, ()>(RequesterTestGuard { key: *key, fence }),
        )
        .expect("operation leases");
        let loaded = self.durable.clone();
        leases
            .run_async(async |witness| {
                let storage = loaded.map_or(NamedRouteV3RequesterStorageState::Absent, |encoded| {
                    NamedRouteV3RequesterStorageState::Present {
                        encoded,
                        minimum_revision: 0,
                    }
                });
                let mut state = self.inner.reconfirm(witness, |_| Ok(storage))?;
                Ok::<_, HnsrProtocolError>(operation(&mut state).await)
            })
            .await
            .expect("reconfirmed requester scope")
    }

    fn persist_pending<F>(&mut self, mut persist: F) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(
            Option<(u64, [u8; 32])>,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        let acknowledged = Rc::new(RefCell::new(None));
        let acknowledged_in_scope = Rc::clone(&acknowledged);
        let result = self.with_reconfirmed(|state| {
            state.persist_pending(|expectation, snapshot| {
                let result = persist(legacy_requester_expectation(expectation), snapshot);
                if result.is_ok() {
                    *acknowledged_in_scope.borrow_mut() = Some(snapshot.encode());
                }
                result
            })
        });
        if let Some(encoded) = acknowledged.borrow_mut().take() {
            self.durable = Some(encoded);
        }
        result
    }

    fn advance_trusted_time_persisted<F>(
        &mut self,
        now: u64,
        mut persist: F,
    ) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(
            Option<(u64, [u8; 32])>,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        let acknowledged = Rc::new(RefCell::new(None));
        let acknowledged_in_scope = Rc::clone(&acknowledged);
        let result = self.with_reconfirmed(|state| {
            state.advance_trusted_time_persisted(now, |expectation, snapshot| {
                let result = persist(legacy_requester_expectation(expectation), snapshot);
                if result.is_ok() {
                    *acknowledged_in_scope.borrow_mut() = Some(snapshot.encode());
                }
                result
            })
        });
        if let Some(encoded) = acknowledged.borrow_mut().take() {
            self.durable = Some(encoded);
        }
        result
    }

    fn observe_current_persisted_uncommitted<'a, F>(
        &mut self,
        record: &'a NamedRouteRecordV3,
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        mut persist: F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        F: FnMut(
            Option<(u64, [u8; 32])>,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        let acknowledged = Rc::new(RefCell::new(None));
        let acknowledged_in_scope = Rc::clone(&acknowledged);
        let result = self.with_reconfirmed(|state| {
            state.observe_current_persisted_uncommitted(
                record,
                service,
                policy,
                now,
                |expectation, snapshot| {
                    let result = persist(legacy_requester_expectation(expectation), snapshot);
                    if result.is_ok() {
                        *acknowledged_in_scope.borrow_mut() = Some(snapshot.encode());
                    }
                    result
                },
            )
        });
        if let Some(encoded) = acknowledged.borrow_mut().take() {
            self.durable = Some(encoded);
        }
        result
    }

    fn select_and_observe_current_persisted_uncommitted<'a, I, F>(
        &mut self,
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
            Option<(u64, [u8; 32])>,
            &NamedRouteV3RequesterSnapshot,
        ) -> Result<(), HnsrProtocolError>,
    {
        let acknowledged = Rc::new(RefCell::new(None));
        let acknowledged_in_scope = Rc::clone(&acknowledged);
        let result = self.with_reconfirmed(|state| {
            state.select_and_observe_current_persisted_uncommitted(
                candidates,
                endpoint_key,
                service,
                policy,
                now,
                |expectation, snapshot| {
                    let result = persist(legacy_requester_expectation(expectation), snapshot);
                    if result.is_ok() {
                        *acknowledged_in_scope.borrow_mut() = Some(snapshot.encode());
                    }
                    result
                },
            )
        });
        if let Some(encoded) = acknowledged.borrow_mut().take() {
            self.durable = Some(encoded);
        }
        result
    }

    async fn persist_pending_async<F, Fut>(
        &mut self,
        mut persist: F,
    ) -> Result<(), HnsrProtocolError>
    where
        F: FnMut(Option<(u64, [u8; 32])>, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        let acknowledged = Rc::new(RefCell::new(None));
        let acknowledged_in_scope = Rc::clone(&acknowledged);
        let result = self
            .with_reconfirmed_async(async |state| {
                state
                    .persist_pending_async(|expectation, snapshot| {
                        let expected = legacy_requester_expectation(expectation);
                        let proposed = snapshot.clone();
                        let future = persist(expected, snapshot);
                        let acknowledged = Rc::clone(&acknowledged_in_scope);
                        async move {
                            let result = future.await;
                            if result.is_ok() {
                                *acknowledged.borrow_mut() = Some(proposed.encode());
                            }
                            result
                        }
                    })
                    .await
            })
            .await;
        if let Some(encoded) = acknowledged.borrow_mut().take() {
            self.durable = Some(encoded);
        }
        result
    }

    async fn observe_current_persisted_uncommitted_async<'a, F, Fut>(
        &mut self,
        record: &'a NamedRouteRecordV3,
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        mut persist: F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        F: FnMut(Option<(u64, [u8; 32])>, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        let acknowledged = Rc::new(RefCell::new(None));
        let acknowledged_in_scope = Rc::clone(&acknowledged);
        let result = self
            .with_reconfirmed_async(async |state| {
                state
                    .observe_current_persisted_uncommitted_async(
                        record,
                        service,
                        policy,
                        now,
                        |expectation, snapshot| {
                            let expected = legacy_requester_expectation(expectation);
                            let proposed = snapshot.clone();
                            let future = persist(expected, snapshot);
                            let acknowledged = Rc::clone(&acknowledged_in_scope);
                            async move {
                                let result = future.await;
                                if result.is_ok() {
                                    *acknowledged.borrow_mut() = Some(proposed.encode());
                                }
                                result
                            }
                        },
                    )
                    .await
            })
            .await;
        if let Some(encoded) = acknowledged.borrow_mut().take() {
            self.durable = Some(encoded);
        }
        result
    }

    async fn select_and_observe_current_persisted_uncommitted_async<'a, I, F, Fut>(
        &mut self,
        candidates: I,
        endpoint_key: &[u8; 33],
        service: &'a VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        mut persist: F,
    ) -> Result<VerifiedNamedRouteV3<'a>, HnsrProtocolError>
    where
        I: IntoIterator<Item = &'a NamedRouteRecordV3>,
        F: FnMut(Option<(u64, [u8; 32])>, NamedRouteV3RequesterSnapshot) -> Fut,
        Fut: Future<Output = Result<(), HnsrProtocolError>>,
    {
        let acknowledged = Rc::new(RefCell::new(None));
        let acknowledged_in_scope = Rc::clone(&acknowledged);
        let result = self
            .with_reconfirmed_async(async |state| {
                state
                    .select_and_observe_current_persisted_uncommitted_async(
                        candidates,
                        endpoint_key,
                        service,
                        policy,
                        now,
                        |expectation, snapshot| {
                            let expected = legacy_requester_expectation(expectation);
                            let proposed = snapshot.clone();
                            let future = persist(expected, snapshot);
                            let acknowledged = Rc::clone(&acknowledged_in_scope);
                            async move {
                                let result = future.await;
                                if result.is_ok() {
                                    *acknowledged.borrow_mut() = Some(proposed.encode());
                                }
                                result
                            }
                        },
                    )
                    .await
            })
            .await;
        if let Some(encoded) = acknowledged.borrow_mut().take() {
            self.durable = Some(encoded);
        }
        result
    }
}

fn with_current_operation<R, F>(
    authority: &mut NamedServiceAuthorityState,
    committed: &CommittedNamedService,
    authority_now: u64,
    requester: &mut NamedRouteV3RequesterState,
    operation: F,
) -> R
where
    F: for<'op> FnOnce(
        &mut ReconfirmedNamedRouteV3RequesterState<'op>,
        &'op CurrentCommittedNamedService<'op>,
    ) -> R,
{
    let authority_key = AuthorityLeaseKey::new(
        StorageNamespaceId::new(AUTHORITY_NAMESPACE).expect("authority namespace"),
        authority.inner.snapshot().network_magic(),
        authority.inner.snapshot().subject(),
    );
    let requester_key = NamedRouteV3RequesterLeaseKey::new(
        StorageNamespaceId::new(REQUESTER_NAMESPACE).expect("requester namespace"),
        requester.inner.snapshot().network_magic(),
    );
    let fence_value = authority.next_fence.max(requester.next_fence);
    authority.next_fence = fence_value + 1;
    requester.next_fence = fence_value + 1;
    let fence = FencingToken::new(fence_value).expect("fence");
    let leases = HeldNamedRouteV3OperationLeases::acquire(
        authority_key,
        requester_key,
        |key| Ok::<_, ()>(AuthorityTestGuard { key: *key, fence }),
        |key| Ok::<_, ()>(RequesterTestGuard { key: *key, fence }),
    )
    .expect("operation leases");
    let authority_durable = authority.durable.clone();
    let requester_durable = requester.durable.clone();
    let result = leases
        .run(|witness| {
            let authority_storage =
                authority_durable.map_or(NamedServiceAuthorityStorageState::Absent, |encoded| {
                    NamedServiceAuthorityStorageState::Present {
                        encoded,
                        minimum_revision: 0,
                    }
                });
            let authority_state = authority
                .inner
                .reconfirm(witness.authority(), |_| {
                    Ok::<_, HnsrProtocolError>(authority_storage)
                })
                .map_err(|_| HnsrProtocolError::Invalid("authority reconfirmation"))?;
            let current = authority_state
                .bind_current_at(committed, authority_now)
                .map_err(|_| HnsrProtocolError::Invalid("authority current binding"))?;
            let requester_storage =
                requester_durable.map_or(NamedRouteV3RequesterStorageState::Absent, |encoded| {
                    NamedRouteV3RequesterStorageState::Present {
                        encoded,
                        minimum_revision: 0,
                    }
                });
            let mut requester_state = requester
                .inner
                .reconfirm(witness, |_| Ok(requester_storage))?;
            Ok::<_, HnsrProtocolError>(operation(&mut requester_state, &current))
        })
        .expect("current operation scope");
    if !requester.inner.has_pending_persistence() {
        requester.durable = Some(requester.inner.snapshot().encode());
    }
    result
}

fn authority_binding_is_err(
    authority: &mut NamedServiceAuthorityState,
    committed: &CommittedNamedService,
    trusted_now: u64,
) -> bool {
    let key = AuthorityLeaseKey::new(
        StorageNamespaceId::new(AUTHORITY_NAMESPACE).expect("authority namespace"),
        authority.inner.snapshot().network_magic(),
        authority.inner.snapshot().subject(),
    );
    let fence = FencingToken::new(authority.next_fence).expect("fence");
    authority.next_fence += 1;
    let held = HeldAuthorityLease::acquire(key, |_| Ok::<_, ()>(AuthorityTestGuard { key, fence }))
        .expect("authority lease");
    let durable = authority.durable.clone().expect("durable authority");
    held.run(|witness| {
        let state = authority
            .inner
            .reconfirm(witness, |_| {
                Ok::<_, HnsrProtocolError>(NamedServiceAuthorityStorageState::Present {
                    encoded: durable,
                    minimum_revision: 0,
                })
            })
            .map_err(|_| HnsrProtocolError::Invalid("authority reconfirmation"))?;
        Ok::<_, HnsrProtocolError>(state.bind_current_at(committed, trusted_now).is_err())
    })
    .expect("authority binding scope")
}

fn committed_active_authority() -> (NamedServiceAuthorityState, CommittedNamedService) {
    let identity = identity("pool-stats");
    let mut authority =
        NamedServiceAuthorityState::new(MAGIC, identity.name_hash, 1, NOW).expect("authority");
    let mut persist = acknowledge_authority_snapshot;
    let active = authority
        .retrieve_validate_and_observe(
            NOW,
            |retrieval_now| {
                assert_eq!(retrieval_now, NOW);
                Ok::<_, Infallible>(authority_manifest(&identity, "hrm_envelope", 9))
            },
            &identity,
            &service_policy(),
            ValidationLimits::default(),
            &mut persist,
        )
        .expect("committed active service");
    assert!(active.active().is_some());
    (authority, active)
}

fn refresh_active_authority_at(
    authority: &mut NamedServiceAuthorityState,
    trusted_now: u64,
) -> CommittedNamedService {
    let identity = identity("pool-stats");
    let mut persist = acknowledge_authority_snapshot;
    authority
        .retrieve_validate_and_observe(
            trusted_now,
            |retrieval_now| {
                assert_eq!(retrieval_now, trusted_now);
                Ok::<_, Infallible>(authority_manifest(&identity, "hrm_envelope", 9))
            },
            &identity,
            &service_policy(),
            ValidationLimits::default(),
            &mut persist,
        )
        .expect("refreshed committed active service")
}

fn committed_withdrawn_authority() -> (
    NamedServiceAuthorityState,
    CommittedNamedService,
    CommittedNamedService,
) {
    let identity = identity("pool-stats");
    let (mut authority, active) = committed_active_authority();
    let mut persist = acknowledge_authority_snapshot;
    authority
        .retrieve_validate_and_observe(
            NOW,
            |retrieval_now| {
                assert_eq!(retrieval_now, NOW);
                Ok::<_, Infallible>(authority_manifest(
                    &identity,
                    "replacement_hrm_envelope",
                    10,
                ))
            },
            &identity,
            &service_policy(),
            ValidationLimits::default(),
            &mut persist,
        )
        .expect("committed replacement service");
    let withdrawn = authority
        .retrieve_validate_and_observe(
            NOW,
            |retrieval_now| {
                assert_eq!(retrieval_now, NOW);
                Ok::<_, Infallible>(authority_manifest(&identity, "removal_hrm_envelope", 11))
            },
            &identity,
            &service_policy(),
            ValidationLimits::default(),
            &mut persist,
        )
        .expect("committed withdrawn service");
    assert!(withdrawn.is_withdrawn());
    (authority, active, withdrawn)
}

fn verified_service() -> VerifiedNamedService {
    verified_service_for("pool-stats", "hrm_envelope", 9)
}

fn verified_service_for(
    service_name: &str,
    envelope_name: &str,
    sequence: u64,
) -> VerifiedNamedService {
    let identity = identity(service_name);
    let manifest = current_manifest(&identity, envelope_name, sequence);
    observe_named_service(&manifest, &identity, &service_policy(), None)
        .expect("observe service")
        .into_active()
        .expect("active service")
}

fn route() -> NamedRouteRecordV3 {
    NamedRouteRecordV3::decode(&bytes("named_route_record_v3")).expect("route fixture")
}

fn canonical_route(record: &NamedRouteRecordV3) -> Vec<u8> {
    record.encode().expect("canonical route")
}

fn signed_route(
    template: &NamedRouteRecordV3,
    endpoint_sequence: u64,
    route_sequence: u64,
    endpoint_expires_at: u64,
    route_expires_at: u64,
) -> NamedRouteRecordV3 {
    route_for_endpoint(
        template,
        &verified_service(),
        4,
        endpoint_sequence,
        route_sequence,
        endpoint_expires_at,
        route_expires_at,
    )
}

#[allow(clippy::too_many_arguments)]
fn route_for_endpoint(
    template: &NamedRouteRecordV3,
    service: &VerifiedNamedService,
    endpoint_private_byte: u8,
    endpoint_sequence: u64,
    route_sequence: u64,
    endpoint_expires_at: u64,
    route_expires_at: u64,
) -> NamedRouteRecordV3 {
    let endpoint_private = [endpoint_private_byte; 32];
    let endpoint_key = public_key(&endpoint_private).expect("endpoint key");
    let mut endpoint = template.endpoint_delegation.clone();
    endpoint.network_magic = service.identity().network_magic;
    endpoint.service_resource_id = service.resource_id();
    endpoint.service_delegation_id = service.delegation_id();
    endpoint.service_generation = service.service_generation();
    endpoint.endpoint_key = endpoint_key;
    endpoint.endpoint_sequence = endpoint_sequence;
    endpoint.expires_at = endpoint_expires_at;
    endpoint.service_signature.clear();
    endpoint
        .sign_uncommitted(service, NOW, &[3; 32])
        .expect("endpoint delegation");

    let mut ticket = template.tickets[0].clone();
    ticket.network_magic = service.identity().network_magic;
    ticket.profile = service.identity().application_profile_id;
    ticket.endpoint_key = endpoint_key;
    ticket.relay_signature.clear();
    ticket.sign_relay(&[5; 32]).expect("relay signature");
    ticket.endpoint_signature.clear();
    ticket
        .sign_endpoint(&endpoint_private)
        .expect("ticket confirmation");

    let mut candidate = template.clone();
    candidate.route_key = named_route_key_v3(service.identity()).expect("route key");
    candidate.profile_id = service.identity().application_profile_id;
    candidate.record_sequence = route_sequence;
    candidate.expires_at = route_expires_at;
    candidate.service_resource_id = service.resource_id();
    candidate.service_delegation_id = service.delegation_id();
    candidate.service_generation = service.service_generation();
    candidate.service_controller_key = service.service_controller_key();
    candidate.endpoint_delegation = endpoint;
    candidate.tickets = vec![ticket];
    candidate.endpoint_signature.clear();
    candidate.sign(&endpoint_private).expect("route signature");
    candidate
}

#[derive(Default)]
struct CasStore {
    current: Option<NamedRouteV3RequesterSnapshot>,
    calls: usize,
    fail_before_commit: usize,
    commit_then_fail: bool,
}

impl CasStore {
    fn cas(
        &mut self,
        expected: Option<(u64, [u8; 32])>,
        proposed: &NamedRouteV3RequesterSnapshot,
    ) -> Result<(), HnsrProtocolError> {
        self.calls += 1;
        if self.current.as_ref() == Some(proposed) {
            return Ok(());
        }
        let matches = match (expected, self.current.as_ref()) {
            (None, None) => true,
            (Some((revision, fingerprint)), Some(current)) => {
                current.revision() == revision && current.fingerprint() == fingerprint
            }
            _ => false,
        };
        if !matches {
            return Err(HnsrProtocolError::Invalid("test CAS mismatch"));
        }
        if self.fail_before_commit != 0 {
            self.fail_before_commit -= 1;
            return Err(HnsrProtocolError::Invalid("test persistence failure"));
        }
        self.current = Some(proposed.clone());
        if self.commit_then_fail {
            self.commit_then_fail = false;
            return Err(HnsrProtocolError::Invalid("test ambiguous persistence"));
        }
        Ok(())
    }
}

fn initialize(state: &mut NamedRouteV3RequesterState, store: &mut CasStore) {
    assert!(state.has_pending_persistence());
    state
        .persist_pending(|expected, proposed| store.cas(expected, proposed))
        .expect("initialize requester state");
    assert!(!state.has_pending_persistence());
}

fn assert_current_route_guard(
    guard: &CurrentNamedRouteV3<'_>,
    record: &NamedRouteRecordV3,
    authority_revision: u64,
    authority_time: u64,
    requester_revision: u64,
) {
    assert_eq!(guard.record(), record);
    assert_eq!(guard.authority_revision(), authority_revision);
    assert_eq!(guard.authority_trusted_time(), authority_time);
    assert_eq!(guard.requester_revision(), requester_revision);
    assert_eq!(guard.cache_until(), record.expires_at);
    assert_eq!(guard.name_hash(), &guard.service().identity().name_hash);
    assert_eq!(
        guard.service_name(),
        guard.service().identity().service_name
    );
    assert_eq!(
        guard.application_profile_id(),
        guard.service().identity().application_profile_id
    );
    assert_eq!(guard.resource_id(), &record.service_resource_id);
    assert_eq!(guard.route_key(), &record.route_key);
    assert_eq!(
        guard.endpoint_key(),
        &record.endpoint_delegation.endpoint_key
    );
    assert_eq!(
        guard.endpoint_sequence(),
        record.endpoint_delegation.endpoint_sequence
    );
    assert_eq!(
        guard.endpoint_delegation_id(),
        &record.endpoint_delegation.id().expect("endpoint ID")
    );
    assert_eq!(guard.route_sequence(), record.record_sequence);
    assert_eq!(
        guard.route_canonical_hash(),
        &blake2b_256(&[
            b"HNSR-NAMED-V3-CANONICAL-RECORD-V1\0",
            &record.encode().expect("canonical route"),
        ])
    );
}

#[test]
fn fresh_create_and_outcome_ambiguous_cas_retries_are_fail_closed() {
    let service = verified_service();
    let record = route();
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).expect("state");
    let mut store = CasStore {
        fail_before_commit: 1,
        ..CasStore::default()
    };

    assert!(
        state
            .advance_trusted_time_persisted(NOW, |expected, proposed| {
                assert!(expected.is_none());
                store.cas(expected, proposed)
            })
            .is_err()
    );
    assert!(state.has_pending_persistence());
    assert_eq!(state.revision(), 0);
    state
        .advance_trusted_time_persisted(NOW, |expected, proposed| store.cas(expected, proposed))
        .expect("fresh create retry");
    assert!(!state.has_pending_persistence());

    store.fail_before_commit = 2;
    for _ in 0..2 {
        assert!(
            state
                .observe_current_persisted_uncommitted(
                    &record,
                    &service,
                    route_policy(),
                    NOW,
                    |expected, proposed| {
                        assert!(expected.is_some());
                        store.cas(expected, proposed)
                    }
                )
                .is_err()
        );
        assert!(state.has_pending_persistence());
        assert_eq!(state.revision(), 1);
    }
    state
        .observe_current_persisted_uncommitted(
            &record,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        )
        .expect("same-route persistence retry");
    assert!(!state.has_pending_persistence());
    assert_eq!(state.revision(), 1);

    let ambiguous = signed_route(
        &record,
        record.endpoint_delegation.endpoint_sequence,
        record.record_sequence + 1,
        record.endpoint_delegation.expires_at,
        record.expires_at,
    );
    ambiguous
        .verify_current_uncommitted(&service, route_policy(), NOW)
        .unwrap();
    store.commit_then_fail = true;
    assert!(
        state
            .observe_current_persisted_uncommitted(
                &ambiguous,
                &service,
                route_policy(),
                NOW,
                |expected, proposed| store.cas(expected, proposed),
            )
            .is_err()
    );
    assert!(state.has_pending_persistence());
    state
        .observe_current_persisted_uncommitted(
            &ambiguous,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        )
        .expect("already-exact ambiguous retry");
    assert!(!state.has_pending_persistence());

    let mut divergent_store = CasStore {
        current: Some(
            NamedRouteV3RequesterState::new(MAGIC, 32, NOW + 1)
                .unwrap()
                .snapshot(),
        ),
        ..CasStore::default()
    };
    let mut divergent = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    assert!(
        divergent
            .persist_pending(|expected, proposed| divergent_store.cas(expected, proposed))
            .is_err()
    );
    assert!(divergent.has_pending_persistence());
}

#[test]
fn cas_fingerprint_rejects_same_revision_divergent_state() {
    let service = verified_service();
    let record = route();
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);
    state
        .observe_current_persisted_uncommitted(
            &record,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        )
        .unwrap();
    let committed = store.current.clone().unwrap();
    let mut divergent_bytes = committed.encode();
    divergent_bytes[28..36].copy_from_slice(&(NOW + 1).to_le_bytes());
    rechecksum_snapshot(&mut divergent_bytes);
    let divergent = NamedRouteV3RequesterSnapshot::decode(&divergent_bytes).unwrap();
    assert_eq!(divergent.revision(), committed.revision());
    assert_ne!(divergent.fingerprint(), committed.fingerprint());
    store.current = Some(divergent);

    let greater = signed_route(
        &record,
        record.endpoint_delegation.endpoint_sequence,
        record.record_sequence + 1,
        record.endpoint_delegation.expires_at,
        record.expires_at,
    );
    assert!(
        state
            .observe_current_persisted_uncommitted(
                &greater,
                &service,
                route_policy(),
                NOW,
                |expected, proposed| store.cas(expected, proposed),
            )
            .is_err()
    );
    assert!(state.has_pending_persistence());
    assert_eq!(
        store.current.as_ref().unwrap().revision(),
        committed.revision()
    );
}

#[test]
fn endpoint_sequence_precedes_independent_route_sequence_across_restart() {
    let service = verified_service();
    let template = route();
    let endpoint_base = template.endpoint_delegation.endpoint_sequence;
    let route_base = template.record_sequence;
    let endpoint2_route10 = signed_route(
        &template,
        endpoint_base + 2,
        route_base + 10,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    let endpoint3_route9 = signed_route(
        &template,
        endpoint_base + 3,
        route_base + 9,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    let endpoint2_route11 = signed_route(
        &template,
        endpoint_base + 2,
        route_base + 11,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    let endpoint3_route11 = signed_route(
        &template,
        endpoint_base + 3,
        route_base + 11,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    let endpoint3_route12 = signed_route(
        &template,
        endpoint_base + 3,
        route_base + 12,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );

    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);
    state
        .observe_current_persisted_uncommitted(
            &endpoint2_route10,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        )
        .expect("first endpoint/route observation");
    let before_endpoint_advance = state.revision();
    assert!(matches!(
        state.observe_current_persisted_uncommitted(
            &endpoint3_route9,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));
    assert!(state.revision() > before_endpoint_advance);
    assert_eq!(store.current.as_ref().unwrap(), &state.snapshot());

    let snapshot =
        NamedRouteV3RequesterSnapshot::decode(&store.current.as_ref().expect("stored").encode())
            .expect("snapshot");
    let revision = snapshot.revision();
    let mut restarted =
        NamedRouteV3RequesterState::restore(MAGIC, 32, snapshot, revision, NOW).unwrap();
    let before_stale_endpoint_route_advance = restarted.revision();
    assert!(matches!(
        restarted.observe_current_persisted_uncommitted(
            &endpoint2_route11,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));
    assert!(restarted.revision() > before_stale_endpoint_route_advance);
    assert!(matches!(
        restarted.observe_current_persisted_uncommitted(
            &endpoint3_route11,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    restarted
        .observe_current_persisted_uncommitted(
            &endpoint3_route12,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        )
        .expect("greater route under selected endpoint clears route conflict");
}

#[test]
fn endpoint_and_route_conflicts_are_independent_deterministic_tombstones() {
    let service = verified_service();
    let template = route();
    let endpoint_sequence = template.endpoint_delegation.endpoint_sequence + 1;
    let route_sequence = template.record_sequence + 1;
    let first = signed_route(
        &template,
        endpoint_sequence,
        route_sequence,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    let endpoint_conflict = signed_route(
        &template,
        endpoint_sequence,
        route_sequence + 100,
        template.endpoint_delegation.expires_at - 1,
        template.expires_at,
    );
    let endpoint_recovery_same_route = signed_route(
        &template,
        endpoint_sequence + 1,
        route_sequence + 100,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    let route_recovery = signed_route(
        &template,
        endpoint_sequence + 1,
        route_sequence + 101,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );

    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);
    state
        .observe_current_persisted_uncommitted(
            &first,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        )
        .unwrap();
    assert!(matches!(
        state.observe_current_persisted_uncommitted(
            &endpoint_conflict,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    let endpoint_tombstone = state.snapshot().encode();
    assert_eq!(endpoint_tombstone[SNAPSHOT_HEADER_SIZE + 203], 1);
    assert_eq!(
        &endpoint_tombstone[SNAPSHOT_HEADER_SIZE + 204..SNAPSHOT_HEADER_SIZE + 236],
        &[0; 32]
    );
    NamedRouteV3RequesterSnapshot::decode(&endpoint_tombstone).unwrap();
    let mut poisoned_endpoint_tombstone = endpoint_tombstone.clone();
    poisoned_endpoint_tombstone[SNAPSHOT_HEADER_SIZE + 204] = 1;
    rechecksum_snapshot(&mut poisoned_endpoint_tombstone);
    assert!(matches!(
        NamedRouteV3RequesterSnapshot::decode(&poisoned_endpoint_tombstone),
        Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)
    ));

    assert!(matches!(
        state.observe_current_persisted_uncommitted(
            &endpoint_recovery_same_route,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    let route_tombstone = state.snapshot().encode();
    assert_eq!(route_tombstone[SNAPSHOT_HEADER_SIZE + 203], 0);
    assert_eq!(route_tombstone[SNAPSHOT_HEADER_SIZE + 244], 1);
    assert_eq!(
        &route_tombstone[SNAPSHOT_HEADER_SIZE + 245..SNAPSHOT_HEADER_SIZE + 277],
        &[0; 32]
    );
    NamedRouteV3RequesterSnapshot::decode(&route_tombstone).unwrap();
    let mut poisoned_route_tombstone = route_tombstone.clone();
    poisoned_route_tombstone[SNAPSHOT_HEADER_SIZE + 245] = 1;
    rechecksum_snapshot(&mut poisoned_route_tombstone);
    assert!(matches!(
        NamedRouteV3RequesterSnapshot::decode(&poisoned_route_tombstone),
        Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)
    ));
    state
        .observe_current_persisted_uncommitted(
            &route_recovery,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        )
        .expect("greater route clears route conflict");
}

#[test]
fn batch_product_maxima_must_be_realized_by_one_exact_route() {
    let service = verified_service();
    let template = route();
    let endpoint_base = template.endpoint_delegation.endpoint_sequence;
    let route_base = template.record_sequence;
    let old_endpoint_high_route = signed_route(
        &template,
        endpoint_base + 1,
        route_base + 100,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    let new_endpoint_low_route = signed_route(
        &template,
        endpoint_base + 2,
        route_base + 10,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    let coherent_recovery = signed_route(
        &template,
        endpoint_base + 2,
        route_base + 101,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    let endpoint_key = template.endpoint_delegation.endpoint_key;

    assert!(matches!(
        select_named_route_v3_uncommitted(
            [&old_endpoint_high_route, &new_endpoint_low_route],
            &endpoint_key,
            &service,
            route_policy(),
            NOW,
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));

    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);
    assert!(matches!(
        state.select_and_observe_current_persisted_uncommitted(
            [&old_endpoint_high_route, &new_endpoint_low_route],
            &endpoint_key,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));
    let product_snapshot = state.snapshot();

    let mut reversed_batch = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut reversed_store = CasStore::default();
    initialize(&mut reversed_batch, &mut reversed_store);
    assert!(matches!(
        reversed_batch.select_and_observe_current_persisted_uncommitted(
            [&new_endpoint_low_route, &old_endpoint_high_route],
            &endpoint_key,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| reversed_store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));

    let mut endpoint_then_route = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut endpoint_then_route_store = CasStore::default();
    initialize(&mut endpoint_then_route, &mut endpoint_then_route_store);
    endpoint_then_route
        .observe_current_persisted_uncommitted(
            &new_endpoint_low_route,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| endpoint_then_route_store.cas(expected, proposed),
        )
        .unwrap();
    assert!(matches!(
        endpoint_then_route.observe_current_persisted_uncommitted(
            &old_endpoint_high_route,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| endpoint_then_route_store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));

    let mut route_then_endpoint = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut route_then_endpoint_store = CasStore::default();
    initialize(&mut route_then_endpoint, &mut route_then_endpoint_store);
    route_then_endpoint
        .observe_current_persisted_uncommitted(
            &old_endpoint_high_route,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| route_then_endpoint_store.cas(expected, proposed),
        )
        .unwrap();
    assert!(matches!(
        route_then_endpoint.observe_current_persisted_uncommitted(
            &new_endpoint_low_route,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| route_then_endpoint_store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));

    let expected = normalized_snapshot(&product_snapshot);
    for snapshot in [
        reversed_batch.snapshot(),
        endpoint_then_route.snapshot(),
        route_then_endpoint.snapshot(),
    ] {
        assert_eq!(normalized_snapshot(&snapshot), expected);
    }
    let restarted = NamedRouteV3RequesterState::restore(
        MAGIC,
        32,
        NamedRouteV3RequesterSnapshot::decode(&product_snapshot.encode()).unwrap(),
        product_snapshot.revision(),
        NOW,
    )
    .unwrap();
    assert_eq!(normalized_snapshot(&restarted.snapshot()), expected);

    let selected = state
        .select_and_observe_current_persisted_uncommitted(
            [&coherent_recovery],
            &endpoint_key,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        )
        .expect("one route realizes both product maxima");
    assert_eq!(selected.record(), &coherent_recovery);
}

#[test]
fn time_only_empty_and_expired_batches_prevent_revival_after_restart() {
    let service = verified_service();
    let record = route();
    let endpoint_key = record.endpoint_delegation.endpoint_key;
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);
    state
        .select_and_observe_current_persisted_uncommitted(
            [&record],
            &endpoint_key,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        )
        .expect("active route");

    let before_empty = state.revision();
    assert!(
        state
            .select_and_observe_current_persisted_uncommitted(
                std::iter::empty(),
                &endpoint_key,
                &service,
                route_policy(),
                record.expires_at - 1,
                |expected, proposed| store.cas(expected, proposed),
            )
            .is_err()
    );
    assert!(state.revision() > before_empty);
    assert_eq!(state.trusted_time_high_water(), record.expires_at - 1);
    assert!(
        state
            .select_and_observe_current_persisted_uncommitted(
                [&record],
                &endpoint_key,
                &service,
                route_policy(),
                record.expires_at,
                |expected, proposed| store.cas(expected, proposed),
            )
            .is_err()
    );
    assert_eq!(state.trusted_time_high_water(), record.expires_at);

    let snapshot = store.current.clone().unwrap();
    let revision = snapshot.revision();
    assert!(matches!(
        NamedRouteV3RequesterState::restore(
            MAGIC,
            32,
            snapshot.clone(),
            revision,
            record.expires_at - 1,
        ),
        Err(HnsrProtocolError::ClockRollback)
    ));
    let mut restarted =
        NamedRouteV3RequesterState::restore(MAGIC, 32, snapshot, revision, record.expires_at)
            .unwrap();
    assert!(matches!(
        restarted.observe_current_persisted_uncommitted(
            &record,
            &service,
            route_policy(),
            record.expires_at - 1,
            |expected, proposed| store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::ClockRollback)
    ));

    store.fail_before_commit = 1;
    assert!(
        restarted
            .select_and_observe_current_persisted_uncommitted(
                std::iter::empty(),
                &endpoint_key,
                &service,
                route_policy(),
                record.expires_at + 1,
                |expected, proposed| store.cas(expected, proposed),
            )
            .is_err()
    );
    assert!(restarted.has_pending_persistence());
    assert!(
        restarted
            .select_and_observe_current_persisted_uncommitted(
                std::iter::empty(),
                &endpoint_key,
                &service,
                route_policy(),
                record.expires_at + 1,
                |expected, proposed| store.cas(expected, proposed),
            )
            .is_err()
    );
    assert!(!restarted.has_pending_persistence());
}

#[test]
fn single_observe_persists_time_before_stale_invalid_and_expired_results() {
    let service = verified_service();
    let record = route();
    let greater = signed_route(
        &record,
        record.endpoint_delegation.endpoint_sequence,
        record.record_sequence + 1,
        record.endpoint_delegation.expires_at,
        record.expires_at,
    );
    let mut invalid = signed_route(
        &record,
        record.endpoint_delegation.endpoint_sequence,
        record.record_sequence + 2,
        record.endpoint_delegation.expires_at,
        record.expires_at,
    );
    invalid.endpoint_signature[10] ^= 1;
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);
    state
        .observe_current_persisted_uncommitted(
            &greater,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        )
        .unwrap();

    assert!(matches!(
        state.observe_current_persisted_uncommitted(
            &record,
            &service,
            route_policy(),
            NOW + 1,
            |expected, proposed| store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));
    assert_eq!(state.trusted_time_high_water(), NOW + 1);
    assert!(
        state
            .observe_current_persisted_uncommitted(
                &invalid,
                &service,
                route_policy(),
                NOW + 2,
                |expected, proposed| store.cas(expected, proposed),
            )
            .is_err()
    );
    assert_eq!(state.trusted_time_high_water(), NOW + 2);
    assert!(
        state
            .observe_current_persisted_uncommitted(
                &record,
                &service,
                route_policy(),
                record.expires_at,
                |expected, proposed| store.cas(expected, proposed),
            )
            .is_err()
    );
    assert_eq!(state.trusted_time_high_water(), record.expires_at);

    let snapshot = store.current.clone().unwrap();
    assert!(matches!(
        NamedRouteV3RequesterState::restore(
            MAGIC,
            32,
            snapshot.clone(),
            snapshot.revision(),
            record.expires_at - 1,
        ),
        Err(HnsrProtocolError::ClockRollback)
    ));

    let mut wrong_network_state = NamedRouteV3RequesterState::new(MAGIC - 1, 4, NOW).unwrap();
    let mut wrong_network_store = CasStore::default();
    initialize(&mut wrong_network_state, &mut wrong_network_store);
    assert!(
        wrong_network_state
            .observe_current_persisted_uncommitted(
                &record,
                &service,
                route_policy(),
                NOW + 3,
                |expected, proposed| wrong_network_store.cas(expected, proposed),
            )
            .is_err()
    );
    assert_eq!(wrong_network_state.trusted_time_high_water(), NOW + 3);
    assert_eq!(
        wrong_network_store
            .current
            .as_ref()
            .unwrap()
            .trusted_time_high_water(),
        NOW + 3
    );
}

#[test]
fn snapshot_is_canonical_bound_and_strictly_restored() {
    let service = verified_service();
    let template = route();
    let first = route_for_endpoint(
        &template,
        &service,
        7,
        template.endpoint_delegation.endpoint_sequence + 1,
        template.record_sequence + 1,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    let second = route_for_endpoint(
        &template,
        &service,
        8,
        template.endpoint_delegation.endpoint_sequence + 1,
        template.record_sequence + 1,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 4, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);
    for candidate in [&first, &second] {
        state
            .observe_current_persisted_uncommitted(
                candidate,
                &service,
                route_policy(),
                NOW,
                |expected, proposed| store.cas(expected, proposed),
            )
            .unwrap();
    }
    let snapshot = state.snapshot();
    let encoded = snapshot.encode();
    assert_eq!(
        encoded.len(),
        SNAPSHOT_HEADER_SIZE + 2 * SNAPSHOT_ENTRY_SIZE + 32
    );
    assert_eq!(
        NamedRouteV3RequesterSnapshot::decode(&encoded).unwrap(),
        snapshot
    );

    let mut corrupt = encoded.clone();
    corrupt[SNAPSHOT_HEADER_SIZE + 10] ^= 1;
    assert!(matches!(
        NamedRouteV3RequesterSnapshot::decode(&corrupt),
        Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)
    ));

    let mut reserved = encoded.clone();
    reserved[9] = 1;
    rechecksum_snapshot(&mut reserved);
    assert!(matches!(
        NamedRouteV3RequesterSnapshot::decode(&reserved),
        Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)
    ));

    let mut wrong_network = encoded.clone();
    wrong_network[12..16].copy_from_slice(&(MAGIC - 1).to_le_bytes());
    rechecksum_snapshot(&mut wrong_network);
    assert!(matches!(
        NamedRouteV3RequesterSnapshot::decode(&wrong_network),
        Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)
    ));
    let other_network = NamedRouteV3RequesterState::new(MAGIC - 1, 4, NOW)
        .unwrap()
        .snapshot();
    assert!(matches!(
        NamedRouteV3RequesterState::restore(MAGIC, 4, other_network, 0, NOW),
        Err(HnsrProtocolError::IncompatibleNamedRouteRequesterSnapshot)
    ));

    let mut wrong_capacity = encoded.clone();
    wrong_capacity[16..20].copy_from_slice(&3_u32.to_le_bytes());
    rechecksum_snapshot(&mut wrong_capacity);
    let wrong_capacity = NamedRouteV3RequesterSnapshot::decode(&wrong_capacity).unwrap();
    assert!(matches!(
        NamedRouteV3RequesterState::restore(MAGIC, 4, wrong_capacity, 0, NOW),
        Err(HnsrProtocolError::IncompatibleNamedRouteRequesterSnapshot)
    ));
    let mut undersized_capacity = encoded.clone();
    undersized_capacity[16..20].copy_from_slice(&1_u32.to_le_bytes());
    rechecksum_snapshot(&mut undersized_capacity);
    assert!(matches!(
        NamedRouteV3RequesterSnapshot::decode(&undersized_capacity),
        Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)
    ));

    let mut exhausted_revision = encoded.clone();
    exhausted_revision[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
    rechecksum_snapshot(&mut exhausted_revision);
    assert!(matches!(
        NamedRouteV3RequesterSnapshot::decode(&exhausted_revision),
        Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)
    ));
    let mut unreachable_revision = encoded.clone();
    unreachable_revision[20..28].copy_from_slice(&1_u64.to_le_bytes());
    rechecksum_snapshot(&mut unreachable_revision);
    assert!(matches!(
        NamedRouteV3RequesterSnapshot::decode(&unreachable_revision),
        Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)
    ));

    let mut zero_route_floor = encoded.clone();
    zero_route_floor[SNAPSHOT_HEADER_SIZE + 236..SNAPSHOT_HEADER_SIZE + 244].fill(0);
    zero_route_floor[SNAPSHOT_HEADER_SIZE + 244] = 0;
    zero_route_floor[SNAPSHOT_HEADER_SIZE + 245..SNAPSHOT_HEADER_SIZE + 277].fill(0);
    rechecksum_snapshot(&mut zero_route_floor);
    assert!(matches!(
        NamedRouteV3RequesterSnapshot::decode(&zero_route_floor),
        Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)
    ));

    assert!(matches!(
        NamedRouteV3RequesterState::restore(
            MAGIC,
            4,
            snapshot.clone(),
            snapshot.revision() + 1,
            NOW,
        ),
        Err(HnsrProtocolError::IncompatibleNamedRouteRequesterSnapshot)
    ));

    let mut wrong_identity = encoded.clone();
    wrong_identity[SNAPSHOT_HEADER_SIZE + 33] ^= 1;
    rechecksum_snapshot(&mut wrong_identity);
    assert!(matches!(
        NamedRouteV3RequesterSnapshot::decode(&wrong_identity),
        Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)
    ));

    let mut unsorted = encoded.clone();
    let entries_end = SNAPSHOT_HEADER_SIZE + 2 * SNAPSHOT_ENTRY_SIZE;
    let mut entries = unsorted[SNAPSHOT_HEADER_SIZE..entries_end].to_vec();
    entries.rotate_left(SNAPSHOT_ENTRY_SIZE);
    unsorted[SNAPSHOT_HEADER_SIZE..entries_end].copy_from_slice(&entries);
    rechecksum_snapshot(&mut unsorted);
    assert!(matches!(
        NamedRouteV3RequesterSnapshot::decode(&unsorted),
        Err(HnsrProtocolError::CorruptNamedRouteRequesterSnapshot)
    ));

    let max_time = NamedRouteV3RequesterState::new(MAGIC, 1, u64::MAX)
        .unwrap()
        .snapshot();
    let decoded = NamedRouteV3RequesterSnapshot::decode(&max_time.encode()).unwrap();
    assert_eq!(decoded.trusted_time_high_water(), u64::MAX);
    assert!(matches!(
        NamedRouteV3RequesterState::restore(MAGIC, 1, decoded, 0, u64::MAX - 1),
        Err(HnsrProtocolError::ClockRollback)
    ));
}

#[test]
fn per_origin_endpoint_cap_preserves_room_for_another_origin() {
    let service = verified_service();
    let other_service = verified_service_for(
        "other-service",
        "wrong_identity_service_name_hrm_envelope",
        10,
    );
    let template = route();
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 17, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);

    for offset in 0..16_u8 {
        let candidate = route_for_endpoint(
            &template,
            &service,
            7 + offset,
            template.endpoint_delegation.endpoint_sequence + 1,
            template.record_sequence + 1,
            template.endpoint_delegation.expires_at,
            template.expires_at,
        );
        state
            .observe_current_persisted_uncommitted(
                &candidate,
                &service,
                route_policy(),
                NOW,
                |expected, proposed| store.cas(expected, proposed),
            )
            .unwrap();
    }
    let seventeenth_same_origin = route_for_endpoint(
        &template,
        &service,
        23,
        template.endpoint_delegation.endpoint_sequence + 1,
        template.record_sequence + 1,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    assert!(matches!(
        state.observe_current_persisted_uncommitted(
            &seventeenth_same_origin,
            &service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        ),
        Err(HnsrProtocolError::Capacity)
    ));
    assert_eq!(state.len(), 16);

    let other_origin = route_for_endpoint(
        &template,
        &other_service,
        24,
        template.endpoint_delegation.endpoint_sequence + 1,
        template.record_sequence + 1,
        template.endpoint_delegation.expires_at,
        template.expires_at,
    );
    state
        .observe_current_persisted_uncommitted(
            &other_origin,
            &other_service,
            route_policy(),
            NOW,
            |expected, proposed| store.cas(expected, proposed),
        )
        .expect("other origin retains one global slot");
    assert_eq!(state.len(), 17);
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::thread::yield_now();
    }
}

struct RawRouteProbe {
    bytes: Vec<u8>,
    reads: Rc<Cell<usize>>,
}

impl AsRef<[u8]> for RawRouteProbe {
    fn as_ref(&self) -> &[u8] {
        self.reads.set(self.reads.get() + 1);
        &self.bytes
    }
}

struct RawBatchProbe {
    candidates: Vec<RawRouteProbe>,
    iterations: Rc<Cell<usize>>,
}

impl IntoIterator for RawBatchProbe {
    type Item = RawRouteProbe;
    type IntoIter = std::vec::IntoIter<RawRouteProbe>;

    fn into_iter(self) -> Self::IntoIter {
        self.iterations.set(self.iterations.get() + 1);
        self.candidates.into_iter()
    }
}

struct GatedCasFuture {
    gate: Arc<AtomicBool>,
    store: Rc<RefCell<CasStore>>,
    expected: Option<(u64, [u8; 32])>,
    proposed: Option<NamedRouteV3RequesterSnapshot>,
}

struct SequencedGatedCasFuture {
    permitted: Arc<AtomicUsize>,
    ordinal: usize,
    store: Rc<RefCell<CasStore>>,
    expected: Option<(u64, [u8; 32])>,
    proposed: Option<NamedRouteV3RequesterSnapshot>,
}

impl Future for SequencedGatedCasFuture {
    type Output = Result<(), HnsrProtocolError>;

    fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.permitted.load(Ordering::SeqCst) < self.ordinal {
            return Poll::Pending;
        }
        let proposed = self.proposed.take().expect("polled after completion");
        Poll::Ready(self.store.borrow_mut().cas(self.expected, &proposed))
    }
}

impl Future for GatedCasFuture {
    type Output = Result<(), HnsrProtocolError>;

    fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.gate.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        let proposed = self.proposed.take().expect("polled after completion");
        Poll::Ready(self.store.borrow_mut().cas(self.expected, &proposed))
    }
}

#[test]
fn async_selector_withholds_result_until_owned_snapshot_cas_is_acknowledged() {
    let service = verified_service();
    let record = route();
    let endpoint_key = record.endpoint_delegation.endpoint_key;
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let store = Rc::new(RefCell::new(CasStore::default()));
    let gate = Arc::new(AtomicBool::new(false));
    let callback_store = Rc::clone(&store);
    let callback_gate = Arc::clone(&gate);
    let mut operation = Box::pin(
        state.select_and_observe_current_persisted_uncommitted_async(
            [&record],
            &endpoint_key,
            &service,
            route_policy(),
            NOW,
            move |expected, proposed| GatedCasFuture {
                gate: Arc::clone(&callback_gate),
                store: Rc::clone(&callback_store),
                expected,
                proposed: Some(proposed),
            },
        ),
    );
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    assert!(matches!(
        operation.as_mut().poll(&mut context),
        Poll::Pending
    ));
    assert!(store.borrow().current.is_none());
    gate.store(true, Ordering::SeqCst);
    let result = loop {
        if let Poll::Ready(result) = operation.as_mut().poll(&mut context) {
            break result;
        }
    };
    assert_eq!(result.expect("awaited route").record(), &record);
    drop(operation);
    assert!(!state.has_pending_persistence());
    assert_eq!(store.borrow().current.as_ref().unwrap(), &state.snapshot());
}

#[test]
fn async_callback_failure_remains_pending_until_exact_retry_acknowledges() {
    let service = verified_service();
    let record = route();
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut initial_store = CasStore::default();
    initialize(&mut state, &mut initial_store);
    initial_store.fail_before_commit = 1;
    let store = Rc::new(RefCell::new(initial_store));

    let failing_store = Rc::clone(&store);
    let result = block_on(state.observe_current_persisted_uncommitted_async(
        &record,
        &service,
        route_policy(),
        NOW,
        move |expected, proposed| {
            std::future::ready(failing_store.borrow_mut().cas(expected, &proposed))
        },
    ));
    assert!(result.is_err());
    assert!(state.has_pending_persistence());
    assert_eq!(state.revision(), 1);
    assert_eq!(store.borrow().current.as_ref().unwrap().revision(), 0);

    let retry_store = Rc::clone(&store);
    let verified = block_on(state.observe_current_persisted_uncommitted_async(
        &record,
        &service,
        route_policy(),
        NOW,
        move |expected, proposed| {
            std::future::ready(retry_store.borrow_mut().cas(expected, &proposed))
        },
    ))
    .expect("async exact CAS retry");
    assert_eq!(verified.record(), &record);
    assert!(!state.has_pending_persistence());
    assert_eq!(store.borrow().current.as_ref().unwrap(), &state.snapshot());
}

#[test]
fn production_time_cas_failure_prevents_raw_batch_iteration_and_decode() {
    let (mut authority, committed) = committed_active_authority();
    let record = route();
    let endpoint_key = record.endpoint_delegation.endpoint_key;
    let iterations = Rc::new(Cell::new(0));
    let reads = Rc::new(Cell::new(0));
    let retrievals = Rc::new(Cell::new(0));
    let batch = RawBatchProbe {
        candidates: vec![RawRouteProbe {
            bytes: vec![0xff],
            reads: Rc::clone(&reads),
        }],
        iterations: Rc::clone(&iterations),
    };
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);
    store.fail_before_commit = 1;

    let result = with_current_operation(
        &mut authority,
        &committed,
        NOW,
        &mut state,
        |state, current| {
            infallible_requester_operation(state.retrieve_select_and_observe_current_persisted(
                NOW + 1,
                |_| {
                    retrievals.set(retrievals.get() + 1);
                    Ok::<_, Infallible>(batch)
                },
                &endpoint_key,
                current,
                route_policy(),
                |expected, proposed| store.cas(legacy_requester_expectation(expected), proposed),
            ))
            .map(|_| ())
        },
    );

    assert!(matches!(
        result,
        Err(HnsrProtocolError::Invalid("test persistence failure"))
    ));
    assert_eq!(retrievals.get(), 0, "retrieval must not start before T CAS");
    assert_eq!(iterations.get(), 0, "raw batch iterator must remain opaque");
    assert_eq!(reads.get(), 0, "candidate bytes must not reach the decoder");
    assert_eq!(state.trusted_time_high_water(), NOW + 1);
    assert!(state.has_pending_persistence());
    assert_eq!(
        store.current.as_ref().unwrap().trusted_time_high_water(),
        NOW
    );
}

#[test]
fn unavailable_sync_retrieval_leaves_requester_time_durable_without_a_route() {
    let record = route();
    let endpoint_key = record.endpoint_delegation.endpoint_key;
    let (mut authority, _) = committed_active_authority();
    let committed = refresh_active_authority_at(&mut authority, NOW + 1);
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);
    let retrievals = Rc::new(Cell::new(0));

    let result = with_current_operation(
        &mut authority,
        &committed,
        NOW + 1,
        &mut state,
        |state, current| {
            state
                .retrieve_select_and_observe_current_persisted(
                    NOW + 1,
                    |retrieval_now| {
                        assert_eq!(retrieval_now, NOW + 1);
                        retrievals.set(retrievals.get() + 1);
                        Err::<[Vec<u8>; 0], _>("route lookup unavailable")
                    },
                    &endpoint_key,
                    current,
                    route_policy(),
                    |expected, proposed| {
                        store.cas(legacy_requester_expectation(expected), proposed)
                    },
                )
                .map(|_| ())
        },
    );

    assert!(matches!(
        result,
        Err(NamedRouteV3RequesterOperationError::Retrieval(
            "route lookup unavailable"
        ))
    ));
    assert_eq!(retrievals.get(), 1);
    assert_eq!(state.trusted_time_high_water(), NOW + 1);
    assert_eq!(state.revision(), 1);
    assert_eq!(state.len(), 0);
    assert!(!state.has_pending_persistence());
    assert_eq!(store.current.as_ref().unwrap(), &state.snapshot());
}

#[test]
fn async_time_cas_failure_blocks_task_local_retrieval_future_creation() {
    let record = route();
    let endpoint_key = record.endpoint_delegation.endpoint_key;
    let (mut authority, committed) = committed_active_authority();
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut initial_store = CasStore::default();
    initialize(&mut state, &mut initial_store);
    initial_store.fail_before_commit = 1;
    let store = Rc::new(RefCell::new(initial_store));
    let retrievals = Rc::new(Cell::new(0));

    let result = with_current_operation(
        &mut authority,
        &committed,
        NOW,
        &mut state,
        |state, current| {
            let callback_store = Rc::clone(&store);
            let retrieval_count = Rc::clone(&retrievals);
            infallible_requester_operation(block_on(
                state.retrieve_select_and_observe_current_persisted_async(
                    NOW + 1,
                    move |_| {
                        retrieval_count.set(retrieval_count.get() + 1);
                        std::future::ready(Ok::<[Vec<u8>; 0], Infallible>([]))
                    },
                    &endpoint_key,
                    current,
                    route_policy(),
                    move |expected, proposed| {
                        std::future::ready(
                            callback_store
                                .borrow_mut()
                                .cas(legacy_requester_expectation(expected), &proposed),
                        )
                    },
                ),
            ))
            .map(|_| ())
        },
    );

    assert!(matches!(
        result,
        Err(HnsrProtocolError::Invalid("test persistence failure"))
    ));
    assert_eq!(retrievals.get(), 0);
    assert_eq!(state.trusted_time_high_water(), NOW + 1);
    assert!(state.has_pending_persistence());
    assert_eq!(
        store
            .borrow()
            .current
            .as_ref()
            .unwrap()
            .trusted_time_high_water(),
        NOW
    );
}

#[test]
fn unavailable_async_non_send_retrieval_retains_durable_time() {
    let record = route();
    let endpoint_key = record.endpoint_delegation.endpoint_key;
    let (mut authority, _) = committed_active_authority();
    let committed = refresh_active_authority_at(&mut authority, NOW + 1);
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut initial_store = CasStore::default();
    initialize(&mut state, &mut initial_store);
    let store = Rc::new(RefCell::new(initial_store));
    let retrievals = Rc::new(Cell::new(0));

    let result = with_current_operation(
        &mut authority,
        &committed,
        NOW + 1,
        &mut state,
        |state, current| {
            let callback_store = Rc::clone(&store);
            let retrieval_count = Rc::clone(&retrievals);
            block_on(state.retrieve_select_and_observe_current_persisted_async(
                NOW + 1,
                move |retrieval_now| async move {
                    assert_eq!(retrieval_now, NOW + 1);
                    retrieval_count.set(retrieval_count.get() + 1);
                    Err::<[Vec<u8>; 0], _>("async route lookup unavailable")
                },
                &endpoint_key,
                current,
                route_policy(),
                move |expected, proposed| {
                    std::future::ready(
                        callback_store
                            .borrow_mut()
                            .cas(legacy_requester_expectation(expected), &proposed),
                    )
                },
            ))
            .map(|_| ())
        },
    );

    assert!(matches!(
        result,
        Err(NamedRouteV3RequesterOperationError::Retrieval(
            "async route lookup unavailable"
        ))
    ));
    assert_eq!(retrievals.get(), 1);
    assert_eq!(state.trusted_time_high_water(), NOW + 1);
    assert_eq!(state.revision(), 1);
    assert_eq!(state.len(), 0);
    assert_eq!(store.borrow().current.as_ref().unwrap(), &state.snapshot());
}

#[test]
fn raw_batch_early_errors_and_all_expired_results_have_durable_time() {
    let template = route();
    let endpoint_key = template.endpoint_delegation.endpoint_key;
    let expired = signed_route(
        &template,
        template.endpoint_delegation.endpoint_sequence,
        template.record_sequence,
        template.endpoint_delegation.expires_at,
        NOW + 1,
    );
    let canonical = canonical_route(&template);
    let cases = vec![
        ("malformed", vec![vec![0xff]]),
        ("oversized-record", vec![vec![0; MAX_RECORD_SIZE + 1]]),
        ("empty", Vec::new()),
        ("oversized-batch", vec![canonical; MAX_RECORDS_PER_KEY + 1]),
        ("all-expired", vec![canonical_route(&expired)]),
    ];

    for (case, batch) in cases {
        let (mut authority, _) = committed_active_authority();
        let committed = refresh_active_authority_at(&mut authority, NOW + 1);
        let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
        let mut store = CasStore::default();
        initialize(&mut state, &mut store);

        let result = with_current_operation(
            &mut authority,
            &committed,
            NOW + 1,
            &mut state,
            |state, current| {
                infallible_requester_operation(state.retrieve_select_and_observe_current_persisted(
                    NOW + 1,
                    |_| Ok::<_, Infallible>(batch),
                    &endpoint_key,
                    current,
                    route_policy(),
                    |expected, proposed| {
                        store.cas(legacy_requester_expectation(expected), proposed)
                    },
                ))
                .map(|_| ())
            },
        );

        assert!(result.is_err(), "{case} must fail closed");
        assert_eq!(state.trusted_time_high_water(), NOW + 1, "{case}");
        assert_eq!(state.revision(), 1, "{case}");
        assert!(!state.has_pending_persistence(), "{case}");
        assert_eq!(store.calls, 2, "{case}");
        assert_eq!(store.current.as_ref().unwrap(), &state.snapshot(), "{case}");
    }
}

#[test]
fn async_production_selector_awaits_time_before_decode_and_withholds_until_observation_cas() {
    let record = route();
    let endpoint_key = record.endpoint_delegation.endpoint_key;
    let (mut authority, _) = committed_active_authority();
    let committed = refresh_active_authority_at(&mut authority, NOW + 1);
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut initial_store = CasStore::default();
    initialize(&mut state, &mut initial_store);
    let store = Rc::new(RefCell::new(initial_store));
    let permitted = Arc::new(AtomicUsize::new(0));
    let callback_count = Arc::new(AtomicUsize::new(0));
    let retrievals = Rc::new(Cell::new(0));
    let iterations = Rc::new(Cell::new(0));
    let reads = Rc::new(Cell::new(0));

    with_current_operation(
        &mut authority,
        &committed,
        NOW + 1,
        &mut state,
        |state, current| {
            let callback_store = Rc::clone(&store);
            let callback_permitted = Arc::clone(&permitted);
            let callback_count_inner = Arc::clone(&callback_count);
            let retrieval_record = record.clone();
            let retrieval_reads = Rc::clone(&reads);
            let retrieval_iterations = Rc::clone(&iterations);
            let retrieval_count = Rc::clone(&retrievals);
            let mut operation =
                Box::pin(state.retrieve_select_and_observe_current_persisted_async(
                    NOW + 1,
                    move |retrieval_now| {
                        assert_eq!(retrieval_now, NOW + 1);
                        retrieval_count.set(retrieval_count.get() + 1);
                        let batch = RawBatchProbe {
                            candidates: vec![RawRouteProbe {
                                bytes: canonical_route(&retrieval_record),
                                reads: Rc::clone(&retrieval_reads),
                            }],
                            iterations: Rc::clone(&retrieval_iterations),
                        };
                        std::future::ready(Ok::<_, Infallible>(batch))
                    },
                    &endpoint_key,
                    current,
                    route_policy(),
                    move |expected, proposed| {
                        let ordinal = callback_count_inner.fetch_add(1, Ordering::SeqCst) + 1;
                        SequencedGatedCasFuture {
                            permitted: Arc::clone(&callback_permitted),
                            ordinal,
                            store: Rc::clone(&callback_store),
                            expected: legacy_requester_expectation(expected),
                            proposed: Some(proposed),
                        }
                    },
                ));
            let waker = Waker::from(Arc::new(NoopWake));
            let mut context = Context::from_waker(&waker);

            assert!(matches!(
                operation.as_mut().poll(&mut context),
                Poll::Pending
            ));
            assert_eq!(callback_count.load(Ordering::SeqCst), 1);
            assert_eq!(retrievals.get(), 0);
            assert_eq!(iterations.get(), 0);
            assert_eq!(reads.get(), 0);
            assert_eq!(
                store
                    .borrow()
                    .current
                    .as_ref()
                    .unwrap()
                    .trusted_time_high_water(),
                NOW
            );

            permitted.store(1, Ordering::SeqCst);
            assert!(matches!(
                operation.as_mut().poll(&mut context),
                Poll::Pending
            ));
            assert_eq!(callback_count.load(Ordering::SeqCst), 2);
            assert_eq!(retrievals.get(), 1);
            assert_eq!(iterations.get(), 1);
            assert_eq!(reads.get(), 1);
            assert_eq!(
                store
                    .borrow()
                    .current
                    .as_ref()
                    .unwrap()
                    .trusted_time_high_water(),
                NOW + 1
            );
            assert_eq!(store.borrow().current.as_ref().unwrap().revision(), 1);

            permitted.store(2, Ordering::SeqCst);
            let selected = match operation.as_mut().poll(&mut context) {
                Poll::Ready(result) => infallible_requester_operation(result)
                    .expect("fully acknowledged current route"),
                Poll::Pending => panic!("route remained withheld after both acknowledgements"),
            };
            assert_current_route_guard(
                &selected,
                &record,
                current.authority_revision(),
                NOW + 1,
                2,
            );
        },
    );
    assert_eq!(store.borrow().current.as_ref().unwrap(), &state.snapshot());
}

#[test]
fn committed_authority_batch_selectors_release_active_routes_after_sync_and_async_cas() {
    let (mut authority, committed) = committed_active_authority();
    let record = route();
    let endpoint_key = record.endpoint_delegation.endpoint_key;

    let mut sync_state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut sync_store = CasStore::default();
    initialize(&mut sync_state, &mut sync_store);
    with_current_operation(
        &mut authority,
        &committed,
        NOW,
        &mut sync_state,
        |state, current| {
            let selected = retrieve_current!(
                state,
                NOW,
                [canonical_route(&record)],
                &endpoint_key,
                current,
                route_policy(),
                |expected, proposed| {
                    sync_store.cas(legacy_requester_expectation(expected), proposed)
                }
            )
            .expect("sync committed selection");
            assert_current_route_guard(&selected, &record, current.authority_revision(), NOW, 1);
        },
    );
    assert_eq!(sync_store.current.as_ref().unwrap(), &sync_state.snapshot());

    let mut async_state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let async_store = Rc::new(RefCell::new(CasStore::default()));
    with_current_operation(
        &mut authority,
        &committed,
        NOW,
        &mut async_state,
        |state, current| {
            let select_store = Rc::clone(&async_store);
            let selected = retrieve_current_async!(
                state,
                NOW,
                [canonical_route(&record)],
                &endpoint_key,
                current,
                route_policy(),
                move |expected, proposed| {
                    std::future::ready(
                        select_store
                            .borrow_mut()
                            .cas(legacy_requester_expectation(expected), &proposed),
                    )
                }
            )
            .expect("async committed selection");
            assert_current_route_guard(&selected, &record, current.authority_revision(), NOW, 1);
        },
    );
    assert_eq!(
        async_store.borrow().current.as_ref().unwrap(),
        &async_state.snapshot()
    );
}

#[test]
fn batch_selectors_require_exact_authority_time_after_persisting_requester_time() {
    let record = route();
    let endpoint_key = record.endpoint_delegation.endpoint_key;

    let (mut sync_authority, sync_committed) = committed_active_authority();
    let mut sync_state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut sync_store = CasStore::default();
    initialize(&mut sync_state, &mut sync_store);
    let mismatch = with_current_operation(
        &mut sync_authority,
        &sync_committed,
        NOW,
        &mut sync_state,
        |state, current| {
            retrieve_current!(
                state,
                NOW + 1,
                [canonical_route(&record)],
                &endpoint_key,
                current,
                route_policy(),
                |expected, proposed| {
                    sync_store.cas(legacy_requester_expectation(expected), proposed)
                }
            )
            .map(|_| ())
        },
    );
    assert!(matches!(
        mismatch,
        Err(HnsrProtocolError::Invalid(
            "committed HNSA authority operation-time mismatch"
        ))
    ));
    assert_eq!(sync_state.trusted_time_high_water(), NOW + 1);
    assert_eq!(sync_state.revision(), 1);
    assert_eq!(sync_store.current.as_ref().unwrap(), &sync_state.snapshot());
    let sync_refreshed = refresh_active_authority_at(&mut sync_authority, NOW + 1);
    with_current_operation(
        &mut sync_authority,
        &sync_refreshed,
        NOW + 1,
        &mut sync_state,
        |state, current| {
            let route = retrieve_current!(
                state,
                NOW + 1,
                [canonical_route(&record)],
                &endpoint_key,
                current,
                route_policy(),
                |expected, proposed| {
                    sync_store.cas(legacy_requester_expectation(expected), proposed)
                }
            )
            .expect("sync exact-time route");
            assert_current_route_guard(&route, &record, current.authority_revision(), NOW + 1, 2);
        },
    );

    let (mut async_authority, async_committed) = committed_active_authority();
    let mut async_state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let async_store = Rc::new(RefCell::new(CasStore::default()));
    let initialize_store = Rc::clone(&async_store);
    block_on(
        async_state.persist_pending_async(move |expected, proposed| {
            std::future::ready(initialize_store.borrow_mut().cas(expected, &proposed))
        }),
    )
    .expect("initialize async requester state");
    let mismatch_store = Rc::clone(&async_store);
    let mismatch = with_current_operation(
        &mut async_authority,
        &async_committed,
        NOW,
        &mut async_state,
        |state, current| {
            retrieve_current_async!(
                state,
                NOW + 1,
                [canonical_route(&record)],
                &endpoint_key,
                current,
                route_policy(),
                move |expected, proposed| {
                    std::future::ready(
                        mismatch_store
                            .borrow_mut()
                            .cas(legacy_requester_expectation(expected), &proposed),
                    )
                }
            )
            .map(|_| ())
        },
    );
    assert!(matches!(
        mismatch,
        Err(HnsrProtocolError::Invalid(
            "committed HNSA authority operation-time mismatch"
        ))
    ));
    assert_eq!(async_state.trusted_time_high_water(), NOW + 1);
    assert_eq!(async_state.revision(), 1);
    let async_refreshed = refresh_active_authority_at(&mut async_authority, NOW + 1);
    with_current_operation(
        &mut async_authority,
        &async_refreshed,
        NOW + 1,
        &mut async_state,
        |state, current| {
            let select_store = Rc::clone(&async_store);
            let route = retrieve_current_async!(
                state,
                NOW + 1,
                [canonical_route(&record)],
                &endpoint_key,
                current,
                route_policy(),
                move |expected, proposed| {
                    std::future::ready(
                        select_store
                            .borrow_mut()
                            .cas(legacy_requester_expectation(expected), &proposed),
                    )
                }
            )
            .expect("async exact-time route");
            assert_current_route_guard(&route, &record, current.authority_revision(), NOW + 1, 2);
        },
    );
}

#[test]
fn production_guard_tracks_exact_requester_revision_and_old_routes_cannot_rebind() {
    let (mut authority, committed) = committed_active_authority();
    let first = route();
    let endpoint_key = first.endpoint_delegation.endpoint_key;
    let greater = signed_route(
        &first,
        first.endpoint_delegation.endpoint_sequence,
        first.record_sequence + 1,
        first.endpoint_delegation.expires_at,
        first.expires_at,
    );
    let conflicting_greater = signed_route(
        &first,
        first.endpoint_delegation.endpoint_sequence,
        first.record_sequence + 1,
        first.endpoint_delegation.expires_at,
        first.expires_at - 1,
    );
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);

    with_current_operation(
        &mut authority,
        &committed,
        NOW,
        &mut state,
        |state, current| {
            let guard = retrieve_current!(
                state,
                NOW,
                [canonical_route(&first)],
                &endpoint_key,
                current,
                route_policy(),
                |expected, proposed| {
                    store.cas(legacy_requester_expectation(expected), proposed)
                }
            )
            .expect("first current guard");
            assert_current_route_guard(&guard, &first, current.authority_revision(), NOW, 1);
        },
    );
    with_current_operation(
        &mut authority,
        &committed,
        NOW,
        &mut state,
        |state, current| {
            let guard = retrieve_current!(
                state,
                NOW,
                [canonical_route(&greater)],
                &endpoint_key,
                current,
                route_policy(),
                |expected, proposed| {
                    store.cas(legacy_requester_expectation(expected), proposed)
                }
            )
            .expect("greater current guard");
            assert_current_route_guard(&guard, &greater, current.authority_revision(), NOW, 2);
        },
    );

    let stale = with_current_operation(
        &mut authority,
        &committed,
        NOW,
        &mut state,
        |state, current| {
            retrieve_current!(
                state,
                NOW,
                [canonical_route(&first)],
                &endpoint_key,
                current,
                route_policy(),
                |expected, proposed| {
                    store.cas(legacy_requester_expectation(expected), proposed)
                }
            )
            .map(|_| ())
        },
    );
    assert!(matches!(stale, Err(HnsrProtocolError::StaleSequence)));
    assert_eq!(state.revision(), 2);

    let conflict = with_current_operation(
        &mut authority,
        &committed,
        NOW,
        &mut state,
        |state, current| {
            retrieve_current!(
                state,
                NOW,
                [canonical_route(&conflicting_greater)],
                &endpoint_key,
                current,
                route_policy(),
                |expected, proposed| {
                    store.cas(legacy_requester_expectation(expected), proposed)
                }
            )
            .map(|_| ())
        },
    );
    assert!(matches!(
        conflict,
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    assert_eq!(state.revision(), 3);
    let tombstone = with_current_operation(
        &mut authority,
        &committed,
        NOW,
        &mut state,
        |state, current| {
            retrieve_current!(
                state,
                NOW,
                [canonical_route(&greater)],
                &endpoint_key,
                current,
                route_policy(),
                |expected, proposed| {
                    store.cas(legacy_requester_expectation(expected), proposed)
                }
            )
            .map(|_| ())
        },
    );
    assert!(matches!(
        tombstone,
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    assert_eq!(store.current.as_ref().unwrap(), &state.snapshot());
}

#[test]
fn committed_withdrawal_persists_time_before_error_and_retries_failed_cas() {
    let (mut authority, historical_active, withdrawn) = committed_withdrawn_authority();
    assert!(
        authority_binding_is_err(&mut authority, &historical_active, NOW),
        "an active historical handle must not survive withdrawal"
    );
    let record = route();
    let endpoint_key = record.endpoint_delegation.endpoint_key;
    let mut state = NamedRouteV3RequesterState::new(MAGIC, 32, NOW).unwrap();
    let mut store = CasStore::default();
    initialize(&mut state, &mut store);
    store.fail_before_commit = 1;

    let failed = with_current_operation(
        &mut authority,
        &withdrawn,
        NOW,
        &mut state,
        |state, current| {
            retrieve_current!(
                state,
                NOW + 1,
                [canonical_route(&record)],
                &endpoint_key,
                current,
                route_policy(),
                |expected, proposed| {
                    store.cas(legacy_requester_expectation(expected), proposed)
                }
            )
            .map(|_| ())
        },
    );
    assert!(matches!(
        failed,
        Err(HnsrProtocolError::Invalid("test persistence failure"))
    ));
    assert_eq!(state.trusted_time_high_water(), NOW + 1);
    assert_eq!(state.revision(), 1);
    assert!(state.has_pending_persistence());
    assert_eq!(
        store.current.as_ref().unwrap().trusted_time_high_water(),
        NOW
    );

    state
        .persist_pending(|expected, proposed| store.cas(expected, proposed))
        .expect("retry trusted-time CAS");
    assert!(!state.has_pending_persistence());
    assert_eq!(
        store.current.as_ref().unwrap().trusted_time_high_water(),
        NOW + 1
    );
    let withdrawn_identity = identity("pool-stats");
    let refreshed_withdrawal = authority
        .retrieve_validate_and_observe(
            NOW + 1,
            |retrieval_now| {
                assert_eq!(retrieval_now, NOW + 1);
                Ok::<_, Infallible>(authority_manifest(
                    &withdrawn_identity,
                    "removal_hrm_envelope",
                    11,
                ))
            },
            &withdrawn_identity,
            &service_policy(),
            ValidationLimits::default(),
            &mut acknowledge_authority_snapshot,
        )
        .expect("refresh withdrawal at exact operation time");
    let withdrawn_error = with_current_operation(
        &mut authority,
        &refreshed_withdrawal,
        NOW + 1,
        &mut state,
        |state, current| {
            retrieve_current!(
                state,
                NOW + 1,
                [canonical_route(&record)],
                &endpoint_key,
                current,
                route_policy(),
                |expected, proposed| {
                    store.cas(legacy_requester_expectation(expected), proposed)
                }
            )
            .map(|_| ())
        },
    );
    assert!(matches!(
        withdrawn_error,
        Err(HnsrProtocolError::Invalid(
            "committed HNSA service is withdrawn"
        ))
    ));
    assert_eq!(store.current.as_ref().unwrap(), &state.snapshot());
}
