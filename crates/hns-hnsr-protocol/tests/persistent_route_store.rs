use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fmt;
use std::future::{Future, pending, ready};
use std::num::NonZeroU64;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hns_hnsr_protocol::{
    GetRouteBody, HnsrOpcode, HnsrPacket, HnsrProtocolError, HrmNamedRoutePolicy,
    LeasedPersistentRendezvousError, LeasedPersistentRendezvousService,
    LeasedPersistentRouteMutationError, NamedRouteRecordV3, NamedRouteV3Emission,
    NamedRouteV3GuardedCallbackError, NamedRouteV3LeaseContext, NamedRouteV3LeaseLost,
    NamedRouteV3LedgerExpectation, NamedRouteV3LedgerSnapshot, NamedRouteV3LedgerStorageState,
    NamedRouteV3OpenError, NamedRouteV3SoleOwnerLease, NamedRouteV3StorageNamespace, PutRouteBody,
    RouteStoreLimits,
};
use hns_hrm::validation::{AuthenticatedNameState, ResolvedManifest, ValidationLimits};
use hns_service_authority::authority_state::{
    NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot, NamedServiceAuthorityState,
    NamedServiceAuthorityStorageState,
};
use hns_service_authority::hrm::{NamedServiceIdentity, NamedServicePolicy};
use hns_service_authority::lease::{
    AuthorityLeaseKey, FencedLeaseGuard, FencingToken, HeldAuthorityLease, LeaseError,
    LeaseScopeError, StorageNamespaceId,
};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_700_000_300;
const MAGIC: u32 = 2_922_943_951;
const PROFILE: u16 = 0xff00;

fn fixtures() -> BTreeMap<&'static str, &'static str> {
    include_str!("../fixtures/hnsa-hnsr-v3/hnsa-hnsr-v3.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once('=').expect("fixture key/value"))
        .collect()
}

fn bytes(values: &BTreeMap<&str, &str>, key: &str) -> Vec<u8> {
    hex::decode(values.get(key).unwrap_or_else(|| panic!("missing {key}")))
        .unwrap_or_else(|_| panic!("invalid hex for {key}"))
}

fn integer<T>(values: &BTreeMap<&str, &str>, key: &str) -> T
where
    T: std::str::FromStr,
    T::Err: fmt::Debug,
{
    values[key]
        .parse()
        .unwrap_or_else(|_| panic!("invalid integer for {key}"))
}

fn route(values: &BTreeMap<&str, &str>, key: &str) -> NamedRouteRecordV3 {
    NamedRouteRecordV3::decode(&bytes(values, key)).expect("fixture route")
}

fn greater_route(values: &BTreeMap<&str, &str>) -> NamedRouteRecordV3 {
    let mut route = route(values, "named_route_record_v3");
    route.record_sequence += 1;
    route.endpoint_signature.clear();
    route.sign(&[4; 32]).expect("greater signed route");
    route
}

fn limits() -> RouteStoreLimits {
    RouteStoreLimits {
        total_records: 32,
        ..RouteStoreLimits::default()
    }
}

fn namespace(values: &BTreeMap<&str, &str>) -> NamedRouteV3StorageNamespace {
    NamedRouteV3StorageNamespace::new([0x51; 32], integer(values, "network_magic"), true, limits())
        .expect("nonzero namespace")
}

fn service_identity() -> NamedServiceIdentity {
    NamedServiceIdentity::new(MAGIC, [15; 32], "pool-stats", PROFILE).expect("service identity")
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

fn authority_manifest(
    values: &BTreeMap<&str, &str>,
    envelope_name: &str,
    sequence: u64,
) -> ResolvedManifest {
    let identity = service_identity();
    let envelope = bytes(values, envelope_name);
    let digest = Sha256::digest(&envelope);
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
    }
}

#[derive(Debug)]
struct TestAuthorityGuard {
    key: AuthorityLeaseKey,
    fencing_token: FencingToken,
    held: Rc<Cell<bool>>,
}

impl FencedLeaseGuard<AuthorityLeaseKey> for TestAuthorityGuard {
    fn key(&self) -> &AuthorityLeaseKey {
        &self.key
    }

    fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    fn ensure_held(&self) -> Result<(), LeaseError> {
        if self.held.get() {
            Ok(())
        } else {
            Err(LeaseError::Lost)
        }
    }
}

fn held_authority_lease(identity: &NamedServiceIdentity) -> HeldAuthorityLease<TestAuthorityGuard> {
    held_authority_lease_revocable(identity).0
}

fn held_authority_lease_revocable(
    identity: &NamedServiceIdentity,
) -> (HeldAuthorityLease<TestAuthorityGuard>, Rc<Cell<bool>>) {
    let key = AuthorityLeaseKey::new(
        StorageNamespaceId::new([0x61; 32]).expect("authority namespace"),
        MAGIC,
        identity.name_hash,
    );
    let held = Rc::new(Cell::new(true));
    let guard_held = Rc::clone(&held);
    let lease = HeldAuthorityLease::acquire(key, |requested| {
        Ok::<_, TestError>(TestAuthorityGuard {
            key: *requested,
            fencing_token: FencingToken::new(1).expect("authority fencing token"),
            held: guard_held,
        })
    })
    .expect("authority lease");
    (lease, held)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestError {
    Unavailable,
    CasMismatch,
}

impl fmt::Display for TestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for TestError {}

type Guarded<T> = NamedRouteV3GuardedCallbackError<T>;

#[derive(Debug)]
struct BrokerState {
    namespace: NamedRouteV3StorageNamespace,
    current_token: u64,
    held_token: Option<u64>,
    snapshot: Option<NamedRouteV3LedgerSnapshot>,
    minimum_revision: u64,
    writes: usize,
    fail_next: bool,
    log: Vec<&'static str>,
}

impl BrokerState {
    fn new(namespace: NamedRouteV3StorageNamespace) -> Self {
        Self {
            namespace,
            current_token: 0,
            held_token: None,
            snapshot: None,
            minimum_revision: 0,
            writes: 0,
            fail_next: false,
            log: Vec::new(),
        }
    }

    fn acquire(shared: &Rc<RefCell<Self>>, requested: NamedRouteV3StorageNamespace) -> TestLease {
        let mut state = shared.borrow_mut();
        state.log.push("acquire");
        state.current_token += 1;
        state.held_token = Some(state.current_token);
        TestLease {
            shared: Rc::clone(shared),
            namespace: requested,
            token: NonZeroU64::new(state.current_token).expect("positive broker epoch"),
        }
    }

    fn revoke(&mut self) {
        self.current_token += 1;
        self.held_token = None;
    }

    fn persist(
        &mut self,
        expectation: NamedRouteV3LedgerExpectation,
        proposed: &NamedRouteV3LedgerSnapshot,
    ) -> Result<(), Guarded<TestError>> {
        let token = expectation.fencing_token().get();
        if expectation.namespace() != self.namespace
            || token != self.current_token
            || self.held_token != Some(token)
        {
            return Err(Guarded::LeaseLost);
        }
        if self.snapshot.as_ref() == Some(proposed) {
            return Ok(());
        }
        let matches = match (expectation, self.snapshot.as_ref()) {
            (NamedRouteV3LedgerExpectation::Absent { .. }, None) => true,
            (
                NamedRouteV3LedgerExpectation::Exact {
                    revision,
                    fingerprint,
                    ..
                },
                Some(current),
            ) => current.revision() == revision && current.fingerprint() == fingerprint,
            _ => false,
        };
        if !matches {
            return Err(Guarded::Other(TestError::CasMismatch));
        }
        if self.fail_next {
            self.fail_next = false;
            return Err(Guarded::Other(TestError::Unavailable));
        }
        self.snapshot = Some(proposed.clone());
        self.minimum_revision = proposed.revision();
        self.writes += 1;
        Ok(())
    }

    fn load(
        shared: &Rc<RefCell<Self>>,
        context: NamedRouteV3LeaseContext,
    ) -> Result<NamedRouteV3LedgerStorageState, Guarded<TestError>> {
        let mut state = shared.borrow_mut();
        state.log.push("load");
        if context.namespace() != state.namespace
            || context.fencing_token().get() != state.current_token
            || state.held_token != Some(context.fencing_token().get())
        {
            return Err(Guarded::LeaseLost);
        }
        Ok(match state.snapshot.clone() {
            Some(snapshot) => NamedRouteV3LedgerStorageState::Initialized {
                snapshot,
                minimum_revision: state.minimum_revision,
            },
            None => NamedRouteV3LedgerStorageState::Absent,
        })
    }
}

#[derive(Debug)]
struct TestLease {
    shared: Rc<RefCell<BrokerState>>,
    namespace: NamedRouteV3StorageNamespace,
    token: NonZeroU64,
}

impl NamedRouteV3SoleOwnerLease for TestLease {
    fn namespace(&self) -> NamedRouteV3StorageNamespace {
        self.namespace
    }

    fn fencing_token(&self) -> NonZeroU64 {
        self.token
    }

    fn ensure_held(&mut self) -> Result<(), NamedRouteV3LeaseLost> {
        let state = self.shared.borrow();
        if state.current_token == self.token.get() && state.held_token == Some(self.token.get()) {
            Ok(())
        } else {
            Err(NamedRouteV3LeaseLost)
        }
    }
}

impl Drop for TestLease {
    fn drop(&mut self) {
        let mut state = self.shared.borrow_mut();
        if state.held_token == Some(self.token.get()) {
            state.held_token = None;
        }
    }
}

type TestService = LeasedPersistentRendezvousService<TestLease>;
type TestOpenError = NamedRouteV3OpenError<TestError, TestError>;

fn open_service(
    state: &Rc<RefCell<BrokerState>>,
    requested: NamedRouteV3StorageNamespace,
) -> Result<TestService, TestOpenError> {
    let acquire_state = Rc::clone(state);
    let load_state = Rc::clone(state);
    TestService::open(
        requested,
        NOW,
        false,
        move |namespace| Ok::<_, TestError>(BrokerState::acquire(&acquire_state, namespace)),
        move |context| BrokerState::load(&load_state, context),
    )
}

fn get_packet(key: [u8; 32]) -> HnsrPacket {
    HnsrPacket::new(
        HnsrOpcode::GetRoute,
        [0x21; 8],
        GetRouteBody {
            route_key: key,
            maximum_records: 8,
        }
        .encode()
        .expect("GET body"),
    )
    .expect("GET packet")
}

fn put_packet(route: &NamedRouteRecordV3) -> HnsrPacket {
    HnsrPacket::new(
        HnsrOpcode::PutRoute,
        [0x22; 8],
        PutRouteBody {
            route_key: route.route_key,
            record: route.encode().expect("route bytes"),
        }
        .encode()
        .expect("PUT body"),
    )
    .expect("PUT packet")
}

fn initialize(service: &mut TestService, state: &Rc<RefCell<BrokerState>>) {
    let persist_state = Rc::clone(state);
    let mut persist = move |expectation: NamedRouteV3LedgerExpectation,
                            proposed: &NamedRouteV3LedgerSnapshot| {
        persist_state.borrow_mut().persist(expectation, proposed)
    };
    service
        .handle_and_emit(
            &get_packet([9; 32]),
            "peer-init",
            NOW,
            &mut persist,
            |context, emission| {
                assert_eq!(context, service_context_for_event(&emission, context));
                assert!(matches!(emission, NamedRouteV3Emission::Response(_)));
                Ok::<(), Guarded<TestError>>(())
            },
        )
        .expect("initialize and emit");
}

fn service_context_for_event(
    _emission: &NamedRouteV3Emission,
    context: NamedRouteV3LeaseContext,
) -> NamedRouteV3LeaseContext {
    context
}

#[test]
fn acquisition_precedes_loader_and_every_cas_is_fully_bound() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let mut service = open_service(&state, namespace).expect("leased service");
    assert_eq!(state.borrow().log, ["acquire", "load"]);
    assert_ne!(service.lease_context().fencing_token().get(), 0);

    let seen = Rc::new(RefCell::new(Vec::new()));
    let seen_callback = Rc::clone(&seen);
    let persist_state = Rc::clone(&state);
    let expected_context = service.lease_context();
    let mut persist = move |expectation: NamedRouteV3LedgerExpectation,
                            proposed: &NamedRouteV3LedgerSnapshot| {
        assert_eq!(expectation.namespace(), namespace);
        assert_eq!(
            expectation.fencing_token(),
            expected_context.fencing_token()
        );
        seen_callback.borrow_mut().push(expectation);
        persist_state.borrow_mut().persist(expectation, proposed)
    };
    let emitted = Rc::new(RefCell::new(false));
    let emitted_callback = Rc::clone(&emitted);
    service
        .handle_and_emit(
            &get_packet([7; 32]),
            "peer-a",
            NOW,
            &mut persist,
            move |context, emission| {
                assert_eq!(context.namespace(), namespace);
                assert!(matches!(emission, NamedRouteV3Emission::Response(_)));
                assert_eq!(state.borrow().writes, 1, "CAS precedes emission");
                *emitted_callback.borrow_mut() = true;
                Ok::<(), Guarded<TestError>>(())
            },
        )
        .expect("guarded GET");
    assert!(*emitted.borrow());
    assert!(matches!(
        seen.borrow().as_slice(),
        [NamedRouteV3LedgerExpectation::Absent { .. }]
    ));
}

#[test]
fn persistence_failure_after_mutation_withholds_every_protocol_outcome() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let mut service = open_service(&state, namespace).expect("leased service");
    initialize(&mut service, &state);
    state.borrow_mut().fail_next = true;

    let persist_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
        persist_state.borrow_mut().persist(expectation, proposed)
    };
    let mut emitter_called = false;
    let result: Result<(), LeasedPersistentRendezvousError<TestError, TestError>> = service
        .handle_and_emit(
            &put_packet(&route(&values, "named_route_record_v3")),
            "peer-a",
            NOW,
            &mut persist,
            |_, _| {
                emitter_called = true;
                Ok(())
            },
        );
    assert!(matches!(
        result,
        Err(LeasedPersistentRendezvousError::Persistence(
            TestError::Unavailable
        ))
    ));
    assert!(!emitter_called);
    assert_eq!(state.borrow().snapshot.as_ref().unwrap().revision(), 0);
    assert!(
        !service.is_poisoned(),
        "retryable backend failure retains lineage"
    );
}

#[test]
fn fail_closed_protocol_error_is_persisted_before_guarded_emission() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let mut service = open_service(&state, namespace).expect("leased service");
    initialize(&mut service, &state);

    let persist_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
        persist_state.borrow_mut().persist(expectation, proposed)
    };
    service
        .handle_and_emit(
            &put_packet(&route(&values, "named_route_record_v3")),
            "peer-a",
            NOW,
            &mut persist,
            |_, emission| {
                assert!(matches!(emission, NamedRouteV3Emission::Response(_)));
                Ok::<(), Guarded<TestError>>(())
            },
        )
        .expect("base route");
    let before = state.borrow().snapshot.as_ref().unwrap().revision();

    let persist_state = Rc::clone(&state);
    let inspect_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
        persist_state.borrow_mut().persist(expectation, proposed)
    };
    service
        .handle_and_emit(
            &put_packet(&route(&values, "conflicting_route_same_sequence")),
            "peer-b",
            NOW,
            &mut persist,
            move |_, emission| {
                assert!(matches!(
                    emission,
                    NamedRouteV3Emission::ProtocolError(HnsrProtocolError::ConflictingSequence)
                ));
                assert!(
                    inspect_state.borrow().snapshot.as_ref().unwrap().revision() > before,
                    "conflict tombstone must be durable before emission"
                );
                Ok::<(), Guarded<TestError>>(())
            },
        )
        .expect("durably emitted conflict");
}

#[test]
fn loss_or_binding_failure_before_load_never_invokes_loader() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let acquire_state = Rc::clone(&state);
    let loader_called = Rc::new(RefCell::new(false));
    let loader_flag = Rc::clone(&loader_called);
    let result: Result<TestService, TestOpenError> = TestService::open(
        namespace,
        NOW,
        false,
        move |requested| {
            let lease = BrokerState::acquire(&acquire_state, requested);
            acquire_state.borrow_mut().revoke();
            Ok(lease)
        },
        move |_| {
            *loader_flag.borrow_mut() = true;
            Ok(NamedRouteV3LedgerStorageState::Absent)
        },
    );
    assert!(matches!(result, Err(NamedRouteV3OpenError::LeaseLost)));
    assert!(!*loader_called.borrow());

    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let acquire_state = Rc::clone(&state);
    let loader_called = Rc::new(RefCell::new(false));
    let loader_flag = Rc::clone(&loader_called);
    let mut wrong = namespace;
    // A valid but different namespace/configuration must not reach the loader.
    wrong = NamedRouteV3StorageNamespace::new(
        [0x52; 32],
        wrong.network_magic(),
        wrong.allow_private_routes(),
        wrong.limits(),
    )
    .unwrap();
    let result: Result<TestService, TestOpenError> = TestService::open(
        namespace,
        NOW,
        false,
        move |_| Ok(BrokerState::acquire(&acquire_state, wrong)),
        move |_| {
            *loader_flag.borrow_mut() = true;
            Ok(NamedRouteV3LedgerStorageState::Absent)
        },
    );
    assert!(matches!(result, Err(NamedRouteV3OpenError::LeaseBinding)));
    assert!(!*loader_called.borrow());
}

#[test]
fn loss_during_load_is_detected_before_open_returns() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let acquire_state = Rc::clone(&state);
    let load_state = Rc::clone(&state);
    let result: Result<TestService, TestOpenError> = TestService::open(
        namespace,
        NOW,
        false,
        move |requested| Ok(BrokerState::acquire(&acquire_state, requested)),
        move |_| {
            load_state.borrow_mut().revoke();
            Ok(NamedRouteV3LedgerStorageState::Absent)
        },
    );
    assert!(matches!(result, Err(NamedRouteV3OpenError::LeaseLost)));
}

#[test]
fn stale_fence_is_rejected_across_two_restored_contexts() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let mut first = open_service(&state, namespace).expect("first context");
    initialize(&mut first, &state);

    let persist_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
        persist_state.borrow_mut().persist(expectation, proposed)
    };
    first
        .handle_and_emit(
            &put_packet(&route(&values, "named_route_record_v3")),
            "peer-a",
            NOW,
            &mut persist,
            |_, _| Ok::<(), Guarded<TestError>>(()),
        )
        .expect("base route");

    let captured = Rc::new(RefCell::new(None));
    let captured_callback = Rc::clone(&captured);
    let mut fail = move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
        *captured_callback.borrow_mut() = Some((expectation, proposed.clone()));
        Err(Guarded::Other(TestError::Unavailable))
    };
    let result: Result<(), LeasedPersistentRendezvousError<TestError, TestError>> = first
        .handle_and_emit(
            &put_packet(&route(&values, "conflicting_route_same_sequence")),
            "peer-b",
            NOW,
            &mut fail,
            |_, _| Ok(()),
        );
    assert!(matches!(
        result,
        Err(LeasedPersistentRendezvousError::Persistence(
            TestError::Unavailable
        ))
    ));
    let old_context = first.lease_context();

    // Test broker forcibly revokes the first guard when issuing the next epoch.
    let mut second = open_service(&state, namespace).expect("restored second context");
    assert_ne!(
        old_context.fencing_token(),
        second.lease_context().fencing_token()
    );
    let (expectation, proposed) = captured.borrow().clone().expect("captured exact CAS");
    assert!(matches!(
        expectation,
        NamedRouteV3LedgerExpectation::Exact { .. }
    ));
    assert!(matches!(
        state.borrow_mut().persist(expectation, &proposed),
        Err(Guarded::LeaseLost)
    ));

    let mut unreachable_persist =
        |_, _: &NamedRouteV3LedgerSnapshot| panic!("lost lease must fail before persistence");
    let result: Result<(), LeasedPersistentRendezvousError<TestError, TestError>> = first
        .handle_and_emit(
            &get_packet([4; 32]),
            "peer-old",
            NOW,
            &mut unreachable_persist,
            |_, _| Ok(()),
        );
    assert!(matches!(
        result,
        Err(LeasedPersistentRendezvousError::LeaseLost)
    ));
    assert!(first.is_poisoned());
    assert_eq!(first.volatile_route_count(), 0);
    assert_eq!(
        second.volatile_route_count(),
        0,
        "restores discard live bytes"
    );
    initialize(&mut second, &state);
}

#[test]
fn lease_loss_after_cas_but_before_emission_poisons_and_withholds() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let mut service = open_service(&state, namespace).expect("leased service");
    initialize(&mut service, &state);

    let persist_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
        let result = persist_state.borrow_mut().persist(expectation, proposed);
        if result.is_ok() {
            persist_state.borrow_mut().revoke();
        }
        result
    };
    let mut emitter_called = false;
    let result: Result<(), LeasedPersistentRendezvousError<TestError, TestError>> = service
        .handle_and_emit(
            &put_packet(&route(&values, "named_route_record_v3")),
            "peer-a",
            NOW,
            &mut persist,
            |_, _| {
                emitter_called = true;
                Ok(())
            },
        );
    assert!(matches!(
        result,
        Err(LeasedPersistentRendezvousError::LeaseLost)
    ));
    assert!(!emitter_called);
    assert!(service.is_poisoned());
    assert_eq!(service.volatile_route_count(), 0);
}

#[test]
fn caught_sync_callback_panics_immediately_poison_and_drop_inner_state() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let mut persistence_panic = open_service(&state, namespace).expect("leased service");
    let caught = catch_unwind(AssertUnwindSafe(|| {
        let mut persist = |_, _: &NamedRouteV3LedgerSnapshot| -> Result<(), Guarded<TestError>> {
            panic!("storage callback panic")
        };
        let _: Result<(), LeasedPersistentRendezvousError<TestError, TestError>> =
            persistence_panic.handle_and_emit(
                &get_packet([1; 32]),
                "peer-panic",
                NOW,
                &mut persist,
                |_, _| Ok(()),
            );
    }));
    assert!(caught.is_err());
    assert!(persistence_panic.is_poisoned());
    assert_eq!(persistence_panic.volatile_route_count(), 0);
    drop(persistence_panic);

    let mut emission_panic = open_service(&state, namespace).expect("reacquired service");
    initialize(&mut emission_panic, &state);
    let persist_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
        persist_state.borrow_mut().persist(expectation, proposed)
    };
    emission_panic
        .handle_and_emit(
            &put_packet(&route(&values, "named_route_record_v3")),
            "peer-a",
            NOW,
            &mut persist,
            |_, _| Ok::<(), Guarded<TestError>>(()),
        )
        .expect("live route before emitter panic");
    assert_eq!(emission_panic.volatile_route_count(), 1);

    let persist_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
        persist_state.borrow_mut().persist(expectation, proposed)
    };
    let caught = catch_unwind(AssertUnwindSafe(|| {
        let _: Result<(), LeasedPersistentRendezvousError<TestError, TestError>> = emission_panic
            .handle_and_emit(
                &get_packet(route(&values, "named_route_record_v3").route_key),
                "peer-panic",
                NOW,
                &mut persist,
                |_, _| -> Result<(), Guarded<TestError>> { panic!("emitter callback panic") },
            );
    }));
    assert!(caught.is_err());
    assert!(emission_panic.is_poisoned());
    assert_eq!(emission_panic.volatile_route_count(), 0);
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn run_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

#[test]
fn leased_current_authority_put_revalidation_and_withdrawal_are_durable() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let mut service = open_service(&state, namespace).expect("leased service");
    let identity = service_identity();
    let record = route(&values, "named_route_record_v3");
    let mut authority = NamedServiceAuthorityState::new(MAGIC, identity.name_hash, 1, NOW)
        .expect("authority state");
    let authority_lease = held_authority_lease(&identity);
    let persist_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
        persist_state.borrow_mut().persist(expectation, proposed)
    };
    let sequence: u64 = integer(&values, "hrm_sequence");
    authority_lease
        .run(|witness| {
            let expected_namespace = witness.key().storage_namespace_id();
            let expected_fence = witness.fencing_token();
            let mut leased = authority
                .reconfirm(witness, |loader_witness| {
                    assert_eq!(loader_witness.key(), witness.key());
                    assert_eq!(loader_witness.fencing_token(), expected_fence);
                    Ok::<_, HnsrProtocolError>(NamedServiceAuthorityStorageState::Absent)
                })
                .expect("reconfirmed authority state");
            let mut authority_persist =
                |expectation: NamedServiceAuthorityExpectation,
                 _: &NamedServiceAuthoritySnapshot| {
                    assert_eq!(expectation.storage_namespace_id(), expected_namespace);
                    assert_eq!(expectation.fencing_token(), expected_fence);
                    Ok::<(), HnsrProtocolError>(())
                };
            let active = leased
                .retrieve_validate_and_observe(
                    NOW,
                    |_| {
                        Ok::<_, std::convert::Infallible>(authority_manifest(
                            &values,
                            "hrm_envelope",
                            sequence,
                        ))
                    },
                    &identity,
                    &service_policy(),
                    ValidationLimits::default(),
                    &mut authority_persist,
                )
                .expect("committed active authority");
            {
                let current = leased
                    .bind_current_at(&active, NOW)
                    .expect("current active authority");
                service
                    .put_named_v3_current(
                        record.route_key,
                        record.encode().expect("route bytes"),
                        &current,
                        route_policy(),
                        NOW,
                        "peer-current".to_owned(),
                        &mut persist,
                    )
                    .expect("durable current-authority put");
                assert_eq!(service.volatile_route_count(), 1);
                assert_eq!(
                    service
                        .revalidate_named_v3_current(
                            &identity,
                            &current,
                            route_policy(),
                            NOW,
                            &mut persist,
                        )
                        .expect("durable current revalidation"),
                    1
                );
            }
            leased
                .retrieve_validate_and_observe(
                    NOW,
                    |_| {
                        Ok::<_, std::convert::Infallible>(authority_manifest(
                            &values,
                            "replacement_hrm_envelope",
                            sequence + 1,
                        ))
                    },
                    &identity,
                    &service_policy(),
                    ValidationLimits::default(),
                    &mut authority_persist,
                )
                .expect("committed replacement authority");
            let withdrawn = leased
                .retrieve_validate_and_observe(
                    NOW,
                    |_| {
                        Ok::<_, std::convert::Infallible>(authority_manifest(
                            &values,
                            "removal_hrm_envelope",
                            sequence + 2,
                        ))
                    },
                    &identity,
                    &service_policy(),
                    ValidationLimits::default(),
                    &mut authority_persist,
                )
                .expect("committed withdrawal");
            let current = leased
                .bind_current_at(&withdrawn, NOW)
                .expect("current withdrawal authority");
            assert_eq!(
                service
                    .invalidate_named_v3_withdrawal(&identity, &current, NOW, &mut persist)
                    .expect("durable exact-time withdrawal"),
                1
            );
            Ok::<(), TestError>(())
        })
        .expect("held authority operation");
    assert_eq!(service.volatile_route_count(), 0);
}

#[test]
fn async_leased_current_authority_operations_complete_under_the_same_fence() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let mut service = open_service(&state, namespace).expect("leased service");
    let identity = service_identity();
    let record = route(&values, "named_route_record_v3");
    let mut authority = NamedServiceAuthorityState::new(MAGIC, identity.name_hash, 1, NOW)
        .expect("authority state");
    let authority_lease = held_authority_lease(&identity);
    let persist_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed| {
        ready(persist_state.borrow_mut().persist(expectation, &proposed))
    };
    let sequence: u64 = integer(&values, "hrm_sequence");
    authority_lease
        .run(|witness| {
            let expected_namespace = witness.key().storage_namespace_id();
            let expected_fence = witness.fencing_token();
            let mut leased = authority
                .reconfirm(witness, |_| {
                    Ok::<_, HnsrProtocolError>(NamedServiceAuthorityStorageState::Absent)
                })
                .expect("reconfirmed authority state");
            let mut authority_persist =
                |expectation: NamedServiceAuthorityExpectation,
                 _: &NamedServiceAuthoritySnapshot| {
                    assert_eq!(expectation.storage_namespace_id(), expected_namespace);
                    assert_eq!(expectation.fencing_token(), expected_fence);
                    Ok::<(), HnsrProtocolError>(())
                };
            let active = leased
                .retrieve_validate_and_observe(
                    NOW,
                    |_| {
                        Ok::<_, std::convert::Infallible>(authority_manifest(
                            &values,
                            "hrm_envelope",
                            sequence,
                        ))
                    },
                    &identity,
                    &service_policy(),
                    ValidationLimits::default(),
                    &mut authority_persist,
                )
                .expect("committed active authority");
            {
                let current = leased
                    .bind_current_at(&active, NOW)
                    .expect("current active authority");
                run_ready(service.put_named_v3_current_async(
                    record.route_key,
                    record.encode().expect("route bytes"),
                    &current,
                    route_policy(),
                    NOW,
                    "peer-current-async".to_owned(),
                    &mut persist,
                ))
                .expect("async durable current-authority put");
                assert_eq!(
                    run_ready(service.revalidate_named_v3_current_async(
                        &identity,
                        &current,
                        route_policy(),
                        NOW,
                        &mut persist,
                    ))
                    .expect("async durable current revalidation"),
                    1
                );
            }
            leased
                .retrieve_validate_and_observe(
                    NOW,
                    |_| {
                        Ok::<_, std::convert::Infallible>(authority_manifest(
                            &values,
                            "replacement_hrm_envelope",
                            sequence + 1,
                        ))
                    },
                    &identity,
                    &service_policy(),
                    ValidationLimits::default(),
                    &mut authority_persist,
                )
                .expect("committed replacement authority");
            let withdrawn = leased
                .retrieve_validate_and_observe(
                    NOW,
                    |_| {
                        Ok::<_, std::convert::Infallible>(authority_manifest(
                            &values,
                            "removal_hrm_envelope",
                            sequence + 2,
                        ))
                    },
                    &identity,
                    &service_policy(),
                    ValidationLimits::default(),
                    &mut authority_persist,
                )
                .expect("committed withdrawal");
            let current = leased
                .bind_current_at(&withdrawn, NOW)
                .expect("current withdrawal authority");
            assert_eq!(
                run_ready(service.invalidate_named_v3_withdrawal_async(
                    &identity,
                    &current,
                    NOW,
                    &mut persist,
                ))
                .expect("async durable exact-time withdrawal"),
                1
            );
            Ok::<(), TestError>(())
        })
        .expect("held authority operation");
    assert_eq!(service.volatile_route_count(), 0);
}

#[derive(Clone, Copy, Debug)]
enum CurrentOperation {
    Put,
    Revalidate,
    Withdrawal,
}

#[test]
fn authority_loss_during_each_sync_and_async_current_cas_poisons() {
    let values = fixtures();
    let sequence: u64 = integer(&values, "hrm_sequence");
    for asynchronous in [false, true] {
        for operation in [
            CurrentOperation::Put,
            CurrentOperation::Revalidate,
            CurrentOperation::Withdrawal,
        ] {
            let namespace = namespace(&values);
            let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
            let mut service = open_service(&state, namespace).expect("leased service");
            let identity = service_identity();
            let record = route(&values, "named_route_record_v3");
            let mut authority = NamedServiceAuthorityState::new(MAGIC, identity.name_hash, 1, NOW)
                .expect("authority state");
            let (authority_lease, authority_held) = held_authority_lease_revocable(&identity);
            let scoped = authority_lease.run(|witness| {
                let expected_namespace = witness.key().storage_namespace_id();
                let expected_fence = witness.fencing_token();
                let mut leased = authority
                    .reconfirm(witness, |_| {
                        Ok::<_, HnsrProtocolError>(NamedServiceAuthorityStorageState::Absent)
                    })
                    .expect("reconfirmed authority state");
                let mut authority_persist =
                    |expectation: NamedServiceAuthorityExpectation,
                     _: &NamedServiceAuthoritySnapshot| {
                        assert_eq!(expectation.storage_namespace_id(), expected_namespace);
                        assert_eq!(expectation.fencing_token(), expected_fence);
                        Ok::<(), HnsrProtocolError>(())
                    };
                let active = leased
                    .retrieve_validate_and_observe(
                        NOW,
                        |_| {
                            Ok::<_, std::convert::Infallible>(authority_manifest(
                                &values,
                                "hrm_envelope",
                                sequence,
                            ))
                        },
                        &identity,
                        &service_policy(),
                        ValidationLimits::default(),
                        &mut authority_persist,
                    )
                    .expect("committed active authority");

                if !matches!(operation, CurrentOperation::Put) {
                    {
                        let current = leased
                            .bind_current_at(&active, NOW)
                            .expect("current active authority");
                        let persist_state = Rc::clone(&state);
                        let mut persist =
                            move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
                                persist_state.borrow_mut().persist(expectation, proposed)
                            };
                        service
                            .put_named_v3_current(
                                record.route_key,
                                record.encode().expect("route bytes"),
                                &current,
                                route_policy(),
                                NOW,
                                "peer-prepare".to_owned(),
                                &mut persist,
                            )
                            .expect("prepare live current route");
                    }

                    // Leave one exact proposal pending so revalidation and
                    // withdrawal both cross a real CAS during the tested call.
                    state.borrow_mut().fail_next = true;
                    let persist_state = Rc::clone(&state);
                    let mut fail = move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
                        persist_state.borrow_mut().persist(expectation, proposed)
                    };
                    let pending_result: Result<
                        (),
                        LeasedPersistentRendezvousError<TestError, TestError>,
                    > = service.handle_and_emit(
                        &put_packet(&route(&values, "conflicting_route_same_sequence")),
                        "peer-conflict",
                        NOW,
                        &mut fail,
                        |_, _| Ok(()),
                    );
                    assert!(matches!(
                        pending_result,
                        Err(LeasedPersistentRendezvousError::Persistence(
                            TestError::Unavailable
                        ))
                    ));
                }

                match operation {
                    CurrentOperation::Put => {
                        let current = leased
                            .bind_current_at(&active, NOW)
                            .expect("current active authority");
                        let result = if asynchronous {
                            let persist_state = Rc::clone(&state);
                            let authority_held = Rc::clone(&authority_held);
                            let mut lose = move |expectation, proposed| {
                                let result =
                                    persist_state.borrow_mut().persist(expectation, &proposed);
                                authority_held.set(false);
                                ready(result)
                            };
                            run_ready(service.put_named_v3_current_async(
                                record.route_key,
                                record.encode().expect("route bytes"),
                                &current,
                                route_policy(),
                                NOW,
                                "peer-loss".to_owned(),
                                &mut lose,
                            ))
                        } else {
                            let persist_state = Rc::clone(&state);
                            let authority_held = Rc::clone(&authority_held);
                            let mut lose =
                                move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
                                    let result =
                                        persist_state.borrow_mut().persist(expectation, proposed);
                                    authority_held.set(false);
                                    result
                                };
                            service.put_named_v3_current(
                                record.route_key,
                                record.encode().expect("route bytes"),
                                &current,
                                route_policy(),
                                NOW,
                                "peer-loss".to_owned(),
                                &mut lose,
                            )
                        };
                        assert!(matches!(
                            result,
                            Err(LeasedPersistentRouteMutationError::AuthorityLeaseLost)
                        ));
                    }
                    CurrentOperation::Revalidate => {
                        let current = leased
                            .bind_current_at(&active, NOW)
                            .expect("current active authority");
                        let result = if asynchronous {
                            let persist_state = Rc::clone(&state);
                            let authority_held = Rc::clone(&authority_held);
                            let mut lose = move |expectation, proposed| {
                                let result =
                                    persist_state.borrow_mut().persist(expectation, &proposed);
                                authority_held.set(false);
                                ready(result)
                            };
                            run_ready(service.revalidate_named_v3_current_async(
                                &identity,
                                &current,
                                route_policy(),
                                NOW,
                                &mut lose,
                            ))
                        } else {
                            let persist_state = Rc::clone(&state);
                            let authority_held = Rc::clone(&authority_held);
                            let mut lose =
                                move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
                                    let result =
                                        persist_state.borrow_mut().persist(expectation, proposed);
                                    authority_held.set(false);
                                    result
                                };
                            service.revalidate_named_v3_current(
                                &identity,
                                &current,
                                route_policy(),
                                NOW,
                                &mut lose,
                            )
                        };
                        assert!(matches!(
                            result,
                            Err(LeasedPersistentRouteMutationError::AuthorityLeaseLost)
                        ));
                    }
                    CurrentOperation::Withdrawal => {
                        leased
                            .retrieve_validate_and_observe(
                                NOW,
                                |_| {
                                    Ok::<_, std::convert::Infallible>(authority_manifest(
                                        &values,
                                        "replacement_hrm_envelope",
                                        sequence + 1,
                                    ))
                                },
                                &identity,
                                &service_policy(),
                                ValidationLimits::default(),
                                &mut authority_persist,
                            )
                            .expect("committed replacement authority");
                        let withdrawn = leased
                            .retrieve_validate_and_observe(
                                NOW,
                                |_| {
                                    Ok::<_, std::convert::Infallible>(authority_manifest(
                                        &values,
                                        "removal_hrm_envelope",
                                        sequence + 2,
                                    ))
                                },
                                &identity,
                                &service_policy(),
                                ValidationLimits::default(),
                                &mut authority_persist,
                            )
                            .expect("committed withdrawal");
                        let current = leased
                            .bind_current_at(&withdrawn, NOW)
                            .expect("current withdrawal authority");
                        let result = if asynchronous {
                            let persist_state = Rc::clone(&state);
                            let authority_held = Rc::clone(&authority_held);
                            let mut lose = move |expectation, proposed| {
                                let result =
                                    persist_state.borrow_mut().persist(expectation, &proposed);
                                authority_held.set(false);
                                ready(result)
                            };
                            run_ready(service.invalidate_named_v3_withdrawal_async(
                                &identity, &current, NOW, &mut lose,
                            ))
                        } else {
                            let persist_state = Rc::clone(&state);
                            let authority_held = Rc::clone(&authority_held);
                            let mut lose =
                                move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
                                    let result =
                                        persist_state.borrow_mut().persist(expectation, proposed);
                                    authority_held.set(false);
                                    result
                                };
                            service
                                .invalidate_named_v3_withdrawal(&identity, &current, NOW, &mut lose)
                        };
                        assert!(matches!(
                            result,
                            Err(LeasedPersistentRouteMutationError::AuthorityLeaseLost)
                        ));
                    }
                }
                assert!(service.is_poisoned());
                assert_eq!(service.volatile_route_count(), 0);
                Ok::<(), TestError>(())
            });
            assert!(matches!(
                scoped,
                Err(LeaseScopeError::Lease(LeaseError::Lost))
            ));
        }
    }
}

struct PendingOncePersist {
    state: Rc<RefCell<BrokerState>>,
    expectation: NamedRouteV3LedgerExpectation,
    proposed: NamedRouteV3LedgerSnapshot,
    polled: bool,
}

impl Future for PendingOncePersist {
    type Output = Result<(), Guarded<TestError>>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.polled {
            self.polled = true;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(
            self.state
                .borrow_mut()
                .persist(self.expectation, &self.proposed),
        )
    }
}

struct PendingOnceEmit {
    emission: Option<NamedRouteV3Emission>,
    emitted: Rc<RefCell<bool>>,
    polled: bool,
}

impl Future for PendingOnceEmit {
    type Output = Result<(), Guarded<TestError>>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.polled {
            self.polled = true;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        assert!(matches!(
            self.emission.take(),
            Some(NamedRouteV3Emission::Response(_))
        ));
        *self.emitted.borrow_mut() = true;
        Poll::Ready(Ok(()))
    }
}

#[test]
fn async_response_is_withheld_until_cas_and_awaited_emission_complete() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let mut service = open_service(&state, namespace).expect("leased service");
    initialize(&mut service, &state);
    let before = state.borrow().snapshot.as_ref().unwrap().revision();

    let persist_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed| PendingOncePersist {
        state: Rc::clone(&persist_state),
        expectation,
        proposed,
        polled: false,
    };
    let emitted = Rc::new(RefCell::new(false));
    let emitted_callback = Rc::clone(&emitted);
    let packet = put_packet(&route(&values, "named_route_record_v3"));
    let mut future = std::pin::pin!(service.handle_and_emit_async(
        &packet,
        "peer-a",
        NOW,
        &mut persist,
        move |_, emission| PendingOnceEmit {
            emission: Some(emission),
            emitted: emitted_callback,
            polled: false,
        },
    ));
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(state.borrow().snapshot.as_ref().unwrap().revision(), before);
    assert!(!*emitted.borrow());
    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert!(state.borrow().snapshot.as_ref().unwrap().revision() > before);
    assert!(!*emitted.borrow());
    assert!(matches!(
        future.as_mut().poll(&mut context),
        Poll::Ready(Ok(()))
    ));
    assert!(*emitted.borrow());
}

#[test]
fn dropping_async_emission_immediately_discards_live_bytes_and_poisoned_reopen_is_empty() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let mut service = open_service(&state, namespace).expect("leased service");
    initialize(&mut service, &state);

    let persist_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed| {
        ready(persist_state.borrow_mut().persist(expectation, &proposed))
    };
    let packet = put_packet(&greater_route(&values));
    {
        let mut future = std::pin::pin!(service.handle_and_emit_async(
            &packet,
            "peer-a",
            NOW,
            &mut persist,
            |_, emission| async move {
                let _held_until_cancel = emission;
                pending::<Result<(), Guarded<TestError>>>().await
            },
        ));
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    }
    assert!(service.is_poisoned());
    assert_eq!(service.volatile_route_count(), 0);
    drop(service);

    let mut reopened = open_service(&state, namespace).expect("reacquired service");
    assert_eq!(reopened.volatile_route_count(), 0);
    let persist_state = Rc::clone(&state);
    let mut persist = move |expectation, proposed: &NamedRouteV3LedgerSnapshot| {
        persist_state.borrow_mut().persist(expectation, proposed)
    };
    let saw_stale = Rc::new(RefCell::new(false));
    let saw_stale_callback = Rc::clone(&saw_stale);
    reopened
        .handle_and_emit(
            &put_packet(&route(&values, "named_route_record_v3")),
            "peer-b",
            NOW,
            &mut persist,
            move |_, emission| {
                *saw_stale_callback.borrow_mut() = matches!(
                    emission,
                    NamedRouteV3Emission::ProtocolError(HnsrProtocolError::StaleSequence)
                );
                Ok::<(), Guarded<TestError>>(())
            },
        )
        .expect("durably emit rollback rejection");
    assert!(*saw_stale.borrow());
}

struct LoseDuringPersist {
    state: Rc<RefCell<BrokerState>>,
    polled: bool,
}

impl Future for LoseDuringPersist {
    type Output = Result<(), Guarded<TestError>>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.polled {
            self.polled = true;
            self.state.borrow_mut().revoke();
            context.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Err(Guarded::LeaseLost))
        }
    }
}

#[test]
fn lease_loss_during_async_cas_poisons_without_emission() {
    let values = fixtures();
    let namespace = namespace(&values);
    let state = Rc::new(RefCell::new(BrokerState::new(namespace)));
    let mut service = open_service(&state, namespace).expect("leased service");
    initialize(&mut service, &state);
    let persist_state = Rc::clone(&state);
    let mut persist = move |_, _| LoseDuringPersist {
        state: Rc::clone(&persist_state),
        polled: false,
    };
    let emitter_called = Rc::new(RefCell::new(false));
    let emitter_flag = Rc::clone(&emitter_called);
    let packet = put_packet(&route(&values, "named_route_record_v3"));
    {
        let mut future = std::pin::pin!(service.handle_and_emit_async(
            &packet,
            "peer-a",
            NOW,
            &mut persist,
            move |_, _| {
                *emitter_flag.borrow_mut() = true;
                ready(Ok::<(), Guarded<TestError>>(()))
            },
        ));
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        assert!(matches!(
            future.as_mut().poll(&mut context),
            Poll::Ready(Err(LeasedPersistentRendezvousError::LeaseLost))
        ));
    }
    assert!(!*emitter_called.borrow());
    assert!(service.is_poisoned());
    assert_eq!(service.volatile_route_count(), 0);
}
