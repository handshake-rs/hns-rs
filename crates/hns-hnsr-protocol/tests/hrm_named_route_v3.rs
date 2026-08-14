use std::cell::Cell;
use std::rc::Rc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_hnsr_protocol::{
    GetRouteBody, HnsrOpcode, HnsrPacket, HnsrProtocolError, HnsrService, HrmNamedRoutePolicy,
    MAX_ROUTE_LIFETIME, NamedRouteRecordV2, NamedRouteRecordV3, NamedRouteV3LedgerSnapshot,
    PutRouteBody, RendezvousService, RouteRecordModel, RouteStore, RouteStoreLimits, RoutesBody,
    named_route_key_v3, select_named_route_v3_uncommitted,
};
use hns_hnsr_protocol::{NamedRoutePolicy, NamedRouteTrust, RelayTicket};
use hns_hrm::validation::{
    AuthenticatedNameState, ResolvedManifest, RollbackObservations, ValidatedCurrentManifest,
    ValidationLimits, validate_current_manifest,
};
use hns_service_authority::authority_state::{
    CommittedNamedService, NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot,
    NamedServiceAuthorityState, NamedServiceAuthorityStorageState,
    ReconfirmedNamedServiceAuthorityState,
};
use hns_service_authority::hrm::{
    NamedServiceIdentity, NamedServicePolicy, VerifiedNamedService, observe_named_service,
};
use hns_service_authority::lease::{
    AuthorityLeaseKey, FencedLeaseGuard, FencingToken, HeldAuthorityLease, LeaseError,
    LeaseScopeError, StorageNamespaceId,
};
use hns_service_authority::{
    AuthorityRecord, EndpointDelegationV1 as LegacyEndpointDelegationV1, ServiceAuthorizationV1,
    ServiceIdentity,
};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_700_000_300;
const MAGIC: u32 = 2_922_943_951;
const PROFILE: u16 = 0xff00;

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

fn array<const N: usize>(name: &str) -> [u8; N] {
    bytes(name)
        .try_into()
        .unwrap_or_else(|_| panic!("invalid fixture array {name}"))
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

fn ledger_checksum(payload: &[u8]) -> [u8; 32] {
    blake2b_256(&[b"HNSR-NAMED-V3-LEDGER-SNAPSHOT-V1\0", payload])
}

fn rechecksum_ledger_snapshot(encoded: &mut [u8]) {
    let payload_len = encoded.len() - 32;
    let checksum = ledger_checksum(&encoded[..payload_len]);
    encoded[payload_len..].copy_from_slice(&checksum);
}

fn identity() -> NamedServiceIdentity {
    NamedServiceIdentity::new(MAGIC, [15; 32], "pool-stats", PROFILE).expect("identity")
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

fn current_manifest(envelope_name: &str, sequence: u64) -> ValidatedCurrentManifest {
    current_manifest_at(envelope_name, sequence, NOW, ValidationLimits::default())
}

fn current_manifest_at(
    envelope_name: &str,
    sequence: u64,
    now: u64,
    limits: ValidationLimits,
) -> ValidatedCurrentManifest {
    let identity = identity();
    let root = authority_manifest(envelope_name, sequence);
    validate_current_manifest(
        root,
        MAGIC,
        identity.name_hash,
        now,
        limits,
        &RollbackObservations::new(),
    )
    .expect("current HRM manifest")
}

fn authority_manifest(envelope_name: &str, sequence: u64) -> ResolvedManifest {
    let identity = identity();
    let envelope = bytes(envelope_name);
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

const TEST_AUTHORITY_STORAGE_NAMESPACE: [u8; 32] = [0xa7; 32];

#[derive(Debug)]
struct TestAuthorityGuard {
    key: AuthorityLeaseKey,
    fencing_token: FencingToken,
    control: TestAuthorityLeaseControl,
}

#[derive(Clone, Debug)]
struct TestAuthorityLeaseControl {
    checks: Rc<Cell<usize>>,
    lose_at: Rc<Cell<Option<usize>>>,
}

impl TestAuthorityLeaseControl {
    fn held() -> Self {
        Self {
            checks: Rc::new(Cell::new(0)),
            lose_at: Rc::new(Cell::new(None)),
        }
    }

    fn lose_on_second_future_check(&self) {
        self.lose_at.set(Some(self.checks.get() + 2));
    }
}

impl FencedLeaseGuard<AuthorityLeaseKey> for TestAuthorityGuard {
    fn key(&self) -> &AuthorityLeaseKey {
        &self.key
    }

    fn fencing_token(&self) -> FencingToken {
        self.fencing_token
    }

    fn ensure_held(&self) -> Result<(), LeaseError> {
        let checks = self.control.checks.get() + 1;
        self.control.checks.set(checks);
        if self
            .control
            .lose_at
            .get()
            .is_some_and(|lose_at| checks >= lose_at)
        {
            Err(LeaseError::Lost)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct TestAuthorityDurable {
    encoded: Option<Vec<u8>>,
    minimum_revision: u64,
    current_fence: FencingToken,
}

impl TestAuthorityDurable {
    fn load(&self) -> NamedServiceAuthorityStorageState {
        match &self.encoded {
            Some(encoded) => NamedServiceAuthorityStorageState::Present {
                encoded: encoded.clone(),
                minimum_revision: self.minimum_revision,
            },
            None => NamedServiceAuthorityStorageState::Absent,
        }
    }

    fn persist(
        &mut self,
        expectation: NamedServiceAuthorityExpectation,
        proposed: &NamedServiceAuthoritySnapshot,
    ) -> Result<(), ()> {
        assert_eq!(
            expectation.storage_namespace_id().as_bytes(),
            &TEST_AUTHORITY_STORAGE_NAMESPACE
        );
        assert_eq!(expectation.fencing_token(), self.current_fence);
        let proposed_encoded = proposed.encode().expect("authority snapshot encoding");
        if self.encoded.as_deref() == Some(proposed_encoded.as_slice()) {
            return Ok(());
        }
        match expectation {
            NamedServiceAuthorityExpectation::Absent { .. } => {
                assert!(self.encoded.is_none(), "authority create must be absent");
            }
            NamedServiceAuthorityExpectation::Exact {
                revision,
                fingerprint,
                ..
            } => {
                let current = NamedServiceAuthoritySnapshot::decode(
                    self.encoded.as_deref().expect("authority exact CAS value"),
                )
                .expect("authenticated authority snapshot");
                assert_eq!(current.revision(), revision);
                assert_eq!(
                    current.fingerprint().expect("authority fingerprint"),
                    fingerprint
                );
            }
        }
        self.minimum_revision = proposed.revision();
        self.encoded = Some(proposed_encoded);
        Ok(())
    }
}

#[derive(Debug)]
struct TestAuthority {
    state: NamedServiceAuthorityState,
    durable: TestAuthorityDurable,
    next_fence: u64,
}

impl TestAuthority {
    fn new() -> Self {
        let service_identity = identity();
        Self {
            state: NamedServiceAuthorityState::new(MAGIC, service_identity.name_hash, 1, NOW)
                .expect("authority state"),
            durable: TestAuthorityDurable {
                encoded: None,
                minimum_revision: 0,
                current_fence: FencingToken::new(1).expect("initial authority fence"),
            },
            next_fence: 1,
        }
    }

    fn run<R, F>(&mut self, operation: F) -> R
    where
        F: for<'lease> FnOnce(
            &mut ReconfirmedNamedServiceAuthorityState<'lease>,
            &mut TestAuthorityDurable,
        ) -> R,
    {
        self.run_controlled(|reconfirmed, durable, _| operation(reconfirmed, durable))
            .expect("held authority operation")
    }

    fn run_controlled<R, F>(&mut self, operation: F) -> Result<R, LeaseScopeError<()>>
    where
        F: for<'lease> FnOnce(
            &mut ReconfirmedNamedServiceAuthorityState<'lease>,
            &mut TestAuthorityDurable,
            TestAuthorityLeaseControl,
        ) -> R,
    {
        let identity = identity();
        let key = AuthorityLeaseKey::new(
            StorageNamespaceId::new(TEST_AUTHORITY_STORAGE_NAMESPACE).expect("authority namespace"),
            MAGIC,
            identity.name_hash,
        );
        let fence = FencingToken::new(self.next_fence).expect("authority fence");
        self.next_fence = self
            .next_fence
            .checked_add(1)
            .expect("authority fence space");
        self.durable.current_fence = fence;
        let control = TestAuthorityLeaseControl::held();
        let guard_control = control.clone();
        let lease = HeldAuthorityLease::acquire(key, |requested| {
            Ok::<_, ()>(TestAuthorityGuard {
                key: *requested,
                fencing_token: fence,
                control: guard_control,
            })
        })
        .expect("authority lease");
        let state = &mut self.state;
        let durable = &mut self.durable;
        lease.run(|witness| {
            let storage = durable.load();
            let mut reconfirmed = state
                .reconfirm(witness, |_| Ok::<_, ()>(storage))
                .expect("reconfirmed authority state");
            Ok::<_, ()>(operation(&mut reconfirmed, durable, control))
        })
    }
}

fn committed_active_authority() -> (TestAuthority, CommittedNamedService) {
    let service_identity = identity();
    let mut authority = TestAuthority::new();
    let sequence: u64 = fixture("hrm_sequence").parse().expect("HRM sequence");
    let committed = authority.run(|reconfirmed, durable| {
        reconfirmed
            .retrieve_validate_and_observe(
                NOW,
                |_| Ok::<_, std::convert::Infallible>(authority_manifest("hrm_envelope", sequence)),
                &service_identity,
                &service_policy(),
                ValidationLimits::default(),
                &mut |expectation, proposed| durable.persist(expectation, proposed),
            )
            .expect("committed active authority")
    });
    (authority, committed)
}

fn advance_authority_to_withdrawal(authority: &mut TestAuthority) -> CommittedNamedService {
    let service_identity = identity();
    let sequence: u64 = fixture("hrm_sequence").parse().expect("HRM sequence");
    authority.run(|reconfirmed, durable| {
        let mut persist = |expectation, proposed: &NamedServiceAuthoritySnapshot| {
            durable.persist(expectation, proposed)
        };
        reconfirmed
            .retrieve_validate_and_observe(
                NOW,
                |_| {
                    Ok::<_, std::convert::Infallible>(authority_manifest(
                        "replacement_hrm_envelope",
                        sequence + 1,
                    ))
                },
                &service_identity,
                &service_policy(),
                ValidationLimits::default(),
                &mut persist,
            )
            .expect("committed replacement authority");
        reconfirmed
            .retrieve_validate_and_observe(
                NOW,
                |_| {
                    Ok::<_, std::convert::Infallible>(authority_manifest(
                        "removal_hrm_envelope",
                        sequence + 2,
                    ))
                },
                &service_identity,
                &service_policy(),
                ValidationLimits::default(),
                &mut persist,
            )
            .expect("committed withdrawn authority")
    })
}

fn verified_service() -> VerifiedNamedService {
    let identity = identity();
    let sequence = fixture("hrm_sequence").parse().expect("HRM sequence");
    let manifest = current_manifest("hrm_envelope", sequence);
    observe_named_service(&manifest, &identity, &service_policy(), None)
        .expect("observe service")
        .into_active()
        .expect("active service")
}

fn verified_service_with_cache(now: u64, maximum_cache_lifetime: u64) -> VerifiedNamedService {
    let identity = identity();
    let sequence = fixture("hrm_sequence").parse().expect("HRM sequence");
    let manifest = current_manifest_at(
        "hrm_envelope",
        sequence,
        now,
        ValidationLimits {
            maximum_cache_lifetime,
            ..ValidationLimits::default()
        },
    );
    observe_named_service(&manifest, &identity, &service_policy(), None)
        .expect("observe service")
        .into_active()
        .expect("active service")
}

fn route(name: &str) -> NamedRouteRecordV3 {
    NamedRouteRecordV3::decode(&bytes(name)).unwrap_or_else(|_| panic!("decode {name}"))
}

fn signed_route(
    template: &NamedRouteRecordV3,
    sequence: u64,
    expires_at: u64,
) -> NamedRouteRecordV3 {
    signed_route_interval(template, sequence, template.issued_at, expires_at)
}

fn signed_route_interval(
    template: &NamedRouteRecordV3,
    sequence: u64,
    issued_at: u64,
    expires_at: u64,
) -> NamedRouteRecordV3 {
    let mut candidate = template.clone();
    candidate.record_sequence = sequence;
    candidate.issued_at = issued_at;
    candidate.expires_at = expires_at;
    candidate.endpoint_signature.clear();
    candidate.sign(&[4; 32]).expect("sign route variant");
    candidate
}

fn alternate_endpoint_route(template: &NamedRouteRecordV3, expires_at: u64) -> NamedRouteRecordV3 {
    let mut route = template.clone();
    route.endpoint_delegation = hns_service_authority::hrm::EndpointDelegationV1::decode(&bytes(
        "alternate_endpoint_key_endpoint",
    ))
    .expect("alternate endpoint");
    route.tickets[0].endpoint_key = route.endpoint_delegation.endpoint_key;
    route.tickets[0].relay_signature.clear();
    route.tickets[0]
        .sign_relay(&[5; 32])
        .expect("alternate relay ticket");
    route.tickets[0].endpoint_signature.clear();
    route.tickets[0]
        .sign_endpoint(&[7; 32])
        .expect("alternate ticket confirmation");
    route.expires_at = expires_at;
    route.endpoint_signature.clear();
    route.sign(&[7; 32]).expect("alternate route");
    route
}

fn endpoint_sequence_route(
    template: &NamedRouteRecordV3,
    endpoint_sequence: u64,
    record_sequence: u64,
) -> NamedRouteRecordV3 {
    let mut route = template.clone();
    route.endpoint_delegation.endpoint_sequence = endpoint_sequence;
    route.endpoint_delegation.service_signature.clear();
    route
        .endpoint_delegation
        .sign_uncommitted(&verified_service(), NOW, &[3; 32])
        .expect("sign endpoint delegation variant");
    route.record_sequence = record_sequence;
    route.endpoint_signature.clear();
    route.sign(&[4; 32]).expect("sign endpoint sequence route");
    route
}

fn low_capacity_limits(capacity: usize) -> RouteStoreLimits {
    RouteStoreLimits {
        total_records: capacity,
        records_per_key: capacity.min(16),
        records_per_source: capacity.max(1),
        ..RouteStoreLimits::default()
    }
}

#[test]
fn independent_route_vector_round_trips_and_verifies_both_trust_levels() {
    let service = verified_service();
    let record = route("named_route_record_v3");

    assert_eq!(
        record.encode().expect("encode"),
        bytes("named_route_record_v3")
    );
    assert_eq!(
        record.encode_body().expect("body"),
        bytes("named_route_body_v3")
    );
    assert_eq!(record.route_key, array::<32>("named_route_key"));
    assert_eq!(
        record.route_key,
        named_route_key_v3(service.identity()).expect("key")
    );
    assert_eq!(record.record_sequence, 9_007_199_254_741_013);
    assert_eq!(
        record
            .endpoint_delegation
            .encode_body()
            .expect("endpoint body"),
        bytes("endpoint_delegation_body")
    );
    assert_eq!(
        record.endpoint_delegation.service_signature,
        bytes("endpoint_delegation_signature")
    );
    assert_eq!(
        blake2b_256(&[
            b"HNS-HRM-HNSA-ENDPOINT-DELEGATION-V1\0",
            &bytes("endpoint_delegation_body"),
        ]),
        array::<32>("endpoint_delegation_signature_digest")
    );
    assert_eq!(
        record.endpoint_delegation.id().expect("endpoint ID"),
        array::<32>("endpoint_delegation_id")
    );
    assert_eq!(
        record.tickets[0].encode_unsigned().expect("ticket body"),
        bytes("relay_ticket_unsigned")
    );
    assert_eq!(
        record.tickets[0].relay_signature,
        bytes("relay_ticket_relay_signature")
    );
    assert_eq!(
        record.tickets[0].endpoint_signature,
        bytes("relay_ticket_endpoint_confirmation_signature")
    );
    assert_eq!(
        blake2b_256(&[b"HNSR-RELAY-TICKET-V1\0", &bytes("relay_ticket_unsigned"),]),
        array::<32>("relay_ticket_relay_signature_digest")
    );
    assert_eq!(
        blake2b_256(&[
            b"HNSR-RELAY-CONFIRM-V1\0",
            &bytes("relay_ticket_unsigned"),
            &bytes("relay_ticket_relay_signature"),
        ]),
        array::<32>("relay_ticket_endpoint_confirmation_digest")
    );
    assert_eq!(
        record.tickets[0].encode().expect("ticket"),
        bytes("relay_ticket")
    );
    assert_eq!(
        record.tickets[0].id().expect("ticket ID"),
        array::<32>("relay_ticket_id")
    );
    assert_eq!(record.endpoint_signature, bytes("named_route_signature"));
    assert_eq!(
        blake2b_256(&[
            b"HNSR-HRM-HNSA-ROUTE-RECORD-V3\0",
            &bytes("named_route_body_v3"),
        ]),
        array::<32>("named_route_signature_digest")
    );
    record
        .verify_admission(NOW, true)
        .expect("internal admission");
    let verified = record
        .verify_current_uncommitted(&service, route_policy(), NOW)
        .expect("current HRM/HNSA route");
    assert_eq!(verified.cache_until(), 1_700_001_100);
    assert_eq!(verified.record(), &record);
    assert_eq!(verified.service(), &service);
    assert!(
        record
            .verify_current_uncommitted(&service, route_policy(), service.validated_at() - 1)
            .is_err()
    );

    let mut resigned = record.clone();
    resigned.endpoint_signature.clear();
    resigned
        .sign_current_uncommitted(&service, route_policy(), NOW, &[4; 32])
        .expect("current deterministic publication signature");
    assert_eq!(
        resigned.encode().expect("encode"),
        bytes("named_route_record_v3")
    );
    assert!(
        resigned
            .sign_current_uncommitted(&service, route_policy(), NOW, &[8; 32])
            .is_err()
    );

    let mut invalid_ticket = record.clone();
    invalid_ticket.tickets[0].relay_signature[10] ^= 1;
    let original_signature = invalid_ticket.endpoint_signature.clone();
    assert!(
        invalid_ticket
            .sign_current_uncommitted(&service, route_policy(), NOW, &[4; 32])
            .is_err()
    );
    assert_eq!(invalid_ticket.endpoint_signature, original_signature);
}

#[test]
fn route_cache_deadline_requires_fresh_hrm_validation_not_shorter_signed_authority() {
    let identity = identity();
    let sequence = fixture("hrm_sequence").parse().expect("HRM sequence");
    let limits = ValidationLimits {
        maximum_cache_lifetime: 60,
        ..ValidationLimits::default()
    };
    let manifest = current_manifest_at("hrm_envelope", sequence, NOW, limits);
    let service = observe_named_service(&manifest, &identity, &service_policy(), None)
        .expect("service")
        .into_active()
        .expect("active");
    let record = route("named_route_record_v3");
    let verified = record
        .verify_current_uncommitted(&service, route_policy(), NOW)
        .expect("route valid at decision time");
    assert_eq!(verified.cache_until(), NOW + 60);
    assert!(record.expires_at > verified.cache_until());
    assert!(
        record
            .verify_current_uncommitted(&service, route_policy(), NOW + 60)
            .is_err()
    );

    let refreshed_manifest = current_manifest_at("hrm_envelope", sequence, NOW + 60, limits);
    let refreshed = observe_named_service(
        &refreshed_manifest,
        &identity,
        &service_policy(),
        Some(service.generation_observation()),
    )
    .expect("refreshed service")
    .into_active()
    .expect("active refreshed service");
    record
        .verify_current_uncommitted(&refreshed, route_policy(), NOW + 60)
        .expect("fresh HRM decision accepts still-signed route");
}

#[test]
fn route_policy_requires_service_flags_as_an_allowed_subset() {
    let service = verified_service();
    let record = route("named_route_record_v3");
    let mut invalid_policy = route_policy();
    invalid_policy.required_service_flags = 1;
    assert!(
        record
            .verify_current_uncommitted(&service, invalid_policy, NOW)
            .is_err()
    );

    let mut unmet_policy = route_policy();
    unmet_policy.allowed_service_flags = 1;
    unmet_policy.required_service_flags = 1;
    assert!(
        record
            .verify_current_uncommitted(&service, unmet_policy, NOW)
            .is_err()
    );
}

#[test]
fn malformed_and_cross_model_vectors_fail_closed() {
    for name in [
        "zero_sequence_route",
        "mismatched_resource_route",
        "wrong_delegation_id_route",
        "wrong_generation_route",
        "over_lifetime_route",
        "wrong_ticket_network_route",
        "route_before_ticket",
        "route_after_ticket",
        "nonminimal_der_relay_ticket_route",
        "nonminimal_der_ticket_confirmation_route",
        "zero_ticket_route",
        "duplicate_ticket_route",
        "nine_ticket_route",
        "high_s_route",
        "nonminimal_der_route",
        "invalid_endpoint_length_route",
        "legacy_named_route_record_v2",
        "legacy_v2_authority_v1_route",
        "wrong_v3_authority_v1_route",
        "wrong_v2_authority_v2_route",
        "trailing_route",
    ] {
        assert!(
            NamedRouteRecordV3::decode(&bytes(name)).is_err(),
            "{name} was accepted"
        );
    }

    for name in [
        "wrong_controller_key_route",
        "not_current_route",
        "expired_route",
        "route_before_endpoint",
        "route_after_endpoint",
    ] {
        let record = route(name);
        assert!(record.verify_admission(NOW, true).is_err(), "{name}");
    }

    let service = verified_service();
    for name in [
        "wrong_route_key_route",
        "wrong_profile_route",
        "wrong_embedded_endpoint_route",
    ] {
        let record = route(name);
        record
            .verify_admission(NOW, true)
            .unwrap_or_else(|_| panic!("{name} must remain internally consistent"));
        assert!(
            record
                .verify_current_uncommitted(&service, route_policy(), NOW)
                .is_err(),
            "{name} matched current authority"
        );
    }
}

#[test]
fn real_legacy_fixture_preserves_the_complete_v2_compatibility_chain() {
    const LEGACY_NOW: u64 = 1_700_000_000;
    let authority = AuthorityRecord::parse(fixture("legacy_hsa1_authority_record"))
        .expect("legacy authority record");
    assert_eq!(
        authority.encode().expect("authority encode"),
        fixture("legacy_hsa1_authority_record")
    );

    let authorization = ServiceAuthorizationV1::decode(&bytes("legacy_service_authorization"))
        .expect("legacy authorization");
    assert_eq!(
        authorization
            .encode_unsigned()
            .expect("unsigned authorization"),
        bytes("legacy_service_authorization_unsigned")
    );
    assert_eq!(
        authorization.root_signature,
        bytes("legacy_service_authorization_signature")
    );
    assert_eq!(
        blake2b_256(&[
            b"HNS-SERVICE-AUTH-V1\0",
            &bytes("legacy_service_authorization_unsigned")[1..],
        ]),
        array::<32>("legacy_service_authorization_signature_digest")
    );
    assert_eq!(
        authorization.id().expect("authorization ID"),
        array::<32>("legacy_service_authorization_id")
    );
    assert_eq!(
        blake2b_256(&[
            b"HNS-SERVICE-AUTH-ID-V1\0",
            &bytes("legacy_service_authorization"),
        ]),
        array::<32>("legacy_service_authorization_id")
    );
    assert_eq!(
        authorization.encode().expect("authorization encode"),
        bytes("legacy_service_authorization")
    );
    let identity = ServiceIdentity {
        network_magic: MAGIC,
        name_hash: array("name_hash"),
        service_name: fixture("service_name").to_owned(),
        profile_id: PROFILE,
    };
    authorization
        .verify(&authority, &identity, 150, 0)
        .expect("legacy authorization trust");

    let delegation = LegacyEndpointDelegationV1::decode(&bytes("legacy_endpoint_delegation"))
        .expect("legacy endpoint delegation");
    assert_eq!(
        delegation.encode_unsigned().expect("unsigned delegation"),
        bytes("legacy_endpoint_delegation_unsigned")
    );
    assert_eq!(
        delegation.service_signature,
        bytes("legacy_endpoint_delegation_signature")
    );
    assert_eq!(
        blake2b_256(&[
            b"HNS-ENDPOINT-DELEGATION-V1\0",
            &bytes("legacy_endpoint_delegation_unsigned")[1..],
        ]),
        array::<32>("legacy_endpoint_delegation_signature_digest")
    );
    assert_eq!(
        delegation.id().expect("delegation ID"),
        array::<32>("legacy_endpoint_delegation_id")
    );
    assert_eq!(
        blake2b_256(&[
            b"HNS-ENDPOINT-DELEGATION-ID-V1\0",
            &bytes("legacy_endpoint_delegation"),
        ]),
        array::<32>("legacy_endpoint_delegation_id")
    );
    assert_eq!(
        delegation.encode().expect("delegation encode"),
        bytes("legacy_endpoint_delegation")
    );
    delegation
        .verify(&authorization, LEGACY_NOW, 1, [0; 32])
        .expect("legacy endpoint trust");

    let ticket = RelayTicket::decode(&bytes("legacy_relay_ticket")).expect("legacy relay ticket");
    assert_eq!(
        ticket.encode().expect("ticket encode"),
        bytes("legacy_relay_ticket")
    );
    ticket
        .verify_for_profile(MAGIC, PROFILE, LEGACY_NOW, true)
        .expect("legacy ticket verification");

    let route = NamedRouteRecordV2::decode(&bytes("legacy_named_route_record_v2"))
        .expect("real legacy V2 route");
    assert_eq!(
        route.encode_unsigned().expect("legacy route body"),
        bytes("legacy_named_route_body_v2")
    );
    assert_eq!(
        route.endpoint_signature,
        bytes("legacy_named_route_signature")
    );
    assert_eq!(
        blake2b_256(&[
            b"HNSR-HNSA-ROUTE-RECORD-V2\0",
            &bytes("legacy_named_route_body_v2"),
        ]),
        array::<32>("legacy_named_route_signature_digest")
    );
    assert_eq!(route.authorization, authorization);
    assert_eq!(route.delegation, delegation);
    assert_eq!(route.tickets, vec![ticket]);
    assert_eq!(
        route.encode().expect("legacy route encode"),
        bytes("legacy_named_route_record_v2")
    );
    route
        .verify_untrusted_admission(LEGACY_NOW, true)
        .expect("legacy internal admission");
    route
        .verify(
            &NamedRouteTrust {
                authority: &authority,
                identity: &identity,
                current_height: 150,
                policy: NamedRoutePolicy {
                    maximum_route_lifetime: 900,
                    allowed_authorization_flags: 0,
                    allowed_endpoint_capabilities: 1,
                    required_endpoint_capabilities: 1,
                    expected_constraints_hash: [0; 32],
                    allow_private_relays: true,
                },
            },
            LEGACY_NOW,
        )
        .expect("complete legacy current trust");
    assert!(NamedRouteRecordV3::decode(&bytes("legacy_named_route_record_v2")).is_err());
}

#[test]
fn store_validates_before_poisoning_and_greater_sequence_recovers_scope() {
    let first = route("named_route_record_v3");
    let key = first.route_key;
    let endpoint_key = first.endpoint_delegation.endpoint_key;
    let raw = first.encode().expect("route");
    let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");

    store
        .put_named_v3_for_admission(key, raw.clone(), NOW, "peer-a".to_owned())
        .expect("first insert");
    store
        .put_named_v3_for_admission(key, raw, NOW, "peer-b".to_owned())
        .expect("idempotent duplicate");

    let mut bad_route_signature = bytes("named_route_record_v3");
    *bad_route_signature.last_mut().expect("route signature") ^= 1;
    assert!(
        store
            .put_named_v3_for_admission(key, bad_route_signature, NOW, "peer-b".to_owned(),)
            .is_err()
    );
    assert!(!store.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW));

    let mut bad_ticket_signature = first.clone();
    bad_ticket_signature.tickets[0].relay_signature[10] ^= 1;
    bad_ticket_signature.endpoint_signature.clear();
    bad_ticket_signature
        .sign(&[4; 32])
        .expect("route signature over malformed ticket proof");
    assert!(
        store
            .put_named_v3_for_admission(
                key,
                bad_ticket_signature.encode().expect("canonical route"),
                NOW,
                "peer-b".to_owned(),
            )
            .is_err()
    );
    assert!(!store.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW));

    assert!(
        store
            .put_named_v3_for_admission(
                key,
                bytes("wrong_ticket_network_route"),
                NOW,
                "peer-b".to_owned(),
            )
            .is_err()
    );
    assert!(!store.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW));
    assert_eq!(store.get_named_v3(&key, 8, NOW).len(), 1);

    assert!(matches!(
        store.put_named_v3_for_admission(
            key,
            bytes("conflicting_route_same_sequence"),
            NOW,
            "peer-c".to_owned(),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    assert!(store.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW));
    assert!(store.get_named_v3(&key, 8, NOW).is_empty());
    assert!(store.sample(8, &[9; 32], NOW).is_empty());

    let mut newer = first;
    newer.record_sequence += 1;
    newer.endpoint_signature.clear();
    newer.sign(&[4; 32]).expect("new route");
    store
        .put_named_v3_for_admission(
            key,
            newer.encode().expect("new route"),
            NOW,
            "peer-d".to_owned(),
        )
        .expect("greater sequence clears conflict");
    assert!(!store.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW));
    assert_eq!(store.get_named_v3(&key, 8, NOW).len(), 1);
}

#[test]
fn endpoint_and_route_product_lattice_survives_restart() {
    let template = route("named_route_record_v3");
    let key = template.route_key;
    let endpoint_key = template.endpoint_delegation.endpoint_key;
    let endpoint_sequence = template.endpoint_delegation.endpoint_sequence;
    let e2_r10 = endpoint_sequence_route(&template, endpoint_sequence + 1, 10);
    let e3_r9 = endpoint_sequence_route(&template, endpoint_sequence + 2, 9);
    let e2_r11 = endpoint_sequence_route(&template, endpoint_sequence + 1, 11);
    let e3_r11 = endpoint_sequence_route(&template, endpoint_sequence + 2, 11);
    let e3_r12 = endpoint_sequence_route(&template, endpoint_sequence + 2, 12);
    let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
    store
        .put_named_v3_for_admission(
            key,
            e2_r10.encode().expect("E2/R10"),
            NOW,
            "peer-a".to_owned(),
        )
        .expect("store E2/R10");

    let before_endpoint_advance = store.named_v3_ledger_revision();
    assert!(matches!(
        store.put_named_v3_for_admission(
            key,
            e3_r9.encode().expect("E3/R9"),
            NOW + 10,
            "peer-b".to_owned(),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));
    assert!(store.named_v3_ledger_revision() > before_endpoint_advance);
    assert!(store.get_named_v3(&key, 1, NOW + 10).is_empty());

    let snapshot = store.named_v3_ledger_snapshot(NOW + 10).unwrap();
    let mut restored = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    restored
        .restore_named_v3_ledger(snapshot.clone(), NOW + 10, snapshot.revision())
        .unwrap();

    // Endpoint-stale does not make a possible route advance cheap: invalid
    // bytes fail before either durable dimension can change.
    let mut invalid_e2_r11 = e2_r11.clone();
    *invalid_e2_r11.endpoint_signature.last_mut().unwrap() ^= 1;
    let before_invalid = restored.named_v3_ledger_snapshot(NOW + 10).unwrap();
    assert!(matches!(
        restored.put_named_v3_for_admission(
            key,
            invalid_e2_r11.encode().expect("canonical invalid E2/R11"),
            NOW + 10,
            "peer-c".to_owned(),
        ),
        Err(HnsrProtocolError::Cryptography)
    ));
    assert_eq!(
        restored.named_v3_ledger_snapshot(NOW + 10).unwrap(),
        before_invalid
    );

    // E2 is stale, but its greater R11 observation still advances the route
    // dimension and leaves no live record realizing the split maxima E3/R11.
    let before_route_advance = restored.named_v3_ledger_revision();
    assert!(matches!(
        restored.put_named_v3_for_admission(
            key,
            e2_r11.encode().expect("E2/R11"),
            NOW + 10,
            "peer-d".to_owned(),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));
    assert!(restored.named_v3_ledger_revision() > before_route_advance);
    assert!(restored.get_named_v3(&key, 1, NOW + 10).is_empty());

    let split_snapshot = restored.named_v3_ledger_snapshot(NOW + 10).unwrap();
    let mut split_restored = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    split_restored
        .restore_named_v3_ledger(split_snapshot.clone(), NOW + 10, split_snapshot.revision())
        .unwrap();

    // E3/R11 cannot reuse R11 after E2/R11 established its canonical hash.
    assert!(matches!(
        split_restored.put_named_v3_for_admission(
            key,
            e3_r11.encode().expect("E3/R11"),
            NOW + 10,
            "peer-e".to_owned(),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    assert!(split_restored.is_conflicted(
        RouteRecordModel::HrmNamedV3,
        &key,
        &endpoint_key,
        NOW + 10,
    ));
    assert!(split_restored.get_named_v3(&key, 1, NOW + 10).is_empty());

    split_restored
        .put_named_v3_for_admission(
            key,
            e3_r12.encode().expect("E3/R12"),
            NOW + 10,
            "peer-f".to_owned(),
        )
        .expect("E3/R12 realizes both independent maxima");
    assert!(!split_restored.is_conflicted(
        RouteRecordModel::HrmNamedV3,
        &key,
        &endpoint_key,
        NOW + 10,
    ));
    assert_eq!(
        split_restored.get_named_v3(&key, 1, NOW + 10),
        vec![e3_r12.encode().unwrap()]
    );
}

#[test]
fn split_product_maxima_are_order_independent_and_require_a_joining_record() {
    let template = route("named_route_record_v3");
    let key = template.route_key;
    let endpoint_sequence = template.endpoint_delegation.endpoint_sequence;
    let e1_r100 = endpoint_sequence_route(&template, endpoint_sequence, 100);
    let e2_r10 = endpoint_sequence_route(&template, endpoint_sequence + 1, 10);
    let e2_r101 = endpoint_sequence_route(&template, endpoint_sequence + 1, 101);

    let mut left = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    left.put_named_v3_for_admission(key, e1_r100.encode().unwrap(), NOW, "left-a".to_owned())
        .unwrap();
    assert!(matches!(
        left.put_named_v3_for_admission(key, e2_r10.encode().unwrap(), NOW, "left-b".to_owned(),),
        Err(HnsrProtocolError::StaleSequence)
    ));

    let mut right = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    right
        .put_named_v3_for_admission(key, e2_r10.encode().unwrap(), NOW, "right-a".to_owned())
        .unwrap();
    assert!(matches!(
        right
            .put_named_v3_for_admission(key, e1_r100.encode().unwrap(), NOW, "right-b".to_owned(),),
        Err(HnsrProtocolError::StaleSequence)
    ));

    assert!(left.get_named_v3(&key, 8, NOW).is_empty());
    assert!(right.get_named_v3(&key, 8, NOW).is_empty());
    assert_eq!(
        left.named_v3_ledger_snapshot(NOW).unwrap(),
        right.named_v3_ledger_snapshot(NOW).unwrap()
    );

    for (store, source) in [(&mut left, "left-c"), (&mut right, "right-c")] {
        store
            .put_named_v3_for_admission(key, e2_r101.encode().unwrap(), NOW, source.to_owned())
            .expect("one record joins both product maxima");
        assert_eq!(
            store.get_named_v3(&key, 8, NOW),
            vec![e2_r101.encode().unwrap()]
        );
    }
    assert_eq!(
        left.named_v3_ledger_snapshot(NOW).unwrap(),
        right.named_v3_ledger_snapshot(NOW).unwrap()
    );
}

#[test]
fn stale_endpoint_still_creates_an_equal_route_conflict() {
    let template = route("named_route_record_v3");
    let key = template.route_key;
    let endpoint_key = template.endpoint_delegation.endpoint_key;
    let endpoint_sequence = template.endpoint_delegation.endpoint_sequence;
    let e3_r10 = endpoint_sequence_route(&template, endpoint_sequence + 2, 10);
    let e2_r10 = endpoint_sequence_route(&template, endpoint_sequence + 1, 10);
    let e3_r11 = endpoint_sequence_route(&template, endpoint_sequence + 2, 11);
    let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();

    store
        .put_named_v3_for_admission(key, e3_r10.encode().unwrap(), NOW, "peer-a".to_owned())
        .unwrap();
    assert!(matches!(
        store.put_named_v3_for_admission(key, e2_r10.encode().unwrap(), NOW, "peer-b".to_owned(),),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    assert!(store.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW));
    assert!(store.get_named_v3(&key, 8, NOW).is_empty());

    store
        .put_named_v3_for_admission(key, e3_r11.encode().unwrap(), NOW, "peer-c".to_owned())
        .expect("greater route clears only the route conflict");
    assert_eq!(
        store.get_named_v3(&key, 8, NOW),
        vec![e3_r11.encode().unwrap()]
    );
}

#[test]
fn equal_conflict_tombstones_are_canonical_across_observation_order() {
    let template = route("named_route_record_v3");
    let key = template.route_key;
    let mut conflict = template.clone();
    conflict.endpoint_delegation.expires_at -= 1;
    conflict.endpoint_delegation.service_signature.clear();
    conflict
        .endpoint_delegation
        .sign_uncommitted(&verified_service(), NOW, &[3; 32])
        .expect("sign conflicting endpoint delegation");
    conflict.endpoint_signature.clear();
    conflict.sign(&[4; 32]).expect("sign conflicting route");

    let mut left = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    left.put_named_v3_for_admission(key, template.encode().unwrap(), NOW, "left-a".to_owned())
        .unwrap();
    assert!(matches!(
        left.put_named_v3_for_admission(key, conflict.encode().unwrap(), NOW, "left-b".to_owned(),),
        Err(HnsrProtocolError::ConflictingSequence)
    ));

    let mut right = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    right
        .put_named_v3_for_admission(key, conflict.encode().unwrap(), NOW, "right-a".to_owned())
        .unwrap();
    assert!(matches!(
        right.put_named_v3_for_admission(
            key,
            template.encode().unwrap(),
            NOW,
            "right-b".to_owned(),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));

    assert!(left.get_named_v3(&key, 8, NOW).is_empty());
    assert!(right.get_named_v3(&key, 8, NOW).is_empty());
    let left_snapshot = left.named_v3_ledger_snapshot(NOW).unwrap();
    let right_snapshot = right.named_v3_ledger_snapshot(NOW).unwrap();
    assert_eq!(left_snapshot, right_snapshot);
    assert_eq!(left_snapshot.fingerprint(), right_snapshot.fingerprint());
}

#[test]
fn equal_endpoint_sequence_distinct_delegations_require_a_product_join() {
    let template = route("named_route_record_v3");
    let key = template.route_key;
    let endpoint_key = template.endpoint_delegation.endpoint_key;
    let mut conflict = template.clone();
    conflict.endpoint_delegation.expires_at -= 1;
    conflict.endpoint_delegation.service_signature.clear();
    conflict
        .endpoint_delegation
        .sign_uncommitted(&verified_service(), NOW, &[3; 32])
        .expect("sign conflicting endpoint delegation");
    conflict.endpoint_signature.clear();
    conflict.sign(&[4; 32]).expect("sign conflicting route");
    let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    store
        .put_named_v3_for_admission(key, template.encode().unwrap(), NOW, "peer-a".to_owned())
        .unwrap();
    assert!(matches!(
        store
            .put_named_v3_for_admission(key, conflict.encode().unwrap(), NOW, "peer-b".to_owned(),),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    assert!(store.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW));
    assert!(store.get_named_v3(&key, 8, NOW).is_empty());

    let greater_route_same_endpoint =
        signed_route(&template, template.record_sequence + 1, template.expires_at);
    assert!(matches!(
        store.put_named_v3_for_admission(
            key,
            greater_route_same_endpoint.encode().unwrap(),
            NOW,
            "peer-c".to_owned(),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));

    let endpoint_advance = endpoint_sequence_route(
        &template,
        template.endpoint_delegation.endpoint_sequence + 1,
        template.record_sequence + 1,
    );
    assert!(matches!(
        store.put_named_v3_for_admission(
            key,
            endpoint_advance.encode().unwrap(),
            NOW,
            "peer-d".to_owned(),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    assert!(store.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW));
    assert!(store.get_named_v3(&key, 8, NOW).is_empty());

    let joint_advance = endpoint_sequence_route(
        &template,
        template.endpoint_delegation.endpoint_sequence + 1,
        template.record_sequence + 2,
    );
    store
        .put_named_v3_for_admission(
            key,
            joint_advance.encode().unwrap(),
            NOW,
            "peer-e".to_owned(),
        )
        .expect("greater route joins the advanced endpoint and clears both conflicts");
    assert!(!store.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW));
    assert_eq!(
        store.get_named_v3(&key, 8, NOW),
        vec![joint_advance.encode().unwrap()]
    );
}

#[test]
fn verified_later_stale_route_extends_storage_horizon_across_restart() {
    let template = route("named_route_record_v3");
    let key = template.route_key;
    let endpoint_key = template.endpoint_delegation.endpoint_key;
    let sequence = template.record_sequence;
    let later = NOW + 100;
    let original_horizon = NOW + MAX_ROUTE_LIFETIME;
    let extended_horizon = later + MAX_ROUTE_LIFETIME;
    let short = signed_route(&template, sequence + 1, NOW + 10);
    let lower_long = signed_route_interval(&template, sequence, later, NOW + 500);
    let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");

    store
        .put_named_v3_for_admission(
            key,
            short.encode().expect("short"),
            NOW,
            "peer-a".to_owned(),
        )
        .expect("sequence 10");
    let revision = store.named_v3_ledger_revision();
    assert_eq!(store.get_named_v3(&key, 8, NOW + 10).len(), 0);
    let mut invalid_lower = lower_long.clone();
    *invalid_lower.endpoint_signature.last_mut().unwrap() ^= 1;
    assert!(matches!(
        store.put_named_v3_for_admission(
            key,
            invalid_lower.encode().expect("canonical invalid lower"),
            later,
            "peer-invalid".to_owned(),
        ),
        Err(HnsrProtocolError::Cryptography)
    ));
    assert_eq!(store.named_v3_ledger_revision(), revision);
    assert!(matches!(
        store.put_named_v3_for_admission(
            key,
            lower_long.encode().expect("lower"),
            later,
            "peer-b".to_owned(),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));
    assert!(store.named_v3_ledger_revision() > revision);

    let snapshot = store.named_v3_ledger_snapshot(later).expect("snapshot");
    let encoded = snapshot.encode();
    assert_eq!(
        NamedRouteV3LedgerSnapshot::decode(&encoded).unwrap(),
        snapshot
    );
    let mut restored =
        RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("restored store");
    restored
        .restore_named_v3_ledger(
            NamedRouteV3LedgerSnapshot::decode(&encoded).expect("decode"),
            later,
            snapshot.revision(),
        )
        .expect("restore");
    assert!(matches!(
        restored.put_named_v3_for_admission(
            key,
            lower_long.encode().expect("lower"),
            later,
            "peer-c".to_owned(),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));
    assert_eq!(restored.named_v3_ledger_len(), 1);
    assert!(!restored.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, later,));
    assert_eq!(restored.prune_named_v3_ledger(NOW + 500).unwrap(), 0);
    assert_eq!(restored.prune_named_v3_ledger(original_horizon).unwrap(), 0);
    assert_eq!(restored.prune_named_v3_ledger(extended_horizon).unwrap(), 1);
    assert_eq!(restored.named_v3_ledger_len(), 0);
}

#[test]
fn current_cache_refreshes_and_admission_only_cannot_extend_current_trust() {
    let record = route("named_route_record_v3");
    let key = record.route_key;
    let raw = record.encode().expect("route");
    let initial = verified_service_with_cache(NOW, 60);
    let refreshed_early = verified_service_with_cache(NOW + 30, 180);
    let refreshed_at_deadline = verified_service_with_cache(NOW + 60, 180);

    let mut put_refresh = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    assert_eq!(
        put_refresh
            .put_named_v3_uncommitted(
                key,
                raw.clone(),
                &initial,
                route_policy(),
                NOW,
                "peer-a".to_owned(),
            )
            .unwrap(),
        NOW + 60
    );
    let refreshed_until = put_refresh
        .put_named_v3_uncommitted(
            key,
            raw.clone(),
            &refreshed_early,
            route_policy(),
            NOW + 30,
            "peer-a".to_owned(),
        )
        .expect("full-current idempotent refresh");
    assert!(refreshed_until > NOW + 60);
    assert_eq!(put_refresh.get_named_v3(&key, 8, NOW + 60).len(), 1);

    let mut admission = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    admission
        .put_named_v3_uncommitted(
            key,
            raw.clone(),
            &initial,
            route_policy(),
            NOW,
            "peer-a".to_owned(),
        )
        .unwrap();
    assert_eq!(
        admission
            .put_named_v3_for_admission(key, raw.clone(), NOW + 30, "peer-b".to_owned(),)
            .expect("admission-only idempotence"),
        NOW + 60
    );
    assert!(admission.get_named_v3(&key, 8, NOW + 60).is_empty());

    let mut upgraded = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    upgraded
        .put_named_v3_for_admission(key, raw.clone(), NOW, "peer-a".to_owned())
        .unwrap();
    assert_eq!(
        upgraded
            .put_named_v3_uncommitted(
                key,
                raw.clone(),
                &initial,
                route_policy(),
                NOW,
                "peer-b".to_owned(),
            )
            .expect("upgrade admission-only bytes to current trust"),
        NOW + 60
    );
    assert!(upgraded.get_named_v3(&key, 8, NOW + 60).is_empty());

    let mut maintenance = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    maintenance
        .put_named_v3_uncommitted(key, raw, &initial, route_policy(), NOW, "peer-a".to_owned())
        .unwrap();
    assert_eq!(
        maintenance
            .revalidate_named_v3_current_uncommitted(
                &refreshed_at_deadline,
                route_policy(),
                NOW + 60,
            )
            .expect("refresh exactly at old cache deadline"),
        1
    );
    assert_eq!(maintenance.get_named_v3(&key, 8, NOW + 61).len(), 1);
}

#[test]
fn exact_equal_is_idempotent_after_live_cache_expiry_and_restart() {
    let identity = identity();
    let sequence = fixture("hrm_sequence").parse().expect("sequence");
    let manifest = current_manifest_at(
        "hrm_envelope",
        sequence,
        NOW,
        ValidationLimits {
            maximum_cache_lifetime: 60,
            ..ValidationLimits::default()
        },
    );
    let service = observe_named_service(&manifest, &identity, &service_policy(), None)
        .expect("service")
        .into_active()
        .expect("active");
    let record = route("named_route_record_v3");
    let raw = record.encode().expect("route");
    let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    assert_eq!(
        store
            .put_named_v3_uncommitted(
                record.route_key,
                raw.clone(),
                &service,
                route_policy(),
                NOW,
                "peer-a".to_owned(),
            )
            .expect("current route"),
        NOW + 60
    );
    assert!(
        store
            .get_named_v3(&record.route_key, 8, NOW + 60)
            .is_empty()
    );
    let snapshot = store.named_v3_ledger_snapshot(NOW + 60).expect("snapshot");
    let revision = snapshot.revision();
    let mut restored = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    restored
        .restore_named_v3_ledger(snapshot, NOW + 60, revision)
        .expect("restore");
    restored
        .put_named_v3_for_admission(record.route_key, raw, NOW + 60, "peer-b".to_owned())
        .expect("exact equal repopulates live cache");
    assert!(restored.named_v3_ledger_revision() > revision);
    assert_eq!(
        restored.get_named_v3(&record.route_key, 8, NOW + 60).len(),
        1
    );
}

#[test]
fn conflict_error_is_revision_visible_and_snapshot_restore_preserves_it() {
    let first = route("named_route_record_v3");
    let key = first.route_key;
    let endpoint_key = first.endpoint_delegation.endpoint_key;
    let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
    store
        .put_named_v3_for_admission(
            key,
            first.encode().expect("first"),
            NOW,
            "peer-a".to_owned(),
        )
        .expect("first");
    let before_conflict = store.named_v3_ledger_revision();
    assert!(matches!(
        store.put_named_v3_for_admission(
            key,
            bytes("conflicting_route_same_sequence"),
            NOW,
            "peer-b".to_owned(),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    assert!(store.named_v3_ledger_revision() > before_conflict);
    let snapshot = store.named_v3_ledger_snapshot(NOW).expect("snapshot");
    let mut restored = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("restored");
    restored
        .restore_named_v3_ledger(
            NamedRouteV3LedgerSnapshot::decode(&snapshot.encode()).expect("decode"),
            NOW,
            snapshot.revision(),
        )
        .expect("restore");
    assert!(restored.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW,));
    assert!(restored.get_named_v3(&key, 8, NOW).is_empty());
    assert!(matches!(
        restored.put_named_v3_for_admission(
            key,
            first.encode().expect("first"),
            NOW,
            "peer-c".to_owned(),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
}

#[test]
fn malformed_greater_cannot_clear_conflict_but_verified_greater_does() {
    let first = route("named_route_record_v3");
    let key = first.route_key;
    let endpoint_key = first.endpoint_delegation.endpoint_key;
    let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
    store
        .put_named_v3_for_admission(
            key,
            first.encode().expect("first"),
            NOW,
            "peer-a".to_owned(),
        )
        .unwrap();
    assert!(matches!(
        store.put_named_v3_for_admission(
            key,
            bytes("conflicting_route_same_sequence"),
            NOW,
            "peer-b".to_owned(),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    let conflict_revision = store.named_v3_ledger_revision();
    let mut malformed_greater = signed_route(&first, first.record_sequence + 1, first.expires_at);
    *malformed_greater.endpoint_signature.last_mut().unwrap() ^= 1;
    assert!(
        store
            .put_named_v3_for_admission(
                key,
                {
                    let mut raw = malformed_greater.encode().expect("encoded route");
                    let body_index = 40;
                    raw[body_index] ^= 1;
                    raw
                },
                NOW,
                "peer-c".to_owned(),
            )
            .is_err()
    );
    assert_eq!(store.named_v3_ledger_revision(), conflict_revision);
    assert!(store.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW,));

    let greater = signed_route(&first, first.record_sequence + 1, first.expires_at);
    store
        .put_named_v3_for_admission(
            key,
            greater.encode().expect("greater"),
            NOW,
            "peer-d".to_owned(),
        )
        .expect("verified greater clears storage conflict");
    assert!(store.named_v3_ledger_revision() > conflict_revision);
    assert!(!store.is_conflicted(RouteRecordModel::HrmNamedV3, &key, &endpoint_key, NOW,));
}

#[test]
fn ledger_capacity_preflight_is_cheap_and_scope_releases_only_after_horizon() {
    let template = route("named_route_record_v3");
    let first = signed_route(&template, template.record_sequence, NOW + 20);
    let second = alternate_endpoint_route(&template, NOW + 100);
    let mut store = RouteStore::new(MAGIC, true, low_capacity_limits(1)).expect("store");
    store
        .put_named_v3_for_admission(
            template.route_key,
            first.encode().expect("first"),
            NOW,
            "peer-a".to_owned(),
        )
        .expect("first");
    let mut invalid_second = second.clone();
    *invalid_second.endpoint_signature.last_mut().unwrap() ^= 1;
    assert!(matches!(
        store.put_named_v3_for_admission(
            template.route_key,
            invalid_second.encode().expect("canonical invalid second"),
            NOW,
            "peer-b".to_owned(),
        ),
        Err(HnsrProtocolError::Capacity)
    ));
    assert_eq!(store.named_v3_ledger_len(), 1);
    let before_prune = store.named_v3_ledger_revision();
    assert_eq!(store.prune_named_v3_ledger(NOW + 20).unwrap(), 0);
    assert_eq!(store.named_v3_ledger_revision(), before_prune);
    assert_eq!(
        store
            .prune_named_v3_ledger(NOW + MAX_ROUTE_LIFETIME - 1)
            .unwrap(),
        0
    );
    assert_eq!(store.named_v3_ledger_revision(), before_prune);
    assert_eq!(
        store
            .prune_named_v3_ledger(NOW + MAX_ROUTE_LIFETIME)
            .unwrap(),
        1
    );
    assert!(store.named_v3_ledger_revision() > before_prune);
    assert_eq!(store.named_v3_ledger_len(), 0);
    assert_eq!(store.named_v3_pruned_through(), NOW + MAX_ROUTE_LIFETIME);
}

#[test]
fn ledger_per_route_scope_limit_survives_conflict_and_restart() {
    let first = route("named_route_record_v3");
    let second = alternate_endpoint_route(&first, NOW + 100);
    let mut limits = low_capacity_limits(2);
    limits.records_per_key = 1;
    let mut store = RouteStore::new(MAGIC, true, limits).expect("store");
    store
        .put_named_v3_for_admission(
            first.route_key,
            first.encode().expect("first"),
            NOW,
            "peer-a".to_owned(),
        )
        .expect("first endpoint");
    assert!(matches!(
        store.put_named_v3_for_admission(
            first.route_key,
            bytes("conflicting_route_same_sequence"),
            NOW,
            "peer-b".to_owned(),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    assert!(store.get_named_v3(&first.route_key, 8, NOW).is_empty());
    assert!(matches!(
        store.put_named_v3_for_admission(
            first.route_key,
            second.encode().expect("second endpoint"),
            NOW,
            "peer-c".to_owned(),
        ),
        Err(HnsrProtocolError::Capacity)
    ));

    let snapshot = store.named_v3_ledger_snapshot(NOW).expect("snapshot");
    assert_eq!(snapshot.records_per_key(), 1);
    let mut restored = RouteStore::new(MAGIC, true, limits).expect("restored");
    restored
        .restore_named_v3_ledger(snapshot.clone(), NOW, snapshot.revision())
        .expect("restore per-route count");
    assert!(matches!(
        restored.put_named_v3_for_admission(
            first.route_key,
            second.encode().expect("second endpoint"),
            NOW,
            "peer-d".to_owned(),
        ),
        Err(HnsrProtocolError::Capacity)
    ));

    let mut relaxed_limits = limits;
    relaxed_limits.records_per_key = 2;
    let mut incompatible = RouteStore::new(MAGIC, true, relaxed_limits).unwrap();
    assert!(matches!(
        incompatible.restore_named_v3_ledger(snapshot.clone(), NOW, snapshot.revision()),
        Err(HnsrProtocolError::IncompatibleNamedRouteLedgerSnapshot)
    ));
}

#[test]
fn persisted_pruning_floor_and_minimum_revision_reject_rollback() {
    let template = route("named_route_record_v3");
    let short = signed_route(&template, template.record_sequence, NOW + 20);
    let raw = short.encode().expect("short route");
    let horizon = NOW + MAX_ROUTE_LIFETIME;
    let mut store = RouteStore::new(MAGIC, true, low_capacity_limits(1)).expect("store");
    store
        .put_named_v3_for_admission(template.route_key, raw.clone(), NOW, "peer-a".to_owned())
        .expect("store route");
    assert_eq!(store.prune_named_v3_ledger(horizon).unwrap(), 1);
    assert_eq!(store.named_v3_pruned_through(), horizon);
    assert!(
        store.get_named_v3(&template.route_key, 8, NOW).is_empty(),
        "a rolled-back read clock must be clamped to the pruning floor"
    );

    let snapshot = store.named_v3_ledger_snapshot(horizon).expect("snapshot");
    assert!(snapshot.is_empty());
    assert_eq!(snapshot.pruned_through(), horizon);
    let snapshot = NamedRouteV3LedgerSnapshot::decode(&snapshot.encode()).expect("decode");

    let mut old_clock = RouteStore::new(MAGIC, true, low_capacity_limits(1)).unwrap();
    assert!(matches!(
        old_clock.restore_named_v3_ledger(snapshot.clone(), horizon - 1, snapshot.revision(),),
        Err(HnsrProtocolError::ClockRollback)
    ));
    let mut stale_snapshot = RouteStore::new(MAGIC, true, low_capacity_limits(1)).unwrap();
    assert!(matches!(
        stale_snapshot.restore_named_v3_ledger(snapshot.clone(), horizon, snapshot.revision() + 1,),
        Err(HnsrProtocolError::IncompatibleNamedRouteLedgerSnapshot)
    ));

    let mut restored = RouteStore::new(MAGIC, true, low_capacity_limits(1)).unwrap();
    restored
        .restore_named_v3_ledger(snapshot.clone(), horizon, snapshot.revision())
        .expect("restore at persisted floor");
    assert_eq!(restored.named_v3_pruned_through(), horizon);
    assert!(matches!(
        restored.prune_named_v3_ledger(horizon - 1),
        Err(HnsrProtocolError::ClockRollback)
    ));
    assert!(matches!(
        restored.named_v3_ledger_snapshot(horizon - 1),
        Err(HnsrProtocolError::ClockRollback)
    ));
    assert!(matches!(
        restored.put_named_v3_for_admission(
            template.route_key,
            raw,
            horizon - 1,
            "peer-b".to_owned(),
        ),
        Err(HnsrProtocolError::ClockRollback)
    ));
    assert!(matches!(
        restored.revalidate_named_v3_current_uncommitted(
            &verified_service(),
            route_policy(),
            horizon - 1,
        ),
        Err(HnsrProtocolError::ClockRollback)
    ));
}

#[test]
fn corrupt_noncanonical_network_capacity_and_revision_snapshots_fail_closed() {
    let first = route("named_route_record_v3");
    let mut store = RouteStore::new(MAGIC, true, low_capacity_limits(2)).expect("store");
    store
        .put_named_v3_for_admission(
            first.route_key,
            first.encode().expect("first"),
            NOW,
            "peer-a".to_owned(),
        )
        .expect("first");
    let snapshot = store.named_v3_ledger_snapshot(NOW).expect("snapshot");
    let fingerprint = snapshot.fingerprint();
    assert_eq!(
        NamedRouteV3LedgerSnapshot::decode(&snapshot.encode())
            .unwrap()
            .fingerprint(),
        fingerprint
    );
    let greater = signed_route(&first, first.record_sequence + 1, first.expires_at);
    store
        .put_named_v3_for_admission(
            first.route_key,
            greater.encode().unwrap(),
            NOW,
            "peer-b".to_owned(),
        )
        .unwrap();
    assert_ne!(
        store.named_v3_ledger_snapshot(NOW).unwrap().fingerprint(),
        fingerprint
    );
    let mut corrupt = snapshot.encode();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(matches!(
        NamedRouteV3LedgerSnapshot::decode(&corrupt),
        Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)
    ));
    let mut extended = snapshot.encode();
    extended.push(0);
    assert!(NamedRouteV3LedgerSnapshot::decode(&extended).is_err());
    let mut exhausted_revision = snapshot.encode();
    exhausted_revision[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    rechecksum_ledger_snapshot(&mut exhausted_revision);
    assert!(matches!(
        NamedRouteV3LedgerSnapshot::decode(&exhausted_revision),
        Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)
    ));

    let mut noncanonical = snapshot.encode();
    let first_entry = 44;
    let entry_size = 155;
    noncanonical.splice(
        first_entry..first_entry,
        noncanonical[first_entry..first_entry + entry_size].to_vec(),
    );
    noncanonical[40..44].copy_from_slice(&2_u32.to_le_bytes());
    rechecksum_ledger_snapshot(&mut noncanonical);
    assert!(matches!(
        NamedRouteV3LedgerSnapshot::decode(&noncanonical),
        Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)
    ));

    let mut impossible_lineage = snapshot.encode();
    let mut alternate_entry = impossible_lineage[first_entry..first_entry + entry_size].to_vec();
    alternate_entry[32..65].copy_from_slice(&array::<33>("alternate_endpoint_public_key"));
    impossible_lineage.splice(first_entry..first_entry, alternate_entry);
    impossible_lineage[40..44].copy_from_slice(&2_u32.to_le_bytes());
    rechecksum_ledger_snapshot(&mut impossible_lineage);
    assert!(matches!(
        NamedRouteV3LedgerSnapshot::decode(&impossible_lineage),
        Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)
    ));

    let mut too_many_per_key = snapshot.encode();
    let mut alternate_entry = too_many_per_key[first_entry..first_entry + entry_size].to_vec();
    alternate_entry[32..65].copy_from_slice(&array::<33>("alternate_endpoint_public_key"));
    too_many_per_key.splice(first_entry..first_entry, alternate_entry);
    too_many_per_key[20..24].copy_from_slice(&1_u32.to_le_bytes());
    too_many_per_key[40..44].copy_from_slice(&2_u32.to_le_bytes());
    rechecksum_ledger_snapshot(&mut too_many_per_key);
    assert!(matches!(
        NamedRouteV3LedgerSnapshot::decode(&too_many_per_key),
        Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)
    ));

    let mut wrong_network = RouteStore::new(MAGIC + 1, true, low_capacity_limits(2)).unwrap();
    assert!(matches!(
        wrong_network.restore_named_v3_ledger(snapshot.clone(), NOW, snapshot.revision()),
        Err(HnsrProtocolError::IncompatibleNamedRouteLedgerSnapshot)
    ));
    let mut wrong_capacity = RouteStore::new(MAGIC, true, low_capacity_limits(3)).unwrap();
    assert!(matches!(
        wrong_capacity.restore_named_v3_ledger(snapshot.clone(), NOW, snapshot.revision()),
        Err(HnsrProtocolError::IncompatibleNamedRouteLedgerSnapshot)
    ));
    let mut nonempty = RouteStore::new(MAGIC, true, low_capacity_limits(2)).unwrap();
    nonempty
        .put_named_v3_for_admission(
            first.route_key,
            first.encode().expect("first"),
            NOW,
            "peer-a".to_owned(),
        )
        .unwrap();
    assert!(matches!(
        nonempty.restore_named_v3_ledger(snapshot, NOW, 0),
        Err(HnsrProtocolError::IncompatibleNamedRouteLedgerSnapshot)
    ));
}

#[test]
fn production_current_apis_require_a_live_committed_authority_guard() {
    let service_identity = identity();
    let record = route("named_route_record_v3");
    let key = record.route_key;
    let raw = record.encode().expect("route");
    let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
    let (mut authority, active) = committed_active_authority();

    authority.run(|reconfirmed, _| {
        let current = reconfirmed
            .bind_current_at(&active, NOW)
            .expect("current active guard");
        store
            .put_named_v3(
                key,
                raw.clone(),
                &current,
                route_policy(),
                NOW,
                "peer-a".to_owned(),
            )
            .expect("committed current insertion");
        assert_eq!(
            store
                .revalidate_named_v3_current(&service_identity, &current, route_policy(), NOW,)
                .expect("committed active revalidation"),
            1
        );
        assert!(matches!(
            store.invalidate_named_v3_withdrawal(&service_identity, &current, NOW),
            Err(HnsrProtocolError::Invalid(
                "committed HNSA service is active"
            ))
        ));
    });

    let withdrawn = advance_authority_to_withdrawal(&mut authority);
    authority.run(|reconfirmed, _| {
        assert!(reconfirmed.bind_current_at(&active, NOW).is_err());
        let current = reconfirmed
            .bind_current_at(&withdrawn, NOW)
            .expect("current withdrawal guard");
        assert!(matches!(
            store.put_named_v3(
                key,
                raw.clone(),
                &current,
                route_policy(),
                NOW,
                "peer-b".to_owned(),
            ),
            Err(HnsrProtocolError::Invalid(
                "committed HNSA service is withdrawn"
            ))
        ));
        let wrong_identity =
            NamedServiceIdentity::new(MAGIC, [15; 32], "other", PROFILE).expect("wrong identity");
        assert!(
            store
                .invalidate_named_v3_withdrawal(&wrong_identity, &current, NOW)
                .is_err()
        );
        assert_eq!(
            store
                .revalidate_named_v3_current(&service_identity, &current, route_policy(), NOW,)
                .expect("committed withdrawal"),
            1
        );
    });
    assert!(store.get_named_v3(&key, 8, NOW).is_empty());

    let mut runtime =
        RendezvousService::new(MAGIC, true, RouteStoreLimits::default()).expect("runtime");
    let (mut runtime_authority, runtime_active) = committed_active_authority();
    runtime_authority.run(|reconfirmed, _| {
        let current = reconfirmed
            .bind_current_at(&runtime_active, NOW)
            .expect("runtime active guard");
        runtime
            .put_named_v3(
                key,
                raw,
                &current,
                route_policy(),
                NOW,
                "peer-runtime".to_owned(),
            )
            .expect("runtime committed insertion");
        assert_eq!(
            runtime
                .revalidate_named_v3_current(&service_identity, &current, route_policy(), NOW,)
                .expect("runtime active revalidation"),
            1
        );
    });
    let runtime_withdrawn = advance_authority_to_withdrawal(&mut runtime_authority);
    runtime_authority.run(|reconfirmed, _| {
        let current = reconfirmed
            .bind_current_at(&runtime_withdrawn, NOW)
            .expect("runtime withdrawal guard");
        assert_eq!(
            runtime
                .invalidate_named_v3_withdrawal(&service_identity, &current, NOW)
                .expect("runtime committed withdrawal"),
            1
        );
    });
    assert_eq!(runtime.route_count(), 0);
}

#[test]
fn authority_loss_after_current_put_discards_live_bytes_but_retains_replay_state() {
    let record = route("named_route_record_v3");
    let key = record.route_key;
    let raw = record.encode().expect("route");
    let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
    let (mut authority, active) = committed_active_authority();

    let scoped = authority.run_controlled(|reconfirmed, _, control| {
        let current = reconfirmed
            .bind_current_at(&active, NOW)
            .expect("current active guard");
        control.lose_on_second_future_check();
        assert!(matches!(
            store.put_named_v3(
                key,
                raw,
                &current,
                route_policy(),
                NOW,
                "peer-lease-loss".to_owned(),
            ),
            Err(HnsrProtocolError::Invalid(
                "committed HNSA authority lease was lost"
            ))
        ));
        assert!(store.get_named_v3(&key, 8, NOW).is_empty());
        assert_eq!(store.named_v3_ledger_len(), 1);
    });
    assert!(matches!(
        scoped,
        Err(LeaseScopeError::Lease(LeaseError::Lost))
    ));
    assert!(store.get_named_v3(&key, 8, NOW).is_empty());
    assert_eq!(store.named_v3_ledger_len(), 1);
}

#[test]
fn production_route_store_apis_require_exact_authority_operation_time() {
    let service_identity = identity();
    let record = route("named_route_record_v3");
    let key = record.route_key;
    let raw = record.encode().expect("route");
    let (mut authority, active) = committed_active_authority();
    authority.run(|reconfirmed, _| {
        let current = reconfirmed
            .bind_current_at(&active, NOW)
            .expect("current active guard");

        let mut put_store =
            RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
        assert!(matches!(
            put_store.put_named_v3(
                key,
                raw,
                &current,
                route_policy(),
                NOW + 1,
                "peer-a".to_owned(),
            ),
            Err(HnsrProtocolError::Invalid(
                "committed HNSA authority operation-time mismatch"
            ))
        ));

        let mut revalidate_store =
            RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
        assert!(matches!(
            revalidate_store.revalidate_named_v3_current(
                &service_identity,
                &current,
                route_policy(),
                NOW + 1,
            ),
            Err(HnsrProtocolError::Invalid(
                "committed HNSA authority operation-time mismatch"
            ))
        ));
    });

    let withdrawn = advance_authority_to_withdrawal(&mut authority);
    authority.run(|reconfirmed, _| {
        let current = reconfirmed
            .bind_current_at(&withdrawn, NOW)
            .expect("current withdrawal guard");
        let mut withdrawal_store =
            RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
        assert!(matches!(
            withdrawal_store.invalidate_named_v3_withdrawal(&service_identity, &current, NOW + 1,),
            Err(HnsrProtocolError::Invalid(
                "committed HNSA authority operation-time mismatch"
            ))
        ));
    });
}

#[test]
fn current_store_invalidates_rotation_and_withdrawal_without_restoring_old_routes() {
    let identity = identity();
    let policy = service_policy();
    let initial = verified_service();
    let route = route("named_route_record_v3");
    let raw = route.encode().expect("route");
    let key = route.route_key;
    let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
    store
        .put_named_v3_uncommitted(
            key,
            raw.clone(),
            &initial,
            route_policy(),
            NOW,
            "peer-a".to_owned(),
        )
        .expect("initial current route");
    assert!(matches!(
        store.put_named_v3_for_admission(
            key,
            bytes("conflicting_route_same_sequence"),
            NOW,
            "peer-conflict".to_owned(),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    assert!(store.is_conflicted(
        RouteRecordModel::HrmNamedV3,
        &key,
        &route.endpoint_delegation.endpoint_key,
        NOW,
    ));

    let sequence: u64 = fixture("hrm_sequence").parse().expect("HRM sequence");
    let replacement_manifest = current_manifest("replacement_hrm_envelope", sequence + 1);
    let replacement = observe_named_service(
        &replacement_manifest,
        &identity,
        &policy,
        Some(initial.generation_observation()),
    )
    .expect("replacement observation")
    .into_active()
    .expect("active replacement");
    assert!(
        route
            .verify_current_uncommitted(&replacement, route_policy(), NOW)
            .is_err()
    );
    assert_eq!(
        store
            .revalidate_named_v3_current_uncommitted(&replacement, route_policy(), NOW)
            .expect("revalidate replacement"),
        0
    );
    assert!(store.is_conflicted(
        RouteRecordModel::HrmNamedV3,
        &key,
        &route.endpoint_delegation.endpoint_key,
        NOW,
    ));
    assert!(store.get_named_v3(&key, 8, NOW).is_empty());
    assert!(
        store
            .put_named_v3_uncommitted(
                key,
                raw.clone(),
                &replacement,
                route_policy(),
                NOW,
                "peer-b".to_owned(),
            )
            .is_err()
    );
    assert!(matches!(
        store.put_named_v3_for_admission(key, raw.clone(), NOW, "peer-b".to_owned()),
        Err(HnsrProtocolError::ConflictingSequence)
    ));

    let removal_manifest = current_manifest("removal_hrm_envelope", sequence + 2);
    let removal = observe_named_service(
        &removal_manifest,
        &identity,
        &policy,
        Some(replacement.generation_observation()),
    )
    .expect("withdrawal observation");
    assert!(removal.observation().is_withdrawn());
    assert_eq!(
        store
            .invalidate_named_v3_withdrawal_uncommitted(&identity, removal.observation())
            .expect("apply withdrawal"),
        0
    );

    let restoration_manifest = current_manifest("restoration_hrm_envelope", sequence + 3);
    let restoration = observe_named_service(
        &restoration_manifest,
        &identity,
        &policy,
        Some(removal.observation()),
    )
    .expect("restoration observation")
    .into_active()
    .expect("active restoration");
    assert!(
        route
            .verify_current_uncommitted(&restoration, route_policy(), NOW)
            .is_err()
    );
    assert!(store.is_conflicted(
        RouteRecordModel::HrmNamedV3,
        &key,
        &route.endpoint_delegation.endpoint_key,
        NOW,
    ));
    assert!(
        store
            .put_named_v3_uncommitted(
                key,
                raw,
                &restoration,
                route_policy(),
                NOW,
                "peer-c".to_owned(),
            )
            .is_err()
    );
    assert!(store.get_named_v3(&key, 8, NOW).is_empty());
}

#[test]
fn requester_selection_only_conflicts_at_the_greatest_valid_sequence() {
    let service = verified_service();
    let greatest = route("named_route_record_v3");
    let mut lower_first = greatest.clone();
    lower_first.record_sequence -= 1;
    lower_first.endpoint_signature.clear();
    lower_first.sign(&[4; 32]).expect("lower route");
    let mut lower_conflict = route("conflicting_route_same_sequence");
    lower_conflict.record_sequence -= 1;
    lower_conflict.endpoint_signature.clear();
    lower_conflict.sign(&[4; 32]).expect("lower conflict");

    let selected = select_named_route_v3_uncommitted(
        [&lower_first, &lower_conflict, &greatest],
        &greatest.endpoint_delegation.endpoint_key,
        &service,
        route_policy(),
        NOW,
    )
    .expect("greatest route");
    assert_eq!(selected.record().record_sequence, greatest.record_sequence);

    let equal_conflict = route("conflicting_route_same_sequence");
    assert!(matches!(
        select_named_route_v3_uncommitted(
            [&greatest, &equal_conflict],
            &greatest.endpoint_delegation.endpoint_key,
            &service,
            route_policy(),
            NOW,
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));

    let mut invalid_higher = greatest.clone();
    invalid_higher.record_sequence += 1;
    invalid_higher.endpoint_signature[8] ^= 1;
    assert_eq!(
        select_named_route_v3_uncommitted(
            [&greatest, &invalid_higher],
            &greatest.endpoint_delegation.endpoint_key,
            &service,
            route_policy(),
            NOW,
        )
        .expect("invalid candidate ignored")
        .record()
        .record_sequence,
        greatest.record_sequence
    );

    let too_many = vec![&greatest; 17];
    assert!(matches!(
        select_named_route_v3_uncommitted(
            too_many,
            &greatest.endpoint_delegation.endpoint_key,
            &service,
            route_policy(),
            NOW,
        ),
        Err(HnsrProtocolError::TooLarge { .. })
    ));
}

#[test]
fn runtime_dispatches_exact_version_authority_pairs_and_defaults_legacy_off() {
    let record = route("named_route_record_v3");
    let key = record.route_key;
    let mut service = HnsrService::new(
        None,
        Some(RendezvousService::new(MAGIC, true, RouteStoreLimits::default()).expect("rendezvous")),
    );
    let packet = |raw: Vec<u8>| {
        HnsrPacket::new(
            HnsrOpcode::PutRoute,
            [7; 8],
            PutRouteBody {
                route_key: key,
                record: raw,
            }
            .encode()
            .expect("put route"),
        )
        .expect("packet")
    };

    service
        .handle(&packet(bytes("named_route_record_v3")), "peer-a", NOW)
        .expect("version-3 dispatch");
    let lookup = HnsrPacket::new(
        HnsrOpcode::GetRoute,
        [8; 8],
        GetRouteBody {
            route_key: key,
            maximum_records: 8,
        }
        .encode()
        .expect("lookup"),
    )
    .expect("packet");
    let response = service
        .handle(&lookup, "peer-a", NOW)
        .expect("lookup")
        .expect("response");
    let routes = RoutesBody::decode(&response.body).expect("routes");
    assert_eq!(routes.records.len(), 1);
    assert_eq!(routes.records[0].get(..2), Some([3, 2].as_slice()));

    for name in [
        "legacy_named_route_record_v2",
        "legacy_v2_authority_v1_route",
        "wrong_v3_authority_v1_route",
        "wrong_v2_authority_v2_route",
    ] {
        assert!(
            service.handle(&packet(bytes(name)), "peer-b", NOW).is_err(),
            "runtime accepted {name}"
        );
    }

    let mut legacy_publication = HnsrService::new(
        None,
        Some(
            RendezvousService::new_with_legacy_named_v2(
                MAGIC,
                true,
                RouteStoreLimits::default(),
                true,
            )
            .expect("legacy publication compatibility"),
        ),
    );
    assert!(
        legacy_publication
            .handle(&packet(bytes("named_route_record_v3")), "peer-a", NOW)
            .is_ok(),
        "legacy publication compatibility must not disable V3"
    );
    legacy_publication
        .handle(
            &packet(bytes("legacy_named_route_record_v2")),
            "peer-b",
            NOW,
        )
        .expect("explicit legacy publication");
    let response = legacy_publication
        .handle(&lookup, "peer-a", NOW)
        .expect("lookup")
        .expect("response");
    assert_eq!(
        RoutesBody::decode(&response.body).expect("routes").records,
        vec![bytes("named_route_record_v3")],
        "enabling V2 publication must not alter V3 wire lookup"
    );
    assert_eq!(
        legacy_publication
            .rendezvous_mut()
            .expect("rendezvous")
            .get_legacy_named_v2(&key, 8, NOW),
        vec![bytes("legacy_named_route_record_v2")]
    );
}

#[test]
fn runtime_exposes_conflict_revision_snapshot_and_empty_restore() {
    let record = route("named_route_record_v3");
    let key = record.route_key;
    let packet = |raw: Vec<u8>| {
        HnsrPacket::new(
            HnsrOpcode::PutRoute,
            [42; 8],
            PutRouteBody {
                route_key: key,
                record: raw,
            }
            .encode()
            .expect("put"),
        )
        .expect("packet")
    };
    let mut service = HnsrService::new(
        None,
        Some(RendezvousService::new(MAGIC, true, RouteStoreLimits::default()).unwrap()),
    );
    service
        .handle(&packet(record.encode().expect("route")), "peer-a", NOW)
        .expect("first");
    let revision = service
        .rendezvous()
        .expect("rendezvous")
        .named_v3_ledger_revision();
    assert!(matches!(
        service.handle(
            &packet(bytes("conflicting_route_same_sequence")),
            "peer-b",
            NOW,
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    let rendezvous = service.rendezvous_mut().expect("rendezvous");
    assert!(rendezvous.named_v3_ledger_revision() > revision);
    assert_eq!(rendezvous.named_v3_pruned_through(), 0);
    let snapshot = rendezvous
        .named_v3_ledger_snapshot(NOW)
        .expect("snapshot after error");

    let mut restored = RendezvousService::new(MAGIC, true, RouteStoreLimits::default()).unwrap();
    restored
        .restore_named_v3_ledger(
            NamedRouteV3LedgerSnapshot::decode(&snapshot.encode()).unwrap(),
            NOW,
            snapshot.revision(),
        )
        .expect("restore");
    assert!(restored.named_v3_ledger_revision() >= snapshot.revision());
    assert_eq!(
        restored.named_v3_pruned_through(),
        snapshot.pruned_through()
    );
    assert!(matches!(
        {
            let mut wrapper = HnsrService::new(None, Some(restored));
            wrapper.handle(&packet(record.encode().expect("route")), "peer-c", NOW)
        },
        Err(HnsrProtocolError::ConflictingSequence)
    ));
}

#[test]
fn runtime_maintenance_removes_live_bytes_without_lowering_storage_ledger() {
    let identity = identity();
    let policy = service_policy();
    let initial = verified_service();
    let record = route("named_route_record_v3");
    let key = record.route_key;
    let packet = HnsrPacket::new(
        HnsrOpcode::PutRoute,
        [43; 8],
        PutRouteBody {
            route_key: key,
            record: record.encode().expect("route"),
        }
        .encode()
        .expect("put"),
    )
    .expect("packet");
    let make_service = || {
        HnsrService::new(
            None,
            Some(RendezvousService::new(MAGIC, true, RouteStoreLimits::default()).unwrap()),
        )
    };
    let sequence: u64 = fixture("hrm_sequence").parse().expect("HRM sequence");
    let replacement = observe_named_service(
        &current_manifest("replacement_hrm_envelope", sequence + 1),
        &identity,
        &policy,
        Some(initial.generation_observation()),
    )
    .expect("replacement")
    .into_active()
    .expect("active replacement");
    let removal = observe_named_service(
        &current_manifest("removal_hrm_envelope", sequence + 2),
        &identity,
        &policy,
        Some(replacement.generation_observation()),
    )
    .expect("removal");

    let mut rotated = make_service();
    rotated.handle(&packet, "peer-a", NOW).expect("put");
    let revision = rotated.rendezvous().unwrap().named_v3_ledger_revision();
    assert_eq!(
        rotated
            .rendezvous_mut()
            .unwrap()
            .revalidate_named_v3_current_uncommitted(&replacement, route_policy(), NOW)
            .expect("revalidate"),
        0
    );
    assert_eq!(rotated.rendezvous().unwrap().route_count(), 0);
    assert_eq!(
        rotated.rendezvous().unwrap().named_v3_ledger_revision(),
        revision
    );
    assert_eq!(
        rotated
            .rendezvous_mut()
            .unwrap()
            .named_v3_ledger_snapshot(NOW)
            .unwrap()
            .len(),
        1
    );

    let mut withdrawn = make_service();
    withdrawn.handle(&packet, "peer-b", NOW).expect("put");
    let revision = withdrawn.rendezvous().unwrap().named_v3_ledger_revision();
    assert_eq!(
        withdrawn
            .rendezvous_mut()
            .unwrap()
            .invalidate_named_v3_withdrawal_uncommitted(&identity, removal.observation())
            .expect("withdraw"),
        1
    );
    assert_eq!(withdrawn.rendezvous().unwrap().route_count(), 0);
    assert_eq!(
        withdrawn.rendezvous().unwrap().named_v3_ledger_revision(),
        revision
    );
    assert_eq!(
        withdrawn
            .rendezvous_mut()
            .unwrap()
            .named_v3_ledger_snapshot(NOW)
            .unwrap()
            .len(),
        1
    );
}
