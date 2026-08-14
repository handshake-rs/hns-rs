use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_hnsr_protocol::requester_hrm::{
    HeldNamedRouteV3OperationLeases, NamedRouteV3RequesterExpectation,
    NamedRouteV3RequesterLeaseKey, NamedRouteV3RequesterStorageState,
};
use hns_hnsr_protocol::{
    HnsrProtocolError, HrmNamedRoutePolicy, NamedRouteRecordV3, NamedRouteV3LedgerSnapshot,
    NamedRouteV3RequesterSnapshot, NamedRouteV3RequesterState, RouteStore, RouteStoreLimits,
};
use hns_hrm::validation::{
    AuthenticatedNameState, ResolvedManifest, RollbackObservations, ValidationLimits,
    validate_current_manifest,
};
use hns_service_authority::hrm::{
    NamedServiceIdentity, NamedServicePolicy, VerifiedNamedService, observe_named_service,
};
use hns_service_authority::lease::{
    AuthorityLeaseKey, FencedLeaseGuard, FencingToken, LeaseError, StorageNamespaceId,
};
use sha2::{Digest, Sha256};

fn fixtures() -> BTreeMap<&'static str, &'static str> {
    include_str!("../fixtures/hnsa-hnsr-v3/hnsa-hnsr-v3.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once('=').expect("fixture key/value"))
        .collect()
}

fn bytes(values: &BTreeMap<&str, &str>, key: &str) -> Vec<u8> {
    hex::decode(values.get(key).unwrap_or_else(|| panic!("missing {key}")))
        .unwrap_or_else(|_| panic!("invalid fixture hex {key}"))
}

fn array<const N: usize>(values: &BTreeMap<&str, &str>, key: &str) -> [u8; N] {
    bytes(values, key)
        .try_into()
        .unwrap_or_else(|_| panic!("fixture {key} is not {N} bytes"))
}

fn integer<T>(values: &BTreeMap<&str, &str>, key: &str) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    values[key]
        .parse()
        .unwrap_or_else(|_| panic!("invalid fixture integer {key}"))
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

fn identity(values: &BTreeMap<&str, &str>) -> NamedServiceIdentity {
    NamedServiceIdentity::new(
        integer(values, "network_magic"),
        array(values, "name_hash"),
        values["service_name"],
        integer(values, "application_profile_id"),
    )
    .expect("fixture identity")
}

fn service_policy(values: &BTreeMap<&str, &str>) -> NamedServicePolicy {
    NamedServicePolicy {
        application_profile_id: integer(values, "application_profile_id"),
        allowed_profile_flags: 0,
        required_profile_flags: 0,
        expected_profile_constraints_hash: [0; 32],
        allowed_endpoint_capabilities: integer(values, "allowed_endpoint_capabilities"),
        required_endpoint_capabilities: integer(values, "allowed_endpoint_capabilities"),
        expected_endpoint_constraints_hash: [0; 32],
        maximum_endpoint_lifetime: integer(values, "max_endpoint_lifetime"),
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

fn verified_service(values: &BTreeMap<&str, &str>) -> VerifiedNamedService {
    let identity = identity(values);
    let envelope = bytes(values, "hrm_envelope");
    let digest = Sha256::digest(&envelope);
    let now = integer(values, "validation_now");
    let manifest = validate_current_manifest(
        ResolvedManifest {
            name_state: AuthenticatedNameState {
                network_magic: integer(values, "network_magic"),
                subject: identity.name_hash,
                has_current_owner: true,
                revoked: false,
                expired: false,
                finality_accepted: true,
                chain_height: 109,
                chain_work: [3; 32],
                chain_anchor: [4; 32],
                accepted_reorganization: None,
                commitment_records: vec![vec![
                    "hrm1".to_owned(),
                    format!("seq={}", values["hrm_sequence"]),
                    format!("hash=sha256:{}", URL_SAFE_NO_PAD.encode(digest)),
                    "uri=https://example.test/hrm".to_owned(),
                ]],
            },
            envelope,
        },
        integer(values, "network_magic"),
        identity.name_hash,
        now,
        ValidationLimits::default(),
        &RollbackObservations::new(),
    )
    .expect("current fixture HRM");
    observe_named_service(&manifest, &identity, &service_policy(values), None)
        .expect("fixture service observation")
        .into_active()
        .expect("active fixture service")
}

#[derive(Default)]
struct RequesterCasStore {
    current: Option<NamedRouteV3RequesterSnapshot>,
}

impl RequesterCasStore {
    fn persist(
        &mut self,
        expected: NamedRouteV3RequesterExpectation,
        proposed: &NamedRouteV3RequesterSnapshot,
    ) -> Result<(), HnsrProtocolError> {
        if self.current.as_ref() == Some(proposed) {
            return Ok(());
        }
        let matches = match (expected, self.current.as_ref()) {
            (NamedRouteV3RequesterExpectation::Absent { .. }, None) => true,
            (
                NamedRouteV3RequesterExpectation::Exact {
                    revision,
                    fingerprint,
                    ..
                },
                Some(current),
            ) => current.revision() == revision && current.fingerprint() == fingerprint,
            _ => false,
        };
        if !matches {
            return Err(HnsrProtocolError::Invalid("vector CAS mismatch"));
        }
        self.current = Some(proposed.clone());
        Ok(())
    }
}

#[derive(Debug)]
struct AuthorityTestGuard {
    key: AuthorityLeaseKey,
}

impl FencedLeaseGuard<AuthorityLeaseKey> for AuthorityTestGuard {
    fn key(&self) -> &AuthorityLeaseKey {
        &self.key
    }

    fn fencing_token(&self) -> FencingToken {
        FencingToken::new(1).expect("test fence")
    }

    fn ensure_held(&self) -> Result<(), LeaseError> {
        Ok(())
    }
}

#[derive(Debug)]
struct RequesterTestGuard {
    key: NamedRouteV3RequesterLeaseKey,
}

impl FencedLeaseGuard<NamedRouteV3RequesterLeaseKey> for RequesterTestGuard {
    fn key(&self) -> &NamedRouteV3RequesterLeaseKey {
        &self.key
    }

    fn fencing_token(&self) -> FencingToken {
        FencingToken::new(1).expect("test fence")
    }

    fn ensure_held(&self) -> Result<(), LeaseError> {
        Ok(())
    }
}

fn assert_requester_vector(
    values: &BTreeMap<&str, &str>,
    prefix: &str,
) -> NamedRouteV3RequesterSnapshot {
    let field = |suffix: &str| format!("{prefix}_{suffix}");
    let encoded = bytes(values, &field("snapshot"));
    let payload = bytes(values, &field("snapshot_payload"));
    let checksum = bytes(values, &field("snapshot_checksum"));
    assert_eq!(encoded, [payload.as_slice(), checksum.as_slice()].concat());
    assert_eq!(
        checksum,
        blake2b_256(&[b"HNSR-NAMED-V3-REQUESTER-SNAPSHOT-V1\0", &payload,])
    );
    let snapshot = NamedRouteV3RequesterSnapshot::decode(&encoded).expect("requester vector");
    assert_eq!(snapshot.encode(), encoded);
    assert_eq!(snapshot.network_magic(), integer(values, "network_magic"));
    assert_eq!(
        snapshot.capacity(),
        integer(values, "requester_snapshot_capacity")
    );
    assert_eq!(snapshot.revision(), integer(values, &field("revision")));
    let trusted_time_field = if prefix == "requester_trusted_time" {
        field("high_water")
    } else {
        field("trusted_time")
    };
    assert_eq!(
        snapshot.trusted_time_high_water(),
        integer(values, &trusted_time_field)
    );
    assert_eq!(snapshot.len(), integer(values, &field("entry_count")));
    assert_eq!(
        snapshot.fingerprint(),
        array(values, &field("snapshot_fingerprint"))
    );
    snapshot
}

fn assert_requester_prior(
    values: &BTreeMap<&str, &str>,
    next_prefix: &str,
    prior: &NamedRouteV3RequesterSnapshot,
) {
    assert_eq!(
        prior.revision(),
        integer(values, &format!("{next_prefix}_prior_revision"))
    );
    assert_eq!(
        prior.fingerprint(),
        array(values, &format!("{next_prefix}_prior_fingerprint"))
    );
}

fn assert_storage_vector(
    values: &BTreeMap<&str, &str>,
    prefix: &str,
) -> NamedRouteV3LedgerSnapshot {
    let field = |suffix: &str| format!("{prefix}_{suffix}");
    let encoded = bytes(values, &field("snapshot"));
    let payload = bytes(values, &field("snapshot_payload"));
    let checksum = bytes(values, &field("snapshot_checksum"));
    assert_eq!(encoded, [payload.as_slice(), checksum.as_slice()].concat());
    assert_eq!(
        checksum,
        blake2b_256(&[b"HNSR-NAMED-V3-LEDGER-SNAPSHOT-V1\0", &payload])
    );
    let snapshot = NamedRouteV3LedgerSnapshot::decode(&encoded).expect("storage ledger vector");
    assert_eq!(snapshot.encode(), encoded);
    assert_eq!(snapshot.network_magic(), integer(values, "network_magic"));
    assert_eq!(
        snapshot.capacity(),
        integer(values, "storage_ledger_capacity")
    );
    assert_eq!(
        snapshot.records_per_key(),
        integer(values, "storage_ledger_records_per_key")
    );
    assert_eq!(snapshot.revision(), integer(values, &field("revision")));
    assert_eq!(
        snapshot.pruned_through(),
        integer(values, &field("pruned_through"))
    );
    assert_eq!(snapshot.len(), integer(values, &field("entry_count")));
    assert_eq!(
        snapshot.fingerprint(),
        array(values, &field("snapshot_fingerprint"))
    );
    snapshot
}

fn assert_storage_prior(
    values: &BTreeMap<&str, &str>,
    next_prefix: &str,
    prior: &NamedRouteV3LedgerSnapshot,
) {
    assert_eq!(
        prior.revision(),
        integer(values, &format!("{next_prefix}_prior_revision"))
    );
    assert_eq!(
        prior.fingerprint(),
        array(values, &format!("{next_prefix}_prior_fingerprint"))
    );
}

#[test]
fn requester_vectors_round_trip_and_real_transitions_reproduce_cas_lineage() {
    let values = fixtures();
    assert_eq!(values["requester_fresh_prior_expectation"], "absent");
    let fresh = assert_requester_vector(&values, "requester_fresh");
    let active = assert_requester_vector(&values, "requester_active");
    let endpoint_intermediate = assert_requester_vector(&values, "requester_endpoint_intermediate");
    let split = assert_requester_vector(&values, "requester_split");
    let conflict = assert_requester_vector(&values, "requester_conflict");
    let trusted_time = assert_requester_vector(&values, "requester_trusted_time");
    assert_requester_prior(&values, "requester_active", &fresh);
    assert_requester_prior(&values, "requester_endpoint_intermediate", &active);
    assert_requester_prior(&values, "requester_split", &endpoint_intermediate);
    assert_requester_prior(&values, "requester_conflict", &split);
    assert_requester_prior(&values, "requester_trusted_time", &conflict);
    assert!(trusted_time.trusted_time_high_water() > (1_u64 << 53));
    assert!(integer::<u64>(&values, "endpoint_sequence") > (1_u64 << 53));
    assert!(integer::<u64>(&values, "route_record_sequence") > (1_u64 << 53));

    let now = integer(&values, "validation_now");
    let mut state = NamedRouteV3RequesterState::new(
        integer(&values, "network_magic"),
        integer(&values, "requester_snapshot_capacity"),
        now,
    )
    .expect("fresh requester state");
    assert_eq!(state.snapshot(), fresh);
    let store = Rc::new(RefCell::new(RequesterCasStore::default()));
    let authority_key = AuthorityLeaseKey::new(
        StorageNamespaceId::new([1; 32]).expect("authority namespace"),
        integer(&values, "network_magic"),
        array(&values, "name_hash"),
    );
    let requester_key = NamedRouteV3RequesterLeaseKey::new(
        StorageNamespaceId::new([2; 32]).expect("requester namespace"),
        integer(&values, "network_magic"),
    );
    let leases = HeldNamedRouteV3OperationLeases::acquire(
        authority_key,
        requester_key,
        |key| Ok::<_, ()>(AuthorityTestGuard { key: *key }),
        |key| Ok::<_, ()>(RequesterTestGuard { key: *key }),
    )
    .expect("operation leases");
    leases
        .run(|operation| {
            let mut state =
                state.reconfirm(operation, |_| Ok(NamedRouteV3RequesterStorageState::Absent))?;
            let fresh_store = Rc::clone(&store);
            state
                .persist_pending(move |expected, proposed| {
                    assert_eq!(
                        expected.storage_namespace_id(),
                        requester_key.storage_namespace_id()
                    );
                    fresh_store.borrow_mut().persist(expected, proposed)
                })
                .expect("persist fresh requester vector");

            let service = verified_service(&values);
            let route = NamedRouteRecordV3::decode(&bytes(&values, "named_route_record_v3"))
                .expect("fixture route");
            assert_eq!(
                bytes(&values, "canonical_record_hash_domain"),
                b"HNSR-NAMED-V3-CANONICAL-RECORD-V1\0"
            );
            let canonical_record_hash = blake2b_256(&[
                b"HNSR-NAMED-V3-CANONICAL-RECORD-V1\0",
                &route.encode().expect("canonical route"),
            ]);
            assert_eq!(
                array::<32>(&values, "requester_active_route_canonical_hash"),
                canonical_record_hash
            );
            assert_eq!(
                array::<32>(&values, "storage_active_route_canonical_hash"),
                canonical_record_hash
            );
            assert_requester_prior(
                &values,
                "requester_active",
                store.borrow().current.as_ref().unwrap(),
            );
            let active_store = Rc::clone(&store);
            state
                .observe_current_persisted_uncommitted(
                    &route,
                    &service,
                    route_policy(),
                    now,
                    move |expected, proposed| active_store.borrow_mut().persist(expected, proposed),
                )
                .expect("active requester transition");
            assert_eq!(state.snapshot(), active);

            let endpoint_greater_route_stale =
                NamedRouteRecordV3::decode(&bytes(&values, "product_endpoint_greater_route_stale"))
                    .expect("endpoint-greater fixture route");
            assert_requester_prior(
                &values,
                "requester_endpoint_intermediate",
                store.borrow().current.as_ref().unwrap(),
            );
            let intermediate_store = Rc::clone(&store);
            assert!(matches!(
                state.observe_current_persisted_uncommitted(
                    &endpoint_greater_route_stale,
                    &service,
                    route_policy(),
                    now,
                    move |expected, proposed| intermediate_store
                        .borrow_mut()
                        .persist(expected, proposed),
                ),
                Err(HnsrProtocolError::StaleSequence)
            ));
            assert_eq!(state.snapshot(), endpoint_intermediate);

            let endpoint_stale_route_greater =
                NamedRouteRecordV3::decode(&bytes(&values, "product_endpoint_stale_route_greater"))
                    .expect("route-greater fixture route");
            assert_requester_prior(
                &values,
                "requester_split",
                store.borrow().current.as_ref().unwrap(),
            );
            let split_store = Rc::clone(&store);
            assert!(matches!(
                state.observe_current_persisted_uncommitted(
                    &endpoint_stale_route_greater,
                    &service,
                    route_policy(),
                    now,
                    move |expected, proposed| split_store.borrow_mut().persist(expected, proposed),
                ),
                Err(HnsrProtocolError::StaleSequence)
            ));
            assert_eq!(state.snapshot(), split);

            let endpoint_stale_route_conflict = NamedRouteRecordV3::decode(&bytes(
                &values,
                "product_endpoint_stale_route_conflict",
            ))
            .expect("route-conflict fixture route");
            assert_requester_prior(
                &values,
                "requester_conflict",
                store.borrow().current.as_ref().unwrap(),
            );
            let conflict_store = Rc::clone(&store);
            assert!(matches!(
                state.observe_current_persisted_uncommitted(
                    &endpoint_stale_route_conflict,
                    &service,
                    route_policy(),
                    now,
                    move |expected, proposed| conflict_store
                        .borrow_mut()
                        .persist(expected, proposed),
                ),
                Err(HnsrProtocolError::ConflictingSequence)
            ));
            assert_eq!(state.snapshot(), conflict);

            assert_requester_prior(
                &values,
                "requester_trusted_time",
                store.borrow().current.as_ref().unwrap(),
            );
            let time_store = Rc::clone(&store);
            state
                .advance_trusted_time_persisted(
                    integer(&values, "persistence_high_time"),
                    move |expected, proposed| time_store.borrow_mut().persist(expected, proposed),
                )
                .expect("requester trusted-time transition");
            assert_eq!(state.snapshot(), trusted_time);
            Ok::<_, HnsrProtocolError>(())
        })
        .expect("leased requester vector transitions");
}

#[test]
fn storage_vectors_round_trip_and_real_transitions_reproduce_pruned_lineage() {
    let values = fixtures();
    assert_eq!(values["storage_fresh_prior_expectation"], "absent");
    let fresh = assert_storage_vector(&values, "storage_fresh");
    let active = assert_storage_vector(&values, "storage_active");
    let endpoint_intermediate = assert_storage_vector(&values, "storage_endpoint_intermediate");
    let split = assert_storage_vector(&values, "storage_split");
    let conflict = assert_storage_vector(&values, "storage_conflict");
    let pruned = assert_storage_vector(&values, "storage_pruned_empty");
    assert_storage_prior(&values, "storage_active", &fresh);
    assert_storage_prior(&values, "storage_endpoint_intermediate", &active);
    assert_storage_prior(&values, "storage_split", &endpoint_intermediate);
    assert_storage_prior(&values, "storage_conflict", &split);
    assert_storage_prior(&values, "storage_pruned_empty", &conflict);
    assert!(pruned.pruned_through() > (1_u64 << 53));

    let limits = RouteStoreLimits {
        total_records: integer(&values, "storage_ledger_capacity"),
        records_per_key: integer(&values, "storage_ledger_records_per_key"),
        records_per_source: 16,
        verification_attempts_total: 64,
        verification_attempts_per_source: 32,
        verification_window_seconds: 60,
    };
    let now = integer(&values, "validation_now");
    let mut store = RouteStore::new(integer(&values, "network_magic"), true, limits)
        .expect("fresh route store");
    assert_eq!(store.named_v3_ledger_snapshot(now).unwrap(), fresh);

    let route = NamedRouteRecordV3::decode(&bytes(&values, "named_route_record_v3"))
        .expect("fixture route");
    store
        .put_named_v3_for_admission(
            route.route_key,
            route.encode().expect("canonical route"),
            now,
            "peer-a".to_owned(),
        )
        .expect("active storage transition");
    let actual_active = store.named_v3_ledger_snapshot(now).unwrap();
    assert_storage_prior(&values, "storage_endpoint_intermediate", &actual_active);
    assert_eq!(actual_active, active);

    let endpoint_greater_route_stale =
        NamedRouteRecordV3::decode(&bytes(&values, "product_endpoint_greater_route_stale"))
            .expect("endpoint-greater fixture route");
    assert!(matches!(
        store.put_named_v3_for_admission(
            endpoint_greater_route_stale.route_key,
            endpoint_greater_route_stale
                .encode()
                .expect("canonical endpoint-greater route"),
            now,
            "peer-b".to_owned(),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));
    let actual_intermediate = store.named_v3_ledger_snapshot(now).unwrap();
    assert_storage_prior(&values, "storage_split", &actual_intermediate);
    assert_eq!(actual_intermediate, endpoint_intermediate);
    assert!(store.get_named_v3(&route.route_key, 1, now).is_empty());

    let endpoint_stale_route_greater =
        NamedRouteRecordV3::decode(&bytes(&values, "product_endpoint_stale_route_greater"))
            .expect("route-greater fixture route");
    assert!(matches!(
        store.put_named_v3_for_admission(
            endpoint_stale_route_greater.route_key,
            endpoint_stale_route_greater
                .encode()
                .expect("canonical route-greater route"),
            now,
            "peer-c".to_owned(),
        ),
        Err(HnsrProtocolError::StaleSequence)
    ));
    let actual_split = store.named_v3_ledger_snapshot(now).unwrap();
    assert_storage_prior(&values, "storage_conflict", &actual_split);
    assert_eq!(actual_split, split);
    assert!(store.get_named_v3(&route.route_key, 1, now).is_empty());

    let endpoint_stale_route_conflict =
        NamedRouteRecordV3::decode(&bytes(&values, "product_endpoint_stale_route_conflict"))
            .expect("route-conflict fixture route");
    assert!(matches!(
        store.put_named_v3_for_admission(
            endpoint_stale_route_conflict.route_key,
            endpoint_stale_route_conflict
                .encode()
                .expect("canonical route-conflict route"),
            now,
            "peer-d".to_owned(),
        ),
        Err(HnsrProtocolError::ConflictingSequence)
    ));
    let actual_conflict = store.named_v3_ledger_snapshot(now).unwrap();
    assert_storage_prior(&values, "storage_pruned_empty", &actual_conflict);
    assert_eq!(actual_conflict, conflict);

    let high_time = integer(&values, "persistence_high_time");
    assert_eq!(store.prune_named_v3_ledger(high_time).unwrap(), 1);
    assert_eq!(store.named_v3_ledger_snapshot(high_time).unwrap(), pruned);
}
