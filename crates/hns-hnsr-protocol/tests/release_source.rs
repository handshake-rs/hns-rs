use hns_hnsr_protocol::NamedRouteRecordV3;
use sha2::{Digest, Sha256};

const FIXTURE: &str = include_str!("../fixtures/hnsa-hnsr-v3/hnsa-hnsr-v3.txt");
const SIDECAR: &str = include_str!("../fixtures/hnsa-hnsr-v3/hnsa-hnsr-v3.txt.sha256");
const PERSISTENT_ROUTING_SOURCE: &str = include_str!("../src/persistent_routing.rs");
const REQUESTER_SOURCE: &str = include_str!("../src/requester_hrm.rs");
const NAMED_HRM_SOURCE: &str = include_str!("../src/named_hrm.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");

fn field(name: &str) -> &str {
    FIXTURE
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
        .unwrap_or_else(|| panic!("missing packaged fixture field {name}"))
}

#[test]
fn packaged_independent_v3_fixture_and_sidecar_are_complete() {
    let expected_digest = SIDECAR.split_whitespace().next().expect("sidecar digest");
    assert_eq!(
        hex::encode(Sha256::digest(FIXTURE.as_bytes())),
        expected_digest
    );
    assert_eq!(SIDECAR.split_whitespace().nth(1), Some("hnsa-hnsr-v3.txt"));

    for required in [
        "named_service_identifier",
        "service_resource_id",
        "service_delegation_id",
        "endpoint_delegation",
        "relay_ticket",
        "named_route_key",
        "named_route_body_v3",
        "named_route_signature",
        "named_route_record_v3",
        "canonical_record_hash_domain",
        "product_endpoint_greater_delegation",
        "product_endpoint_greater_delegation_id",
        "product_endpoint_greater_route_stale",
        "product_endpoint_stale_route_greater",
        "product_endpoint_stale_route_conflict",
        "conflicting_route_same_sequence",
        "wrong_ticket_network_route",
        "duplicate_ticket_route",
        "nonminimal_der_endpoint",
        "nonminimal_der_relay_ticket_route",
        "nonminimal_der_ticket_confirmation_route",
        "nonminimal_der_route",
        "replacement_hrm_envelope",
        "removal_hrm_envelope",
        "restoration_hrm_envelope",
        "legacy_named_route_record_v2",
        "legacy_v2_authority_v1_route",
        "requester_fresh_snapshot",
        "requester_active_snapshot",
        "requester_endpoint_intermediate_snapshot",
        "requester_endpoint_intermediate_prior_fingerprint",
        "requester_split_snapshot",
        "requester_split_prior_fingerprint",
        "requester_conflict_snapshot",
        "requester_trusted_time_snapshot",
        "requester_trusted_time_prior_fingerprint",
        "storage_fresh_snapshot",
        "storage_active_snapshot",
        "storage_endpoint_intermediate_snapshot",
        "storage_endpoint_intermediate_prior_fingerprint",
        "storage_split_snapshot",
        "storage_split_prior_fingerprint",
        "storage_conflict_snapshot",
        "storage_pruned_empty_snapshot",
        "storage_pruned_empty_prior_fingerprint",
    ] {
        assert!(
            !field(required).is_empty(),
            "empty fixture field {required}"
        );
    }

    let encoded = hex::decode(field("named_route_record_v3")).expect("fixture hex");
    assert_eq!(
        NamedRouteRecordV3::decode(&encoded)
            .expect("fixture route")
            .encode()
            .expect("canonical route"),
        encoded
    );
}

#[test]
fn packaged_source_contains_the_persistent_route_boundary() {
    for required in [
        "pub struct LeasedPersistentRendezvousService",
        "pub trait NamedRouteV3SoleOwnerLease",
        "pub enum NamedRouteV3LedgerExpectation",
        "pub fn handle_and_emit<",
        "pub async fn handle_and_emit_async<",
        "pub fn put_named_v3_current<",
        "pub fn invalidate_named_v3_withdrawal<",
        "AuthorityLeaseLost",
        "Capturing an earlier read is invalid",
        "postMessage",
    ] {
        assert!(
            PERSISTENT_ROUTING_SOURCE.contains(required),
            "packaged persistent routing source omits {required}"
        );
    }
    for forbidden in [
        "unsafe",
        "unchecked",
        "pub struct PersistentRouteStore",
        "pub struct PersistentRendezvousService",
        "pub fn open_with_lease",
        "pub fn handle(",
        "fence: u64",
    ] {
        assert!(
            !PERSISTENT_ROUTING_SOURCE.contains(forbidden),
            "packaged persistent routing source exposes forbidden boundary {forbidden}"
        );
    }
}

#[test]
fn production_route_release_surface_is_batch_only_and_canonical() {
    for forbidden in [
        "pub fn observe_current_persisted<'",
        "pub async fn observe_current_persisted_async<'",
        "pub fn select_and_observe_current_persisted<",
        "pub async fn select_and_observe_current_persisted_async<",
        "verified: VerifiedNamedRouteV3<'a>,",
        "HNSR-NAMED-V3-REQUESTER-RECORD-V1",
        "pub fn sign_current<'",
    ] {
        assert!(
            !REQUESTER_SOURCE.contains(forbidden) && !NAMED_HRM_SOURCE.contains(forbidden),
            "packaged source exposes forbidden route boundary {forbidden}"
        );
    }
    for required in [
        "pub fn retrieve_select_and_observe_current_persisted<",
        "pub async fn retrieve_select_and_observe_current_persisted_async<",
        "pub enum NamedRouteV3RequesterOperationError<R>",
        "Retrieve: FnOnce(u64)",
        "B: AsRef<[u8]>",
        "fn decode_bounded_raw_route_batch<I, B>(",
        "NamedRouteRecordV3::decode(candidate.as_ref())",
        "record: NamedRouteRecordV3,",
        "Capturing a preloaded batch",
        "previously started future",
        "HNSR-NAMED-V3-CANONICAL-RECORD-V1\\0",
    ] {
        assert!(
            REQUESTER_SOURCE.contains(required),
            "packaged requester source omits {required}"
        );
    }
    let sync_start = REQUESTER_SOURCE
        .find("fn retrieve_select_and_observe_current_persisted<")
        .expect("production sync retrieval source");
    let async_start = REQUESTER_SOURCE
        .find("async fn retrieve_select_and_observe_current_persisted_async<")
        .expect("production async retrieval source");
    let apply_start = REQUESTER_SOURCE[async_start..]
        .find("fn apply_observation")
        .map(|offset| async_start + offset)
        .expect("requester observation helper source");
    let sync_source = &REQUESTER_SOURCE[sync_start..async_start];
    let async_source = &REQUESTER_SOURCE[async_start..apply_start];
    let sync_time = sync_source
        .find("advance_trusted_time_persisted")
        .expect("sync trusted-time boundary");
    let sync_retrieve = sync_source
        .find("let retrieved = retrieve(now);")
        .expect("sync retrieval boundary");
    let sync_recheck = sync_source
        .find("self.validate_operation_lease(operation_lease)")
        .expect("sync post-retrieval lease check");
    assert!(
        sync_time < sync_retrieve
            && sync_retrieve < sync_recheck
            && sync_recheck
                < sync_source
                    .find("decode_bounded_raw_route_batch")
                    .expect("sync decode boundary")
    );
    let async_time = async_source
        .find("advance_trusted_time_persisted_async")
        .expect("async trusted-time boundary");
    let async_retrieve = async_source
        .find("let retrieved = retrieve(now).await;")
        .expect("async retrieval boundary");
    let async_recheck = async_source
        .find("self.validate_operation_lease(operation_lease)")
        .expect("async post-retrieval lease check");
    assert!(
        async_time < async_retrieve
            && async_retrieve < async_recheck
            && async_recheck
                < async_source
                    .find("decode_bounded_raw_route_batch")
                    .expect("async decode boundary")
    );
    assert!(NAMED_HRM_SOURCE.contains("pub fn sign_current_uncommitted<'"));
    assert!(!LIB_SOURCE.contains("VerifiedNamedRouteV3,"));
    assert!(LIB_SOURCE.contains("NamedRouteV3RequesterOperationError"));
}
