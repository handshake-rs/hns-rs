use std::collections::BTreeMap;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_hrm::validation::{
    AcceptedReorganization, AuthenticatedNameState, ResolvedManifest, RollbackObservations,
    ValidatedCurrentManifest, ValidationLimits, validate_current_manifest,
};
use hns_hrm::{
    DecodeLimits, Envelope, ResourceAuthority, Value, decode_canonical, encode_canonical,
};
use hns_service_authority::hrm::{
    EndpointDelegationV1, HnsaError, NamedServiceAttributes, NamedServiceIdentity,
    NamedServicePolicy, ObservedNamedService, SERVICE_GENERATION_OBSERVATION_SIZE,
    SERVICE_GENERATION_OBSERVATION_VERSION, ServiceDelegationConstraints,
    ServiceGenerationObservation, named_service_resource, observe_named_service,
    service_controller_delegation, service_delegation_id,
};
use sha2::{Digest, Sha256};

const AUTHORITY_STATE_SOURCE: &str = include_str!("../src/authority_state.rs");
const HRM_SOURCE: &str = include_str!("../src/hrm.rs");
const LEASE_SOURCE: &str = include_str!("../src/lease.rs");

const NOW: u64 = 1_700_000_300;

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
    T::Err: std::fmt::Debug,
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

fn current_manifest_with_reorganization(
    fixtures: &BTreeMap<&str, &str>,
    envelope_key: &str,
    accepted_reorganization: Option<AcceptedReorganization>,
) -> ValidatedCurrentManifest {
    let encoded = bytes(fixtures, envelope_key);
    let envelope = Envelope::decode(&encoded).expect("fixture HRM envelope");
    let sequence = envelope.payload.sequence;
    let subject = envelope.payload.subject;
    let (chain_height, chain_work, chain_anchor) = chain_state(sequence);
    let envelope_hash: [u8; 32] = Sha256::digest(&encoded).into();
    let root = ResolvedManifest {
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
    };
    validate_current_manifest(
        root,
        integer(fixtures, "network_magic"),
        subject,
        NOW,
        ValidationLimits::default(),
        &RollbackObservations::new(),
    )
    .expect("authenticated current fixture HRM")
}

fn current_manifest(
    fixtures: &BTreeMap<&str, &str>,
    envelope_key: &str,
) -> ValidatedCurrentManifest {
    current_manifest_with_reorganization(fixtures, envelope_key, None)
}

fn assert_observation_vector(
    values: &BTreeMap<&str, &str>,
    field_prefix: &str,
    encoded_field: &str,
    observation: &ServiceGenerationObservation,
    trusted_identity: &NamedServiceIdentity,
) {
    let field = |suffix: &str| format!("{field_prefix}_{suffix}");
    assert_eq!(
        observation.network_magic(),
        integer(values, &field("network_magic"))
    );
    assert_eq!(observation.subject(), array(values, &field("subject")));
    assert_eq!(
        observation.resource_id(),
        array(values, &field("resource_id"))
    );
    assert_eq!(
        observation.highest_generation(),
        integer(values, &field("highest_generation"))
    );
    assert_eq!(
        observation.high_water_delegation_id(),
        array(values, &field("high_water_delegation_id"))
    );
    let active: u8 = integer(values, &field("state"));
    assert_eq!(
        u8::from(observation.active_delegation_id().is_some()),
        active
    );
    assert_eq!(
        observation.hrm_sequence(),
        integer(values, &field("hrm_sequence"))
    );
    assert_eq!(
        observation.hrm_envelope_hash(),
        array(values, &field("hrm_envelope_sha256"))
    );
    let rollback = observation.rollback_state();
    assert_eq!(
        rollback.chain_height,
        integer(values, &field("chain_height"))
    );
    assert_eq!(rollback.chain_work, array(values, &field("chain_work")));
    assert_eq!(rollback.chain_anchor, array(values, &field("chain_anchor")));

    let encoded = observation.encode().expect("encode observation");
    assert_eq!(encoded, bytes(values, encoded_field));
    assert_eq!(encoded.len(), SERVICE_GENERATION_OBSERVATION_SIZE);
    assert_eq!(
        ServiceGenerationObservation::decode(&encoded).expect("decode exact observation"),
        *observation
    );
    assert_eq!(
        ServiceGenerationObservation::restore(&encoded, trusted_identity)
            .expect("restore exact observation"),
        *observation
    );

    let payload_field = format!("{encoded_field}_payload");
    let checksum_field = format!("{encoded_field}_checksum");
    let payload = bytes(values, &payload_field);
    let checksum = bytes(values, &checksum_field);
    assert_eq!(
        payload.len() + checksum.len(),
        SERVICE_GENERATION_OBSERVATION_SIZE
    );
    assert_eq!(&encoded[..payload.len()], payload);
    assert_eq!(&encoded[payload.len()..], checksum);
    assert_eq!(
        blake2b_256(&[
            b"HNS-HRM-HNSA-SERVICE-GENERATION-OBSERVATION-V1\0",
            &payload,
        ]),
        checksum.as_slice()
    );
}

#[test]
fn packaged_fixture_and_sidecar_are_exact() {
    let source = include_bytes!("../fixtures/hnsa-hnsr-v3/hnsa-hnsr-v3.txt");
    let expected = include_str!("../fixtures/hnsa-hnsr-v3/hnsa-hnsr-v3.txt.sha256")
        .split_whitespace()
        .next()
        .expect("fixture sidecar digest");
    assert_eq!(hex::encode(Sha256::digest(source)), expected);

    let values = fixtures();
    for required in [
        "authority_fresh_snapshot",
        "authority_fresh_snapshot_fingerprint",
        "authority_time_only_snapshot",
        "authority_active_snapshot",
        "authority_replacement_snapshot",
        "authority_withdrawn_snapshot",
        "authority_accepted_reorg_snapshot",
        "authority_accepted_reorg_prior_fingerprint",
    ] {
        assert!(
            values.get(required).is_some_and(|value| !value.is_empty()),
            "missing packaged persistence vector {required}"
        );
    }
}

#[test]
fn production_authority_binding_is_exact_time_and_raw_endpoint_apis_are_explicit() {
    assert!(AUTHORITY_STATE_SOURCE.contains("pub fn bind_current_at<'"));
    assert!(!AUTHORITY_STATE_SOURCE.contains("pub fn bind_current<'"));
    assert!(!AUTHORITY_STATE_SOURCE.contains("pub fn bind_current_uncommitted<'"));
    for required in [
        "pub fn sign_uncommitted(",
        "pub fn verify_uncommitted(",
        "pub fn select_endpoint_delegation_uncommitted<'",
    ] {
        assert!(
            HRM_SOURCE.contains(required),
            "packaged HRM source omits {required}"
        );
    }
    assert!(!HRM_SOURCE.contains("pub fn select_endpoint_delegation<'"));
    assert!(
        !HRM_SOURCE
            .contains("#[derive(Clone, Debug, Eq, PartialEq)]\npub struct VerifiedNamedService")
    );
}

#[test]
fn packaged_source_contains_the_fenced_authority_boundary() {
    for required in [
        "pub trait FencedLeaseGuard<K>",
        "pub struct HeldFencedLease<K, G>",
        "pub struct LeaseWitness<'a, K>",
        "pub type HeldAuthorityLease<G>",
        "pub fn reconfirm<'a, E, F>(",
        "pub struct ReconfirmedNamedServiceAuthorityState<'a>",
        "pub enum NamedServiceAuthorityOperationError<R, P>",
        "pub fn retrieve_validate_and_observe<R, P, Retrieve, Persist>(",
        "pub async fn retrieve_validate_and_observe_async<",
        "storage_namespace_id: StorageNamespaceId",
        "fencing_token: FencingToken",
    ] {
        assert!(
            LEASE_SOURCE.contains(required) || AUTHORITY_STATE_SOURCE.contains(required),
            "packaged authority source omits {required}"
        );
    }
    for forbidden in [
        "unsafe fn",
        "unsafe {",
        "pub struct Noop",
        "impl Default for HeldFencedLease",
        "pub fn bind_current_uncommitted<'",
        "pub fn validate_and_observe<",
        "pub async fn validate_and_observe_async<",
        "pub fn from_acquired",
    ] {
        assert!(
            !LEASE_SOURCE.contains(forbidden) && !AUTHORITY_STATE_SOURCE.contains(forbidden),
            "packaged authority source exposes forbidden boundary {forbidden}"
        );
    }
}

#[test]
fn independent_named_service_and_endpoint_vectors_match() {
    let values = fixtures();
    let identity = NamedServiceIdentity::new(
        values["network_magic"].parse().expect("network magic"),
        array(&values, "name_hash"),
        values["service_name"],
        values["application_profile_id"]
            .parse()
            .expect("application profile"),
    )
    .expect("identity");
    assert_eq!(
        identity.canonical_identifier().expect("identifier"),
        bytes(&values, "named_service_identifier")
    );
    assert_eq!(
        identity.resource_id().expect("resource ID"),
        array(&values, "service_resource_id")
    );
    assert_eq!(
        NamedServiceIdentity::decode_identifier(&bytes(&values, "named_service_identifier"))
            .expect("decode identity"),
        identity
    );

    let envelope = Envelope::decode(&bytes(&values, "hrm_envelope")).expect("HRM envelope");
    assert_eq!(
        envelope.payload.encode().expect("HRM payload encode"),
        bytes(&values, "hrm_payload")
    );
    assert_eq!(
        Sha256::digest(bytes(&values, "hrm_envelope")).as_slice(),
        array::<32>(&values, "hrm_envelope_sha256")
    );

    let payload_value = decode_canonical(&bytes(&values, "hrm_payload"), DecodeLimits::default())
        .expect("fixture payload CBOR");
    let Value::Map(payload_fields) = payload_value else {
        panic!("fixture payload is not a map");
    };
    let Value::Array(resource_values) = &payload_fields
        .iter()
        .find(|(key, _)| *key == 6)
        .expect("payload resources")
        .1
    else {
        panic!("fixture resources are not an array");
    };
    assert_eq!(
        resource_values.first().expect("fixture resource"),
        &decode_canonical(&bytes(&values, "service_resource"), DecodeLimits::default())
            .expect("fixture resource CBOR")
    );
    let Value::Array(delegation_values) = &payload_fields
        .iter()
        .find(|(key, _)| *key == 7)
        .expect("payload delegations")
        .1
    else {
        panic!("fixture delegations are not an array");
    };
    let delegation_value = delegation_values.first().expect("fixture delegation");
    assert_eq!(
        delegation_value,
        &decode_canonical(
            &bytes(&values, "service_delegation"),
            DecodeLimits::default(),
        )
        .expect("fixture delegation CBOR")
    );
    let Value::Map(delegation_fields) = delegation_value else {
        panic!("fixture delegation is not a map");
    };
    assert_eq!(
        &delegation_fields
            .iter()
            .find(|(key, _)| *key == 11)
            .expect("delegation constraints")
            .1,
        &decode_canonical(
            &bytes(&values, "service_delegation_constraints"),
            DecodeLimits::default(),
        )
        .expect("fixture constraint CBOR")
    );
    let resource = &envelope.payload.resources[0];
    assert_eq!(resource.authority, ResourceAuthority::HnsLocal);
    assert_eq!(
        resource.identifier,
        bytes(&values, "named_service_identifier")
    );
    assert_eq!(
        encode_canonical(&Value::Map(
            resource.attributes.clone().expect("resource attributes")
        ))
        .expect("encode attributes"),
        bytes(&values, "service_resource_attributes")
    );
    let built_resource = named_service_resource(
        &identity,
        NamedServiceAttributes {
            profile_flags: 0,
            profile_constraints_hash: [0; 32],
            presentation: None,
        },
        values["resource_not_before"]
            .parse()
            .expect("resource start"),
        values["resource_expires_at"]
            .parse()
            .expect("resource expiry"),
    )
    .expect("build resource");
    assert_eq!(&built_resource, resource);
    let delegation = &envelope.payload.delegations[0];
    assert_eq!(
        encode_canonical(
            &delegation
                .body_value(envelope.payload.issued_at, envelope.payload.expires_at)
                .expect("delegation body")
        )
        .expect("encode delegation body"),
        bytes(&values, "service_delegation_body")
    );
    let built_delegation = service_controller_delegation(
        &identity,
        &built_resource,
        array(&values, "service_controller_public_key"),
        ServiceDelegationConstraints {
            service_generation: values["service_generation"].parse().expect("generation"),
            max_endpoint_lifetime: values["max_endpoint_lifetime"]
                .parse()
                .expect("maximum endpoint lifetime"),
            allowed_endpoint_capabilities: values["allowed_endpoint_capabilities"]
                .parse()
                .expect("endpoint capabilities"),
            endpoint_constraints_hash: [0; 32],
        },
        values["service_not_before"].parse().expect("service start"),
        values["service_expires_at"]
            .parse()
            .expect("service expiry"),
        envelope.payload.issued_at,
        envelope.payload.expires_at,
    )
    .expect("build service delegation");
    assert_eq!(&built_delegation, delegation);
    assert_eq!(
        service_delegation_id(
            delegation,
            envelope.payload.issued_at,
            envelope.payload.expires_at,
        )
        .expect("delegation ID"),
        array(&values, "service_delegation_id")
    );

    let endpoint_bytes = bytes(&values, "endpoint_delegation");
    let endpoint = EndpointDelegationV1::decode(&endpoint_bytes).expect("endpoint delegation");
    assert_eq!(
        endpoint.encode_body().expect("endpoint body"),
        bytes(&values, "endpoint_delegation_body")
    );
    assert_eq!(endpoint.encode().expect("endpoint encode"), endpoint_bytes);
    assert_eq!(
        endpoint.service_signature,
        bytes(&values, "endpoint_delegation_signature")
    );
    assert_eq!(
        blake2b_256(&[
            b"HNS-HRM-HNSA-ENDPOINT-DELEGATION-V1\0",
            &bytes(&values, "endpoint_delegation_body"),
        ]),
        array(&values, "endpoint_delegation_signature_digest")
    );
    assert_eq!(
        endpoint.id().expect("endpoint ID"),
        array(&values, "endpoint_delegation_id")
    );
    endpoint
        .verify_admission(&array(&values, "service_controller_public_key"))
        .expect("service signature");
    let manifest = current_manifest(&values, "hrm_envelope");
    let service = observe_named_service(&manifest, &identity, &policy(&values), None)
        .expect("current named service")
        .into_active()
        .expect("active named service");
    endpoint
        .verify_uncommitted(
            &service,
            NOW,
            integer(&values, "allowed_endpoint_capabilities"),
        )
        .expect("current endpoint authority");
}

#[test]
fn independent_negative_endpoint_vectors_fail_closed() {
    let values = fixtures();
    for key in [
        "zero_sequence_endpoint",
        "high_s_endpoint",
        "nonminimal_der_endpoint",
        "trailing_endpoint",
    ] {
        assert!(
            EndpointDelegationV1::decode(&bytes(&values, key)).is_err(),
            "accepted negative vector {key}"
        );
    }

    let service_key = array(&values, "service_controller_public_key");
    assert!(
        EndpointDelegationV1::decode(&bytes(&values, "wrong_service_key_endpoint"))
            .expect("structurally valid wrong-service-key endpoint")
            .verify_admission(&service_key)
            .is_err()
    );

    let manifest = current_manifest(&values, "hrm_envelope");
    let service = observe_named_service(&manifest, &identity(&values), &policy(&values), None)
        .expect("current named service")
        .into_active()
        .expect("active named service");
    for key in [
        "wrong_network_endpoint",
        "wrong_resource_endpoint",
        "wrong_delegation_id_endpoint",
        "wrong_generation_endpoint",
        "wrong_capabilities_endpoint",
        "wrong_constraints_endpoint",
        "not_current_endpoint",
        "expired_endpoint",
        "over_lifetime_endpoint",
    ] {
        let endpoint = EndpointDelegationV1::decode(&bytes(&values, key))
            .expect("structurally valid negative endpoint");
        endpoint
            .verify_admission(&service_key)
            .expect("negative endpoint has a valid internal signature");
        assert!(
            endpoint.verify_uncommitted(&service, NOW, 1).is_err(),
            "accepted contextual negative endpoint {key}"
        );
    }

    let alternate =
        EndpointDelegationV1::decode(&bytes(&values, "alternate_endpoint_key_endpoint"))
            .expect("alternate endpoint");
    assert_eq!(
        alternate.endpoint_key,
        array(&values, "alternate_endpoint_public_key")
    );
    alternate
        .verify_uncommitted(&service, NOW, 1)
        .expect("concurrent endpoint key is fully current");
}

#[test]
fn independent_identity_resource_and_snapshot_vectors_fail_closed() {
    let values = fixtures();
    let expected_identity = identity(&values);
    let expected_policy = policy(&values);

    let alternatives = [
        (
            "wrong_identity_network",
            NamedServiceIdentity::new(
                integer(&values, "wrong_network_magic"),
                expected_identity.name_hash,
                &expected_identity.service_name,
                expected_identity.application_profile_id,
            )
            .expect("wrong-network identity"),
        ),
        (
            "wrong_identity_name_hash",
            NamedServiceIdentity::new(
                expected_identity.network_magic,
                array(&values, "wrong_name_hash"),
                &expected_identity.service_name,
                expected_identity.application_profile_id,
            )
            .expect("wrong-name-hash identity"),
        ),
        (
            "wrong_identity_service_name",
            NamedServiceIdentity::new(
                expected_identity.network_magic,
                expected_identity.name_hash,
                values["wrong_service_name"],
                expected_identity.application_profile_id,
            )
            .expect("wrong-service identity"),
        ),
        (
            "wrong_identity_application_profile",
            NamedServiceIdentity::new(
                expected_identity.network_magic,
                expected_identity.name_hash,
                &expected_identity.service_name,
                integer(&values, "wrong_application_profile_id"),
            )
            .expect("wrong-profile identity"),
        ),
    ];
    for (stem, alternative) in alternatives {
        assert_eq!(
            alternative.canonical_identifier().expect("identifier"),
            bytes(&values, &format!("{stem}_identifier"))
        );
        assert_eq!(
            alternative.resource_id().expect("resource ID"),
            array(&values, &format!("{stem}_resource_id"))
        );
        let envelope_key = format!("{stem}_hrm_envelope");
        let payload_key = format!("{stem}_hrm_payload");
        let envelope = Envelope::decode(&bytes(&values, &envelope_key)).expect("variant envelope");
        assert_eq!(
            envelope.payload.encode().expect("variant payload"),
            bytes(&values, &payload_key)
        );
        let manifest = current_manifest(&values, &envelope_key);
        assert!(matches!(
            observe_named_service(&manifest, &expected_identity, &expected_policy, None,),
            Ok(ObservedNamedService::Withdrawn(_))
        ));
    }

    for stem in [
        "wrong_resource_origin",
        "wrong_resource_profile_flags",
        "wrong_resource_profile_constraints",
    ] {
        let envelope_key = format!("{stem}_hrm_envelope");
        let payload_key = format!("{stem}_hrm_payload");
        let envelope = Envelope::decode(&bytes(&values, &envelope_key)).expect("variant envelope");
        assert_eq!(
            envelope.payload.encode().expect("variant payload"),
            bytes(&values, &payload_key)
        );
        let manifest = current_manifest(&values, &envelope_key);
        assert!(
            observe_named_service(&manifest, &expected_identity, &expected_policy, None,).is_err(),
            "accepted invalid resource variant {stem}"
        );
    }

    let missing = current_manifest(&values, "missing_operate_delegation_hrm_envelope");
    assert_eq!(
        missing.current_snapshot().sequence(),
        integer::<u64>(&values, "hrm_sequence") + 1
    );
    assert!(matches!(
        observe_named_service(&missing, &expected_identity, &expected_policy, None),
        Ok(ObservedNamedService::Withdrawn(_))
    ));

    let duplicate = current_manifest(&values, "duplicate_operate_delegation_hrm_envelope");
    assert!(matches!(
        observe_named_service(&duplicate, &expected_identity, &expected_policy, None),
        Err(HnsaError::Ambiguous)
    ));

    let removed = current_manifest(&values, "resource_removal_hrm_envelope");
    assert!(matches!(
        observe_named_service(&removed, &expected_identity, &expected_policy, None),
        Ok(ObservedNamedService::Withdrawn(_))
    ));

    let transferred = current_manifest(&values, "ownership_transfer_hrm_envelope");
    assert_eq!(
        transferred.subject(),
        array(&values, "ownership_transfer_subject")
    );
    assert!(
        observe_named_service(&transferred, &expected_identity, &expected_policy, None,).is_err()
    );
}

#[test]
fn independent_generation_withdrawal_restoration_and_reorg_vectors_are_stateful() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let initial_manifest = current_manifest(&values, "hrm_envelope");
    let initial = observe_named_service(&initial_manifest, &identity, &policy, None)
        .expect("initial service")
        .into_active()
        .expect("active initial service");

    let conflict_manifest = current_manifest(&values, "equal_generation_conflict_hrm_envelope");
    assert!(matches!(
        observe_named_service(
            &conflict_manifest,
            &identity,
            &policy,
            Some(initial.generation_observation()),
        ),
        Err(HnsaError::GenerationConflict)
    ));
    let rollback_manifest = current_manifest(&values, "rollback_hrm_envelope");
    assert!(matches!(
        observe_named_service(
            &rollback_manifest,
            &identity,
            &policy,
            Some(initial.generation_observation()),
        ),
        Err(HnsaError::GenerationRollback)
    ));

    let replacement_manifest = current_manifest(&values, "replacement_hrm_envelope");
    let replacement = observe_named_service(
        &replacement_manifest,
        &identity,
        &policy,
        Some(initial.generation_observation()),
    )
    .expect("replacement service")
    .into_active()
    .expect("active replacement service");
    assert_eq!(
        replacement.service_generation(),
        integer(&values, "replacement_service_generation")
    );
    assert_eq!(
        replacement.delegation_id(),
        array(&values, "replacement_service_delegation_id")
    );

    let removal_manifest = current_manifest(&values, "removal_hrm_envelope");
    let removal = observe_named_service(
        &removal_manifest,
        &identity,
        &policy,
        Some(replacement.generation_observation()),
    )
    .expect("service withdrawal");
    assert!(removal.observation().is_withdrawn());
    assert!(matches!(
        observe_named_service(
            &replacement_manifest,
            &identity,
            &policy,
            Some(removal.observation()),
        ),
        Err(HnsaError::GenerationRollback)
    ));

    let restoration_manifest = current_manifest(&values, "restoration_hrm_envelope");
    let restoration = observe_named_service(
        &restoration_manifest,
        &identity,
        &policy,
        Some(removal.observation()),
    )
    .expect("service restoration")
    .into_active()
    .expect("active restored service");
    assert_eq!(
        restoration.service_generation(),
        integer(&values, "restoration_service_generation")
    );
    assert_eq!(
        restoration.delegation_id(),
        array(&values, "restoration_service_delegation_id")
    );

    let previous_sequence: u64 = integer(&values, "reorg_previous_hrm_sequence");
    let current_sequence: u64 = integer(&values, "reorg_current_hrm_sequence");
    assert_eq!(replacement.hrm_sequence(), previous_sequence);
    assert_eq!(initial.hrm_sequence(), current_sequence);
    assert_eq!(
        Sha256::digest(bytes(&values, "replacement_hrm_envelope")).as_slice(),
        array::<32>(&values, "reorg_previous_hrm_envelope_sha256")
    );
    assert_eq!(
        Sha256::digest(bytes(&values, "hrm_envelope")).as_slice(),
        array::<32>(&values, "reorg_current_hrm_envelope_sha256")
    );
    let accepted = AcceptedReorganization {
        previous_chain_height: integer(&values, "reorg_previous_chain_height"),
        previous_chain_work: array(&values, "reorg_previous_chain_work"),
        previous_chain_anchor: array(&values, "reorg_previous_chain_anchor"),
        current_chain_height: integer(&values, "reorg_current_chain_height"),
        current_chain_work: array(&values, "reorg_current_chain_work"),
        current_chain_anchor: array(&values, "reorg_current_chain_anchor"),
    };
    let reorg_manifest =
        current_manifest_with_reorganization(&values, "hrm_envelope", Some(accepted));
    observe_named_service(
        &reorg_manifest,
        &identity,
        &policy,
        Some(replacement.generation_observation()),
    )
    .expect("exact accepted reorganization")
    .into_active()
    .expect("active post-reorganization service");
}

#[test]
fn independent_generation_observation_vectors_are_exact_and_stateful() {
    let values = fixtures();
    assert_eq!(
        bytes(&values, "service_generation_observation_magic"),
        b"HNSASGO\0"
    );
    assert_eq!(
        bytes(&values, "service_generation_observation_checksum_domain"),
        b"HNS-HRM-HNSA-SERVICE-GENERATION-OBSERVATION-V1\0"
    );
    assert_eq!(
        integer::<u8>(&values, "service_generation_observation_version"),
        SERVICE_GENERATION_OBSERVATION_VERSION
    );
    assert_eq!(
        integer::<usize>(&values, "service_generation_observation_size"),
        SERVICE_GENERATION_OBSERVATION_SIZE
    );
    assert_eq!(
        integer::<usize>(&values, "service_generation_observation_payload_size") + 32,
        SERVICE_GENERATION_OBSERVATION_SIZE
    );

    let identity = identity(&values);
    let policy = policy(&values);
    let initial_manifest = current_manifest(&values, "hrm_envelope");
    let initial = observe_named_service(&initial_manifest, &identity, &policy, None)
        .expect("initial service")
        .into_active()
        .expect("active initial service");
    assert_observation_vector(
        &values,
        "active_observation",
        "active_service_generation_observation",
        initial.generation_observation(),
        &identity,
    );
    let restored_initial = ServiceGenerationObservation::restore(
        &bytes(&values, "active_service_generation_observation"),
        &identity,
    )
    .expect("restored active observation");

    let replacement_manifest = current_manifest(&values, "replacement_hrm_envelope");
    let replacement = observe_named_service(
        &replacement_manifest,
        &identity,
        &policy,
        Some(&restored_initial),
    )
    .expect("replacement service")
    .into_active()
    .expect("active replacement service");
    let removal_manifest = current_manifest(&values, "removal_hrm_envelope");
    let withdrawn = observe_named_service(
        &removal_manifest,
        &identity,
        &policy,
        Some(replacement.generation_observation()),
    )
    .expect("ordinary withdrawal");
    assert!(withdrawn.observation().is_withdrawn());
    assert_observation_vector(
        &values,
        "withdrawn_observation",
        "withdrawn_service_generation_observation",
        withdrawn.observation(),
        &identity,
    );
    let restored_withdrawal = ServiceGenerationObservation::restore(
        &bytes(&values, "withdrawn_service_generation_observation"),
        &identity,
    )
    .expect("restored withdrawal tombstone");
    assert!(matches!(
        observe_named_service(
            &replacement_manifest,
            &identity,
            &policy,
            Some(&restored_withdrawal),
        ),
        Err(HnsaError::GenerationRollback)
    ));

    let reorg_envelope = Envelope::decode(&bytes(&values, "reorg_withdrawal_hrm_envelope"))
        .expect("reorganization withdrawal envelope");
    assert_eq!(
        reorg_envelope
            .payload
            .encode()
            .expect("reorganization payload"),
        bytes(&values, "reorg_withdrawal_hrm_payload")
    );
    let unaccepted = current_manifest(&values, "reorg_withdrawal_hrm_envelope");
    assert!(matches!(
        observe_named_service(
            &unaccepted,
            &identity,
            &policy,
            Some(replacement.generation_observation()),
        ),
        Err(HnsaError::GenerationRollback)
    ));
    let accepted = AcceptedReorganization {
        previous_chain_height: integer(&values, "reorg_previous_chain_height"),
        previous_chain_work: array(&values, "reorg_previous_chain_work"),
        previous_chain_anchor: array(&values, "reorg_previous_chain_anchor"),
        current_chain_height: integer(&values, "reorg_current_chain_height"),
        current_chain_work: array(&values, "reorg_current_chain_work"),
        current_chain_anchor: array(&values, "reorg_current_chain_anchor"),
    };
    let accepted_manifest = current_manifest_with_reorganization(
        &values,
        "reorg_withdrawal_hrm_envelope",
        Some(accepted),
    );
    let reset = observe_named_service(
        &accepted_manifest,
        &identity,
        &policy,
        Some(replacement.generation_observation()),
    )
    .expect("accepted-reorganization withdrawal");
    assert!(reset.observation().is_withdrawn());
    assert_eq!(reset.observation().highest_generation(), 0);
    assert_eq!(reset.observation().high_water_delegation_id(), [0; 32]);
    assert_observation_vector(
        &values,
        "reorg_reset_observation",
        "reorg_reset_service_generation_observation",
        reset.observation(),
        &identity,
    );
    let restored_reset = ServiceGenerationObservation::restore(
        &bytes(&values, "reorg_reset_service_generation_observation"),
        &identity,
    )
    .expect("restored reorganization-reset tombstone");
    let formerly_rolled_back = current_manifest(&values, "rollback_hrm_envelope");
    let post_reorganization = observe_named_service(
        &formerly_rolled_back,
        &identity,
        &policy,
        Some(&restored_reset),
    )
    .expect("reset high-water permits post-reorganization generation")
    .into_active()
    .expect("active post-reorganization service");
    assert_eq!(
        post_reorganization.service_generation(),
        integer::<u64>(&values, "service_generation") - 1
    );
}

#[test]
fn independent_observation_vectors_reject_corruption_and_identity_substitution() {
    let values = fixtures();
    let encoded = bytes(&values, "active_service_generation_observation");
    ServiceGenerationObservation::decode(&encoded).expect("valid independent observation");

    for offset in [0, encoded.len() - 1] {
        let mut corrupted = encoded.clone();
        corrupted[offset] ^= 1;
        assert!(
            ServiceGenerationObservation::decode(&corrupted).is_err(),
            "accepted corrupted byte at offset {offset}"
        );
    }
    assert!(ServiceGenerationObservation::decode(&encoded[..encoded.len() - 1]).is_err());
    let mut extended = encoded.clone();
    extended.push(0);
    assert!(ServiceGenerationObservation::decode(&extended).is_err());

    let expected = identity(&values);
    let substitutions = [
        NamedServiceIdentity::new(
            integer(&values, "wrong_network_magic"),
            expected.name_hash,
            &expected.service_name,
            expected.application_profile_id,
        )
        .expect("wrong-network identity"),
        NamedServiceIdentity::new(
            expected.network_magic,
            array(&values, "wrong_name_hash"),
            &expected.service_name,
            expected.application_profile_id,
        )
        .expect("wrong-name identity"),
        NamedServiceIdentity::new(
            expected.network_magic,
            expected.name_hash,
            values["wrong_service_name"],
            expected.application_profile_id,
        )
        .expect("wrong-service identity"),
        NamedServiceIdentity::new(
            expected.network_magic,
            expected.name_hash,
            &expected.service_name,
            integer(&values, "wrong_application_profile_id"),
        )
        .expect("wrong-profile identity"),
    ];
    for substitution in substitutions {
        assert!(
            ServiceGenerationObservation::restore(&encoded, &substitution).is_err(),
            "restored an observation under substituted identity {substitution:?}"
        );
    }
}
