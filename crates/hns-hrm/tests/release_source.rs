use std::str::FromStr;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_hrm::model::public_key;
use hns_hrm::{
    CommitmentError, CommitmentLimits, Envelope, Payload, ResourceAuthority, Value,
    parse_txt_commitment, select_commitment,
};
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("../fixtures/hrm-v1/hns-hrm-core-v1.txt");
const VECTORS_SHA256: &str = include_str!("../fixtures/hrm-v1/hns-hrm-core-v1.txt.sha256");

fn vector(name: &str) -> &str {
    VECTORS
        .lines()
        .filter_map(|line| line.split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
        .unwrap_or_else(|| panic!("missing HRM release vector {name}"))
}

fn vector_number<T>(name: &str) -> T
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    vector(name)
        .parse()
        .unwrap_or_else(|error| panic!("invalid numeric HRM vector {name}: {error}"))
}

fn vector_bytes(name: &str) -> Vec<u8> {
    hex::decode(vector(name))
        .unwrap_or_else(|error| panic!("invalid hexadecimal HRM vector {name}: {error}"))
}

fn vector_array<const N: usize>(name: &str) -> [u8; N] {
    vector_bytes(name)
        .try_into()
        .unwrap_or_else(|_| panic!("HRM vector {name} is not {N} bytes"))
}

fn record(fields: &[&str]) -> Vec<String> {
    fields
        .iter()
        .map(|field| vector(field).to_owned())
        .collect()
}

#[test]
fn release_source_payload_and_signature_are_exact() {
    let network_magic = vector_number::<u32>("network_magic");
    assert_eq!(
        network_magic.to_le_bytes(),
        vector_array("network_magic_u32le")
    );

    let private_key = vector_array("private_key");
    assert_eq!(
        public_key(&private_key).expect("derive fixture controller key"),
        vector_array("controller_public_key")
    );

    let payload_bytes = vector_bytes("payload_v1");
    let mut signature_hasher = Blake2bVar::new(32).expect("BLAKE2b-256");
    signature_hasher.update(b"HNS-HRM-v1\0");
    signature_hasher.update(&network_magic.to_le_bytes());
    signature_hasher.update(&payload_bytes);
    let mut signature_digest = [0; 32];
    signature_hasher
        .finalize_variable(&mut signature_digest)
        .expect("BLAKE2b-256 output");
    assert_eq!(signature_digest, vector_array("payload_signature_digest"));

    let payload = Payload::decode(&payload_bytes).expect("canonical HRM payload fixture");
    assert_eq!(payload.encode().expect("encode HRM payload"), payload_bytes);
    assert_eq!(payload.version, 1);
    assert_eq!(payload.subject, vector_array("subject"));
    assert_eq!(payload.sequence, vector_number::<u64>("sequence"));
    assert_eq!(payload.issued_at, vector_number::<u64>("issued_at"));
    assert_eq!(payload.expires_at, vector_number::<u64>("expires_at"));
    assert_eq!(
        payload.controller.public_key,
        vector_array("controller_public_key")
    );
    assert_eq!(payload.resources.len(), 1);
    assert_eq!(payload.resources[0].profile, "example.hrm-core/v1");
    assert_eq!(
        payload.resources[0].resource_id,
        vector_array("resource_id")
    );
    assert_eq!(payload.resources[0].authority, ResourceAuthority::HnsLocal);
    assert_eq!(
        payload.resources[0].attributes,
        Some(vec![
            (0, Value::Unsigned(0)),
            (1, Value::Bytes(vec![0; 32])),
        ])
    );
    assert_eq!(payload.delegations.len(), 1);
    let delegation = &payload.delegations[0];
    assert_eq!(delegation.delegation_id, vector_array("delegation_id"));
    assert_eq!(delegation.parent_resource_id, vector_array("resource_id"));
    assert_eq!(
        delegation.child_resource_id,
        vector_array("child_resource_id")
    );
    assert_eq!(delegation.rights, ["inspect", "operate"]);
    assert!(!delegation.may_subdelegate);
    assert_eq!(
        delegation.child_controller.public_key,
        vector_array("other_public_key")
    );
    assert_eq!(
        payload.extensions,
        Some(vec![
            (0, Value::Text("source-independent".to_owned())),
            (1, Value::Bool(true)),
        ])
    );

    let envelope_bytes = vector_bytes("envelope_v1");
    let envelope = Envelope::decode(&envelope_bytes).expect("canonical HRM envelope fixture");
    assert_eq!(envelope.payload, payload);
    assert_eq!(
        envelope.encode().expect("encode HRM envelope"),
        envelope_bytes
    );
    assert_eq!(
        envelope.signatures[0].signature,
        vector_bytes("controller_signature_der")
    );
    assert_eq!(
        envelope.envelope_hash().expect("hash HRM envelope"),
        vector_array("envelope_sha256")
    );
    envelope
        .validate_context(
            network_magic,
            vector_array("subject"),
            vector_number("sequence"),
            vector_number::<u64>("issued_at") + 1,
            0,
        )
        .expect("valid source-independent HRM context");

    let regenerated = Envelope::sign(envelope.payload.clone(), network_magic, &private_key)
        .expect("deterministically sign HRM fixture payload");
    assert_eq!(
        regenerated
            .encode()
            .expect("encode regenerated HRM envelope"),
        envelope_bytes,
        "Rust deterministic signing diverges from the independent RFC6979 oracle"
    );
}

#[test]
fn release_source_noncanonical_and_false_authority_vectors_fail_closed() {
    for name in ["noncanonical_payload", "unknown_key_payload"] {
        assert!(
            Payload::decode(&vector_bytes(name)).is_err(),
            "accepted invalid HRM payload vector {name}"
        );
    }
    for name in ["high_s_signature_envelope", "trailing_envelope"] {
        assert!(
            Envelope::decode(&vector_bytes(name)).is_err(),
            "accepted invalid HRM envelope vector {name}"
        );
    }

    let network_magic = vector_number::<u32>("network_magic");
    let wrong_network_magic = vector_number::<u32>("wrong_network_magic");
    let wrong_network = Envelope::decode(&vector_bytes("wrong_network_signature_envelope"))
        .expect("structurally valid wrong-network signature vector");
    assert!(
        wrong_network
            .verify_controller_signature(network_magic)
            .is_err()
    );
    wrong_network
        .verify_controller_signature(wrong_network_magic)
        .expect("signature is valid only under its different network domain");

    for name in [
        "wrong_controller_signature_envelope",
        "tampered_payload_envelope",
    ] {
        let envelope = Envelope::decode(&vector_bytes(name))
            .unwrap_or_else(|error| panic!("invalid structural vector {name}: {error}"));
        assert!(
            envelope.verify_controller_signature(network_magic).is_err(),
            "accepted false controller authority vector {name}"
        );
    }

    let envelope = Envelope::decode(&vector_bytes("envelope_v1")).expect("valid envelope");
    let sequence = vector_number::<u64>("sequence");
    let now = vector_number::<u64>("issued_at") + 1;
    assert!(
        envelope
            .validate_context(
                wrong_network_magic,
                vector_array("subject"),
                sequence,
                now,
                0,
            )
            .is_err()
    );
    assert!(
        envelope
            .validate_context(
                network_magic,
                vector_array("wrong_subject"),
                sequence,
                now,
                0,
            )
            .is_err()
    );
    assert!(
        envelope
            .validate_context(network_magic, vector_array("subject"), sequence + 1, now, 0,)
            .is_err()
    );
    assert!(
        envelope
            .validate_context(
                network_magic,
                vector_array("subject"),
                sequence,
                vector_number("expires_at"),
                0,
            )
            .is_err()
    );
}

#[test]
fn release_source_commitment_vectors_select_and_bind_the_envelope() {
    let limits = CommitmentLimits::default();
    let current = record(&[
        "commitment_marker",
        "commitment_seq",
        "commitment_hash",
        "commitment_uri",
    ]);
    let parsed = parse_txt_commitment(&current, &limits).expect("current HRM commitment");
    assert_eq!(parsed.sequence, vector_number::<u64>("sequence"));
    assert_eq!(parsed.envelope_hash, vector_array("envelope_sha256"));
    let actual_envelope_hash: [u8; 32] = Sha256::digest(vector_bytes("envelope_v1")).into();
    assert_eq!(actual_envelope_hash, parsed.envelope_hash);

    let lower = record(&[
        "commitment_marker",
        "lower_commitment_seq",
        "conflict_commitment_hash",
        "commitment_uri",
    ]);
    let replica = record(&[
        "commitment_marker",
        "commitment_seq",
        "commitment_hash",
        "commitment_replica_uri",
    ]);
    let malformed = record(&[
        "commitment_marker",
        "invalid_commitment_seq",
        "commitment_hash",
        "commitment_uri",
    ]);
    let selected = select_commitment(
        [lower, malformed, current.clone(), replica.clone()],
        &limits,
    )
    .expect("greatest unambiguous HRM commitment");
    assert_eq!(selected.sequence, parsed.sequence);
    assert_eq!(selected.envelope_hash, parsed.envelope_hash);
    assert_eq!(selected.uris.len(), 2);

    let conflicting = record(&[
        "commitment_marker",
        "commitment_seq",
        "conflict_commitment_hash",
        "commitment_replica_uri",
    ]);
    assert!(matches!(
        select_commitment([current.clone(), conflicting], &limits),
        Err(CommitmentError::ConflictingSequence { sequence: 7 })
    ));

    let mismatch = record(&[
        "commitment_marker",
        "commitment_seq",
        "mismatch_commitment_hash",
        "commitment_uri",
    ]);
    assert_ne!(
        parse_txt_commitment(&mismatch, &limits)
            .expect("syntactically valid mismatched hash")
            .envelope_hash,
        vector_array::<32>("envelope_sha256")
    );
    let unknown = record(&[
        "commitment_marker",
        "commitment_seq",
        "commitment_hash",
        "commitment_uri",
        "invalid_commitment_unknown",
    ]);
    assert!(parse_txt_commitment(&unknown, &limits).is_err());

    for invalid_uri in [
        "invalid_commitment_uri_unclosed_literal",
        "invalid_commitment_uri_bracketed_reg_name",
        "invalid_commitment_uri_repeated_fragment",
    ] {
        let malformed = record(&[
            "commitment_marker",
            "commitment_seq",
            "commitment_hash",
            invalid_uri,
        ]);
        assert_eq!(
            parse_txt_commitment(&malformed, &limits),
            Err(CommitmentError::InvalidUri { index: 3 }),
            "accepted malformed independent URI vector {invalid_uri}"
        );
    }
}

#[test]
fn release_source_vector_sidecar_authenticates_packaged_bytes() {
    let expected = VECTORS_SHA256
        .split_whitespace()
        .next()
        .expect("HRM fixture digest");
    assert_eq!(hex::encode(Sha256::digest(VECTORS.as_bytes())), expected);
}
