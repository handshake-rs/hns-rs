use std::collections::BTreeMap;
use std::num::NonZeroU64;

use hns_rollback_journal::{
    DatabaseObservation, FencingToken, JournalBinding, JournalBindingParts, JournalLeaseContext,
    JournalRecord, JournalState, RollbackProtectionClass, SnapshotImage, privileged_provision,
};

const FIXTURE: &str = include_str!("../fixtures/rollback-journal-v1/rollback-journal-v1.txt");

fn values() -> BTreeMap<&'static str, &'static str> {
    FIXTURE
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_once('=').expect("fixture key=value"))
        .collect()
}

fn bytes(values: &BTreeMap<&str, &str>, key: &str) -> Vec<u8> {
    hex::decode(values.get(key).unwrap_or_else(|| panic!("missing {key}")))
        .unwrap_or_else(|_| panic!("invalid hex for {key}"))
}

fn integer(values: &BTreeMap<&str, &str>, key: &str) -> u64 {
    values
        .get(key)
        .unwrap_or_else(|| panic!("missing {key}"))
        .parse()
        .unwrap_or_else(|_| panic!("invalid integer for {key}"))
}

fn fixed<const LENGTH: usize>(values: &BTreeMap<&str, &str>, key: &str) -> [u8; LENGTH] {
    bytes(values, key)
        .try_into()
        .unwrap_or_else(|_| panic!("wrong byte length for {key}"))
}

fn lease(binding: &JournalBinding, value: u64) -> JournalLeaseContext {
    JournalLeaseContext::new(
        binding,
        FencingToken::new(NonZeroU64::new(value).expect("nonzero token")),
    )
}

#[test]
fn standard_library_oracle_matches_every_record_transition() {
    let values = values();
    let binding = JournalBinding::new(JournalBindingParts {
        installation_lineage: [1; 32],
        network_magic: integer(&values, "network_magic") as u32,
        role_id: [2; 32],
        storage_namespace_id: [3; 32],
        logical_key: [4; 32],
        protocol_id: [5; 32],
        protocol_version: 3,
        aead_suite: 1,
        key_version: 7,
        key_id: [6; 32],
        protection: RollbackProtectionClass::IndependentLocalRoot,
    })
    .expect("binding");
    assert_eq!(
        binding.fingerprint().as_bytes(),
        &fixed::<32>(&values, "binding_fingerprint")
    );

    let old_plaintext = bytes(&values, "old_plaintext");
    let new_plaintext = bytes(&values, "new_plaintext");
    let old = SnapshotImage::new(
        integer(&values, "old_revision"),
        [0x11; 32],
        &old_plaintext,
        bytes(&values, "old_ciphertext"),
    )
    .expect("old image");
    let new = SnapshotImage::new(
        integer(&values, "new_revision"),
        [0x22; 32],
        &new_plaintext,
        bytes(&values, "new_ciphertext"),
    )
    .expect("new image");
    assert_eq!(
        old.image_fingerprint(),
        fixed::<32>(&values, "old_image_fingerprint")
    );
    assert_eq!(
        new.image_fingerprint(),
        fixed::<32>(&values, "new_image_fingerprint")
    );
    assert_eq!(
        binding.snapshot_associated_data(old.identity(), old.sealed().plaintext_len()),
        bytes(&values, "old_snapshot_aad")
    );

    let provision = privileged_provision(binding, lease(&binding, 1)).expect("provision");
    assert_record(&values, provision.proposed(), "never");
    let stable = provision
        .proposed()
        .privileged_enroll(
            lease(&binding, 2),
            DatabaseObservation::Present(old.identity()),
            old.clone(),
        )
        .expect("enroll");
    assert_record(&values, stable.proposed(), "stable");

    let prepared = stable
        .proposed()
        .prepare_transition(
            lease(&binding, 3),
            DatabaseObservation::Present(old.identity()),
            new.clone(),
        )
        .expect("prepare");
    assert_record(&values, prepared.proposed(), "prepared");
    match prepared.proposed().state() {
        JournalState::Prepared { transition_id, .. } => assert_eq!(
            transition_id.as_bytes(),
            &fixed::<32>(&values, "transition_id")
        ),
        _ => panic!("prepared state"),
    }

    let finalized = prepared
        .proposed()
        .finalize_prepared(
            lease(&binding, 4),
            DatabaseObservation::Present(new.identity()),
        )
        .expect("finalize");
    assert_record(&values, finalized.proposed(), "finalized");

    let retired = finalized
        .proposed()
        .privileged_retire(
            lease(&binding, 5),
            DatabaseObservation::Present(new.identity()),
        )
        .expect("retire");
    assert_record(&values, retired.proposed(), "retired");
    match retired.proposed().state() {
        JournalState::Retired { retirement_id, .. } => assert_eq!(
            retirement_id.as_bytes(),
            &fixed::<32>(&values, "retirement_id")
        ),
        _ => panic!("retired state"),
    }
}

fn assert_record(values: &BTreeMap<&str, &str>, record: &JournalRecord, prefix: &str) {
    let encoded_key = format!("{prefix}_record");
    let fingerprint_key = format!("{prefix}_record_fingerprint");
    let encoded = bytes(values, &encoded_key);
    assert_eq!(record.encode(), encoded);
    assert_eq!(JournalRecord::decode(&encoded), Ok(record.clone()));
    assert_eq!(
        record.fingerprint().as_bytes(),
        &fixed::<32>(values, &fingerprint_key)
    );
}
