use std::collections::BTreeMap;
use std::convert::Infallible;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_hrm::Envelope;
use hns_hrm::validation::{
    AcceptedReorganization, AuthenticatedNameState, ResolvedManifest, ValidationLimits,
};
use hns_service_authority::authority_state::{
    NamedServiceAuthorityExpectation, NamedServiceAuthoritySnapshot, NamedServiceAuthorityState,
    NamedServiceAuthorityStorageState, ReconfirmedNamedServiceAuthorityState,
};
use hns_service_authority::hrm::{NamedServiceIdentity, NamedServicePolicy};
use hns_service_authority::lease::{
    AuthorityLeaseKey, AuthorityLeaseWitness, FencedLeaseGuard, FencingToken, HeldAuthorityLease,
    LeaseError, StorageNamespaceId,
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

fn resolved_manifest(
    values: &BTreeMap<&str, &str>,
    envelope_key: &str,
    accepted_reorganization: Option<AcceptedReorganization>,
) -> ResolvedManifest {
    let encoded = bytes(values, envelope_key);
    let envelope = Envelope::decode(&encoded).expect("fixture HRM envelope");
    let sequence = envelope.payload.sequence;
    let subject = envelope.payload.subject;
    let (chain_height, chain_work, chain_anchor) = chain_state(sequence);
    let envelope_hash: [u8; 32] = Sha256::digest(&encoded).into();
    ResolvedManifest {
        name_state: AuthenticatedNameState {
            network_magic: integer(values, "network_magic"),
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

fn identity(values: &BTreeMap<&str, &str>) -> NamedServiceIdentity {
    NamedServiceIdentity::new(
        integer(values, "network_magic"),
        array(values, "name_hash"),
        values["service_name"],
        integer(values, "application_profile_id"),
    )
    .expect("fixture identity")
}

fn policy(values: &BTreeMap<&str, &str>) -> NamedServicePolicy {
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

#[derive(Debug)]
struct TestAuthorityGuard {
    key: AuthorityLeaseKey,
    fencing_token: FencingToken,
}

impl FencedLeaseGuard<AuthorityLeaseKey> for TestAuthorityGuard {
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

#[derive(Clone)]
struct CasStore {
    namespace: StorageNamespaceId,
    current: Option<NamedServiceAuthoritySnapshot>,
    minimum_revision: u64,
    next_fence: u64,
    current_fence: Option<FencingToken>,
}

impl CasStore {
    fn new(namespace_tag: u8) -> Self {
        Self {
            namespace: StorageNamespaceId::new([namespace_tag; 32])
                .expect("test storage namespace"),
            current: None,
            minimum_revision: 0,
            next_fence: 1,
            current_fence: None,
        }
    }

    fn branch(&self, namespace_tag: u8) -> Self {
        Self {
            namespace: StorageNamespaceId::new([namespace_tag; 32])
                .expect("branch storage namespace"),
            current: self.current.clone(),
            minimum_revision: self.minimum_revision,
            next_fence: 1,
            current_fence: None,
        }
    }

    fn acquire(
        &mut self,
        network_magic: u32,
        subject: [u8; 32],
    ) -> HeldAuthorityLease<TestAuthorityGuard> {
        let key = AuthorityLeaseKey::new(self.namespace, network_magic, subject);
        let fencing_token = FencingToken::new(self.next_fence).expect("test fencing token");
        self.next_fence = self.next_fence.checked_add(1).expect("test fence space");
        self.current_fence = Some(fencing_token);
        HeldAuthorityLease::acquire(key, |requested| {
            Ok::<_, &'static str>(TestAuthorityGuard {
                key: *requested,
                fencing_token,
            })
        })
        .expect("test authority lease")
    }

    fn load(
        &self,
        witness: &AuthorityLeaseWitness<'_>,
    ) -> Result<NamedServiceAuthorityStorageState, &'static str> {
        if witness.key().storage_namespace_id() != self.namespace
            || Some(witness.fencing_token()) != self.current_fence
        {
            return Err("stale authority load fence");
        }
        Ok(match &self.current {
            Some(snapshot) => NamedServiceAuthorityStorageState::Present {
                encoded: snapshot.encode().map_err(|_| "snapshot encoding")?,
                minimum_revision: self.minimum_revision,
            },
            None => NamedServiceAuthorityStorageState::Absent,
        })
    }

    fn persist(
        &mut self,
        expected: NamedServiceAuthorityExpectation,
        proposed: &NamedServiceAuthoritySnapshot,
    ) -> Result<(), &'static str> {
        if expected.storage_namespace_id() != self.namespace
            || Some(expected.fencing_token()) != self.current_fence
        {
            return Err("stale authority CAS fence");
        }
        if self.current.as_ref() == Some(proposed) {
            return Ok(());
        }
        let matches = match (expected, self.current.as_ref()) {
            (NamedServiceAuthorityExpectation::Absent { .. }, None) => true,
            (
                NamedServiceAuthorityExpectation::Exact {
                    revision,
                    fingerprint,
                    ..
                },
                Some(current),
            ) => {
                current.revision() == revision
                    && current.fingerprint().map_err(|_| "fingerprint")? == fingerprint
            }
            _ => false,
        };
        if !matches {
            return Err("CAS mismatch");
        }
        self.current = Some(proposed.clone());
        self.minimum_revision = proposed.revision();
        Ok(())
    }
}

fn run_leased<R, F>(
    state: &mut NamedServiceAuthorityState,
    store: &mut CasStore,
    network_magic: u32,
    subject: [u8; 32],
    operation: F,
) -> R
where
    F: for<'lease> FnOnce(&mut ReconfirmedNamedServiceAuthorityState<'lease>, &mut CasStore) -> R,
{
    let lease = store.acquire(network_magic, subject);
    lease
        .run(|witness| {
            let mut reconfirmed = state
                .reconfirm(witness, |witness| store.load(witness))
                .expect("post-acquisition authority reconfirmation");
            Ok::<_, &'static str>(operation(&mut reconfirmed, store))
        })
        .expect("held authority vector operation")
}

fn assert_snapshot_vector(
    values: &BTreeMap<&str, &str>,
    prefix: &str,
) -> NamedServiceAuthoritySnapshot {
    let field = |suffix: &str| format!("{prefix}_{suffix}");
    let encoded = bytes(values, &field("snapshot"));
    let payload = bytes(values, &field("snapshot_payload"));
    let checksum = bytes(values, &field("snapshot_checksum"));
    assert_eq!(encoded, [payload.as_slice(), checksum.as_slice()].concat());
    assert_eq!(
        checksum,
        blake2b_256(&[b"HNS-HRM-HNSA-AUTHORITY-SNAPSHOT-CHECKSUM-V1\0", &payload,])
    );
    let snapshot =
        NamedServiceAuthoritySnapshot::decode(&encoded).expect("decode authority vector");
    assert_eq!(snapshot.encode().expect("encode authority vector"), encoded);
    assert_eq!(snapshot.network_magic(), integer(values, "network_magic"));
    assert_eq!(snapshot.subject(), array(values, "name_hash"));
    assert_eq!(
        snapshot.capacity(),
        integer(values, "authority_snapshot_capacity")
    );
    assert_eq!(snapshot.revision(), integer(values, &field("revision")));
    assert_eq!(
        snapshot.trusted_time_high_water(),
        integer(values, &field("trusted_time"))
    );
    assert_eq!(snapshot.len(), integer(values, &field("entry_count")));
    assert_eq!(
        snapshot.fingerprint().expect("authority fingerprint"),
        array(values, &field("snapshot_fingerprint"))
    );
    snapshot
}

fn assert_prior(
    values: &BTreeMap<&str, &str>,
    next_prefix: &str,
    prior: &NamedServiceAuthoritySnapshot,
) {
    assert_eq!(
        prior.revision(),
        integer(values, &format!("{next_prefix}_prior_revision"))
    );
    assert_eq!(
        prior.fingerprint().expect("prior fingerprint"),
        array(values, &format!("{next_prefix}_prior_fingerprint"))
    );
}

fn restore_exact(
    snapshot: &NamedServiceAuthoritySnapshot,
    network_magic: u32,
    subject: [u8; 32],
    capacity: usize,
    trusted_now: u64,
) -> NamedServiceAuthorityState {
    NamedServiceAuthorityState::restore(
        &snapshot.encode().expect("encode branch snapshot"),
        network_magic,
        subject,
        capacity,
        snapshot.revision(),
        trusted_now,
    )
    .expect("restore exact authority branch")
}

#[test]
fn independent_authority_snapshots_round_trip_and_publish_exact_cas_lineage() {
    let values = fixtures();
    assert_eq!(values["authority_fresh_prior_expectation"], "absent");
    let fresh = assert_snapshot_vector(&values, "authority_fresh");
    let time_only = assert_snapshot_vector(&values, "authority_time_only");
    let active = assert_snapshot_vector(&values, "authority_active");
    let replacement = assert_snapshot_vector(&values, "authority_replacement");
    let withdrawn = assert_snapshot_vector(&values, "authority_withdrawn");
    let accepted_reorg = assert_snapshot_vector(&values, "authority_accepted_reorg");

    assert!(fresh.rollback_state().is_none());
    assert!(time_only.rollback_state().is_none());
    assert!(
        active
            .observations()
            .all(|observation| !observation.is_withdrawn())
    );
    assert!(
        replacement
            .observations()
            .all(|observation| !observation.is_withdrawn())
    );
    assert!(
        withdrawn
            .observations()
            .all(|observation| observation.is_withdrawn())
    );
    assert!(
        accepted_reorg
            .observations()
            .all(|observation| observation.is_withdrawn())
    );
    assert_eq!(
        accepted_reorg
            .observations()
            .next()
            .expect("reorganization tombstone")
            .highest_generation(),
        0
    );
    assert!(time_only.trusted_time_high_water() > (1_u64 << 53));

    assert_prior(&values, "authority_time_only", &fresh);
    assert_prior(&values, "authority_active", &fresh);
    assert_prior(&values, "authority_replacement", &active);
    assert_prior(&values, "authority_withdrawn", &replacement);
    assert_prior(&values, "authority_accepted_reorg", &replacement);
}

#[test]
fn authority_state_transitions_reproduce_independent_branch_vectors() {
    let values = fixtures();
    let identity = identity(&values);
    let policy = policy(&values);
    let capacity = integer(&values, "authority_snapshot_capacity");
    let now = integer(&values, "validation_now");
    let high_time = integer(&values, "persistence_high_time");
    let fresh_vector = assert_snapshot_vector(&values, "authority_fresh");

    let mut base = NamedServiceAuthorityState::new(
        integer(&values, "network_magic"),
        array(&values, "name_hash"),
        capacity,
        now,
    )
    .expect("fresh authority state");
    assert_eq!(base.snapshot(), &fresh_vector);
    let network_magic = integer(&values, "network_magic");
    let subject = array(&values, "name_hash");
    let mut base_store = CasStore::new(1);
    run_leased(
        &mut base,
        &mut base_store,
        network_magic,
        subject,
        |base, store| {
            base.persist_pending(&mut |expected, proposed| store.persist(expected, proposed))
                .expect("persist fresh authority vector");
        },
    );

    let mut time_only = restore_exact(base.snapshot(), network_magic, subject, capacity, now);
    let mut time_store = base_store.branch(2);
    assert_prior(
        &values,
        "authority_time_only",
        time_store.current.as_ref().unwrap(),
    );
    run_leased(
        &mut time_only,
        &mut time_store,
        network_magic,
        subject,
        |time_only, store| {
            time_only
                .advance_trusted_time_persisted(high_time, &mut |expected, proposed| {
                    store.persist(expected, proposed)
                })
                .expect("time-only transition");
        },
    );
    assert_eq!(
        time_only.snapshot(),
        &assert_snapshot_vector(&values, "authority_time_only")
    );

    let mut active = base;
    let mut active_store = base_store;
    assert_prior(
        &values,
        "authority_active",
        active_store.current.as_ref().unwrap(),
    );
    run_leased(
        &mut active,
        &mut active_store,
        network_magic,
        subject,
        |active, store| {
            active
                .retrieve_validate_and_observe(
                    now,
                    |_| Ok::<_, Infallible>(resolved_manifest(&values, "hrm_envelope", None)),
                    &identity,
                    &policy,
                    ValidationLimits::default(),
                    &mut |expected, proposed| store.persist(expected, proposed),
                )
                .expect("active transition");
        },
    );
    assert_eq!(
        active.snapshot(),
        &assert_snapshot_vector(&values, "authority_active")
    );

    assert_prior(
        &values,
        "authority_replacement",
        active_store.current.as_ref().unwrap(),
    );
    run_leased(
        &mut active,
        &mut active_store,
        network_magic,
        subject,
        |active, store| {
            active
                .retrieve_validate_and_observe(
                    now,
                    |_| {
                        Ok::<_, Infallible>(resolved_manifest(
                            &values,
                            "replacement_hrm_envelope",
                            None,
                        ))
                    },
                    &identity,
                    &policy,
                    ValidationLimits::default(),
                    &mut |expected, proposed| store.persist(expected, proposed),
                )
                .expect("replacement transition");
        },
    );
    assert_eq!(
        active.snapshot(),
        &assert_snapshot_vector(&values, "authority_replacement")
    );

    let mut accepted_reorg =
        restore_exact(active.snapshot(), network_magic, subject, capacity, now);
    let mut reorg_store = active_store.branch(3);
    let mut withdrawn = active;
    let mut withdrawn_store = active_store;

    assert_prior(
        &values,
        "authority_withdrawn",
        withdrawn_store.current.as_ref().unwrap(),
    );
    let committed_withdrawal = run_leased(
        &mut withdrawn,
        &mut withdrawn_store,
        network_magic,
        subject,
        |withdrawn, store| {
            withdrawn
                .retrieve_validate_and_observe(
                    now,
                    |_| {
                        Ok::<_, Infallible>(resolved_manifest(
                            &values,
                            "removal_hrm_envelope",
                            None,
                        ))
                    },
                    &identity,
                    &policy,
                    ValidationLimits::default(),
                    &mut |expected, proposed| store.persist(expected, proposed),
                )
                .expect("withdrawal transition")
        },
    );
    assert!(committed_withdrawal.is_withdrawn());
    assert_eq!(
        withdrawn.snapshot(),
        &assert_snapshot_vector(&values, "authority_withdrawn")
    );

    assert_prior(
        &values,
        "authority_accepted_reorg",
        reorg_store.current.as_ref().unwrap(),
    );
    let accepted = AcceptedReorganization {
        previous_chain_height: integer(&values, "reorg_previous_chain_height"),
        previous_chain_work: array(&values, "reorg_previous_chain_work"),
        previous_chain_anchor: array(&values, "reorg_previous_chain_anchor"),
        current_chain_height: integer(&values, "reorg_current_chain_height"),
        current_chain_work: array(&values, "reorg_current_chain_work"),
        current_chain_anchor: array(&values, "reorg_current_chain_anchor"),
    };
    let committed_reorg = run_leased(
        &mut accepted_reorg,
        &mut reorg_store,
        network_magic,
        subject,
        |accepted_reorg, store| {
            accepted_reorg
                .retrieve_validate_and_observe(
                    now,
                    |_| {
                        Ok::<_, Infallible>(resolved_manifest(
                            &values,
                            "reorg_withdrawal_hrm_envelope",
                            Some(accepted),
                        ))
                    },
                    &identity,
                    &policy,
                    ValidationLimits::default(),
                    &mut |expected, proposed| store.persist(expected, proposed),
                )
                .expect("accepted-reorganization transition")
        },
    );
    assert!(committed_reorg.is_withdrawn());
    assert_eq!(
        accepted_reorg.snapshot(),
        &assert_snapshot_vector(&values, "authority_accepted_reorg")
    );
}
