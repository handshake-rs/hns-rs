#![doc = "Canonical external anti-rollback journal state and recovery contract."]

use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_encoding::{DecodeError, Decoder, Encoder};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"HNSRBJ1\0";
const FORMAT_VERSION: u16 = 1;
const CHECKSUM_DOMAIN: &[u8] = b"HNS-ROLLBACK-JOURNAL-CHECKSUM-V1\0";
const RECORD_FINGERPRINT_DOMAIN: &[u8] = b"HNS-ROLLBACK-JOURNAL-RECORD-V1\0";
const BINDING_FINGERPRINT_DOMAIN: &[u8] = b"HNS-ROLLBACK-JOURNAL-BINDING-V1\0";
const SNAPSHOT_BYTES_DOMAIN: &[u8] = b"HNS-ROLLBACK-JOURNAL-SNAPSHOT-BYTES-V1\0";
const SNAPSHOT_IMAGE_DOMAIN: &[u8] = b"HNS-ROLLBACK-JOURNAL-SNAPSHOT-IMAGE-V1\0";
const SNAPSHOT_AAD_DOMAIN: &[u8] = b"HNS-ROLLBACK-JOURNAL-SNAPSHOT-AAD-V1\0";
const TRANSITION_ID_DOMAIN: &[u8] = b"HNS-ROLLBACK-JOURNAL-TRANSITION-V1\0";
const RETIREMENT_ID_DOMAIN: &[u8] = b"HNS-ROLLBACK-JOURNAL-RETIREMENT-V1\0";

/// Maximum exact plaintext protocol snapshot retained by the journal.
pub const MAX_PLAINTEXT_SNAPSHOT_SIZE: usize = 16 * 1024 * 1024;
/// The only v1 suite: AES-256-GCM with a prepended 12-byte nonce and the
/// standard appended 16-byte authentication tag.
pub const AEAD_SUITE_AES_256_GCM: u16 = 1;
pub const AES_256_GCM_KEY_SIZE: usize = 32;
pub const AES_256_GCM_NONCE_SIZE: usize = 12;
pub const AES_256_GCM_TAG_SIZE: usize = 16;
/// Maximum opaque authenticated ciphertext retained for one snapshot.
pub const MAX_SEALED_SNAPSHOT_SIZE: usize =
    MAX_PLAINTEXT_SNAPSHOT_SIZE + AES_256_GCM_NONCE_SIZE + AES_256_GCM_TAG_SIZE;
/// Maximum canonical record size. A prepared record retains old and new images.
pub const MAX_JOURNAL_RECORD_SIZE: usize = 2048 + 2 * MAX_SEALED_SNAPSHOT_SIZE;

/// Errors in canonical records and privileged or runtime state transitions.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JournalError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("invalid rollback journal value: {0}")]
    Invalid(&'static str),
    #[error("rollback journal operation is invalid in state {0}")]
    WrongState(&'static str),
    #[error("rollback journal revision space is exhausted")]
    JournalRevisionExhausted,
    #[error("observed protocol database state does not match the required exact state")]
    DatabaseMismatch,
}

/// Honest minimum protection classification reported by a qualified backend.
///
/// The value is an immutable part of the namespace binding, but storing the
/// value is not evidence that a backend actually provides the protection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum RollbackProtectionClass {
    /// Integrity only; journal and protected snapshot can be restored together.
    IntegrityOnlySameRollbackDomain = 0,
    /// Journal/key live in an independently administered local root domain.
    IndependentLocalRoot = 1,
    /// A qualified hardware monotonic primitive anchors the journal.
    HardwareMonotonic = 2,
    /// A qualified independent remote witness anchors the journal.
    RemoteWitness = 3,
}

impl RollbackProtectionClass {
    /// Whether the classification claims a rollback domain independent of the
    /// protected protocol database. Configuration still requires qualification.
    pub const fn has_independent_rollback_domain(self) -> bool {
        !matches!(self, Self::IntegrityOnlySameRollbackDomain)
    }

    fn decode(value: u8) -> Result<Self, JournalError> {
        match value {
            0 => Ok(Self::IntegrityOnlySameRollbackDomain),
            1 => Ok(Self::IndependentLocalRoot),
            2 => Ok(Self::HardwareMonotonic),
            3 => Ok(Self::RemoteWitness),
            _ => Err(JournalError::Invalid("unknown rollback protection class")),
        }
    }
}

/// Nonzero fencing token issued by the external journal's live lease broker.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FencingToken(NonZeroU64);

impl FencingToken {
    pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Namespace-bound context exported by a live external journal lease guard.
///
/// This copyable value is only the data carried into an atomic write. It is
/// not a substitute for retaining the backend's actual non-cloneable lease
/// guard through reload, persistence, and dependent use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalLeaseContext {
    binding_fingerprint: BindingFingerprint,
    fencing_token: FencingToken,
}

impl JournalLeaseContext {
    pub fn new(binding: &JournalBinding, fencing_token: FencingToken) -> Self {
        Self {
            binding_fingerprint: binding.fingerprint(),
            fencing_token,
        }
    }

    pub const fn binding_fingerprint(self) -> BindingFingerprint {
        self.binding_fingerprint
    }

    pub const fn fencing_token(self) -> FencingToken {
        self.fencing_token
    }
}

/// Immutable identity of one external journal namespace.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct JournalBinding {
    installation_lineage: [u8; 32],
    network_magic: u32,
    role_id: [u8; 32],
    storage_namespace_id: [u8; 32],
    logical_key: [u8; 32],
    protocol_id: [u8; 32],
    protocol_version: NonZeroU16,
    aead_suite: NonZeroU16,
    key_version: NonZeroU32,
    key_id: [u8; 32],
    protection: RollbackProtectionClass,
}

/// Complete inputs required to construct a [`JournalBinding`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalBindingParts {
    pub installation_lineage: [u8; 32],
    pub network_magic: u32,
    pub role_id: [u8; 32],
    pub storage_namespace_id: [u8; 32],
    pub logical_key: [u8; 32],
    pub protocol_id: [u8; 32],
    pub protocol_version: u16,
    pub aead_suite: u16,
    pub key_version: u32,
    pub key_id: [u8; 32],
    pub protection: RollbackProtectionClass,
}

impl JournalBinding {
    pub fn new(parts: JournalBindingParts) -> Result<Self, JournalError> {
        for (value, field) in [
            (&parts.installation_lineage, "zero installation lineage"),
            (&parts.role_id, "zero role identifier"),
            (&parts.storage_namespace_id, "zero storage namespace"),
            (&parts.protocol_id, "zero protocol identifier"),
            (&parts.key_id, "zero key identifier"),
        ] {
            if is_zero(value) {
                return Err(JournalError::Invalid(field));
            }
        }
        let protocol_version = NonZeroU16::new(parts.protocol_version)
            .ok_or(JournalError::Invalid("zero protocol version"))?;
        let aead_suite =
            NonZeroU16::new(parts.aead_suite).ok_or(JournalError::Invalid("zero AEAD suite"))?;
        if aead_suite.get() != AEAD_SUITE_AES_256_GCM {
            return Err(JournalError::Invalid("unsupported AEAD suite"));
        }
        let key_version =
            NonZeroU32::new(parts.key_version).ok_or(JournalError::Invalid("zero key version"))?;
        Ok(Self {
            installation_lineage: parts.installation_lineage,
            network_magic: parts.network_magic,
            role_id: parts.role_id,
            storage_namespace_id: parts.storage_namespace_id,
            logical_key: parts.logical_key,
            protocol_id: parts.protocol_id,
            protocol_version,
            aead_suite,
            key_version,
            key_id: parts.key_id,
            protection: parts.protection,
        })
    }

    pub const fn installation_lineage(&self) -> &[u8; 32] {
        &self.installation_lineage
    }

    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }

    pub const fn role_id(&self) -> &[u8; 32] {
        &self.role_id
    }

    pub const fn storage_namespace_id(&self) -> &[u8; 32] {
        &self.storage_namespace_id
    }

    pub const fn logical_key(&self) -> &[u8; 32] {
        &self.logical_key
    }

    pub const fn protocol_id(&self) -> &[u8; 32] {
        &self.protocol_id
    }

    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version.get()
    }

    pub const fn aead_suite(&self) -> u16 {
        self.aead_suite.get()
    }

    pub const fn key_version(&self) -> u32 {
        self.key_version.get()
    }

    pub const fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    pub const fn protection(&self) -> RollbackProtectionClass {
        self.protection
    }

    /// Domain-separated identity of the complete immutable binding.
    pub fn fingerprint(&self) -> BindingFingerprint {
        let mut encoded = Encoder::with_capacity(240);
        self.encode_into(&mut encoded);
        BindingFingerprint(hash32(BINDING_FINGERPRINT_DOMAIN, &[&encoded.into_bytes()]))
    }

    /// Associated data that an AEAD backend must bind to one snapshot image.
    pub fn snapshot_associated_data(&self, identity: StateIdentity, plaintext_len: u32) -> Vec<u8> {
        let mut encoded = Encoder::with_capacity(112);
        encoded.put_bytes(SNAPSHOT_AAD_DOMAIN);
        encoded.put_bytes(self.fingerprint().as_bytes());
        identity.encode_into(&mut encoded);
        encoded.put_u32_le(plaintext_len);
        encoded.into_bytes()
    }

    fn encode_into(&self, encoder: &mut Encoder) {
        encoder.put_bytes(&self.installation_lineage);
        encoder.put_u32_le(self.network_magic);
        encoder.put_bytes(&self.role_id);
        encoder.put_bytes(&self.storage_namespace_id);
        encoder.put_bytes(&self.logical_key);
        encoder.put_bytes(&self.protocol_id);
        encoder.put_u16_le(self.protocol_version.get());
        encoder.put_u16_le(self.aead_suite.get());
        encoder.put_u32_le(self.key_version.get());
        encoder.put_bytes(&self.key_id);
        encoder.put_u8(self.protection as u8);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, JournalError> {
        Self::new(JournalBindingParts {
            installation_lineage: decoder.read_array()?,
            network_magic: decoder.read_u32_le()?,
            role_id: decoder.read_array()?,
            storage_namespace_id: decoder.read_array()?,
            logical_key: decoder.read_array()?,
            protocol_id: decoder.read_array()?,
            protocol_version: decoder.read_u16_le()?,
            aead_suite: decoder.read_u16_le()?,
            key_version: decoder.read_u32_le()?,
            key_id: decoder.read_array()?,
            protection: RollbackProtectionClass::decode(decoder.read_u8()?)?,
        })
    }
}

/// Domain-separated identity of a journal binding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BindingFingerprint([u8; 32]);

impl BindingFingerprint {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact protocol state identity: revision, protocol identity, and plaintext bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StateIdentity {
    revision: u64,
    protocol_fingerprint: [u8; 32],
    byte_fingerprint: [u8; 32],
}

impl StateIdentity {
    /// Construct an identity from the exact complete canonical plaintext bytes.
    pub fn from_plaintext(
        revision: u64,
        protocol_fingerprint: [u8; 32],
        plaintext: &[u8],
    ) -> Result<Self, JournalError> {
        if plaintext.len() > MAX_PLAINTEXT_SNAPSHOT_SIZE {
            return Err(JournalError::Invalid("plaintext snapshot is too large"));
        }
        Ok(Self {
            revision,
            protocol_fingerprint,
            byte_fingerprint: snapshot_byte_fingerprint(plaintext),
        })
    }

    pub const fn revision(self) -> u64 {
        self.revision
    }

    pub const fn protocol_fingerprint(self) -> [u8; 32] {
        self.protocol_fingerprint
    }

    pub const fn byte_fingerprint(self) -> [u8; 32] {
        self.byte_fingerprint
    }

    pub fn verifies_plaintext(self, plaintext: &[u8]) -> bool {
        plaintext.len() <= MAX_PLAINTEXT_SNAPSHOT_SIZE
            && self.byte_fingerprint == snapshot_byte_fingerprint(plaintext)
    }

    fn encode_into(self, encoder: &mut Encoder) {
        encoder.put_u64_le(self.revision);
        encoder.put_bytes(&self.protocol_fingerprint);
        encoder.put_bytes(&self.byte_fingerprint);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, JournalError> {
        Ok(Self {
            revision: decoder.read_u64_le()?,
            protocol_fingerprint: decoder.read_array()?,
            byte_fingerprint: decoder.read_array()?,
        })
    }
}

/// Domain-separated exact-byte fingerprint used independently of a protocol's
/// semantic or checksummed snapshot fingerprint.
pub fn snapshot_byte_fingerprint(plaintext: &[u8]) -> [u8; 32] {
    hash32(SNAPSHOT_BYTES_DOMAIN, &[plaintext])
}

/// Opaque authenticated ciphertext for one complete protocol snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedSnapshot {
    plaintext_len: u32,
    ciphertext: Vec<u8>,
}

impl SealedSnapshot {
    pub fn new(plaintext_len: usize, ciphertext: Vec<u8>) -> Result<Self, JournalError> {
        if plaintext_len > MAX_PLAINTEXT_SNAPSHOT_SIZE {
            return Err(JournalError::Invalid("plaintext snapshot is too large"));
        }
        let expected_ciphertext_len = plaintext_len
            .checked_add(AES_256_GCM_NONCE_SIZE + AES_256_GCM_TAG_SIZE)
            .ok_or(JournalError::Invalid("sealed snapshot length overflow"))?;
        if ciphertext.len() != expected_ciphertext_len
            || ciphertext.len() > MAX_SEALED_SNAPSHOT_SIZE
        {
            return Err(JournalError::Invalid("invalid sealed snapshot size"));
        }
        Ok(Self {
            plaintext_len: u32::try_from(plaintext_len)
                .map_err(|_| JournalError::Invalid("plaintext length is not representable"))?,
            ciphertext,
        })
    }

    pub const fn plaintext_len(&self) -> u32 {
        self.plaintext_len
    }

    /// Exact `nonce || encrypted_payload || tag` bytes retained by the journal.
    pub fn sealed_bytes(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn nonce(&self) -> &[u8] {
        &self.ciphertext[..AES_256_GCM_NONCE_SIZE]
    }

    pub fn encrypted_payload(&self) -> &[u8] {
        &self.ciphertext[AES_256_GCM_NONCE_SIZE..self.ciphertext.len() - AES_256_GCM_TAG_SIZE]
    }

    pub fn tag(&self) -> &[u8] {
        &self.ciphertext[self.ciphertext.len() - AES_256_GCM_TAG_SIZE..]
    }

    fn encode_into(&self, encoder: &mut Encoder) {
        encoder.put_u32_le(self.plaintext_len);
        encoder.put_varbytes(&self.ciphertext);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, JournalError> {
        let plaintext_len = decoder.read_u32_le()? as usize;
        let ciphertext = decoder.read_varbytes(MAX_SEALED_SNAPSHOT_SIZE, "sealed snapshot")?;
        Self::new(plaintext_len, ciphertext)
    }
}

/// Exact state identity paired with its complete sealed snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotImage {
    identity: StateIdentity,
    sealed: SealedSnapshot,
}

impl SnapshotImage {
    pub fn new(
        revision: u64,
        protocol_fingerprint: [u8; 32],
        plaintext: &[u8],
        ciphertext: Vec<u8>,
    ) -> Result<Self, JournalError> {
        Ok(Self {
            identity: StateIdentity::from_plaintext(revision, protocol_fingerprint, plaintext)?,
            sealed: SealedSnapshot::new(plaintext.len(), ciphertext)?,
        })
    }

    pub const fn identity(&self) -> StateIdentity {
        self.identity
    }

    pub const fn sealed(&self) -> &SealedSnapshot {
        &self.sealed
    }

    pub fn verifies_plaintext(&self, plaintext: &[u8]) -> bool {
        plaintext.len() == self.sealed.plaintext_len as usize
            && self.identity.verifies_plaintext(plaintext)
    }

    pub fn image_fingerprint(&self) -> [u8; 32] {
        let mut encoded = Encoder::with_capacity(80 + self.sealed.ciphertext.len());
        self.encode_into(&mut encoded);
        hash32(SNAPSHOT_IMAGE_DOMAIN, &[&encoded.into_bytes()])
    }

    fn encode_into(&self, encoder: &mut Encoder) {
        self.identity.encode_into(encoder);
        self.sealed.encode_into(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, JournalError> {
        Ok(Self {
            identity: StateIdentity::decode(decoder)?,
            sealed: SealedSnapshot::decode(decoder)?,
        })
    }
}

/// Exact observation of the protocol database made while its lease is held.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseObservation {
    Absent,
    Present(StateIdentity),
}

impl DatabaseObservation {
    pub fn from_plaintext(
        revision: u64,
        protocol_fingerprint: [u8; 32],
        plaintext: &[u8],
    ) -> Result<Self, JournalError> {
        Ok(Self::Present(StateIdentity::from_plaintext(
            revision,
            protocol_fingerprint,
            plaintext,
        )?))
    }

    pub const fn identity(self) -> Option<StateIdentity> {
        match self {
            Self::Absent => None,
            Self::Present(identity) => Some(identity),
        }
    }
}

/// Deterministic identity of one exact prepared old-to-new transition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TransitionId([u8; 32]);

impl TransitionId {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Terminal retirement identity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RetirementId([u8; 32]);

impl RetirementId {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Durable state of one bound external journal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalState {
    /// Explicit privileged marker. Missing storage is never this state.
    NeverInitialized,
    /// A database snapshot fully acknowledged by the external journal.
    Stable { current: SnapshotImage },
    /// Exact intent durably recorded before the protocol database CAS.
    Prepared {
        transition_id: TransitionId,
        old: SnapshotImage,
        new: SnapshotImage,
    },
    /// Irreversible tombstone; ordinary APIs provide no transition out.
    Retired {
        last: StateIdentity,
        retirement_id: RetirementId,
    },
}

/// Canonical bound journal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    binding: JournalBinding,
    journal_revision: u64,
    state: JournalState,
}

impl JournalRecord {
    pub const fn binding(&self) -> &JournalBinding {
        &self.binding
    }

    pub const fn journal_revision(&self) -> u64 {
        self.journal_revision
    }

    pub const fn state(&self) -> &JournalState {
        &self.state
    }

    /// Canonical checksummed representation. The checksum is not authentication.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.validate().is_ok());
        let mut encoder = Encoder::with_capacity(self.encoded_capacity());
        encoder.put_bytes(MAGIC);
        encoder.put_u16_le(FORMAT_VERSION);
        self.binding.encode_into(&mut encoder);
        encoder.put_u64_le(self.journal_revision);
        match &self.state {
            JournalState::NeverInitialized => encoder.put_u8(0),
            JournalState::Stable { current } => {
                encoder.put_u8(1);
                current.encode_into(&mut encoder);
            }
            JournalState::Prepared {
                transition_id,
                old,
                new,
            } => {
                encoder.put_u8(2);
                encoder.put_bytes(transition_id.as_bytes());
                old.encode_into(&mut encoder);
                new.encode_into(&mut encoder);
            }
            JournalState::Retired {
                last,
                retirement_id,
            } => {
                encoder.put_u8(3);
                last.encode_into(&mut encoder);
                encoder.put_bytes(retirement_id.as_bytes());
            }
        }
        let mut bytes = encoder.into_bytes();
        bytes.extend_from_slice(&journal_checksum(&bytes));
        bytes
    }

    /// Decode a complete canonical record with strict bounds and trailing rejection.
    pub fn decode(input: &[u8]) -> Result<Self, JournalError> {
        if input.len() < MAGIC.len() + 2 + 32 || input.len() > MAX_JOURNAL_RECORD_SIZE {
            return Err(JournalError::Invalid("invalid journal record size"));
        }
        let body_len = input.len() - 32;
        let (body, checksum) = input.split_at(body_len);
        if journal_checksum(body).as_slice() != checksum {
            return Err(JournalError::Invalid("journal checksum mismatch"));
        }
        let mut decoder = Decoder::new(body);
        if decoder.read_array::<8>()? != *MAGIC {
            return Err(JournalError::Invalid("invalid journal magic"));
        }
        if decoder.read_u16_le()? != FORMAT_VERSION {
            return Err(JournalError::Invalid("unsupported journal format version"));
        }
        let binding = JournalBinding::decode(&mut decoder)?;
        let journal_revision = decoder.read_u64_le()?;
        let state = match decoder.read_u8()? {
            0 => JournalState::NeverInitialized,
            1 => JournalState::Stable {
                current: SnapshotImage::decode(&mut decoder)?,
            },
            2 => JournalState::Prepared {
                transition_id: TransitionId(decoder.read_array()?),
                old: SnapshotImage::decode(&mut decoder)?,
                new: SnapshotImage::decode(&mut decoder)?,
            },
            3 => JournalState::Retired {
                last: StateIdentity::decode(&mut decoder)?,
                retirement_id: RetirementId(decoder.read_array()?),
            },
            _ => return Err(JournalError::Invalid("unknown journal state")),
        };
        decoder.finish()?;
        let record = Self {
            binding,
            journal_revision,
            state,
        };
        record.validate()?;
        if record.encode() != input {
            return Err(JournalError::Invalid("noncanonical journal record"));
        }
        Ok(record)
    }

    /// Domain-separated fingerprint of the complete canonical record bytes.
    pub fn fingerprint(&self) -> RecordFingerprint {
        RecordFingerprint(hash32(RECORD_FINGERPRINT_DOMAIN, &[&self.encode()]))
    }

    /// Create a privileged enrollment mutation from the explicit marker.
    /// Runtime startup must never call this to repair missing or replayed state.
    pub fn privileged_enroll(
        &self,
        lease: JournalLeaseContext,
        database: DatabaseObservation,
        current: SnapshotImage,
    ) -> Result<JournalMutation, JournalError> {
        self.ensure_lease_binding(lease)?;
        if !matches!(self.state, JournalState::NeverInitialized) {
            return Err(JournalError::WrongState("not NeverInitialized"));
        }
        if database != DatabaseObservation::Present(current.identity) {
            return Err(JournalError::DatabaseMismatch);
        }
        self.next_mutation(lease, JournalState::Stable { current })
    }

    /// Durably prepare one exact old-to-new database transition.
    pub fn prepare_transition(
        &self,
        lease: JournalLeaseContext,
        database: DatabaseObservation,
        new: SnapshotImage,
    ) -> Result<JournalMutation, JournalError> {
        self.ensure_lease_binding(lease)?;
        let JournalState::Stable { current: old } = &self.state else {
            return Err(JournalError::WrongState("not Stable"));
        };
        if database != DatabaseObservation::Present(old.identity) {
            return Err(JournalError::DatabaseMismatch);
        }
        if new.identity.revision <= old.identity.revision {
            return Err(JournalError::Invalid(
                "prepared revision must advance the protocol state",
            ));
        }
        self.journal_revision
            .checked_add(2)
            .ok_or(JournalError::JournalRevisionExhausted)?;
        let transition_id = transition_id(&self.binding, old, &new);
        self.next_mutation(
            lease,
            JournalState::Prepared {
                transition_id,
                old: old.clone(),
                new,
            },
        )
    }

    /// Finalize a prepared transition only after rereading the exact new database state.
    pub fn finalize_prepared(
        &self,
        lease: JournalLeaseContext,
        database: DatabaseObservation,
    ) -> Result<JournalMutation, JournalError> {
        self.ensure_lease_binding(lease)?;
        let JournalState::Prepared { new, .. } = &self.state else {
            return Err(JournalError::WrongState("not Prepared"));
        };
        if database != DatabaseObservation::Present(new.identity) {
            return Err(JournalError::DatabaseMismatch);
        }
        self.next_mutation(
            lease,
            JournalState::Stable {
                current: new.clone(),
            },
        )
    }

    /// Create the terminal privileged retirement mutation from a settled state.
    pub fn privileged_retire(
        &self,
        lease: JournalLeaseContext,
        database: DatabaseObservation,
    ) -> Result<JournalMutation, JournalError> {
        self.ensure_lease_binding(lease)?;
        let JournalState::Stable { current } = &self.state else {
            return Err(JournalError::WrongState("not Stable"));
        };
        if database != DatabaseObservation::Present(current.identity) {
            return Err(JournalError::DatabaseMismatch);
        }
        let retirement_id = retirement_id(&self.binding, current.identity, self.fingerprint());
        self.next_mutation(
            lease,
            JournalState::Retired {
                last: current.identity,
                retirement_id,
            },
        )
    }

    /// Pure recovery decision for one exact under-lease database observation.
    pub fn recovery_plan(
        &self,
        expected_binding: &JournalBinding,
        database: DatabaseObservation,
    ) -> RecoveryPlan<'_> {
        if self.binding != *expected_binding {
            return RecoveryPlan::FailClosed(FailClosedReason::BindingMismatch);
        }
        match &self.state {
            JournalState::NeverInitialized => {
                RecoveryPlan::FailClosed(FailClosedReason::NotEnrolled)
            }
            JournalState::Retired { .. } => RecoveryPlan::FailClosed(FailClosedReason::Retired),
            JournalState::Stable { current } => match database {
                DatabaseObservation::Present(identity) if identity == current.identity => {
                    RecoveryPlan::Ready { current }
                }
                DatabaseObservation::Absent => RecoveryPlan::RestoreStableThenReread {
                    expected_database: database,
                    current,
                },
                DatabaseObservation::Present(identity)
                    if identity.revision < current.identity.revision =>
                {
                    RecoveryPlan::RestoreStableThenReread {
                        expected_database: database,
                        current,
                    }
                }
                DatabaseObservation::Present(identity)
                    if identity.revision == current.identity.revision =>
                {
                    RecoveryPlan::FailClosed(FailClosedReason::SameRevisionFork)
                }
                DatabaseObservation::Present(_) => {
                    RecoveryPlan::FailClosed(FailClosedReason::DatabaseAhead)
                }
            },
            JournalState::Prepared {
                transition_id,
                old,
                new,
            } => match database {
                DatabaseObservation::Present(identity) if identity == old.identity => {
                    RecoveryPlan::RetryPreparedDatabaseCas {
                        transition_id: *transition_id,
                        expected_old: old.identity,
                        proposed: new,
                    }
                }
                DatabaseObservation::Present(identity) if identity == new.identity => {
                    RecoveryPlan::FinalizePrepared {
                        transition_id: *transition_id,
                    }
                }
                DatabaseObservation::Absent => RecoveryPlan::RestorePreparedOldThenReread {
                    transition_id: *transition_id,
                    expected_database: database,
                    old,
                },
                DatabaseObservation::Present(identity)
                    if identity.revision < old.identity.revision =>
                {
                    RecoveryPlan::RestorePreparedOldThenReread {
                        transition_id: *transition_id,
                        expected_database: database,
                        old,
                    }
                }
                DatabaseObservation::Present(identity)
                    if identity.revision == old.identity.revision
                        || identity.revision == new.identity.revision =>
                {
                    RecoveryPlan::FailClosed(FailClosedReason::SameRevisionFork)
                }
                DatabaseObservation::Present(identity)
                    if identity.revision > new.identity.revision =>
                {
                    RecoveryPlan::FailClosed(FailClosedReason::DatabaseAhead)
                }
                DatabaseObservation::Present(_) => {
                    RecoveryPlan::FailClosed(FailClosedReason::UnexpectedIntermediateState)
                }
            },
        }
    }

    fn validate(&self) -> Result<(), JournalError> {
        match &self.state {
            JournalState::NeverInitialized => {
                if self.journal_revision != 0 {
                    return Err(JournalError::Invalid(
                        "NeverInitialized must have journal revision zero",
                    ));
                }
            }
            JournalState::Stable { .. } => {
                if self.journal_revision == 0 || self.journal_revision.is_multiple_of(2) {
                    return Err(JournalError::Invalid("Stable journal revision must be odd"));
                }
            }
            JournalState::Prepared {
                transition_id: encoded,
                old,
                new,
            } => {
                if self.journal_revision < 2 || !self.journal_revision.is_multiple_of(2) {
                    return Err(JournalError::Invalid(
                        "Prepared journal revision must be even and finalizable",
                    ));
                }
                if new.identity.revision <= old.identity.revision {
                    return Err(JournalError::Invalid(
                        "Prepared protocol revision does not advance",
                    ));
                }
                if *encoded != transition_id(&self.binding, old, new) {
                    return Err(JournalError::Invalid("prepared transition ID mismatch"));
                }
            }
            JournalState::Retired { .. } => {
                if self.journal_revision < 2 || !self.journal_revision.is_multiple_of(2) {
                    return Err(JournalError::Invalid(
                        "Retired journal revision must be even",
                    ));
                }
            }
        }
        Ok(())
    }

    fn next_mutation(
        &self,
        lease: JournalLeaseContext,
        state: JournalState,
    ) -> Result<JournalMutation, JournalError> {
        let journal_revision = self
            .journal_revision
            .checked_add(1)
            .ok_or(JournalError::JournalRevisionExhausted)?;
        let proposed = Self {
            binding: self.binding,
            journal_revision,
            state,
        };
        proposed.validate()?;
        Ok(JournalMutation {
            expectation: JournalWriteExpectation {
                binding_fingerprint: self.binding.fingerprint(),
                fencing_token: lease.fencing_token,
                prior: ExpectedJournalRecord::Exact {
                    journal_revision: self.journal_revision,
                    record_fingerprint: self.fingerprint(),
                },
            },
            proposed,
        })
    }

    fn ensure_lease_binding(&self, lease: JournalLeaseContext) -> Result<(), JournalError> {
        if lease.binding_fingerprint != self.binding.fingerprint() {
            return Err(JournalError::Invalid(
                "journal lease binding does not match the record",
            ));
        }
        Ok(())
    }

    fn encoded_capacity(&self) -> usize {
        let state = match &self.state {
            JournalState::NeverInitialized => 1,
            JournalState::Stable { current } => 1 + current.sealed.ciphertext.len() + 80,
            JournalState::Prepared { old, new, .. } => {
                33 + old.sealed.ciphertext.len() + new.sealed.ciphertext.len() + 160
            }
            JournalState::Retired { .. } => 1 + 104,
        };
        320 + state
    }
}

/// Expected external journal record for one fenced atomic write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedJournalRecord {
    Absent,
    Exact {
        journal_revision: u64,
        record_fingerprint: RecordFingerprint,
    },
}

/// Complete fenced compare-and-swap expectation supplied to the backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalWriteExpectation {
    binding_fingerprint: BindingFingerprint,
    fencing_token: FencingToken,
    prior: ExpectedJournalRecord,
}

impl JournalWriteExpectation {
    pub const fn binding_fingerprint(self) -> BindingFingerprint {
        self.binding_fingerprint
    }

    pub const fn fencing_token(self) -> FencingToken {
        self.fencing_token
    }

    pub const fn prior(self) -> ExpectedJournalRecord {
        self.prior
    }

    fn matches(self, loaded: Option<&JournalRecord>) -> bool {
        match (self.prior, loaded) {
            (ExpectedJournalRecord::Absent, None) => true,
            (
                ExpectedJournalRecord::Exact {
                    journal_revision,
                    record_fingerprint,
                },
                Some(record),
            ) => {
                record.binding.fingerprint() == self.binding_fingerprint
                    && record.journal_revision == journal_revision
                    && record.fingerprint() == record_fingerprint
            }
            _ => false,
        }
    }
}

/// Exact proposed journal write plus its fenced old-state expectation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalMutation {
    expectation: JournalWriteExpectation,
    proposed: JournalRecord,
}

impl JournalMutation {
    pub const fn expectation(&self) -> JournalWriteExpectation {
        self.expectation
    }

    pub const fn proposed(&self) -> &JournalRecord {
        &self.proposed
    }

    pub fn into_proposed(self) -> JournalRecord {
        self.proposed
    }

    /// Resolve an outcome-ambiguous write by comparing an exact reload.
    pub fn reconcile(&self, loaded: Option<&JournalRecord>) -> MutationReconciliation {
        if loaded.is_some_and(|record| {
            record.binding == self.proposed.binding
                && record.fingerprint() == self.proposed.fingerprint()
        }) {
            MutationReconciliation::Committed
        } else if self.expectation.matches(loaded) {
            MutationReconciliation::RetryExact
        } else {
            MutationReconciliation::FailClosedConflict
        }
    }
}

/// Result of reloading after an outcome-ambiguous external journal write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationReconciliation {
    Committed,
    RetryExact,
    FailClosedConflict,
}

/// Domain-separated identity of a complete canonical journal record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecordFingerprint([u8; 32]);

impl RecordFingerprint {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Create the only valid initial record. The backend must expose this solely
/// through a privileged provisioning path and atomically require absence.
pub fn privileged_provision(
    binding: JournalBinding,
    lease: JournalLeaseContext,
) -> Result<JournalMutation, JournalError> {
    if lease.binding_fingerprint != binding.fingerprint() {
        return Err(JournalError::Invalid(
            "journal lease binding does not match the provisioned namespace",
        ));
    }
    Ok(JournalMutation {
        expectation: JournalWriteExpectation {
            binding_fingerprint: binding.fingerprint(),
            fencing_token: lease.fencing_token,
            prior: ExpectedJournalRecord::Absent,
        },
        proposed: JournalRecord {
            binding,
            journal_revision: 0,
            state: JournalState::NeverInitialized,
        },
    })
}

/// Recovery decision. Restore actions must use an exact fenced database CAS,
/// verify decrypted plaintext and protocol semantics, then reread and re-plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryPlan<'record> {
    Ready {
        current: &'record SnapshotImage,
    },
    RestoreStableThenReread {
        expected_database: DatabaseObservation,
        current: &'record SnapshotImage,
    },
    RetryPreparedDatabaseCas {
        transition_id: TransitionId,
        expected_old: StateIdentity,
        proposed: &'record SnapshotImage,
    },
    RestorePreparedOldThenReread {
        transition_id: TransitionId,
        expected_database: DatabaseObservation,
        old: &'record SnapshotImage,
    },
    FinalizePrepared {
        transition_id: TransitionId,
    },
    FailClosed(FailClosedReason),
}

/// Terminal reason that forbids ordinary runtime use or automatic reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailClosedReason {
    MissingJournalRecord,
    BindingMismatch,
    NotEnrolled,
    Retired,
    SameRevisionFork,
    DatabaseAhead,
    UnexpectedIntermediateState,
}

/// Plan recovery while preserving the distinction between a missing record and
/// the explicit privileged `NeverInitialized` marker.
pub fn plan_recovery<'record>(
    expected_binding: &JournalBinding,
    record: Option<&'record JournalRecord>,
    database: DatabaseObservation,
) -> RecoveryPlan<'record> {
    match record {
        Some(record) => record.recovery_plan(expected_binding, database),
        None => RecoveryPlan::FailClosed(FailClosedReason::MissingJournalRecord),
    }
}

fn transition_id(
    binding: &JournalBinding,
    old: &SnapshotImage,
    new: &SnapshotImage,
) -> TransitionId {
    TransitionId(hash32(
        TRANSITION_ID_DOMAIN,
        &[
            binding.fingerprint().as_bytes(),
            &old.image_fingerprint(),
            &new.image_fingerprint(),
        ],
    ))
}

fn retirement_id(
    binding: &JournalBinding,
    last: StateIdentity,
    prior_record: RecordFingerprint,
) -> RetirementId {
    let mut identity = Encoder::with_capacity(72);
    last.encode_into(&mut identity);
    RetirementId(hash32(
        RETIREMENT_ID_DOMAIN,
        &[
            binding.fingerprint().as_bytes(),
            &identity.into_bytes(),
            prior_record.as_bytes(),
        ],
    ))
}

fn journal_checksum(bytes: &[u8]) -> [u8; 32] {
    hash32(CHECKSUM_DOMAIN, &[bytes])
}

fn hash32(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("BLAKE2b-256 output size is valid");
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("BLAKE2b-256 output buffer has the requested size");
    output
}

fn is_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const JS_UNSAFE_REVISION: u64 = 9_007_199_254_740_993;

    fn lease(value: u64) -> JournalLeaseContext {
        JournalLeaseContext::new(
            &binding(),
            FencingToken::new(NonZeroU64::new(value).expect("nonzero token")),
        )
    }

    fn binding_parts() -> JournalBindingParts {
        JournalBindingParts {
            installation_lineage: [1; 32],
            network_magic: 0x5b6e_c86b,
            role_id: [2; 32],
            storage_namespace_id: [3; 32],
            logical_key: [4; 32],
            protocol_id: [5; 32],
            protocol_version: 3,
            aead_suite: 1,
            key_version: 7,
            key_id: [6; 32],
            protection: RollbackProtectionClass::IndependentLocalRoot,
        }
    }

    fn binding() -> JournalBinding {
        JournalBinding::new(binding_parts()).expect("binding")
    }

    fn image(revision: u64, marker: u8) -> SnapshotImage {
        let plaintext = vec![marker; usize::from(marker) + 3];
        let ciphertext = vec![
            marker.wrapping_add(0x40);
            plaintext.len() + AES_256_GCM_NONCE_SIZE + AES_256_GCM_TAG_SIZE
        ];
        SnapshotImage::new(revision, [marker; 32], &plaintext, ciphertext).expect("image")
    }

    fn observation(image: &SnapshotImage) -> DatabaseObservation {
        DatabaseObservation::Present(image.identity())
    }

    fn settled() -> JournalRecord {
        let provision = privileged_provision(binding(), lease(10))
            .expect("provision")
            .into_proposed();
        let initial = image(0, 7);
        provision
            .privileged_enroll(lease(11), observation(&initial), initial)
            .expect("enroll")
            .into_proposed()
    }

    #[test]
    fn missing_is_distinct_from_explicit_uninitialized_and_retirement_is_terminal() {
        assert_eq!(
            plan_recovery(&binding(), None, DatabaseObservation::Absent),
            RecoveryPlan::FailClosed(FailClosedReason::MissingJournalRecord)
        );
        let provision = privileged_provision(binding(), lease(1))
            .expect("provision")
            .into_proposed();
        assert_eq!(
            provision.recovery_plan(&binding(), DatabaseObservation::Absent),
            RecoveryPlan::FailClosed(FailClosedReason::NotEnrolled)
        );
        let stable = settled();
        let current = match stable.state() {
            JournalState::Stable { current } => current,
            _ => panic!("stable"),
        };
        let retired = stable
            .privileged_retire(lease(12), observation(current))
            .expect("retire")
            .into_proposed();
        assert_eq!(
            retired.recovery_plan(&binding(), observation(current)),
            RecoveryPlan::FailClosed(FailClosedReason::Retired)
        );
        assert!(matches!(
            retired.privileged_enroll(lease(13), observation(current), current.clone()),
            Err(JournalError::WrongState(_))
        ));
    }

    #[test]
    fn prepare_database_cas_finalize_and_codec_round_trip() {
        let stable = settled();
        let old = match stable.state() {
            JournalState::Stable { current } => current.clone(),
            _ => panic!("stable"),
        };
        assert_eq!(
            stable.recovery_plan(&binding(), observation(&old)),
            RecoveryPlan::Ready { current: &old }
        );
        let new = image(JS_UNSAFE_REVISION, 8);
        let prepared = stable
            .prepare_transition(lease(20), observation(&old), new.clone())
            .expect("prepare")
            .into_proposed();
        let transition_id = match prepared.state() {
            JournalState::Prepared { transition_id, .. } => *transition_id,
            _ => panic!("prepared"),
        };
        assert_eq!(
            prepared.recovery_plan(&binding(), observation(&old)),
            RecoveryPlan::RetryPreparedDatabaseCas {
                transition_id,
                expected_old: old.identity(),
                proposed: &new,
            }
        );
        assert_eq!(
            prepared.recovery_plan(&binding(), observation(&new)),
            RecoveryPlan::FinalizePrepared { transition_id }
        );
        let finalized = prepared
            .finalize_prepared(lease(21), observation(&new))
            .expect("finalize")
            .into_proposed();
        assert_eq!(
            finalized.recovery_plan(&binding(), observation(&new)),
            RecoveryPlan::Ready { current: &new }
        );
        let encoded = finalized.encode();
        assert_eq!(JournalRecord::decode(&encoded), Ok(finalized));
    }

    #[test]
    fn recovery_restores_only_older_or_missing_database_and_rejects_forks() {
        let initial = settled();
        let initial_image = match initial.state() {
            JournalState::Stable { current } => current.clone(),
            _ => panic!("stable"),
        };
        let current = image(10, 9);
        let prepared = initial
            .prepare_transition(lease(30), observation(&initial_image), current.clone())
            .expect("prepare current")
            .into_proposed();
        let stable = prepared
            .finalize_prepared(lease(31), observation(&current))
            .expect("finalize current")
            .into_proposed();
        let current = match stable.state() {
            JournalState::Stable { current } => current.clone(),
            _ => panic!("stable"),
        };
        assert!(matches!(
            stable.recovery_plan(&binding(), DatabaseObservation::Absent),
            RecoveryPlan::RestoreStableThenReread { .. }
        ));
        let lower = image(current.identity().revision() - 1, 10);
        assert!(matches!(
            stable.recovery_plan(&binding(), observation(&lower)),
            RecoveryPlan::RestoreStableThenReread { .. }
        ));
        let same_revision_fork = image(current.identity().revision(), 11);
        assert_eq!(
            stable.recovery_plan(&binding(), observation(&same_revision_fork)),
            RecoveryPlan::FailClosed(FailClosedReason::SameRevisionFork)
        );
        let ahead = image(current.identity().revision() + 1, 12);
        assert_eq!(
            stable.recovery_plan(&binding(), observation(&ahead)),
            RecoveryPlan::FailClosed(FailClosedReason::DatabaseAhead)
        );

        let new = image(current.identity().revision() + 10, 13);
        let prepared = stable
            .prepare_transition(lease(32), observation(&current), new.clone())
            .expect("prepare")
            .into_proposed();
        assert!(matches!(
            prepared.recovery_plan(&binding(), DatabaseObservation::Absent),
            RecoveryPlan::RestorePreparedOldThenReread { .. }
        ));
        assert!(matches!(
            prepared.recovery_plan(&binding(), observation(&lower)),
            RecoveryPlan::RestorePreparedOldThenReread { .. }
        ));
        let old_revision_fork = image(current.identity().revision(), 14);
        assert_eq!(
            prepared.recovery_plan(&binding(), observation(&old_revision_fork)),
            RecoveryPlan::FailClosed(FailClosedReason::SameRevisionFork)
        );
        let intermediate = image(current.identity().revision() + 1, 15);
        assert_eq!(
            prepared.recovery_plan(&binding(), observation(&intermediate)),
            RecoveryPlan::FailClosed(FailClosedReason::UnexpectedIntermediateState)
        );
        let new_fork = image(new.identity().revision(), 16);
        assert_eq!(
            prepared.recovery_plan(&binding(), observation(&new_fork)),
            RecoveryPlan::FailClosed(FailClosedReason::SameRevisionFork)
        );
        let prepared_ahead = image(new.identity().revision() + 1, 17);
        assert_eq!(
            prepared.recovery_plan(&binding(), observation(&prepared_ahead)),
            RecoveryPlan::FailClosed(FailClosedReason::DatabaseAhead)
        );
    }

    #[test]
    fn ambiguous_journal_writes_are_exactly_reconciled() {
        let provision = privileged_provision(binding(), lease(40)).expect("provision");
        assert_eq!(
            provision.reconcile(None),
            MutationReconciliation::RetryExact
        );
        assert_eq!(
            provision.reconcile(Some(provision.proposed())),
            MutationReconciliation::Committed
        );
        let marker = provision.clone().into_proposed();
        let initial = image(0, 14);
        let enroll = marker
            .privileged_enroll(lease(41), observation(&initial), initial)
            .expect("enroll");
        assert_eq!(
            enroll.reconcile(Some(&marker)),
            MutationReconciliation::RetryExact
        );
        assert_eq!(
            enroll.reconcile(Some(enroll.proposed())),
            MutationReconciliation::Committed
        );
        assert_eq!(
            enroll.reconcile(None),
            MutationReconciliation::FailClosedConflict
        );
        assert_eq!(
            enroll.reconcile(Some(&settled())),
            MutationReconciliation::FailClosedConflict
        );
    }

    #[test]
    fn codec_rejects_corruption_trailing_unknown_and_semantically_invalid_values() {
        let record = settled();
        let encoded = record.encode();

        let mut corrupt = encoded.clone();
        corrupt[20] ^= 1;
        assert_eq!(
            JournalRecord::decode(&corrupt),
            Err(JournalError::Invalid("journal checksum mismatch"))
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(JournalRecord::decode(&trailing).is_err());

        let mut unknown_state = encoded.clone();
        let state_offset = 8 + 2 + 32 * 6 + 4 + 2 + 2 + 4 + 1 + 8;
        unknown_state[state_offset] = 99;
        rechecksum(&mut unknown_state);
        assert_eq!(
            JournalRecord::decode(&unknown_state),
            Err(JournalError::Invalid("unknown journal state"))
        );

        let prepared = record
            .prepare_transition(
                lease(50),
                match record.state() {
                    JournalState::Stable { current } => observation(current),
                    _ => panic!("stable"),
                },
                image(1, 15),
            )
            .expect("prepare")
            .into_proposed();
        let mut bad_transition = prepared.encode();
        let transition_offset = state_offset + 1;
        bad_transition[transition_offset] ^= 1;
        rechecksum(&mut bad_transition);
        assert_eq!(
            JournalRecord::decode(&bad_transition),
            Err(JournalError::Invalid("prepared transition ID mismatch"))
        );

        let mut unfinalizable = prepared.encode();
        unfinalizable[state_offset - 8..state_offset].copy_from_slice(&u64::MAX.to_le_bytes());
        rechecksum(&mut unfinalizable);
        assert_eq!(
            JournalRecord::decode(&unfinalizable),
            Err(JournalError::Invalid(
                "Prepared journal revision must be even and finalizable"
            ))
        );

        let mut stable_even = encoded.clone();
        stable_even[state_offset - 8..state_offset].copy_from_slice(&2_u64.to_le_bytes());
        rechecksum(&mut stable_even);
        assert_eq!(
            JournalRecord::decode(&stable_even),
            Err(JournalError::Invalid("Stable journal revision must be odd"))
        );

        let mut prepared_odd = prepared.encode();
        prepared_odd[state_offset - 8..state_offset].copy_from_slice(&3_u64.to_le_bytes());
        rechecksum(&mut prepared_odd);
        assert_eq!(
            JournalRecord::decode(&prepared_odd),
            Err(JournalError::Invalid(
                "Prepared journal revision must be even and finalizable"
            ))
        );

        let current = match record.state() {
            JournalState::Stable { current } => current,
            _ => panic!("stable"),
        };
        let retired = record
            .privileged_retire(lease(51), observation(current))
            .expect("retire")
            .into_proposed();
        let mut retired_odd = retired.encode();
        retired_odd[state_offset - 8..state_offset].copy_from_slice(&3_u64.to_le_bytes());
        rechecksum(&mut retired_odd);
        assert_eq!(
            JournalRecord::decode(&retired_odd),
            Err(JournalError::Invalid(
                "Retired journal revision must be even"
            ))
        );
    }

    #[test]
    fn bindings_aad_byte_identity_bounds_and_protection_are_exact() {
        let binding = binding();
        let plaintext = b"complete canonical state";
        let identity = StateIdentity::from_plaintext(0, [22; 32], plaintext).expect("identity");
        assert!(identity.verifies_plaintext(plaintext));
        assert!(!identity.verifies_plaintext(b"different"));
        let aad = binding.snapshot_associated_data(identity, plaintext.len() as u32);

        let mut other_parts = JournalBindingParts {
            installation_lineage: *binding.installation_lineage(),
            network_magic: binding.network_magic(),
            role_id: *binding.role_id(),
            storage_namespace_id: *binding.storage_namespace_id(),
            logical_key: *binding.logical_key(),
            protocol_id: *binding.protocol_id(),
            protocol_version: binding.protocol_version(),
            aead_suite: binding.aead_suite(),
            key_version: binding.key_version(),
            key_id: *binding.key_id(),
            protection: binding.protection(),
        };
        other_parts.network_magic ^= 1;
        let other = JournalBinding::new(other_parts).expect("other binding");
        assert_ne!(binding.fingerprint(), other.fingerprint());
        assert_ne!(
            aad,
            other.snapshot_associated_data(identity, plaintext.len() as u32)
        );
        assert!(binding.protection().has_independent_rollback_domain());
        assert!(
            !RollbackProtectionClass::IntegrityOnlySameRollbackDomain
                .has_independent_rollback_domain()
        );

        assert!(SealedSnapshot::new(0, Vec::new()).is_err());
        assert!(
            SealedSnapshot::new(1, vec![0; AES_256_GCM_NONCE_SIZE + AES_256_GCM_TAG_SIZE],)
                .is_err()
        );
        let sealed = SealedSnapshot::new(
            3,
            vec![0x5a; 3 + AES_256_GCM_NONCE_SIZE + AES_256_GCM_TAG_SIZE],
        )
        .expect("fixed AES-GCM sealed layout");
        assert_eq!(sealed.nonce().len(), AES_256_GCM_NONCE_SIZE);
        assert_eq!(sealed.encrypted_payload().len(), 3);
        assert_eq!(sealed.tag().len(), AES_256_GCM_TAG_SIZE);
        assert_eq!(
            sealed.sealed_bytes().len(),
            3 + AES_256_GCM_NONCE_SIZE + AES_256_GCM_TAG_SIZE
        );
        assert!(SealedSnapshot::new(MAX_PLAINTEXT_SNAPSHOT_SIZE + 1, vec![1],).is_err());
        assert!(
            JournalBinding::new(JournalBindingParts {
                installation_lineage: [0; 32],
                ..other_parts
            })
            .is_err()
        );

        let stable = settled();
        let current = match stable.state() {
            JournalState::Stable { current } => current,
            _ => panic!("stable"),
        };
        let wrong_bindings = [
            JournalBindingParts {
                installation_lineage: [9; 32],
                ..binding_parts()
            },
            JournalBindingParts {
                network_magic: binding.network_magic() ^ 1,
                ..binding_parts()
            },
            JournalBindingParts {
                role_id: [9; 32],
                ..binding_parts()
            },
            JournalBindingParts {
                storage_namespace_id: [9; 32],
                ..binding_parts()
            },
            JournalBindingParts {
                logical_key: [9; 32],
                ..binding_parts()
            },
            JournalBindingParts {
                protocol_id: [9; 32],
                ..binding_parts()
            },
            JournalBindingParts {
                protocol_version: 4,
                ..binding_parts()
            },
            JournalBindingParts {
                key_version: 8,
                ..binding_parts()
            },
            JournalBindingParts {
                key_id: [9; 32],
                ..binding_parts()
            },
            JournalBindingParts {
                protection: RollbackProtectionClass::RemoteWitness,
                ..binding_parts()
            },
        ];
        for parts in wrong_bindings {
            let wrong = JournalBinding::new(parts).expect("wrong but valid binding");
            assert_eq!(
                stable.recovery_plan(&wrong, observation(current)),
                RecoveryPlan::FailClosed(FailClosedReason::BindingMismatch)
            );
        }
        let wrong = JournalBinding::new(wrong_bindings[1]).expect("wrong binding");
        let wrong_lease = JournalLeaseContext::new(
            &wrong,
            FencingToken::new(NonZeroU64::new(99).expect("token")),
        );
        assert!(matches!(
            stable.prepare_transition(
                wrong_lease,
                observation(current),
                image(current.identity().revision() + 1, 23),
            ),
            Err(JournalError::Invalid(
                "journal lease binding does not match the record"
            ))
        ));
        assert!(matches!(
            JournalBinding::new(JournalBindingParts {
                aead_suite: 2,
                ..binding_parts()
            }),
            Err(JournalError::Invalid("unsupported AEAD suite"))
        ));
    }

    #[test]
    fn journal_revision_exhaustion_and_nonadvancing_protocol_state_fail() {
        let stable = settled();
        let current = match stable.state() {
            JournalState::Stable { current } => current,
            _ => panic!("stable"),
        };
        assert!(matches!(
            stable.prepare_transition(lease(60), observation(current), image(0, 16)),
            Err(JournalError::Invalid(_))
        ));

        let exhausted = JournalRecord {
            binding: binding(),
            journal_revision: u64::MAX,
            state: JournalState::Stable {
                current: current.clone(),
            },
        };
        assert_eq!(
            exhausted.prepare_transition(lease(61), observation(current), image(1, 17)),
            Err(JournalError::JournalRevisionExhausted)
        );

        let two_revisions_left = JournalRecord {
            binding: binding(),
            journal_revision: u64::MAX - 2,
            state: JournalState::Stable {
                current: current.clone(),
            },
        };
        let last_new = image(1, 19);
        let last_prepared = two_revisions_left
            .prepare_transition(lease(62), observation(current), last_new.clone())
            .expect("last finalizable prepare")
            .into_proposed();
        assert_eq!(last_prepared.journal_revision(), u64::MAX - 1);
        let last_stable = last_prepared
            .finalize_prepared(lease(63), observation(&last_new))
            .expect("last finalization")
            .into_proposed();
        assert_eq!(last_stable.journal_revision(), u64::MAX);
    }

    fn rechecksum(encoded: &mut [u8]) {
        let body_len = encoded.len() - 32;
        let checksum = journal_checksum(&encoded[..body_len]);
        encoded[body_len..].copy_from_slice(&checksum);
    }
}
