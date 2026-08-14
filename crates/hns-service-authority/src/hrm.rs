//! HRM-backed Handshake Named Service Authority (HNSA) version 1.
//!
//! This module is deliberately wire- and type-distinct from the superseded
//! `hsa1` experiment exposed at the crate root. A current service is accepted
//! only from [`hns_hrm::validation::ValidatedCurrentManifest`], whose private
//! snapshot provenance binds the service resource and delegation to one
//! authenticated, current HRM decision.
//!
//! [`crate::hrm::observe_named_service`] and
//! [`crate::hrm::ObservedNamedService::into_active`] are deliberately
//! low-level, **uncommitted** primitives. Production callers
//! should use [`crate::authority_state::NamedServiceAuthorityState`], which
//! owns HRM validation and withholds operational results until the combined
//! subject rollback state and service-generation state are durably committed.
//! Before operational use, its owned historical result must be rebound through
//! [`crate::authority_state::ReconfirmedNamedServiceAuthorityState::bind_current_at`].

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_encoding::{DecodeError, Decoder, Encoder};
use hns_hrm::cbor::{DecodeLimits, Value, decode_canonical, encode_canonical};
use hns_hrm::model::{
    ALGORITHM_SECP256K1_ECDSA, Controller, Delegation, HrmModelError, ResourceAuthority,
    ResourceEntry,
};
use hns_hrm::validation::{
    DelegationValidationContext, ExternalProofContext, ProfilePolicy, ResourcePolicy,
    ResourceValidationContext, RollbackState, ValidatedCurrentManifest, ValidatedExternalProof,
    validate_rollback,
};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const NAMED_SERVICE_PROFILE: &str = "hns.named-service/v1";
pub const OPERATE_ACTION: &str = "operate";
pub const VERSION: u8 = 1;
pub const MAX_SERVICE_NAME: usize = 63;
pub const MIN_SERVICE_ENDPOINT_LIFETIME: u32 = 300;
pub const MAX_SERVICE_ENDPOINT_LIFETIME: u32 = 604_800;
pub const MAX_ENDPOINT_DELEGATION_SIZE: usize = 320;
pub const MAX_ENDPOINT_SIGNATURE_SIZE: usize = 80;
pub const MAX_ENDPOINT_DELEGATION_CANDIDATES: usize = 32;
/// Durable [`ServiceGenerationObservation`] encoding version.
pub const SERVICE_GENERATION_OBSERVATION_VERSION: u8 = 1;
/// Exact byte length accepted by [`ServiceGenerationObservation::decode`].
pub const SERVICE_GENERATION_OBSERVATION_SIZE: usize = 258;

const RESOURCE_ID_DOMAIN: &[u8] = b"HNS-HRM-NAMED-SERVICE-ID-V1\0";
const SERVICE_DELEGATION_ID_DOMAIN: &[u8] = b"HNS-HRM-NAMED-SERVICE-DELEGATION-ID-V1\0";
const ENDPOINT_SIGNATURE_DOMAIN: &[u8] = b"HNS-HRM-HNSA-ENDPOINT-DELEGATION-V1\0";
const ENDPOINT_ID_DOMAIN: &[u8] = b"HNS-HRM-HNSA-ENDPOINT-DELEGATION-ID-V1\0";
const SERVICE_GENERATION_OBSERVATION_MAGIC: &[u8; 8] = b"HNSASGO\0";
const SERVICE_GENERATION_OBSERVATION_CHECKSUM_DOMAIN: &[u8] =
    b"HNS-HRM-HNSA-SERVICE-GENERATION-OBSERVATION-V1\0";
const SERVICE_GENERATION_OBSERVATION_PAYLOAD_SIZE: usize = SERVICE_GENERATION_OBSERVATION_SIZE - 32;

#[derive(Debug, Error)]
pub enum HnsaError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Hrm(#[from] HrmModelError),
    #[error("invalid HRM-backed HNSA object: {0}")]
    Invalid(&'static str),
    #[error("the current HRM has no service-controller delegation")]
    Withdrawn,
    #[error("the current HRM has ambiguous service-controller delegations")]
    Ambiguous,
    #[error("the service generation rolled back without an accepted chain reorganization")]
    GenerationRollback,
    #[error("the same service generation identifies different delegations")]
    GenerationConflict,
    #[error("no current endpoint delegation matches the requested logical endpoint")]
    MissingEndpoint,
    #[error("the same endpoint sequence identifies different delegations")]
    EndpointSequenceConflict,
    #[error("HRM-backed HNSA cryptographic verification failed")]
    Cryptography,
}

/// Stable HNSA security identity. Application profile IDs are supplied by a
/// separately reviewed application profile; this crate assigns none.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NamedServiceIdentity {
    pub network_magic: u32,
    pub name_hash: [u8; 32],
    pub service_name: String,
    pub application_profile_id: u16,
}

impl NamedServiceIdentity {
    pub fn new(
        network_magic: u32,
        name_hash: [u8; 32],
        service_name: impl Into<String>,
        application_profile_id: u16,
    ) -> Result<Self, HnsaError> {
        let identity = Self {
            network_magic,
            name_hash,
            service_name: service_name.into(),
            application_profile_id,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<(), HnsaError> {
        validate_service_name(&self.service_name)?;
        if self.application_profile_id == 0 {
            return Err(HnsaError::Invalid("application profile ID zero is invalid"));
        }
        Ok(())
    }

    pub fn canonical_identifier(&self) -> Result<Vec<u8>, HnsaError> {
        self.validate()?;
        encode_canonical(&Value::Map(vec![
            (0, Value::Unsigned(u64::from(self.network_magic))),
            (1, Value::Bytes(self.name_hash.to_vec())),
            (2, Value::Text(self.service_name.clone())),
            (3, Value::Unsigned(u64::from(self.application_profile_id))),
        ]))
        .map_err(|_| HnsaError::Invalid("named-service identifier exceeds CBOR limits"))
    }

    pub fn decode_identifier(input: &[u8]) -> Result<Self, HnsaError> {
        let limits = DecodeLimits {
            max_depth: 2,
            max_items: 9,
            max_bytes: 160,
            max_array_len: 0,
            max_map_len: 4,
            max_string_bytes: MAX_SERVICE_NAME,
        };
        let Value::Map(fields) = decode_canonical(input, limits)
            .map_err(|_| HnsaError::Invalid("invalid named-service identifier CBOR"))?
        else {
            return Err(HnsaError::Invalid("named-service identifier is not a map"));
        };
        if fields.len() != 4 || fields.iter().map(|(key, _)| *key).ne(0..=3) {
            return Err(HnsaError::Invalid(
                "invalid named-service identifier fields",
            ));
        }
        let network_magic = value_u32(&fields[0].1, "invalid named-service network")?;
        let name_hash = value_array(&fields[1].1, "invalid named-service name hash")?;
        let service_name = match &fields[2].1 {
            Value::Text(value) => value.clone(),
            _ => return Err(HnsaError::Invalid("invalid named-service name")),
        };
        let application_profile_id =
            value_u16(&fields[3].1, "invalid named-service application profile")?;
        let identity = Self {
            network_magic,
            name_hash,
            service_name,
            application_profile_id,
        };
        identity.validate()?;
        if identity.canonical_identifier()?.as_slice() != input {
            return Err(HnsaError::Invalid("noncanonical named-service identifier"));
        }
        Ok(identity)
    }

    pub fn resource_id(&self) -> Result<[u8; 32], HnsaError> {
        Ok(sha256(&[RESOURCE_ID_DOMAIN, &self.canonical_identifier()?]))
    }
}

/// Trusted validation policy supplied by the selected application profile.
/// None of these values may be learned from the untrusted HRM itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedServicePolicy {
    pub application_profile_id: u16,
    pub allowed_profile_flags: u16,
    pub required_profile_flags: u16,
    pub expected_profile_constraints_hash: [u8; 32],
    pub allowed_endpoint_capabilities: u32,
    pub required_endpoint_capabilities: u32,
    pub expected_endpoint_constraints_hash: [u8; 32],
    pub maximum_endpoint_lifetime: u32,
}

impl NamedServicePolicy {
    pub fn validate(self) -> Result<(), HnsaError> {
        if self.application_profile_id == 0 {
            return Err(HnsaError::Invalid("application profile ID zero is invalid"));
        }
        if self.required_profile_flags & !self.allowed_profile_flags != 0 {
            return Err(HnsaError::Invalid("required service flags are not allowed"));
        }
        if self.required_endpoint_capabilities & !self.allowed_endpoint_capabilities != 0 {
            return Err(HnsaError::Invalid(
                "required endpoint capabilities are not allowed",
            ));
        }
        if self.maximum_endpoint_lifetime == 0
            || self.maximum_endpoint_lifetime > MAX_SERVICE_ENDPOINT_LIFETIME
        {
            return Err(HnsaError::Invalid(
                "invalid application endpoint lifetime limit",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedServiceAttributes {
    pub profile_flags: u16,
    pub profile_constraints_hash: [u8; 32],
    pub presentation: Option<Vec<(u64, Value)>>,
}

impl NamedServiceAttributes {
    pub fn to_hrm_map(&self) -> Result<Vec<(u64, Value)>, HnsaError> {
        let mut fields = vec![
            (0, Value::Unsigned(u64::from(self.profile_flags))),
            (1, Value::Bytes(self.profile_constraints_hash.to_vec())),
        ];
        if let Some(presentation) = &self.presentation {
            validate_ordered_map(presentation, "invalid presentation map")?;
            fields.push((2, Value::Map(presentation.clone())));
        }
        Ok(fields)
    }

    fn from_resource(resource: &ResourceEntry) -> Result<Self, HnsaError> {
        let fields = resource
            .attributes
            .as_ref()
            .ok_or(HnsaError::Invalid("named-service attributes are required"))?;
        if fields.len() < 2
            || fields.len() > 3
            || fields[0].0 != 0
            || fields[1].0 != 1
            || fields.get(2).is_some_and(|field| field.0 != 2)
        {
            return Err(HnsaError::Invalid("invalid named-service attribute fields"));
        }
        let profile_flags = value_u16(&fields[0].1, "invalid named-service profile flags")?;
        let profile_constraints_hash = value_array(
            &fields[1].1,
            "invalid named-service profile constraints hash",
        )?;
        let presentation = match fields.get(2).map(|field| &field.1) {
            None => None,
            Some(Value::Map(fields)) => {
                validate_ordered_map(fields, "invalid presentation map")?;
                Some(fields.clone())
            }
            Some(_) => return Err(HnsaError::Invalid("presentation is not a map")),
        };
        Ok(Self {
            profile_flags,
            profile_constraints_hash,
            presentation,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceDelegationConstraints {
    pub service_generation: u64,
    pub max_endpoint_lifetime: u32,
    pub allowed_endpoint_capabilities: u32,
    pub endpoint_constraints_hash: [u8; 32],
}

impl ServiceDelegationConstraints {
    pub fn to_hrm_map(self) -> Result<Vec<(u64, Value)>, HnsaError> {
        self.validate()?;
        Ok(vec![
            (0, Value::Unsigned(self.service_generation)),
            (1, Value::Unsigned(u64::from(self.max_endpoint_lifetime))),
            (
                2,
                Value::Unsigned(u64::from(self.allowed_endpoint_capabilities)),
            ),
            (3, Value::Bytes(self.endpoint_constraints_hash.to_vec())),
        ])
    }

    fn from_delegation(delegation: &Delegation) -> Result<Self, HnsaError> {
        let fields = delegation.constraints.as_ref().ok_or(HnsaError::Invalid(
            "service delegation constraints are required",
        ))?;
        if fields.len() != 4 || fields.iter().map(|(key, _)| *key).ne(0..=3) {
            return Err(HnsaError::Invalid(
                "invalid service delegation constraint fields",
            ));
        }
        let constraints = Self {
            service_generation: value_u64(&fields[0].1, "invalid service delegation generation")?,
            max_endpoint_lifetime: value_u32(&fields[1].1, "invalid maximum endpoint lifetime")?,
            allowed_endpoint_capabilities: value_u32(
                &fields[2].1,
                "invalid endpoint capability mask",
            )?,
            endpoint_constraints_hash: value_array(
                &fields[3].1,
                "invalid endpoint constraints hash",
            )?,
        };
        constraints.validate()?;
        Ok(constraints)
    }

    fn validate(self) -> Result<(), HnsaError> {
        if self.service_generation == 0 {
            return Err(HnsaError::Invalid("service generation must be nonzero"));
        }
        if !(MIN_SERVICE_ENDPOINT_LIFETIME..=MAX_SERVICE_ENDPOINT_LIFETIME)
            .contains(&self.max_endpoint_lifetime)
        {
            return Err(HnsaError::Invalid("invalid maximum endpoint lifetime"));
        }
        Ok(())
    }
}

/// Build the exact HNS-local resource placed in an HRM payload.
pub fn named_service_resource(
    identity: &NamedServiceIdentity,
    attributes: NamedServiceAttributes,
    not_before: u64,
    expires_at: u64,
) -> Result<ResourceEntry, HnsaError> {
    if not_before >= expires_at {
        return Err(HnsaError::Invalid(
            "invalid named-service resource interval",
        ));
    }
    Ok(ResourceEntry {
        profile: NAMED_SERVICE_PROFILE.to_owned(),
        resource_id: identity.resource_id()?,
        identifier: identity.canonical_identifier()?,
        authority: ResourceAuthority::HnsLocal,
        not_before,
        expires_at,
        attributes: Some(attributes.to_hrm_map()?),
    })
}

/// Build an ordinary HRM delegation with the exact HNSA same-subject,
/// same-resource mapping and calculate its profile-defined delegation ID.
#[allow(clippy::too_many_arguments)]
pub fn service_controller_delegation(
    identity: &NamedServiceIdentity,
    resource: &ResourceEntry,
    service_controller_key: [u8; 33],
    constraints: ServiceDelegationConstraints,
    not_before: u64,
    expires_at: u64,
    payload_issued_at: u64,
    payload_expires_at: u64,
) -> Result<Delegation, HnsaError> {
    if resource.profile != NAMED_SERVICE_PROFILE
        || resource.resource_id != identity.resource_id()?
        || resource.identifier != identity.canonical_identifier()?
        || resource.authority != ResourceAuthority::HnsLocal
        || not_before < resource.not_before
        || expires_at > resource.expires_at
    {
        return Err(HnsaError::Invalid(
            "service delegation is outside its named-service resource",
        ));
    }
    let identifier = identity.canonical_identifier()?;
    let resource_id = identity.resource_id()?;
    let mut delegation = Delegation {
        delegation_id: [0; 32],
        parent_resource_id: resource_id,
        child_profile: NAMED_SERVICE_PROFILE.to_owned(),
        child_resource_id: resource_id,
        child_identifier: identifier,
        child_subject: identity.name_hash,
        child_controller: Controller::secp256k1(service_controller_key)?,
        rights: vec!["delegate-endpoint".to_owned(), OPERATE_ACTION.to_owned()],
        not_before,
        expires_at,
        may_subdelegate: false,
        constraints: Some(constraints.to_hrm_map()?),
    };
    delegation.delegation_id =
        service_delegation_id(&delegation, payload_issued_at, payload_expires_at)?;
    Ok(delegation)
}

pub fn service_delegation_id(
    delegation: &Delegation,
    payload_issued_at: u64,
    payload_expires_at: u64,
) -> Result<[u8; 32], HnsaError> {
    let body = encode_canonical(&delegation.body_value(payload_issued_at, payload_expires_at)?)
        .map_err(|_| HnsaError::Invalid("service delegation body exceeds CBOR limits"))?;
    Ok(sha256(&[SERVICE_DELEGATION_ID_DOMAIN, &body]))
}

/// HRM Core profile dispatcher for one trusted expected named-service tuple.
/// Full HNSA service-delegation checks remain in [`observe_named_service`].
#[derive(Clone, Debug)]
pub struct NamedServiceProfilePolicy {
    identity: NamedServiceIdentity,
    policy: NamedServicePolicy,
}

impl NamedServiceProfilePolicy {
    pub fn new(
        identity: NamedServiceIdentity,
        policy: NamedServicePolicy,
    ) -> Result<Self, HnsaError> {
        identity.validate()?;
        policy.validate()?;
        if identity.application_profile_id != policy.application_profile_id {
            return Err(HnsaError::Invalid("application profile policy mismatch"));
        }
        Ok(Self { identity, policy })
    }
}

impl ProfilePolicy for NamedServiceProfilePolicy {
    fn validate_resource(
        &self,
        context: ResourceValidationContext<'_>,
    ) -> Result<ResourcePolicy, String> {
        if context.network_magic != self.identity.network_magic
            || context.subject != self.identity.name_hash
            || context.action != OPERATE_ACTION
        {
            return Err("named-service request context mismatch".to_owned());
        }
        validate_resource(context.resource, &self.identity, &self.policy, context.now)
            .map_err(|error| error.to_string())?;
        Ok(ResourcePolicy {
            permits_hns_local_origin: true,
            permits_external_origin: false,
            permits_parent_delegation: false,
            permits_subdelegation: false,
            cache_until: context.resource.expires_at,
        })
    }

    fn validate_external_proof(
        &self,
        _context: ExternalProofContext<'_>,
        _proof: &[u8],
    ) -> Result<ValidatedExternalProof, String> {
        Err("HNSA version 1 has no external-origin proof".to_owned())
    }

    fn validate_delegation(&self, _context: DelegationValidationContext<'_>) -> Result<(), String> {
        Err("HNSA version 1 has no parent-resource mapping".to_owned())
    }
}

/// Per-service rollback state that must be persisted atomically before a
/// verified service or endpoint is used operationally. A withdrawn observation
/// is a tombstone and must not be discarded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceGenerationObservation {
    network_magic: u32,
    subject: [u8; 32],
    resource_id: [u8; 32],
    highest_generation: u64,
    high_water_delegation_id: [u8; 32],
    active_delegation_id: Option<[u8; 32]>,
    hrm_sequence: u64,
    hrm_envelope_hash: [u8; 32],
    rollback_state: RollbackState,
}

pub type ServiceGenerationKey = (u32, [u8; 32], [u8; 32]);
pub type ServiceGenerationObservations =
    std::collections::BTreeMap<ServiceGenerationKey, ServiceGenerationObservation>;

impl ServiceGenerationObservation {
    pub const fn key(&self) -> ServiceGenerationKey {
        (self.network_magic, self.subject, self.resource_id)
    }

    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }

    pub const fn subject(&self) -> [u8; 32] {
        self.subject
    }

    pub const fn resource_id(&self) -> [u8; 32] {
        self.resource_id
    }

    pub const fn highest_generation(&self) -> u64 {
        self.highest_generation
    }

    pub const fn high_water_delegation_id(&self) -> [u8; 32] {
        self.high_water_delegation_id
    }

    pub const fn active_delegation_id(&self) -> Option<[u8; 32]> {
        self.active_delegation_id
    }

    pub const fn hrm_sequence(&self) -> u64 {
        self.hrm_sequence
    }

    pub const fn hrm_envelope_hash(&self) -> [u8; 32] {
        self.hrm_envelope_hash
    }

    pub const fn rollback_state(&self) -> RollbackState {
        self.rollback_state
    }

    pub const fn is_withdrawn(&self) -> bool {
        self.active_delegation_id.is_none()
    }

    /// Encode the exact version-1 durable representation.
    ///
    /// The trailing domain-separated BLAKE2b-256 checksum detects accidental
    /// corruption. It is deliberately unkeyed and therefore does not
    /// authenticate storage. Callers must atomically persist these bytes in an
    /// authenticated local-state store before relying on the observation.
    pub fn encode(&self) -> Result<Vec<u8>, HnsaError> {
        validate_observation(self)?;
        let mut encoder = Encoder::with_capacity(SERVICE_GENERATION_OBSERVATION_SIZE);
        encoder.put_bytes(SERVICE_GENERATION_OBSERVATION_MAGIC);
        encoder.put_u8(SERVICE_GENERATION_OBSERVATION_VERSION);
        encoder.put_u32_le(self.network_magic);
        encoder.put_bytes(&self.subject);
        encoder.put_bytes(&self.resource_id);
        encoder.put_u64_le(self.highest_generation);
        encoder.put_bytes(&self.high_water_delegation_id);
        encoder.put_u8(u8::from(self.active_delegation_id.is_some()));
        encoder.put_u64_le(self.hrm_sequence);
        encoder.put_bytes(&self.hrm_envelope_hash);
        encoder.put_u32_le(self.rollback_state.chain_height);
        encoder.put_bytes(&self.rollback_state.chain_work);
        encoder.put_bytes(&self.rollback_state.chain_anchor);
        let mut encoded = encoder.into_bytes();
        if encoded.len() != SERVICE_GENERATION_OBSERVATION_PAYLOAD_SIZE {
            return Err(HnsaError::Invalid(
                "invalid service-generation observation encoding size",
            ));
        }
        let checksum = service_generation_observation_checksum(&encoded);
        encoded.extend_from_slice(&checksum);
        Ok(encoded)
    }

    /// Decode an exact, bounded version-1 durable representation.
    ///
    /// This checks canonical structure, the corruption-detection checksum, and
    /// every internal observation invariant. It does not authenticate the
    /// local store and does not establish that this is the observation for a
    /// caller's expected named service; use [`Self::restore`] at an operational
    /// trust boundary.
    pub fn decode(input: &[u8]) -> Result<Self, HnsaError> {
        if input.len() != SERVICE_GENERATION_OBSERVATION_SIZE {
            return Err(HnsaError::Invalid(
                "invalid service-generation observation size",
            ));
        }
        let (payload, supplied_checksum) =
            input.split_at(SERVICE_GENERATION_OBSERVATION_PAYLOAD_SIZE);
        if supplied_checksum != service_generation_observation_checksum(payload) {
            return Err(HnsaError::Invalid(
                "service-generation observation checksum mismatch",
            ));
        }

        let mut decoder = Decoder::new(payload);
        if decoder.read_array::<8>()? != *SERVICE_GENERATION_OBSERVATION_MAGIC {
            return Err(HnsaError::Invalid(
                "invalid service-generation observation magic",
            ));
        }
        if decoder.read_u8()? != SERVICE_GENERATION_OBSERVATION_VERSION {
            return Err(HnsaError::Invalid(
                "unsupported service-generation observation version",
            ));
        }
        let network_magic = decoder.read_u32_le()?;
        let subject = decoder.read_array()?;
        let resource_id = decoder.read_array()?;
        let highest_generation = decoder.read_u64_le()?;
        let high_water_delegation_id = decoder.read_array()?;
        let active_delegation_id = match decoder.read_u8()? {
            0 => None,
            1 => Some(high_water_delegation_id),
            _ => {
                return Err(HnsaError::Invalid(
                    "invalid service-generation observation state",
                ));
            }
        };
        let hrm_sequence = decoder.read_u64_le()?;
        let hrm_envelope_hash = decoder.read_array()?;
        let chain_height = decoder.read_u32_le()?;
        let chain_work = decoder.read_array()?;
        let chain_anchor = decoder.read_array()?;
        decoder.finish()?;

        let observation = Self {
            network_magic,
            subject,
            resource_id,
            highest_generation,
            high_water_delegation_id,
            active_delegation_id,
            hrm_sequence,
            hrm_envelope_hash,
            rollback_state: RollbackState {
                network_magic,
                subject,
                sequence: hrm_sequence,
                envelope_hash: hrm_envelope_hash,
                chain_height,
                chain_work,
                chain_anchor,
            },
        };
        validate_observation(&observation)?;
        if observation.encode()?.as_slice() != input {
            return Err(HnsaError::Invalid(
                "noncanonical service-generation observation",
            ));
        }
        Ok(observation)
    }

    /// Restore an observation for one trusted named-service identity.
    ///
    /// In addition to [`Self::decode`], this rejects cross-network, cross-name,
    /// cross-service, and cross-application-profile substitution by deriving
    /// the expected persistence key from `identity` rather than from the
    /// stored bytes.
    pub fn restore(input: &[u8], identity: &NamedServiceIdentity) -> Result<Self, HnsaError> {
        identity.validate()?;
        let observation = Self::decode(input)?;
        let expected_key = (
            identity.network_magic,
            identity.name_hash,
            identity.resource_id()?,
        );
        if observation.key() != expected_key {
            return Err(HnsaError::Invalid(
                "persisted service-generation observation identity mismatch",
            ));
        }
        Ok(observation)
    }
}

/// Low-level, **uncommitted** HNSA observation.
///
/// Constructing this value does not prove that its rollback/generation state
/// was persisted or remains current. Production code uses
/// [`crate::authority_state::ReconfirmedNamedServiceAuthorityState::retrieve_validate_and_observe`]
/// and then [`crate::authority_state::ReconfirmedNamedServiceAuthorityState::bind_current_at`]
/// before an operational use.
#[derive(Debug, Eq, PartialEq)]
pub enum ObservedNamedService {
    Active(Box<VerifiedNamedService>),
    Withdrawn(Box<ServiceGenerationObservation>),
}

impl ObservedNamedService {
    pub const fn observation(&self) -> &ServiceGenerationObservation {
        match self {
            Self::Active(service) => service.generation_observation(),
            Self::Withdrawn(observation) => observation,
        }
    }

    /// Extract an active service without performing persistence.
    ///
    /// This is a low-level, **uncommitted** operation. Production code instead
    /// obtains an active borrow from
    /// [`crate::authority_state::CurrentCommittedNamedService::active`].
    pub fn into_active(self) -> Result<VerifiedNamedService, HnsaError> {
        match self {
            Self::Active(service) => Ok(*service),
            Self::Withdrawn(_) => Err(HnsaError::Withdrawn),
        }
    }
}

/// Provenance-bearing current HNSA service. It can only be constructed by
/// matching a private HRM Core validated snapshot to the exact HNSA profile.
///
/// The value alone does not prove its rollback and generation observations
/// were durably committed or remain current. Production callers access it only
/// through [`crate::authority_state::CurrentCommittedNamedService::active`]
/// after acknowledged CAS and an exact current-state rebind.
/// It is intentionally non-cloneable so an active borrow cannot be detached
/// from that guard.
///
/// ```compile_fail
/// use hns_service_authority::hrm::VerifiedNamedService;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<VerifiedNamedService>();
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedNamedService {
    identity: NamedServiceIdentity,
    resource_id: [u8; 32],
    delegation_id: [u8; 32],
    service_generation: u64,
    service_controller_key: [u8; 33],
    profile_flags: u16,
    profile_constraints_hash: [u8; 32],
    max_endpoint_lifetime: u32,
    allowed_endpoint_capabilities: u32,
    required_endpoint_capabilities: u32,
    endpoint_constraints_hash: [u8; 32],
    application_maximum_endpoint_lifetime: u32,
    resource_not_before: u64,
    resource_expires_at: u64,
    delegation_not_before: u64,
    delegation_expires_at: u64,
    cache_until: u64,
    validated_at: u64,
    hrm_sequence: u64,
    hrm_envelope_hash: [u8; 32],
    generation_observation: ServiceGenerationObservation,
}

macro_rules! copy_accessor {
    ($name:ident, $field:ident, $ty:ty) => {
        pub const fn $name(&self) -> $ty {
            self.$field
        }
    };
}

impl VerifiedNamedService {
    pub const fn identity(&self) -> &NamedServiceIdentity {
        &self.identity
    }

    copy_accessor!(resource_id, resource_id, [u8; 32]);
    copy_accessor!(delegation_id, delegation_id, [u8; 32]);
    copy_accessor!(service_generation, service_generation, u64);
    copy_accessor!(service_controller_key, service_controller_key, [u8; 33]);
    copy_accessor!(profile_flags, profile_flags, u16);
    copy_accessor!(profile_constraints_hash, profile_constraints_hash, [u8; 32]);
    copy_accessor!(max_endpoint_lifetime, max_endpoint_lifetime, u32);
    copy_accessor!(
        allowed_endpoint_capabilities,
        allowed_endpoint_capabilities,
        u32
    );
    copy_accessor!(
        required_endpoint_capabilities,
        required_endpoint_capabilities,
        u32
    );
    copy_accessor!(
        endpoint_constraints_hash,
        endpoint_constraints_hash,
        [u8; 32]
    );
    copy_accessor!(resource_not_before, resource_not_before, u64);
    copy_accessor!(resource_expires_at, resource_expires_at, u64);
    copy_accessor!(delegation_not_before, delegation_not_before, u64);
    copy_accessor!(delegation_expires_at, delegation_expires_at, u64);
    /// Revalidation deadline for this authenticated current-service result.
    ///
    /// This can be earlier than the signed payload, resource, and delegation
    /// expiries because HRM validation applies a local cache limit. It is not
    /// itself an authority-interval endpoint bound.
    pub const fn cache_until(&self) -> u64 {
        self.cache_until
    }
    copy_accessor!(validated_at, validated_at, u64);
    copy_accessor!(hrm_sequence, hrm_sequence, u64);
    copy_accessor!(hrm_envelope_hash, hrm_envelope_hash, [u8; 32]);

    pub const fn generation_observation(&self) -> &ServiceGenerationObservation {
        &self.generation_observation
    }
}

/// Low-level, **uncommitted** HNSA observation primitive.
///
/// This consumes an already validated HRM Core result, validates its exact
/// HNSA resource and whole-snapshot service-delegation state, and calculates
/// the service-generation high-water/tombstone transition. It does not persist
/// either the HRM rollback state or the service observation. Production code
/// should use
/// [`crate::authority_state::ReconfirmedNamedServiceAuthorityState::retrieve_validate_and_observe`]
/// (or its async counterpart) so time precedes retrieval and no operational
/// result escapes before CAS.
pub fn observe_named_service(
    manifest: &ValidatedCurrentManifest,
    identity: &NamedServiceIdentity,
    policy: &NamedServicePolicy,
    previous: Option<&ServiceGenerationObservation>,
) -> Result<ObservedNamedService, HnsaError> {
    identity.validate()?;
    policy.validate()?;
    let expected_resource_id = identity.resource_id()?;
    let snapshot = manifest.current_snapshot();
    if identity.application_profile_id != policy.application_profile_id
        || manifest.network_magic() != identity.network_magic
        || manifest.subject() != identity.name_hash
        || snapshot.rollback_state().network_magic != identity.network_magic
        || snapshot.rollback_state().subject != identity.name_hash
        || snapshot.rollback_state().sequence != snapshot.sequence()
        || snapshot.rollback_state().envelope_hash != snapshot.envelope_hash()
        || manifest.rollback_observation() != snapshot.rollback_state()
    {
        return Err(HnsaError::Invalid(
            "authenticated current HRM manifest provenance mismatch",
        ));
    }
    validate_previous(previous, identity, expected_resource_id)?;
    let current_rollback = snapshot.rollback_state();
    if let Some(previous) = previous {
        validate_rollback(
            previous.rollback_state,
            current_rollback,
            snapshot.accepted_reorganization().as_ref(),
        )
        .map_err(|_| HnsaError::GenerationRollback)?;
    }
    let reorganization = previous.is_some_and(|previous| {
        let prior = previous.rollback_state;
        let actually_rolls_back = current_rollback.sequence < prior.sequence
            || (current_rollback.sequence == prior.sequence
                && current_rollback.envelope_hash != prior.envelope_hash)
            || current_rollback.chain_work < prior.chain_work;
        actually_rolls_back
            && snapshot
                .accepted_reorganization()
                .is_some_and(|evidence| evidence.matches(prior, current_rollback))
    });
    let Some(resource) = snapshot.resource(&expected_resource_id) else {
        return Ok(ObservedNamedService::Withdrawn(Box::new(
            withdrawn_observation(
                identity,
                expected_resource_id,
                previous,
                snapshot.sequence(),
                snapshot.envelope_hash(),
                current_rollback,
                reorganization,
            ),
        )));
    };
    let attributes = validate_resource(resource, identity, policy, snapshot.validated_at())?;

    // Count every same-parent entry containing `operate` before validating its
    // interval or remaining fields. An invalid second candidate cannot be
    // ignored to resolve ambiguity.
    let candidates = snapshot
        .delegations()
        .iter()
        .filter(|delegation| {
            delegation.parent_resource_id == expected_resource_id
                && delegation
                    .rights
                    .iter()
                    .any(|right| right == OPERATE_ACTION)
        })
        .take(2)
        .collect::<Vec<_>>();
    if candidates.len() > 1 {
        return Err(HnsaError::Ambiguous);
    }
    let Some(delegation) = candidates.first().copied() else {
        return Ok(ObservedNamedService::Withdrawn(Box::new(
            withdrawn_observation(
                identity,
                expected_resource_id,
                previous,
                snapshot.sequence(),
                snapshot.envelope_hash(),
                current_rollback,
                reorganization,
            ),
        )));
    };

    let constraints = validate_service_delegation(
        delegation,
        resource,
        identity,
        policy,
        snapshot.validated_at(),
        snapshot.payload_issued_at(),
        snapshot.payload_expires_at(),
    )?;
    apply_generation_rule(previous, delegation, constraints, reorganization)?;
    let observation = ServiceGenerationObservation {
        network_magic: identity.network_magic,
        subject: identity.name_hash,
        resource_id: expected_resource_id,
        highest_generation: constraints.service_generation,
        high_water_delegation_id: delegation.delegation_id,
        active_delegation_id: Some(delegation.delegation_id),
        hrm_sequence: snapshot.sequence(),
        hrm_envelope_hash: snapshot.envelope_hash(),
        rollback_state: current_rollback,
    };
    Ok(ObservedNamedService::Active(Box::new(
        VerifiedNamedService {
            identity: identity.clone(),
            resource_id: expected_resource_id,
            delegation_id: delegation.delegation_id,
            service_generation: constraints.service_generation,
            service_controller_key: delegation.child_controller.public_key,
            profile_flags: attributes.profile_flags,
            profile_constraints_hash: attributes.profile_constraints_hash,
            max_endpoint_lifetime: constraints.max_endpoint_lifetime,
            allowed_endpoint_capabilities: constraints.allowed_endpoint_capabilities,
            required_endpoint_capabilities: policy.required_endpoint_capabilities,
            endpoint_constraints_hash: constraints.endpoint_constraints_hash,
            application_maximum_endpoint_lifetime: policy.maximum_endpoint_lifetime,
            resource_not_before: resource.not_before,
            resource_expires_at: resource.expires_at,
            delegation_not_before: delegation.not_before,
            delegation_expires_at: delegation.expires_at,
            cache_until: manifest
                .expires_at()
                .min(resource.expires_at)
                .min(delegation.expires_at),
            validated_at: snapshot.validated_at(),
            hrm_sequence: snapshot.sequence(),
            hrm_envelope_hash: snapshot.envelope_hash(),
            generation_observation: observation,
        },
    )))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointDelegationV1 {
    pub version: u8,
    pub network_magic: u32,
    pub service_resource_id: [u8; 32],
    pub service_delegation_id: [u8; 32],
    pub service_generation: u64,
    pub endpoint_key: [u8; 33],
    pub endpoint_sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub capabilities: u32,
    pub constraints_hash: [u8; 32],
    pub service_signature: Vec<u8>,
}

impl EndpointDelegationV1 {
    pub fn encode_body(&self) -> Result<Vec<u8>, HnsaError> {
        self.validate_body()?;
        let mut encoder = Encoder::with_capacity(170);
        encoder.put_u8(self.version);
        encoder.put_u32_le(self.network_magic);
        encoder.put_bytes(&self.service_resource_id);
        encoder.put_bytes(&self.service_delegation_id);
        encoder.put_u64_le(self.service_generation);
        encoder.put_bytes(&self.endpoint_key);
        encoder.put_u64_le(self.endpoint_sequence);
        encoder.put_u64_le(self.issued_at);
        encoder.put_u64_le(self.expires_at);
        encoder.put_u32_le(self.capabilities);
        encoder.put_bytes(&self.constraints_hash);
        Ok(encoder.into_bytes())
    }

    /// Low-level signing against a bare, historical service value.
    ///
    /// This neither reserves a durable endpoint sequence nor proves that the
    /// service remains the exact committed authority result. Production wallet
    /// publication needs a later guard-bound counter-reservation workflow.
    #[doc(hidden)]
    pub fn sign_uncommitted(
        &mut self,
        service: &VerifiedNamedService,
        now: u64,
        service_private_key: &[u8; 32],
    ) -> Result<(), HnsaError> {
        let signing_key = signing_key(service_private_key)?;
        if signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            != service.service_controller_key
        {
            return Err(HnsaError::Invalid(
                "signing key is not the current service controller",
            ));
        }
        self.validate_service_context(service, now, 0)?;
        let body = self.encode_body()?;
        let digest = blake2b_256(&[ENDPOINT_SIGNATURE_DOMAIN, &body]);
        let signature: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| HnsaError::Cryptography)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        self.service_signature = signature.to_der().as_bytes().to_vec();
        self.verify_uncommitted(service, now, 0)?;
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, HnsaError> {
        let body = self.encode_body()?;
        validate_signature(&self.service_signature)?;
        let mut encoder = Encoder::with_capacity(body.len() + 1 + self.service_signature.len());
        encoder.put_bytes(&body);
        encoder.put_u8(self.service_signature.len() as u8);
        encoder.put_bytes(&self.service_signature);
        let encoded = encoder.into_bytes();
        if encoded.len() > MAX_ENDPOINT_DELEGATION_SIZE {
            return Err(HnsaError::Invalid("endpoint delegation exceeds 320 bytes"));
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsaError> {
        if input.is_empty() || input.len() > MAX_ENDPOINT_DELEGATION_SIZE {
            return Err(HnsaError::Invalid("invalid endpoint delegation size"));
        }
        let mut decoder = Decoder::new(input);
        let version = decoder.read_u8()?;
        if version != VERSION {
            return Err(HnsaError::Invalid(
                "unsupported HRM-backed endpoint delegation version",
            ));
        }
        let mut delegation = Self {
            version,
            network_magic: decoder.read_u32_le()?,
            service_resource_id: decoder.read_array()?,
            service_delegation_id: decoder.read_array()?,
            service_generation: decoder.read_u64_le()?,
            endpoint_key: decoder.read_array()?,
            endpoint_sequence: decoder.read_u64_le()?,
            issued_at: decoder.read_u64_le()?,
            expires_at: decoder.read_u64_le()?,
            capabilities: decoder.read_u32_le()?,
            constraints_hash: decoder.read_array()?,
            service_signature: Vec::new(),
        };
        let signature_length = decoder.read_u8()? as usize;
        if !(1..=MAX_ENDPOINT_SIGNATURE_SIZE).contains(&signature_length) {
            return Err(HnsaError::Invalid("invalid endpoint signature length"));
        }
        delegation.service_signature =
            decoder.read_bounded_vec(signature_length, MAX_ENDPOINT_SIGNATURE_SIZE)?;
        decoder.finish()?;
        if delegation.encode()?.as_slice() != input {
            return Err(HnsaError::Invalid("noncanonical endpoint delegation"));
        }
        Ok(delegation)
    }

    /// Check bounded canonical structure and the service-controller signature
    /// for rendezvous admission. This establishes internal consistency only;
    /// it is not current HNS/HRM authorization.
    pub fn verify_admission(&self, service_controller_key: &[u8; 33]) -> Result<(), HnsaError> {
        let body = self.encode_body()?;
        let signature = validate_signature(&self.service_signature)?;
        let verifier = validate_public_key(service_controller_key)?;
        let digest = blake2b_256(&[ENDPOINT_SIGNATURE_DOMAIN, &body]);
        verifier
            .verify_prehash(&digest, &signature)
            .map_err(|_| HnsaError::Cryptography)
    }

    /// Verify against a bare service value without a committed authority guard.
    #[doc(hidden)]
    pub fn verify_uncommitted(
        &self,
        service: &VerifiedNamedService,
        now: u64,
        required_capabilities: u32,
    ) -> Result<(), HnsaError> {
        self.validate_service_context(service, now, required_capabilities)?;
        self.verify_admission(&service.service_controller_key)
    }

    fn validate_service_context(
        &self,
        service: &VerifiedNamedService,
        now: u64,
        required_capabilities: u32,
    ) -> Result<(), HnsaError> {
        let required = required_capabilities | service.required_endpoint_capabilities;
        if self.network_magic != service.identity.network_magic
            || self.service_resource_id != service.resource_id
            || self.service_delegation_id != service.delegation_id
            || self.service_generation != service.service_generation
            || now < service.validated_at
            || now >= service.cache_until
            || now < self.issued_at
            || now >= self.expires_at
            || self.issued_at < service.resource_not_before
            || self.issued_at < service.delegation_not_before
            || self.expires_at > service.resource_expires_at
            || self.expires_at > service.delegation_expires_at
            || self.expires_at.saturating_sub(self.issued_at)
                > u64::from(
                    service
                        .max_endpoint_lifetime
                        .min(service.application_maximum_endpoint_lifetime),
                )
            || self.capabilities & !service.allowed_endpoint_capabilities != 0
            || self.capabilities & required != required
            || self.constraints_hash != service.endpoint_constraints_hash
        {
            return Err(HnsaError::Invalid("endpoint delegation context mismatch"));
        }
        Ok(())
    }

    pub fn id(&self) -> Result<[u8; 32], HnsaError> {
        Ok(sha256(&[ENDPOINT_ID_DOMAIN, &self.encode()?]))
    }

    fn validate_body(&self) -> Result<(), HnsaError> {
        if self.version != VERSION {
            return Err(HnsaError::Invalid(
                "unsupported HRM-backed endpoint delegation version",
            ));
        }
        validate_public_key(&self.endpoint_key)?;
        if self.service_generation == 0
            || self.endpoint_sequence == 0
            || self.issued_at >= self.expires_at
            || self.expires_at.saturating_sub(self.issued_at)
                > u64::from(MAX_SERVICE_ENDPOINT_LIFETIME)
        {
            return Err(HnsaError::Invalid("invalid endpoint delegation fields"));
        }
        Ok(())
    }
}

/// Select the greatest current delegation for one application-defined logical
/// endpoint. All candidates count toward the 32-object bound before filtering;
/// equal greatest sequences with different canonical bytes fail closed.
///
/// This selector is intentionally stateless. The consuming application profile
/// defines the canonical logical-endpoint identifier and its durable sequence
/// key, so it must persist the selected sequence and canonical delegation ID
/// under that profile-defined key before using the result. HNSA cannot safely
/// derive that scope from an endpoint key, capability mask, or caller predicate.
#[doc(hidden)]
pub fn select_endpoint_delegation_uncommitted<'a>(
    candidates: impl IntoIterator<Item = &'a EndpointDelegationV1>,
    service: &VerifiedNamedService,
    now: u64,
    required_capabilities: u32,
    is_logical_endpoint: impl Fn(&EndpointDelegationV1) -> bool,
) -> Result<&'a EndpointDelegationV1, HnsaError> {
    let candidates = candidates
        .into_iter()
        .take(MAX_ENDPOINT_DELEGATION_CANDIDATES.saturating_add(1))
        .collect::<Vec<_>>();
    if candidates.len() > MAX_ENDPOINT_DELEGATION_CANDIDATES {
        return Err(HnsaError::Invalid(
            "too many endpoint-delegation candidates",
        ));
    }
    let valid = candidates
        .into_iter()
        .filter(|candidate| {
            is_logical_endpoint(candidate)
                && candidate
                    .verify_uncommitted(service, now, required_capabilities)
                    .is_ok()
        })
        .collect::<Vec<_>>();
    let greatest = valid
        .iter()
        .map(|candidate| candidate.endpoint_sequence)
        .max()
        .ok_or(HnsaError::MissingEndpoint)?;
    let mut greatest_candidates = valid
        .into_iter()
        .filter(|candidate| candidate.endpoint_sequence == greatest);
    let selected = greatest_candidates
        .next()
        .ok_or(HnsaError::MissingEndpoint)?;
    let selected_bytes = selected.encode()?;
    for candidate in greatest_candidates {
        if candidate.encode()? != selected_bytes {
            return Err(HnsaError::EndpointSequenceConflict);
        }
    }
    Ok(selected)
}

fn validate_resource(
    resource: &ResourceEntry,
    identity: &NamedServiceIdentity,
    policy: &NamedServicePolicy,
    now: u64,
) -> Result<NamedServiceAttributes, HnsaError> {
    if resource.profile != NAMED_SERVICE_PROFILE
        || resource.identifier != identity.canonical_identifier()?
        || resource.resource_id != identity.resource_id()?
        || resource.authority != ResourceAuthority::HnsLocal
        || resource.not_before >= resource.expires_at
        || now < resource.not_before
        || now >= resource.expires_at
    {
        return Err(HnsaError::Invalid("invalid named-service resource"));
    }
    let decoded = NamedServiceIdentity::decode_identifier(&resource.identifier)?;
    if decoded != *identity {
        return Err(HnsaError::Invalid("named-service identity mismatch"));
    }
    let attributes = NamedServiceAttributes::from_resource(resource)?;
    if attributes.profile_flags & !policy.allowed_profile_flags != 0
        || attributes.profile_flags & policy.required_profile_flags != policy.required_profile_flags
        || attributes.profile_constraints_hash != policy.expected_profile_constraints_hash
    {
        return Err(HnsaError::Invalid(
            "named-service application policy mismatch",
        ));
    }
    Ok(attributes)
}

#[allow(clippy::too_many_arguments)]
fn validate_service_delegation(
    delegation: &Delegation,
    resource: &ResourceEntry,
    identity: &NamedServiceIdentity,
    policy: &NamedServicePolicy,
    now: u64,
    payload_issued_at: u64,
    payload_expires_at: u64,
) -> Result<ServiceDelegationConstraints, HnsaError> {
    if delegation.parent_resource_id != resource.resource_id
        || delegation.child_profile != NAMED_SERVICE_PROFILE
        || delegation.child_resource_id != resource.resource_id
        || delegation.child_identifier != resource.identifier
        || delegation.child_subject != identity.name_hash
        || delegation.child_controller.algorithm != ALGORITHM_SECP256K1_ECDSA
        || delegation.rights != ["delegate-endpoint", OPERATE_ACTION]
        || delegation.may_subdelegate
        || delegation.not_before < resource.not_before
        || delegation.expires_at > resource.expires_at
        || delegation.not_before >= delegation.expires_at
        || now < delegation.not_before
        || now >= delegation.expires_at
    {
        return Err(HnsaError::Invalid("invalid service-controller delegation"));
    }
    validate_public_key(&delegation.child_controller.public_key)?;
    let constraints = ServiceDelegationConstraints::from_delegation(delegation)?;
    if constraints.allowed_endpoint_capabilities & !policy.allowed_endpoint_capabilities != 0
        || constraints.allowed_endpoint_capabilities & policy.required_endpoint_capabilities
            != policy.required_endpoint_capabilities
        || constraints.endpoint_constraints_hash != policy.expected_endpoint_constraints_hash
    {
        return Err(HnsaError::Invalid(
            "service delegation violates application policy",
        ));
    }
    if delegation.delegation_id
        != service_delegation_id(delegation, payload_issued_at, payload_expires_at)?
    {
        return Err(HnsaError::Invalid("service delegation ID mismatch"));
    }
    Ok(constraints)
}

fn validate_previous(
    previous: Option<&ServiceGenerationObservation>,
    identity: &NamedServiceIdentity,
    resource_id: [u8; 32],
) -> Result<(), HnsaError> {
    if let Some(previous) = previous {
        validate_observation(previous)?;
        if previous.network_magic != identity.network_magic
            || previous.subject != identity.name_hash
            || previous.resource_id != resource_id
        {
            return Err(HnsaError::Invalid(
                "invalid prior service-generation observation",
            ));
        }
    }
    Ok(())
}

fn validate_observation(observation: &ServiceGenerationObservation) -> Result<(), HnsaError> {
    if observation.rollback_state.network_magic != observation.network_magic
        || observation.rollback_state.subject != observation.subject
        || observation.rollback_state.sequence != observation.hrm_sequence
        || observation.rollback_state.envelope_hash != observation.hrm_envelope_hash
        || (observation.highest_generation == 0
            && (observation.high_water_delegation_id != [0; 32]
                || observation.active_delegation_id.is_some()))
        || observation
            .active_delegation_id
            .is_some_and(|id| id != observation.high_water_delegation_id)
    {
        return Err(HnsaError::Invalid("invalid service-generation observation"));
    }
    Ok(())
}

fn service_generation_observation_checksum(input: &[u8]) -> [u8; 32] {
    blake2b_256(&[SERVICE_GENERATION_OBSERVATION_CHECKSUM_DOMAIN, input])
}

fn withdrawn_observation(
    identity: &NamedServiceIdentity,
    resource_id: [u8; 32],
    previous: Option<&ServiceGenerationObservation>,
    hrm_sequence: u64,
    hrm_envelope_hash: [u8; 32],
    rollback_state: RollbackState,
    accepted_reorganization: bool,
) -> ServiceGenerationObservation {
    let (highest_generation, high_water_delegation_id) = if accepted_reorganization {
        (0, [0; 32])
    } else {
        previous.map_or((0, [0; 32]), |previous| {
            (
                previous.highest_generation,
                previous.high_water_delegation_id,
            )
        })
    };
    ServiceGenerationObservation {
        network_magic: identity.network_magic,
        subject: identity.name_hash,
        resource_id,
        highest_generation,
        high_water_delegation_id,
        active_delegation_id: None,
        hrm_sequence,
        hrm_envelope_hash,
        rollback_state,
    }
}

fn apply_generation_rule(
    previous: Option<&ServiceGenerationObservation>,
    delegation: &Delegation,
    constraints: ServiceDelegationConstraints,
    accepted_reorganization: bool,
) -> Result<(), HnsaError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    if accepted_reorganization {
        return Ok(());
    }
    if constraints.service_generation < previous.highest_generation
        || (previous.is_withdrawn()
            && constraints.service_generation <= previous.highest_generation)
    {
        return Err(HnsaError::GenerationRollback);
    }
    if constraints.service_generation == previous.highest_generation
        && delegation.delegation_id != previous.high_water_delegation_id
    {
        return Err(HnsaError::GenerationConflict);
    }
    Ok(())
}

fn validate_service_name(name: &str) -> Result<(), HnsaError> {
    let bytes = name.as_bytes();
    if !(1..=MAX_SERVICE_NAME).contains(&bytes.len())
        || bytes.first() == Some(&b'-')
        || bytes.last() == Some(&b'-')
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(HnsaError::Invalid("noncanonical named-service name"));
    }
    Ok(())
}

fn validate_ordered_map(fields: &[(u64, Value)], message: &'static str) -> Result<(), HnsaError> {
    if fields.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(HnsaError::Invalid(message));
    }
    Ok(())
}

fn value_u64(value: &Value, message: &'static str) -> Result<u64, HnsaError> {
    match value {
        Value::Unsigned(value) => Ok(*value),
        _ => Err(HnsaError::Invalid(message)),
    }
}

fn value_u32(value: &Value, message: &'static str) -> Result<u32, HnsaError> {
    value_u64(value, message)?
        .try_into()
        .map_err(|_| HnsaError::Invalid(message))
}

fn value_u16(value: &Value, message: &'static str) -> Result<u16, HnsaError> {
    value_u64(value, message)?
        .try_into()
        .map_err(|_| HnsaError::Invalid(message))
}

fn value_array<const N: usize>(value: &Value, message: &'static str) -> Result<[u8; N], HnsaError> {
    match value {
        Value::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| HnsaError::Invalid(message)),
        _ => Err(HnsaError::Invalid(message)),
    }
}

fn validate_public_key(key: &[u8; 33]) -> Result<VerifyingKey, HnsaError> {
    if !matches!(key[0], 0x02 | 0x03) {
        return Err(HnsaError::Invalid(
            "invalid compressed secp256k1 public key",
        ));
    }
    VerifyingKey::from_sec1_bytes(key)
        .map_err(|_| HnsaError::Invalid("invalid compressed secp256k1 public key"))
}

fn signing_key(private_key: &[u8; 32]) -> Result<SigningKey, HnsaError> {
    let private = Zeroizing::new(*private_key);
    SigningKey::from_bytes((&*private).into()).map_err(|_| HnsaError::Cryptography)
}

fn validate_signature(signature: &[u8]) -> Result<Signature, HnsaError> {
    if signature.is_empty() || signature.len() > MAX_ENDPOINT_SIGNATURE_SIZE {
        return Err(HnsaError::Invalid("invalid endpoint signature length"));
    }
    let parsed = Signature::from_der(signature)
        .map_err(|_| HnsaError::Invalid("invalid DER endpoint signature"))?;
    if parsed.normalize_s().is_some() || parsed.to_der().as_bytes() != signature {
        return Err(HnsaError::Invalid("noncanonical endpoint signature"));
    }
    Ok(parsed)
}

fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        Digest::update(&mut hasher, part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use hns_hrm::model::Envelope;
    use hns_hrm::validation::{
        AcceptedReorganization, AuthenticatedNameState, ResolvedManifest, RollbackObservations,
        ValidatedCurrentManifest, ValidationLimits, validate_current_manifest,
    };

    use super::*;

    const NOW: u64 = 1_700_000_300;

    fn fixtures() -> HashMap<&'static str, &'static str> {
        include_str!("../fixtures/hnsa-hnsr-v3/hnsa-hnsr-v3.txt")
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.split_once('=').expect("fixture key/value"))
            .collect()
    }

    fn bytes(values: &HashMap<&str, &str>, key: &str) -> Vec<u8> {
        hex::decode(values.get(key).expect("fixture field")).expect("fixture hex")
    }

    fn array<const N: usize>(values: &HashMap<&str, &str>, key: &str) -> [u8; N] {
        bytes(values, key).try_into().expect("fixture array")
    }

    fn identity(values: &HashMap<&str, &str>) -> NamedServiceIdentity {
        NamedServiceIdentity::new(
            values["network_magic"].parse().expect("network magic"),
            array(values, "name_hash"),
            values["service_name"],
            values["application_profile_id"]
                .parse()
                .expect("profile ID"),
        )
        .expect("identity")
    }

    fn policy(values: &HashMap<&str, &str>) -> NamedServicePolicy {
        NamedServicePolicy {
            application_profile_id: values["application_profile_id"]
                .parse()
                .expect("profile ID"),
            allowed_profile_flags: 0,
            required_profile_flags: 0,
            expected_profile_constraints_hash: [0; 32],
            allowed_endpoint_capabilities: 1,
            required_endpoint_capabilities: 1,
            expected_endpoint_constraints_hash: [0; 32],
            maximum_endpoint_lifetime: 3_600,
        }
    }

    fn authorize_fixture(values: &HashMap<&str, &str>, key: &str) -> ValidatedCurrentManifest {
        let envelope = Envelope::decode(&bytes(values, key)).expect("fixture envelope");
        authorize_envelope(values, envelope)
    }

    fn authorize_envelope(
        values: &HashMap<&str, &str>,
        envelope: Envelope,
    ) -> ValidatedCurrentManifest {
        authorize_envelope_with_reorganization(values, envelope, None)
    }

    fn authorize_envelope_with_reorganization(
        values: &HashMap<&str, &str>,
        envelope: Envelope,
        accepted_reorganization: Option<AcceptedReorganization>,
    ) -> ValidatedCurrentManifest {
        authorize_envelope_with_options(
            values,
            envelope,
            accepted_reorganization,
            NOW,
            ValidationLimits::default(),
        )
    }

    fn authorize_envelope_with_options(
        values: &HashMap<&str, &str>,
        envelope: Envelope,
        accepted_reorganization: Option<AcceptedReorganization>,
        now: u64,
        limits: ValidationLimits,
    ) -> ValidatedCurrentManifest {
        let identity = identity(values);
        let encoded = envelope.encode().expect("envelope encode");
        let envelope_hash: [u8; 32] = Sha256::digest(&encoded).into();
        let sequence = envelope.payload.sequence;
        let mut chain_work = [0; 32];
        chain_work[24..].copy_from_slice(&sequence.to_be_bytes());
        let resolved = ResolvedManifest {
            name_state: AuthenticatedNameState {
                network_magic: identity.network_magic,
                subject: identity.name_hash,
                has_current_owner: true,
                revoked: false,
                expired: false,
                finality_accepted: true,
                chain_height: u32::try_from(sequence).expect("fixture sequence") + 100,
                chain_work,
                chain_anchor: sha256(&[b"test-chain-anchor", &sequence.to_le_bytes()]),
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
            resolved,
            identity.network_magic,
            identity.name_hash,
            now,
            limits,
            &RollbackObservations::new(),
        )
        .expect("validated HRM fixture")
    }

    fn base64url(input: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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

    fn sign_endpoint_unchecked(endpoint: &mut EndpointDelegationV1, private_key: &[u8; 32]) {
        let body = endpoint.encode_body().expect("endpoint body");
        let digest = blake2b_256(&[ENDPOINT_SIGNATURE_DOMAIN, &body]);
        let signature: Signature = signing_key(private_key)
            .expect("test signing key")
            .sign_prehash(&digest)
            .expect("test signature");
        let signature = signature.normalize_s().unwrap_or(signature);
        endpoint.service_signature = signature.to_der().as_bytes().to_vec();
    }

    #[test]
    fn authenticated_fixture_produces_current_service_and_endpoint() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let authorization = authorize_fixture(&values, "hrm_envelope");
        let service = observe_named_service(&authorization, &identity, &policy, None)
            .expect("observe service")
            .into_active()
            .expect("active service");
        assert_eq!(service.resource_id(), array(&values, "service_resource_id"));
        assert_eq!(
            service.delegation_id(),
            array(&values, "service_delegation_id")
        );
        assert_eq!(
            service.service_generation(),
            values["service_generation"].parse().expect("generation")
        );
        assert_eq!(
            service.service_controller_key(),
            array(&values, "service_controller_public_key")
        );

        let endpoint =
            EndpointDelegationV1::decode(&bytes(&values, "endpoint_delegation")).expect("endpoint");
        endpoint
            .verify_uncommitted(&service, NOW, 1)
            .expect("current endpoint");
        assert!(endpoint.verify_uncommitted(&service, NOW - 1, 1).is_err());
        let mut resigned = endpoint.clone();
        resigned.service_signature.clear();
        resigned
            .sign_uncommitted(&service, NOW, &array(&values, "service_private_key"))
            .expect("deterministic endpoint signature");
        assert_eq!(resigned, endpoint);
        for key in [
            "wrong_network_endpoint",
            "wrong_resource_endpoint",
            "wrong_capabilities_endpoint",
        ] {
            assert!(
                EndpointDelegationV1::decode(&bytes(&values, key))
                    .expect("internally signed negative endpoint")
                    .verify_uncommitted(&service, NOW, 1)
                    .is_err(),
                "accepted contextual negative endpoint {key}"
            );
        }

        let mut unsigned = endpoint.clone();
        unsigned.service_signature.clear();
        assert!(
            unsigned
                .sign_uncommitted(&service, NOW, &array(&values, "endpoint_private_key"))
                .is_err()
        );

        // HNSA sets a 300-second minimum on the service's configured maximum,
        // not on each actual endpoint lifetime.
        let mut short = endpoint.clone();
        short.endpoint_sequence += 1;
        short.issued_at = NOW;
        short.expires_at = NOW + 1;
        short
            .sign_uncommitted(&service, NOW, &array(&values, "service_private_key"))
            .expect("sign one-second endpoint");
        short
            .verify_uncommitted(&service, NOW, 1)
            .expect("one-second endpoint is valid");

        let mut later_refresh = endpoint.clone();
        later_refresh.endpoint_sequence += 2;
        later_refresh.issued_at = NOW + 30;
        later_refresh.expires_at = NOW + 60;
        later_refresh.service_signature.clear();
        assert!(
            later_refresh
                .sign_uncommitted(&service, NOW, &array(&values, "service_private_key"))
                .is_err()
        );
        later_refresh
            .sign_uncommitted(&service, NOW + 30, &array(&values, "service_private_key"))
            .expect("sign later endpoint refresh");
        assert!(
            later_refresh
                .verify_uncommitted(&service, service.validated_at() - 1, 1)
                .is_err()
        );
    }

    #[test]
    fn local_cache_limit_requires_revalidation_without_shortening_authority_interval() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let envelope = Envelope::decode(&bytes(&values, "hrm_envelope")).expect("fixture");
        let limits = ValidationLimits {
            maximum_cache_lifetime: 60,
            ..ValidationLimits::default()
        };
        let manifest =
            authorize_envelope_with_options(&values, envelope.clone(), None, NOW, limits);
        let service = observe_named_service(&manifest, &identity, &policy, None)
            .expect("service")
            .into_active()
            .expect("active service");
        let endpoint =
            EndpointDelegationV1::decode(&bytes(&values, "endpoint_delegation")).expect("endpoint");

        assert_eq!(service.cache_until(), NOW + 60);
        assert!(endpoint.expires_at > service.cache_until());
        endpoint
            .verify_uncommitted(&service, NOW, 1)
            .expect("valid signed interval may outlive local cache");
        assert!(
            endpoint
                .verify_uncommitted(&service, service.cache_until(), 1)
                .is_err()
        );

        let refreshed_manifest =
            authorize_envelope_with_options(&values, envelope, None, NOW + 60, limits);
        let refreshed_service =
            observe_named_service(&refreshed_manifest, &identity, &policy, None)
                .expect("refreshed service")
                .into_active()
                .expect("active refreshed service");
        endpoint
            .verify_uncommitted(&refreshed_service, NOW + 60, 1)
            .expect("fresh validation restores use of still-authorized endpoint");
    }

    #[test]
    fn endpoint_replacement_selection_is_bounded_and_conflict_safe() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let authorization = authorize_fixture(&values, "hrm_envelope");
        let service = observe_named_service(&authorization, &identity, &policy, None)
            .expect("service")
            .into_active()
            .expect("active service");
        let first = EndpointDelegationV1::decode(&bytes(&values, "endpoint_delegation"))
            .expect("first endpoint");
        let target_key = first.endpoint_key;
        let mut second = first.clone();
        second.endpoint_sequence += 1;
        second
            .sign_uncommitted(&service, NOW, &array(&values, "service_private_key"))
            .expect("new endpoint sequence");
        let unrelated = EndpointDelegationV1::decode(&bytes(&values, "wrong_resource_endpoint"))
            .expect("unrelated endpoint");
        assert_eq!(
            select_endpoint_delegation_uncommitted(
                [&first, &unrelated, &second],
                &service,
                NOW,
                1,
                |candidate| candidate.endpoint_key == target_key,
            )
            .expect("latest endpoint")
            .endpoint_sequence,
            second.endpoint_sequence
        );

        let mut lower_conflict = first.clone();
        lower_conflict.expires_at -= 1;
        lower_conflict
            .sign_uncommitted(&service, NOW, &array(&values, "service_private_key"))
            .expect("lower-sequence conflict");
        assert_eq!(
            select_endpoint_delegation_uncommitted(
                [&first, &lower_conflict, &second],
                &service,
                NOW,
                1,
                |_| true,
            )
            .expect("greatest endpoint ignores lower conflict")
            .endpoint_sequence,
            second.endpoint_sequence
        );

        let mut conflict = second.clone();
        conflict.expires_at -= 1;
        conflict
            .sign_uncommitted(&service, NOW, &array(&values, "service_private_key"))
            .expect("conflicting endpoint");
        assert!(matches!(
            select_endpoint_delegation_uncommitted([&second, &conflict], &service, NOW, 1, |_| {
                true
            },),
            Err(HnsaError::EndpointSequenceConflict)
        ));

        let too_many = vec![&first; MAX_ENDPOINT_DELEGATION_CANDIDATES + 1];
        assert!(
            select_endpoint_delegation_uncommitted(too_many, &service, NOW, 1, |_| true).is_err()
        );

        let mut globally_too_long = first.clone();
        globally_too_long.expires_at =
            globally_too_long.issued_at + u64::from(MAX_SERVICE_ENDPOINT_LIFETIME) + 1;
        assert!(globally_too_long.encode_body().is_err());
    }

    #[test]
    fn endpoint_all_security_bindings_fail_independently() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let manifest = authorize_fixture(&values, "hrm_envelope");
        let service = observe_named_service(&manifest, &identity, &policy, None)
            .expect("service")
            .into_active()
            .expect("active service");
        let endpoint =
            EndpointDelegationV1::decode(&bytes(&values, "endpoint_delegation")).expect("endpoint");
        let service_private = array(&values, "service_private_key");

        let mut wrong_delegation = endpoint.clone();
        wrong_delegation.service_delegation_id[0] ^= 1;
        sign_endpoint_unchecked(&mut wrong_delegation, &service_private);
        assert!(
            wrong_delegation
                .verify_uncommitted(&service, NOW, 1)
                .is_err()
        );

        let mut wrong_generation = endpoint.clone();
        wrong_generation.service_generation += 1;
        sign_endpoint_unchecked(&mut wrong_generation, &service_private);
        assert!(
            wrong_generation
                .verify_uncommitted(&service, NOW, 1)
                .is_err()
        );

        let mut wrong_constraints = endpoint.clone();
        wrong_constraints.constraints_hash[0] ^= 1;
        sign_endpoint_unchecked(&mut wrong_constraints, &service_private);
        assert!(
            wrong_constraints
                .verify_uncommitted(&service, NOW, 1)
                .is_err()
        );

        let mut future = endpoint.clone();
        future.issued_at = NOW + 1;
        future.expires_at = NOW + 10;
        sign_endpoint_unchecked(&mut future, &service_private);
        assert!(future.verify_uncommitted(&service, NOW, 1).is_err());

        let mut expired = endpoint.clone();
        expired.issued_at = NOW - 10;
        expired.expires_at = NOW;
        sign_endpoint_unchecked(&mut expired, &service_private);
        assert!(expired.verify_uncommitted(&service, NOW, 1).is_err());

        let mut over_service_lifetime = endpoint.clone();
        over_service_lifetime.issued_at = NOW;
        over_service_lifetime.expires_at = NOW + u64::from(service.max_endpoint_lifetime()) + 1;
        sign_endpoint_unchecked(&mut over_service_lifetime, &service_private);
        assert!(
            over_service_lifetime
                .verify_uncommitted(&service, NOW, 1)
                .is_err()
        );

        let mut lower_application_policy = policy;
        lower_application_policy.maximum_endpoint_lifetime = 600;
        let lower_application_service =
            observe_named_service(&manifest, &identity, &lower_application_policy, None)
                .expect("service under lower application lifetime")
                .into_active()
                .expect("active service under lower application lifetime");
        assert!(
            endpoint
                .verify_uncommitted(&lower_application_service, NOW, 1)
                .is_err()
        );

        let mut wrong_signer = endpoint.clone();
        sign_endpoint_unchecked(&mut wrong_signer, &[9; 32]);
        assert!(wrong_signer.verify_uncommitted(&service, NOW, 1).is_err());

        let mut zero_sequence = endpoint;
        zero_sequence.endpoint_sequence = 0;
        assert!(zero_sequence.encode_body().is_err());
    }

    #[test]
    fn replacement_withdrawal_restoration_and_rollbacks_are_stateful() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let initial_authorization = authorize_fixture(&values, "hrm_envelope");
        let initial = observe_named_service(&initial_authorization, &identity, &policy, None)
            .expect("initial service")
            .into_active()
            .expect("active initial service");

        let rollback_authorization = authorize_fixture(&values, "rollback_hrm_envelope");
        assert!(matches!(
            observe_named_service(
                &rollback_authorization,
                &identity,
                &policy,
                Some(initial.generation_observation()),
            ),
            Err(HnsaError::GenerationRollback)
        ));

        let conflict_authorization =
            authorize_fixture(&values, "equal_generation_conflict_hrm_envelope");
        assert!(matches!(
            observe_named_service(
                &conflict_authorization,
                &identity,
                &policy,
                Some(initial.generation_observation()),
            ),
            Err(HnsaError::GenerationConflict)
        ));

        let replacement_authorization = authorize_fixture(&values, "replacement_hrm_envelope");
        let replacement = observe_named_service(
            &replacement_authorization,
            &identity,
            &policy,
            Some(initial.generation_observation()),
        )
        .expect("replacement")
        .into_active()
        .expect("active replacement");
        assert!(replacement.service_generation() > initial.service_generation());

        let removal_authorization = authorize_fixture(&values, "removal_hrm_envelope");
        let removal = observe_named_service(
            &removal_authorization,
            &identity,
            &policy,
            Some(replacement.generation_observation()),
        )
        .expect("withdrawal");
        assert!(matches!(removal, ObservedNamedService::Withdrawn(_)));
        assert_eq!(
            removal.observation().highest_generation(),
            replacement.service_generation()
        );

        // Restoring the previous generation is forbidden after a tombstone.
        assert!(matches!(
            observe_named_service(
                &replacement_authorization,
                &identity,
                &policy,
                Some(removal.observation()),
            ),
            Err(HnsaError::GenerationRollback)
        ));

        let restoration_authorization = authorize_fixture(&values, "restoration_hrm_envelope");
        let restoration = observe_named_service(
            &restoration_authorization,
            &identity,
            &policy,
            Some(removal.observation()),
        )
        .expect("restoration")
        .into_active()
        .expect("active restoration");
        assert!(restoration.service_generation() > replacement.service_generation());
    }

    #[test]
    fn complete_snapshot_resource_removal_creates_a_restoration_tombstone() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let initial_manifest = authorize_fixture(&values, "hrm_envelope");
        let initial = observe_named_service(&initial_manifest, &identity, &policy, None)
            .expect("initial")
            .into_active()
            .expect("active initial");

        let mut removed_payload = Envelope::decode(&bytes(&values, "removal_hrm_envelope"))
            .expect("removal envelope")
            .payload;
        removed_payload.resources.clear();
        let removed_envelope = Envelope::sign(
            removed_payload,
            identity.network_magic,
            &array(&values, "hrm_private_key"),
        )
        .expect("resource removal envelope");
        let removed_manifest = authorize_envelope(&values, removed_envelope);
        let tombstone = observe_named_service(
            &removed_manifest,
            &identity,
            &policy,
            Some(initial.generation_observation()),
        )
        .expect("resource tombstone");
        assert!(matches!(tombstone, ObservedNamedService::Withdrawn(_)));
        assert_eq!(
            tombstone.observation().highest_generation(),
            initial.service_generation()
        );

        let same_generation_manifest = authorize_fixture(&values, "hrm_envelope");
        assert!(matches!(
            observe_named_service(
                &same_generation_manifest,
                &identity,
                &policy,
                Some(tombstone.observation()),
            ),
            Err(HnsaError::GenerationRollback)
        ));
        let restoration_manifest = authorize_fixture(&values, "restoration_hrm_envelope");
        observe_named_service(
            &restoration_manifest,
            &identity,
            &policy,
            Some(tombstone.observation()),
        )
        .expect("greater-generation resource restoration")
        .into_active()
        .expect("active restored resource");
    }

    #[test]
    fn hrm_snapshot_rollback_is_enforced_again_at_the_hnsa_boundary() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let initial_envelope =
            Envelope::decode(&bytes(&values, "hrm_envelope")).expect("initial envelope");
        let initial_authorization = authorize_envelope(&values, initial_envelope.clone());
        let initial = observe_named_service(&initial_authorization, &identity, &policy, None)
            .expect("initial")
            .into_active()
            .expect("active initial");

        let mut lower_payload = initial_envelope.payload.clone();
        lower_payload.sequence -= 1;
        let lower_envelope = Envelope::sign(
            lower_payload,
            identity.network_magic,
            &array(&values, "hrm_private_key"),
        )
        .expect("lower sequence envelope");
        let lower_authorization = authorize_envelope(&values, lower_envelope);
        assert!(matches!(
            observe_named_service(
                &lower_authorization,
                &identity,
                &policy,
                Some(initial.generation_observation()),
            ),
            Err(HnsaError::GenerationRollback)
        ));

        let mut conflicting_payload = initial_envelope.payload.clone();
        conflicting_payload.extensions = Some(vec![(0, Value::Null)]);
        let conflicting_envelope = Envelope::sign(
            conflicting_payload,
            identity.network_magic,
            &array(&values, "hrm_private_key"),
        )
        .expect("equal sequence conflicting envelope");
        let conflicting_authorization = authorize_envelope(&values, conflicting_envelope);
        assert!(matches!(
            observe_named_service(
                &conflicting_authorization,
                &identity,
                &policy,
                Some(initial.generation_observation()),
            ),
            Err(HnsaError::GenerationRollback)
        ));
    }

    #[test]
    fn only_exact_accepted_reorganization_can_reset_generation_state() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let replacement_authorization = authorize_fixture(&values, "replacement_hrm_envelope");
        let replacement =
            observe_named_service(&replacement_authorization, &identity, &policy, None)
                .expect("replacement")
                .into_active()
                .expect("active replacement");
        let initial_envelope =
            Envelope::decode(&bytes(&values, "hrm_envelope")).expect("initial envelope");
        let current_without_evidence = authorize_envelope(&values, initial_envelope.clone());
        let previous = replacement.generation_observation().rollback_state();
        let current = current_without_evidence.current_snapshot().rollback_state();
        let exact = AcceptedReorganization {
            previous_chain_height: previous.chain_height,
            previous_chain_work: previous.chain_work,
            previous_chain_anchor: previous.chain_anchor,
            current_chain_height: current.chain_height,
            current_chain_work: current.chain_work,
            current_chain_anchor: current.chain_anchor,
        };
        let accepted =
            authorize_envelope_with_reorganization(&values, initial_envelope.clone(), Some(exact));
        observe_named_service(
            &accepted,
            &identity,
            &policy,
            Some(replacement.generation_observation()),
        )
        .expect("exact accepted reorganization resets generation state")
        .into_active()
        .expect("active post-reorganization service");

        // Reorganization evidence does not itself authorize an independent
        // service-generation reset. A forward HRM observation must still
        // reject the older service generation even when its chain anchors
        // exactly match caller-supplied accepted-event evidence.
        let mut forward_payload = initial_envelope.payload.clone();
        forward_payload.sequence = replacement.hrm_sequence() + 1;
        let forward_envelope = Envelope::sign(
            forward_payload,
            identity.network_magic,
            &array(&values, "hrm_private_key"),
        )
        .expect("forward envelope with old generation");
        let forward_without_evidence = authorize_envelope(&values, forward_envelope.clone());
        let forward_current = forward_without_evidence.current_snapshot().rollback_state();
        let forward_event = AcceptedReorganization {
            previous_chain_height: previous.chain_height,
            previous_chain_work: previous.chain_work,
            previous_chain_anchor: previous.chain_anchor,
            current_chain_height: forward_current.chain_height,
            current_chain_work: forward_current.chain_work,
            current_chain_anchor: forward_current.chain_anchor,
        };
        let forward_with_evidence =
            authorize_envelope_with_reorganization(&values, forward_envelope, Some(forward_event));
        assert!(matches!(
            observe_named_service(
                &forward_with_evidence,
                &identity,
                &policy,
                Some(replacement.generation_observation()),
            ),
            Err(HnsaError::GenerationRollback)
        ));

        let mismatched_events = [
            AcceptedReorganization {
                previous_chain_height: exact.previous_chain_height + 1,
                ..exact
            },
            AcceptedReorganization {
                previous_chain_work: [0x11; 32],
                ..exact
            },
            AcceptedReorganization {
                previous_chain_anchor: [0x12; 32],
                ..exact
            },
            AcceptedReorganization {
                current_chain_height: exact.current_chain_height + 1,
                ..exact
            },
            AcceptedReorganization {
                current_chain_work: [0x13; 32],
                ..exact
            },
            AcceptedReorganization {
                current_chain_anchor: [0x14; 32],
                ..exact
            },
        ];
        for mismatched in mismatched_events {
            let rejected = authorize_envelope_with_reorganization(
                &values,
                initial_envelope.clone(),
                Some(mismatched),
            );
            assert!(matches!(
                observe_named_service(
                    &rejected,
                    &identity,
                    &policy,
                    Some(replacement.generation_observation()),
                ),
                Err(HnsaError::GenerationRollback)
            ));
        }
    }

    #[test]
    fn every_current_operate_candidate_counts_before_validation() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let mut envelope = Envelope::decode(&bytes(&values, "hrm_envelope")).expect("envelope");
        let mut invalid_second = envelope.payload.delegations[0].clone();
        invalid_second.child_resource_id = [0xaa; 32];
        invalid_second.delegation_id = service_delegation_id(
            &invalid_second,
            envelope.payload.issued_at,
            envelope.payload.expires_at,
        )
        .expect("second ID");
        envelope.payload.delegations.push(invalid_second);
        let signed = Envelope::sign(
            envelope.payload,
            identity.network_magic,
            &array(&values, "hrm_private_key"),
        )
        .expect("sign ambiguous envelope");
        let authorization = authorize_envelope(&values, signed);
        assert!(matches!(
            observe_named_service(&authorization, &identity, &policy, None),
            Err(HnsaError::Ambiguous)
        ));
    }

    #[test]
    fn policy_fields_and_exact_rights_are_not_manifest_selected() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let envelope = Envelope::decode(&bytes(&values, "hrm_envelope")).expect("envelope");
        let mut resource = envelope.payload.resources[0].clone();
        resource.attributes.as_mut().expect("attributes")[0].1 = Value::Unsigned(1);
        assert!(validate_resource(&resource, &identity, &policy, NOW).is_err());
        let mut wrong_origin = envelope.payload.resources[0].clone();
        wrong_origin.authority = ResourceAuthority::ParentDelegation {
            parent_subject: [1; 32],
            parent_resource_id: [2; 32],
            delegation_id: [3; 32],
        };
        assert!(validate_resource(&wrong_origin, &identity, &policy, NOW).is_err());
        for wrong_identity in [
            NamedServiceIdentity::new(
                identity.network_magic ^ 1,
                identity.name_hash,
                &identity.service_name,
                identity.application_profile_id,
            )
            .expect("wrong-network identity"),
            NamedServiceIdentity::new(
                identity.network_magic,
                [0xee; 32],
                &identity.service_name,
                identity.application_profile_id,
            )
            .expect("wrong-subject identity"),
            NamedServiceIdentity::new(
                identity.network_magic,
                identity.name_hash,
                "other-service",
                identity.application_profile_id,
            )
            .expect("wrong-service identity"),
            NamedServiceIdentity::new(
                identity.network_magic,
                identity.name_hash,
                &identity.service_name,
                identity.application_profile_id - 1,
            )
            .expect("wrong-profile identity"),
        ] {
            let mut wrong = envelope.payload.resources[0].clone();
            wrong.identifier = wrong_identity
                .canonical_identifier()
                .expect("wrong identifier");
            wrong.resource_id = wrong_identity.resource_id().expect("wrong resource ID");
            assert!(validate_resource(&wrong, &identity, &policy, NOW).is_err());
        }
        let mut future_resource = envelope.payload.resources[0].clone();
        future_resource.not_before = NOW + 1;
        assert!(validate_resource(&future_resource, &identity, &policy, NOW).is_err());
        let mut expired_resource = envelope.payload.resources[0].clone();
        expired_resource.expires_at = NOW;
        assert!(validate_resource(&expired_resource, &identity, &policy, NOW).is_err());

        let mut delegation = envelope.payload.delegations[0].clone();
        delegation.rights.reverse();
        delegation.delegation_id = service_delegation_id(
            &delegation,
            envelope.payload.issued_at,
            envelope.payload.expires_at,
        )
        .expect("reversed-rights ID");
        assert!(
            validate_service_delegation(
                &delegation,
                &envelope.payload.resources[0],
                &identity,
                &policy,
                NOW,
                envelope.payload.issued_at,
                envelope.payload.expires_at,
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_endpoint_bytes_are_not_hrm_endpoint_bytes() {
        let values = fixtures();
        let mut legacy = crate::EndpointDelegationV1 {
            network_magic: identity(&values).network_magic,
            authorization_id: [7; 32],
            endpoint_key: array(&values, "endpoint_public_key"),
            endpoint_sequence: 1,
            issued_at: NOW,
            expires_at: NOW + 60,
            capabilities: 1,
            constraints_hash: [0; 32],
            service_signature: Vec::new(),
        };
        legacy
            .sign(&array(&values, "service_private_key"))
            .expect("legacy signature");
        assert!(EndpointDelegationV1::decode(&legacy.encode().expect("legacy bytes")).is_err());
    }

    #[test]
    fn active_observation_persistence_is_exact_and_round_trips() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let authorization = authorize_fixture(&values, "hrm_envelope");
        let service = observe_named_service(&authorization, &identity, &policy, None)
            .expect("service")
            .into_active()
            .expect("active");
        let observation = service.generation_observation();
        let encoded = observation.encode().expect("durable observation");

        assert_eq!(encoded.len(), SERVICE_GENERATION_OBSERVATION_SIZE);
        assert_eq!(
            &encoded[..SERVICE_GENERATION_OBSERVATION_MAGIC.len()],
            SERVICE_GENERATION_OBSERVATION_MAGIC
        );
        assert_eq!(
            encoded[SERVICE_GENERATION_OBSERVATION_MAGIC.len()],
            SERVICE_GENERATION_OBSERVATION_VERSION
        );
        assert_eq!(
            ServiceGenerationObservation::decode(&encoded).expect("decoded observation"),
            *observation
        );
        assert_eq!(
            ServiceGenerationObservation::restore(&encoded, &identity)
                .expect("identity-bound restore"),
            *observation
        );
        assert_eq!(
            observation.encode().expect("repeat encoding"),
            encoded,
            "canonical observation bytes must be deterministic"
        );
    }

    #[test]
    fn observation_persistence_rejects_corruption_and_nonexact_input() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let authorization = authorize_fixture(&values, "hrm_envelope");
        let service = observe_named_service(&authorization, &identity, &policy, None)
            .expect("service")
            .into_active()
            .expect("active");
        let encoded = service
            .generation_observation()
            .encode()
            .expect("durable observation");

        let mut corrupted_payload = encoded.clone();
        corrupted_payload[20] ^= 1;
        assert!(ServiceGenerationObservation::decode(&corrupted_payload).is_err());
        let mut corrupted_checksum = encoded.clone();
        corrupted_checksum[SERVICE_GENERATION_OBSERVATION_PAYLOAD_SIZE] ^= 1;
        assert!(ServiceGenerationObservation::decode(&corrupted_checksum).is_err());
        assert!(ServiceGenerationObservation::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(ServiceGenerationObservation::decode(&extended).is_err());

        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        refresh_observation_checksum(&mut wrong_magic);
        assert!(ServiceGenerationObservation::decode(&wrong_magic).is_err());
        let mut wrong_version = encoded;
        wrong_version[SERVICE_GENERATION_OBSERVATION_MAGIC.len()] += 1;
        refresh_observation_checksum(&mut wrong_version);
        assert!(ServiceGenerationObservation::decode(&wrong_version).is_err());
    }

    #[test]
    fn observation_persistence_rejects_rechecksummed_invariant_violations() {
        const HIGHEST_GENERATION_OFFSET: usize = 8 + 1 + 4 + 32 + 32;
        const HIGH_WATER_ID_OFFSET: usize = HIGHEST_GENERATION_OFFSET + 8;
        const ACTIVE_STATE_OFFSET: usize = HIGH_WATER_ID_OFFSET + 32;

        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let authorization = authorize_fixture(&values, "hrm_envelope");
        let service = observe_named_service(&authorization, &identity, &policy, None)
            .expect("service")
            .into_active()
            .expect("active");
        let observation = service.generation_observation();

        let mut impossible = observation.clone();
        impossible.highest_generation = 0;
        assert!(impossible.encode().is_err());
        impossible = observation.clone();
        impossible.active_delegation_id = Some([0xaa; 32]);
        assert!(impossible.encode().is_err());

        // An untrusted store can recompute an unkeyed checksum, so decoding
        // independently enforces state invariants after checksum verification.
        let mut zero_generation_active = observation.encode().expect("observation");
        zero_generation_active[HIGHEST_GENERATION_OFFSET..HIGH_WATER_ID_OFFSET].fill(0);
        zero_generation_active[HIGH_WATER_ID_OFFSET..ACTIVE_STATE_OFFSET].fill(0);
        refresh_observation_checksum(&mut zero_generation_active);
        assert!(ServiceGenerationObservation::decode(&zero_generation_active).is_err());

        let mut invalid_state = observation.encode().expect("observation");
        invalid_state[ACTIVE_STATE_OFFSET] = 2;
        refresh_observation_checksum(&mut invalid_state);
        assert!(ServiceGenerationObservation::decode(&invalid_state).is_err());
    }

    #[test]
    fn observation_restore_rejects_cross_network_and_cross_profile_substitution() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let authorization = authorize_fixture(&values, "hrm_envelope");
        let service = observe_named_service(&authorization, &identity, &policy, None)
            .expect("service")
            .into_active()
            .expect("active");
        let encoded = service
            .generation_observation()
            .encode()
            .expect("durable observation");

        let wrong_network = NamedServiceIdentity::new(
            identity.network_magic ^ 1,
            identity.name_hash,
            &identity.service_name,
            identity.application_profile_id,
        )
        .expect("other-network identity");
        assert!(ServiceGenerationObservation::restore(&encoded, &wrong_network).is_err());

        let wrong_profile = NamedServiceIdentity::new(
            identity.network_magic,
            identity.name_hash,
            &identity.service_name,
            identity.application_profile_id - 1,
        )
        .expect("other-profile identity");
        assert!(ServiceGenerationObservation::restore(&encoded, &wrong_profile).is_err());
    }

    #[test]
    fn withdrawal_tombstone_survives_restart_and_blocks_stale_restoration() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let replacement_authorization = authorize_fixture(&values, "replacement_hrm_envelope");
        let replacement =
            observe_named_service(&replacement_authorization, &identity, &policy, None)
                .expect("replacement")
                .into_active()
                .expect("active replacement");
        let removal_authorization = authorize_fixture(&values, "removal_hrm_envelope");
        let removal = observe_named_service(
            &removal_authorization,
            &identity,
            &policy,
            Some(replacement.generation_observation()),
        )
        .expect("withdrawal");
        assert!(removal.observation().is_withdrawn());

        let encoded = removal.observation().encode().expect("durable tombstone");
        let restored =
            ServiceGenerationObservation::restore(&encoded, &identity).expect("restored tombstone");
        assert!(restored.is_withdrawn());
        assert_eq!(
            restored.highest_generation(),
            replacement.service_generation()
        );
        assert_eq!(
            restored.high_water_delegation_id(),
            replacement.delegation_id()
        );
        assert!(matches!(
            observe_named_service(
                &replacement_authorization,
                &identity,
                &policy,
                Some(&restored),
            ),
            Err(HnsaError::GenerationRollback)
        ));
    }

    #[test]
    fn observation_map_key_is_network_subject_and_resource() {
        let values = fixtures();
        let identity = identity(&values);
        let policy = policy(&values);
        let authorization = authorize_fixture(&values, "hrm_envelope");
        let service = observe_named_service(&authorization, &identity, &policy, None)
            .expect("service")
            .into_active()
            .expect("active");
        let observation = service.generation_observation().clone();
        let mut persisted = BTreeMap::new();
        persisted.insert(
            (
                observation.network_magic,
                observation.subject,
                observation.resource_id,
            ),
            observation,
        );
        assert_eq!(persisted.len(), 1);
    }

    fn refresh_observation_checksum(encoded: &mut [u8]) {
        let checksum = service_generation_observation_checksum(
            &encoded[..SERVICE_GENERATION_OBSERVATION_PAYLOAD_SIZE],
        );
        encoded[SERVICE_GENERATION_OBSERVATION_PAYLOAD_SIZE..].copy_from_slice(&checksum);
    }
}
