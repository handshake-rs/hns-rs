use std::collections::{BTreeMap, BTreeSet};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::cbor::{CborError, DecodeLimits, Value, decode_canonical, encode_canonical_with_limits};
use crate::uri::is_valid_absolute_uri;

const HRM_SIGNATURE_DOMAIN: &[u8] = b"HNS-HRM-v1\0";

pub const VERSION: u64 = 1;
pub const ALGORITHM_SECP256K1_ECDSA: u64 = 1;
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576;
pub const MAX_RESOURCES: usize = 1_024;
pub const MAX_DELEGATIONS: usize = 4_096;
pub const MAX_SIGNATURES: usize = 16;
pub const MAX_SIGNATURE_BYTES: usize = 80;
pub const MAX_PROFILE_IDENTIFIER_BYTES: usize = 128;
pub const MAX_RESOURCE_IDENTIFIER_BYTES: usize = 65_536;
pub const MAX_PROOF_URIS: usize = 4;
pub const MAX_URI_BYTES: usize = 2_048;
pub const MAX_RIGHTS: usize = 64;
pub const MAX_RIGHT_BYTES: usize = 128;

pub type ExtensionMap = Vec<(u64, Value)>;

#[derive(Debug, Error)]
pub enum HrmModelError {
    #[error(transparent)]
    Cbor(#[from] CborError),
    #[error("invalid HRM object: {0}")]
    Invalid(&'static str),
    #[error("HRM cryptographic operation failed")]
    Cryptography,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureObject {
    pub algorithm: u64,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignatureObject {
    fn validate(&self) -> Result<(), HrmModelError> {
        if self.public_key.is_empty()
            || self.public_key.len() > 256
            || self.signature.is_empty()
            || self.signature.len() > 512
        {
            return Err(HrmModelError::Invalid("invalid signature object size"));
        }
        if self.algorithm == ALGORITHM_SECP256K1_ECDSA {
            let key: [u8; 33] = self
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| HrmModelError::Invalid("invalid controller public key length"))?;
            validate_public_key(&key)?;
            validate_der_low_s(&self.signature)?;
        }
        Ok(())
    }

    fn to_value(&self) -> Result<Value, HrmModelError> {
        self.validate()?;
        Ok(Value::Map(vec![
            (0, Value::Unsigned(self.algorithm)),
            (1, Value::Bytes(self.public_key.clone())),
            (2, Value::Bytes(self.signature.clone())),
        ]))
    }

    fn from_value(value: Value) -> Result<Self, HrmModelError> {
        let mut fields = exact_fields(value, &[0, 1, 2], &[])?;
        let signature = Self {
            algorithm: take_unsigned(&mut fields, 0)?,
            public_key: take_bytes(&mut fields, 1)?,
            signature: take_bytes(&mut fields, 2)?,
        };
        signature.validate()?;
        Ok(signature)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Controller {
    pub algorithm: u64,
    pub public_key: [u8; 33],
}

impl Controller {
    pub fn secp256k1(public_key: [u8; 33]) -> Result<Self, HrmModelError> {
        validate_public_key(&public_key)?;
        Ok(Self {
            algorithm: ALGORITHM_SECP256K1_ECDSA,
            public_key,
        })
    }

    fn validate(&self) -> Result<(), HrmModelError> {
        if self.algorithm != ALGORITHM_SECP256K1_ECDSA {
            return Err(HrmModelError::Invalid(
                "unsupported HRM controller algorithm",
            ));
        }
        validate_public_key(&self.public_key)
    }

    fn to_value(&self) -> Result<Value, HrmModelError> {
        self.validate()?;
        Ok(Value::Map(vec![
            (0, Value::Unsigned(self.algorithm)),
            (1, Value::Bytes(self.public_key.to_vec())),
        ]))
    }

    fn from_value(value: Value) -> Result<Self, HrmModelError> {
        let mut fields = exact_fields(value, &[0, 1], &[])?;
        let algorithm = take_unsigned(&mut fields, 0)?;
        let public_key = take_array::<33>(&mut fields, 1)?;
        let controller = Self {
            algorithm,
            public_key,
        };
        controller.validate()?;
        Ok(controller)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceAuthority {
    HnsLocal,
    External {
        proof_profile: String,
        proof_hash: [u8; 32],
        proof_uris: Vec<String>,
    },
    ParentDelegation {
        parent_subject: [u8; 32],
        parent_resource_id: [u8; 32],
        delegation_id: [u8; 32],
    },
}

impl ResourceAuthority {
    fn validate(&self) -> Result<(), HrmModelError> {
        match self {
            Self::HnsLocal | Self::ParentDelegation { .. } => Ok(()),
            Self::External {
                proof_profile,
                proof_uris,
                ..
            } => {
                validate_profile_identifier(proof_profile)?;
                if proof_uris.len() > MAX_PROOF_URIS {
                    return Err(HrmModelError::Invalid("invalid external proof URI count"));
                }
                let mut unique = BTreeSet::new();
                for uri in proof_uris {
                    validate_uri(uri)?;
                    if !unique.insert(uri) {
                        return Err(HrmModelError::Invalid("duplicate external proof URI"));
                    }
                }
                Ok(())
            }
        }
    }

    fn to_value(&self) -> Result<Value, HrmModelError> {
        self.validate()?;
        Ok(match self {
            Self::HnsLocal => Value::Map(vec![(0, Value::Unsigned(0))]),
            Self::External {
                proof_profile,
                proof_hash,
                proof_uris,
            } => Value::Map(vec![
                (0, Value::Unsigned(1)),
                (1, Value::Text(proof_profile.clone())),
                (2, Value::Bytes(proof_hash.to_vec())),
                (
                    3,
                    Value::Array(
                        proof_uris
                            .iter()
                            .map(|uri| Value::Text(uri.clone()))
                            .collect(),
                    ),
                ),
            ]),
            Self::ParentDelegation {
                parent_subject,
                parent_resource_id,
                delegation_id,
            } => Value::Map(vec![
                (0, Value::Unsigned(2)),
                (1, Value::Bytes(parent_subject.to_vec())),
                (2, Value::Bytes(parent_resource_id.to_vec())),
                (3, Value::Bytes(delegation_id.to_vec())),
            ]),
        })
    }

    fn from_value(value: Value) -> Result<Self, HrmModelError> {
        let kind = match &value {
            Value::Map(fields) => fields
                .iter()
                .find(|(key, _)| *key == 0)
                .and_then(|(_, value)| match value {
                    Value::Unsigned(kind) => Some(*kind),
                    _ => None,
                })
                .ok_or(HrmModelError::Invalid("missing resource authority kind"))?,
            _ => return Err(HrmModelError::Invalid("resource authority is not a map")),
        };
        let authority = match kind {
            0 => {
                exact_fields(value, &[0], &[])?;
                Self::HnsLocal
            }
            1 => {
                let mut fields = exact_fields(value, &[0, 1, 2, 3], &[])?;
                let actual_kind = take_unsigned(&mut fields, 0)?;
                if actual_kind != 1 {
                    return Err(HrmModelError::Invalid("invalid external authority kind"));
                }
                Self::External {
                    proof_profile: take_text(&mut fields, 1)?,
                    proof_hash: take_array(&mut fields, 2)?,
                    proof_uris: take_text_array(&mut fields, 3)?,
                }
            }
            2 => {
                let mut fields = exact_fields(value, &[0, 1, 2, 3], &[])?;
                let actual_kind = take_unsigned(&mut fields, 0)?;
                if actual_kind != 2 {
                    return Err(HrmModelError::Invalid("invalid parent authority kind"));
                }
                Self::ParentDelegation {
                    parent_subject: take_array(&mut fields, 1)?,
                    parent_resource_id: take_array(&mut fields, 2)?,
                    delegation_id: take_array(&mut fields, 3)?,
                }
            }
            _ => return Err(HrmModelError::Invalid("unknown resource authority kind")),
        };
        authority.validate()?;
        Ok(authority)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceEntry {
    pub profile: String,
    pub resource_id: [u8; 32],
    pub identifier: Vec<u8>,
    pub authority: ResourceAuthority,
    pub not_before: u64,
    pub expires_at: u64,
    pub attributes: Option<ExtensionMap>,
}

impl ResourceEntry {
    fn validate(
        &self,
        payload_issued_at: u64,
        payload_expires_at: u64,
    ) -> Result<(), HrmModelError> {
        validate_profile_identifier(&self.profile)?;
        if self.identifier.len() > MAX_RESOURCE_IDENTIFIER_BYTES {
            return Err(HrmModelError::Invalid("resource identifier is too large"));
        }
        if self.not_before < payload_issued_at
            || self.expires_at > payload_expires_at
            || self.not_before >= self.expires_at
        {
            return Err(HrmModelError::Invalid(
                "resource validity is outside the HRM payload",
            ));
        }
        self.authority.validate()?;
        if let Some(attributes) = &self.attributes {
            validate_open_map(attributes)?;
        }
        Ok(())
    }

    fn to_value(
        &self,
        payload_issued_at: u64,
        payload_expires_at: u64,
    ) -> Result<Value, HrmModelError> {
        self.validate(payload_issued_at, payload_expires_at)?;
        let mut fields = vec![
            (0, Value::Text(self.profile.clone())),
            (1, Value::Bytes(self.resource_id.to_vec())),
            (2, Value::Bytes(self.identifier.clone())),
            (3, self.authority.to_value()?),
            (4, Value::Unsigned(self.not_before)),
            (5, Value::Unsigned(self.expires_at)),
        ];
        if let Some(attributes) = &self.attributes {
            fields.push((6, Value::Map(attributes.clone())));
        }
        Ok(Value::Map(fields))
    }

    fn from_value(
        value: Value,
        payload_issued_at: u64,
        payload_expires_at: u64,
    ) -> Result<Self, HrmModelError> {
        let mut fields = exact_fields(value, &[0, 1, 2, 3, 4, 5], &[6])?;
        let resource = Self {
            profile: take_text(&mut fields, 0)?,
            resource_id: take_array(&mut fields, 1)?,
            identifier: take_bytes(&mut fields, 2)?,
            authority: ResourceAuthority::from_value(take_value(&mut fields, 3)?)?,
            not_before: take_unsigned(&mut fields, 4)?,
            expires_at: take_unsigned(&mut fields, 5)?,
            attributes: take_optional_map(&mut fields, 6)?,
        };
        resource.validate(payload_issued_at, payload_expires_at)?;
        Ok(resource)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delegation {
    pub delegation_id: [u8; 32],
    pub parent_resource_id: [u8; 32],
    pub child_profile: String,
    pub child_resource_id: [u8; 32],
    pub child_identifier: Vec<u8>,
    pub child_subject: [u8; 32],
    pub child_controller: Controller,
    pub rights: Vec<String>,
    pub not_before: u64,
    pub expires_at: u64,
    pub may_subdelegate: bool,
    pub constraints: Option<ExtensionMap>,
}

impl Delegation {
    fn validate(
        &self,
        payload_issued_at: u64,
        payload_expires_at: u64,
    ) -> Result<(), HrmModelError> {
        validate_profile_identifier(&self.child_profile)?;
        if self.child_identifier.len() > MAX_RESOURCE_IDENTIFIER_BYTES {
            return Err(HrmModelError::Invalid(
                "child resource identifier is too large",
            ));
        }
        self.child_controller.validate()?;
        if self.rights.is_empty() || self.rights.len() > MAX_RIGHTS {
            return Err(HrmModelError::Invalid("invalid delegation rights count"));
        }
        for right in &self.rights {
            if right.is_empty() || right.len() > MAX_RIGHT_BYTES {
                return Err(HrmModelError::Invalid("invalid delegation right"));
            }
        }
        if self.not_before < payload_issued_at
            || self.expires_at > payload_expires_at
            || self.not_before >= self.expires_at
        {
            return Err(HrmModelError::Invalid(
                "delegation validity is outside the HRM payload",
            ));
        }
        if let Some(constraints) = &self.constraints {
            validate_open_map(constraints)?;
        }
        Ok(())
    }

    /// Return the deterministic delegation body used by profile-defined ID
    /// calculations after enforcing containment in its manifest payload.
    pub fn body_value(
        &self,
        payload_issued_at: u64,
        payload_expires_at: u64,
    ) -> Result<Value, HrmModelError> {
        self.validate(payload_issued_at, payload_expires_at)?;
        Ok(Value::Map(self.fields_without_id()?))
    }

    fn fields_without_id(&self) -> Result<ExtensionMap, HrmModelError> {
        self.child_controller.validate()?;
        let mut fields = vec![
            (1, Value::Bytes(self.parent_resource_id.to_vec())),
            (2, Value::Text(self.child_profile.clone())),
            (3, Value::Bytes(self.child_resource_id.to_vec())),
            (4, Value::Bytes(self.child_identifier.clone())),
            (5, Value::Bytes(self.child_subject.to_vec())),
            (6, self.child_controller.to_value()?),
            (
                7,
                Value::Array(
                    self.rights
                        .iter()
                        .map(|right| Value::Text(right.clone()))
                        .collect(),
                ),
            ),
            (8, Value::Unsigned(self.not_before)),
            (9, Value::Unsigned(self.expires_at)),
            (10, Value::Bool(self.may_subdelegate)),
        ];
        if let Some(constraints) = &self.constraints {
            validate_open_map(constraints)?;
            fields.push((11, Value::Map(constraints.clone())));
        }
        Ok(fields)
    }

    fn to_value(
        &self,
        payload_issued_at: u64,
        payload_expires_at: u64,
    ) -> Result<Value, HrmModelError> {
        self.validate(payload_issued_at, payload_expires_at)?;
        let mut fields = vec![(0, Value::Bytes(self.delegation_id.to_vec()))];
        fields.extend(self.fields_without_id()?);
        Ok(Value::Map(fields))
    }

    fn from_value(
        value: Value,
        payload_issued_at: u64,
        payload_expires_at: u64,
    ) -> Result<Self, HrmModelError> {
        let mut fields = exact_fields(value, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], &[11])?;
        let delegation = Self {
            delegation_id: take_array(&mut fields, 0)?,
            parent_resource_id: take_array(&mut fields, 1)?,
            child_profile: take_text(&mut fields, 2)?,
            child_resource_id: take_array(&mut fields, 3)?,
            child_identifier: take_bytes(&mut fields, 4)?,
            child_subject: take_array(&mut fields, 5)?,
            child_controller: Controller::from_value(take_value(&mut fields, 6)?)?,
            rights: take_text_array(&mut fields, 7)?,
            not_before: take_unsigned(&mut fields, 8)?,
            expires_at: take_unsigned(&mut fields, 9)?,
            may_subdelegate: take_bool(&mut fields, 10)?,
            constraints: take_optional_map(&mut fields, 11)?,
        };
        delegation.validate(payload_issued_at, payload_expires_at)?;
        Ok(delegation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payload {
    pub version: u64,
    pub subject: [u8; 32],
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub controller: Controller,
    pub resources: Vec<ResourceEntry>,
    pub delegations: Vec<Delegation>,
    pub extensions: Option<ExtensionMap>,
}

impl Payload {
    pub fn validate(&self) -> Result<(), HrmModelError> {
        if self.version != VERSION {
            return Err(HrmModelError::Invalid("unsupported HRM payload version"));
        }
        if self.issued_at >= self.expires_at {
            return Err(HrmModelError::Invalid("invalid HRM payload validity"));
        }
        self.controller.validate()?;
        if self.resources.len() > MAX_RESOURCES {
            return Err(HrmModelError::Invalid("too many HRM resources"));
        }
        if self.delegations.len() > MAX_DELEGATIONS {
            return Err(HrmModelError::Invalid("too many HRM delegations"));
        }
        let mut resource_ids = BTreeSet::new();
        for resource in &self.resources {
            resource.validate(self.issued_at, self.expires_at)?;
            if !resource_ids.insert(resource.resource_id) {
                return Err(HrmModelError::Invalid("duplicate HRM resource identifier"));
            }
        }
        let mut delegation_ids = BTreeSet::new();
        for delegation in &self.delegations {
            delegation.validate(self.issued_at, self.expires_at)?;
            if !delegation_ids.insert(delegation.delegation_id) {
                return Err(HrmModelError::Invalid(
                    "duplicate HRM delegation identifier",
                ));
            }
        }
        if let Some(extensions) = &self.extensions {
            validate_open_map(extensions)?;
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, HrmModelError> {
        self.validate()?;
        let encoded = encode_canonical_with_limits(&self.to_value()?, model_decode_limits())?;
        if encoded.len() > MAX_ENVELOPE_BYTES {
            return Err(HrmModelError::Invalid("HRM payload is too large"));
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, HrmModelError> {
        if input.is_empty() || input.len() > MAX_ENVELOPE_BYTES {
            return Err(HrmModelError::Invalid("invalid HRM payload size"));
        }
        let payload = Self::from_value(decode_canonical(input, model_decode_limits())?)?;
        if payload.encode()?.as_slice() != input {
            return Err(HrmModelError::Invalid("noncanonical HRM payload"));
        }
        Ok(payload)
    }

    pub fn validate_context(
        &self,
        subject: [u8; 32],
        sequence: u64,
        now: u64,
        clock_skew: u64,
    ) -> Result<(), HrmModelError> {
        self.validate()?;
        if self.subject != subject || self.sequence != sequence {
            return Err(HrmModelError::Invalid("HRM subject or sequence mismatch"));
        }
        let earliest = self.issued_at.saturating_sub(clock_skew);
        let latest = self.expires_at.saturating_add(clock_skew);
        if now < earliest || now >= latest {
            return Err(HrmModelError::Invalid("HRM payload is not currently valid"));
        }
        Ok(())
    }

    fn to_value(&self) -> Result<Value, HrmModelError> {
        self.validate()?;
        let mut fields = vec![
            (0, Value::Unsigned(self.version)),
            (1, Value::Bytes(self.subject.to_vec())),
            (2, Value::Unsigned(self.sequence)),
            (3, Value::Unsigned(self.issued_at)),
            (4, Value::Unsigned(self.expires_at)),
            (5, self.controller.to_value()?),
            (
                6,
                Value::Array(
                    self.resources
                        .iter()
                        .map(|resource| resource.to_value(self.issued_at, self.expires_at))
                        .collect::<Result<_, _>>()?,
                ),
            ),
            (
                7,
                Value::Array(
                    self.delegations
                        .iter()
                        .map(|delegation| delegation.to_value(self.issued_at, self.expires_at))
                        .collect::<Result<_, _>>()?,
                ),
            ),
        ];
        if let Some(extensions) = &self.extensions {
            fields.push((8, Value::Map(extensions.clone())));
        }
        Ok(Value::Map(fields))
    }

    fn from_value(value: Value) -> Result<Self, HrmModelError> {
        let mut fields = exact_fields(value, &[0, 1, 2, 3, 4, 5, 6, 7], &[8])?;
        let version = take_unsigned(&mut fields, 0)?;
        let subject = take_array(&mut fields, 1)?;
        let sequence = take_unsigned(&mut fields, 2)?;
        let issued_at = take_unsigned(&mut fields, 3)?;
        let expires_at = take_unsigned(&mut fields, 4)?;
        let controller = Controller::from_value(take_value(&mut fields, 5)?)?;
        let resource_values = take_array_values(&mut fields, 6)?;
        if resource_values.len() > MAX_RESOURCES {
            return Err(HrmModelError::Invalid("too many HRM resources"));
        }
        let resources = resource_values
            .into_iter()
            .map(|resource| ResourceEntry::from_value(resource, issued_at, expires_at))
            .collect::<Result<Vec<_>, _>>()?;
        let delegation_values = take_array_values(&mut fields, 7)?;
        if delegation_values.len() > MAX_DELEGATIONS {
            return Err(HrmModelError::Invalid("too many HRM delegations"));
        }
        let delegations = delegation_values
            .into_iter()
            .map(|delegation| Delegation::from_value(delegation, issued_at, expires_at))
            .collect::<Result<Vec<_>, _>>()?;
        let payload = Self {
            version,
            subject,
            sequence,
            issued_at,
            expires_at,
            controller,
            resources,
            delegations,
            extensions: take_optional_map(&mut fields, 8)?,
        };
        payload.validate()?;
        Ok(payload)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub payload: Payload,
    pub signatures: Vec<SignatureObject>,
}

impl Envelope {
    pub fn sign(
        payload: Payload,
        network_magic: u32,
        private_key: &[u8; 32],
    ) -> Result<Self, HrmModelError> {
        payload.validate()?;
        let signing_key = signing_key(private_key)?;
        let public_key = signing_key.verifying_key().to_encoded_point(true);
        if public_key.as_bytes() != payload.controller.public_key {
            return Err(HrmModelError::Invalid(
                "private key does not match the HRM controller",
            ));
        }
        let payload_bytes = payload.encode()?;
        let digest = signature_digest(network_magic, &payload_bytes);
        let signature: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| HrmModelError::Cryptography)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let envelope = Self {
            payload,
            signatures: vec![SignatureObject {
                algorithm: ALGORITHM_SECP256K1_ECDSA,
                public_key: public_key.as_bytes().to_vec(),
                signature: signature.to_der().as_bytes().to_vec(),
            }],
        };
        envelope.validate_structure()?;
        // Make `sign` uphold the complete encoded-envelope size invariant,
        // rather than returning an object that only fails when later encoded.
        envelope.encode()?;
        Ok(envelope)
    }

    pub fn encode(&self) -> Result<Vec<u8>, HrmModelError> {
        self.validate_structure()?;
        let payload = self.payload.encode()?;
        let signatures = self
            .signatures
            .iter()
            .map(SignatureObject::to_value)
            .collect::<Result<Vec<_>, _>>()?;
        let encoded = encode_canonical_with_limits(
            &Value::Map(vec![
                (0, Value::Bytes(payload)),
                (1, Value::Array(signatures)),
            ]),
            model_decode_limits(),
        )?;
        if encoded.len() > MAX_ENVELOPE_BYTES {
            return Err(HrmModelError::Invalid("HRM envelope is too large"));
        }
        Ok(encoded)
    }

    /// Decode and structurally validate a canonical envelope.
    ///
    /// This does not authenticate the controller signature because signature
    /// authority is network-bound. Call [`Self::validate_context`] before
    /// treating decoded bytes as an authorized HRM.
    pub fn decode(input: &[u8]) -> Result<Self, HrmModelError> {
        if input.is_empty() || input.len() > MAX_ENVELOPE_BYTES {
            return Err(HrmModelError::Invalid("invalid HRM envelope size"));
        }
        let mut fields = exact_fields(
            decode_canonical(input, model_decode_limits())?,
            &[0, 1],
            &[],
        )?;
        let payload = Payload::decode(&take_bytes(&mut fields, 0)?)?;
        let signatures = take_array_values(&mut fields, 1)?
            .into_iter()
            .map(SignatureObject::from_value)
            .collect::<Result<Vec<_>, _>>()?;
        let envelope = Self {
            payload,
            signatures,
        };
        envelope.validate_structure()?;
        if envelope.encode()?.as_slice() != input {
            return Err(HrmModelError::Invalid("noncanonical HRM envelope"));
        }
        Ok(envelope)
    }

    pub fn envelope_hash(&self) -> Result<[u8; 32], HrmModelError> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    pub fn verify_controller_signature(&self, network_magic: u32) -> Result<(), HrmModelError> {
        self.validate_structure()?;
        let payload = self.payload.encode()?;
        let digest = signature_digest(network_magic, &payload);
        let controller_key = self.payload.controller.public_key;
        let verifier = VerifyingKey::from_sec1_bytes(&controller_key)
            .map_err(|_| HrmModelError::Cryptography)?;
        for signature in &self.signatures {
            if signature.algorithm != ALGORITHM_SECP256K1_ECDSA
                || signature.public_key.as_slice() != controller_key
            {
                continue;
            }
            let parsed = match Signature::from_der(&signature.signature) {
                Ok(parsed) if parsed.normalize_s().is_none() => parsed,
                _ => continue,
            };
            if verifier.verify_prehash(&digest, &parsed).is_ok() {
                return Ok(());
            }
        }
        Err(HrmModelError::Cryptography)
    }

    pub fn validate_context(
        &self,
        network_magic: u32,
        subject: [u8; 32],
        sequence: u64,
        now: u64,
        clock_skew: u64,
    ) -> Result<(), HrmModelError> {
        self.payload
            .validate_context(subject, sequence, now, clock_skew)?;
        self.verify_controller_signature(network_magic)
    }

    fn validate_structure(&self) -> Result<(), HrmModelError> {
        self.payload.validate()?;
        if self.signatures.is_empty() || self.signatures.len() > MAX_SIGNATURES {
            return Err(HrmModelError::Invalid("invalid HRM signature count"));
        }
        for signature in &self.signatures {
            signature.validate()?;
        }
        Ok(())
    }
}

pub fn public_key(private_key: &[u8; 32]) -> Result<[u8; 33], HrmModelError> {
    let signing_key = signing_key(private_key)?;
    signing_key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| HrmModelError::Cryptography)
}

fn signature_digest(network_magic: u32, payload: &[u8]) -> [u8; 32] {
    blake2b_256(&[HRM_SIGNATURE_DOMAIN, &network_magic.to_le_bytes(), payload])
}

fn signing_key(private_key: &[u8; 32]) -> Result<SigningKey, HrmModelError> {
    let private = Zeroizing::new(*private_key);
    SigningKey::from_bytes((&*private).into()).map_err(|_| HrmModelError::Cryptography)
}

fn validate_public_key(public_key: &[u8; 33]) -> Result<(), HrmModelError> {
    if !matches!(public_key[0], 0x02 | 0x03) {
        return Err(HrmModelError::Invalid(
            "invalid compressed secp256k1 public key",
        ));
    }
    VerifyingKey::from_sec1_bytes(public_key)
        .map(|_| ())
        .map_err(|_| HrmModelError::Invalid("invalid compressed secp256k1 public key"))
}

fn validate_der_low_s(signature: &[u8]) -> Result<(), HrmModelError> {
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        return Err(HrmModelError::Invalid("invalid secp256k1 signature size"));
    }
    let parsed = Signature::from_der(signature)
        .map_err(|_| HrmModelError::Invalid("invalid DER secp256k1 signature"))?;
    if parsed.normalize_s().is_some() || parsed.to_der().as_bytes() != signature {
        return Err(HrmModelError::Invalid("noncanonical secp256k1 signature"));
    }
    Ok(())
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

fn model_decode_limits() -> DecodeLimits {
    DecodeLimits {
        max_depth: 32,
        max_items: MAX_ENVELOPE_BYTES,
        max_bytes: MAX_ENVELOPE_BYTES,
        max_array_len: MAX_DELEGATIONS,
        max_map_len: 64,
        max_string_bytes: MAX_ENVELOPE_BYTES,
    }
}

fn validate_profile_identifier(profile: &str) -> Result<(), HrmModelError> {
    if profile.is_empty()
        || profile.len() > MAX_PROFILE_IDENTIFIER_BYTES
        || !profile.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'/')
        })
    {
        return Err(HrmModelError::Invalid("invalid HRM profile identifier"));
    }
    Ok(())
}

fn validate_uri(uri: &str) -> Result<(), HrmModelError> {
    if uri.len() > MAX_URI_BYTES || !is_valid_absolute_uri(uri) {
        return Err(HrmModelError::Invalid("invalid HRM retrieval URI"));
    }
    Ok(())
}

fn validate_open_map(fields: &ExtensionMap) -> Result<(), HrmModelError> {
    let mut previous = None;
    for (key, _) in fields {
        if previous.is_some_and(|previous| previous >= *key) {
            return Err(HrmModelError::Invalid(
                "open HRM map keys are not strictly increasing",
            ));
        }
        previous = Some(*key);
    }
    Ok(())
}

fn exact_fields(
    value: Value,
    required: &[u64],
    optional: &[u64],
) -> Result<BTreeMap<u64, Value>, HrmModelError> {
    let Value::Map(fields) = value else {
        return Err(HrmModelError::Invalid("expected HRM CBOR map"));
    };
    let allowed = required
        .iter()
        .chain(optional)
        .copied()
        .collect::<BTreeSet<_>>();
    let map = fields.into_iter().collect::<BTreeMap<_, _>>();
    if map.keys().any(|key| !allowed.contains(key)) {
        return Err(HrmModelError::Invalid("unknown HRM map key"));
    }
    if required.iter().any(|key| !map.contains_key(key)) {
        return Err(HrmModelError::Invalid("missing required HRM map key"));
    }
    Ok(map)
}

fn take_value(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<Value, HrmModelError> {
    fields
        .remove(&key)
        .ok_or(HrmModelError::Invalid("missing required HRM field"))
}

fn take_unsigned(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<u64, HrmModelError> {
    match take_value(fields, key)? {
        Value::Unsigned(value) => Ok(value),
        _ => Err(HrmModelError::Invalid("HRM field is not unsigned")),
    }
}

fn take_bytes(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<Vec<u8>, HrmModelError> {
    match take_value(fields, key)? {
        Value::Bytes(value) => Ok(value),
        _ => Err(HrmModelError::Invalid("HRM field is not a byte string")),
    }
}

fn take_array<const N: usize>(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
) -> Result<[u8; N], HrmModelError> {
    take_bytes(fields, key)?
        .try_into()
        .map_err(|_| HrmModelError::Invalid("HRM byte string has the wrong size"))
}

fn take_text(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<String, HrmModelError> {
    match take_value(fields, key)? {
        Value::Text(value) => Ok(value),
        _ => Err(HrmModelError::Invalid("HRM field is not text")),
    }
}

fn take_bool(fields: &mut BTreeMap<u64, Value>, key: u64) -> Result<bool, HrmModelError> {
    match take_value(fields, key)? {
        Value::Bool(value) => Ok(value),
        _ => Err(HrmModelError::Invalid("HRM field is not boolean")),
    }
}

fn take_array_values(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
) -> Result<Vec<Value>, HrmModelError> {
    match take_value(fields, key)? {
        Value::Array(values) => Ok(values),
        _ => Err(HrmModelError::Invalid("HRM field is not an array")),
    }
}

fn take_text_array(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
) -> Result<Vec<String>, HrmModelError> {
    take_array_values(fields, key)?
        .into_iter()
        .map(|value| match value {
            Value::Text(value) => Ok(value),
            _ => Err(HrmModelError::Invalid("HRM array item is not text")),
        })
        .collect()
}

fn take_optional_map(
    fields: &mut BTreeMap<u64, Value>,
    key: u64,
) -> Result<Option<ExtensionMap>, HrmModelError> {
    match fields.remove(&key) {
        None => Ok(None),
        Some(Value::Map(map)) => {
            validate_open_map(&map)?;
            Ok(Some(map))
        }
        Some(_) => Err(HrmModelError::Invalid("HRM optional field is not a map")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: u32 = 0xae38_95cf;

    fn sample_payload(private_key: &[u8; 32]) -> Payload {
        Payload {
            version: VERSION,
            subject: [0x0f; 32],
            sequence: 7,
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            controller: Controller::secp256k1(public_key(private_key).expect("public key"))
                .expect("controller"),
            resources: vec![ResourceEntry {
                profile: "hns.named-service/v1".to_owned(),
                resource_id: [3; 32],
                identifier: vec![0xa1, 0x00, 0x01],
                authority: ResourceAuthority::HnsLocal,
                not_before: 1_700_000_000,
                expires_at: 1_700_080_000,
                attributes: Some(vec![(0, Value::Unsigned(0))]),
            }],
            delegations: Vec::new(),
            extensions: None,
        }
    }

    #[test]
    fn signed_envelope_round_trips_and_binds_network_context() {
        let private_key = [1; 32];
        let envelope = Envelope::sign(sample_payload(&private_key), MAGIC, &private_key)
            .expect("signed envelope");
        envelope
            .validate_context(MAGIC, [0x0f; 32], 7, 1_700_000_001, 0)
            .expect("valid context");
        let encoded = envelope.encode().expect("encode");
        assert_eq!(Envelope::decode(&encoded).expect("decode"), envelope);
        assert!(envelope.verify_controller_signature(MAGIC ^ 1).is_err());
        assert!(
            envelope
                .validate_context(MAGIC, [0x0e; 32], 7, 1_700_000_001, 0)
                .is_err()
        );
    }

    #[test]
    fn controller_key_is_separate_and_required_for_signing() {
        let payload = sample_payload(&[1; 32]);
        assert!(Envelope::sign(payload, MAGIC, &[2; 32]).is_err());
    }

    #[test]
    fn duplicate_resources_and_out_of_bounds_intervals_fail_closed() {
        let mut payload = sample_payload(&[1; 32]);
        payload.resources.push(payload.resources[0].clone());
        assert!(payload.validate().is_err());

        let mut payload = sample_payload(&[1; 32]);
        payload.resources[0].expires_at = payload.expires_at + 1;
        assert!(payload.validate().is_err());
    }

    #[test]
    fn all_resource_authority_forms_round_trip() {
        let authorities = [
            ResourceAuthority::HnsLocal,
            ResourceAuthority::External {
                proof_profile: "test.proof/v1".to_owned(),
                proof_hash: [4; 32],
                proof_uris: vec!["https://example.test/proof".to_owned()],
            },
            ResourceAuthority::ParentDelegation {
                parent_subject: [5; 32],
                parent_resource_id: [6; 32],
                delegation_id: [7; 32],
            },
        ];
        for authority in authorities {
            assert_eq!(
                ResourceAuthority::from_value(authority.to_value().expect("encode authority"))
                    .expect("decode authority"),
                authority
            );
        }
    }

    #[test]
    fn external_proof_uris_are_absolute_and_canonical_ascii() {
        let valid = ResourceAuthority::External {
            proof_profile: "test.proof/v1".to_owned(),
            proof_hash: [4; 32],
            proof_uris: vec!["https://example.test/proof%20object".to_owned()],
        };
        assert!(valid.validate().is_ok());

        for uri in [
            "relative/path",
            ":missing-scheme",
            "1invalid:scheme",
            "https:",
            "https://example.test/bad%2",
            "https://example.test/white space",
            "https://example.test/é",
            "https://[",
            "https://exa[mple",
            "https://example.test/a#one#two",
        ] {
            let invalid = ResourceAuthority::External {
                proof_profile: "test.proof/v1".to_owned(),
                proof_hash: [4; 32],
                proof_uris: vec![uri.to_owned()],
            };
            assert!(invalid.validate().is_err(), "accepted invalid URI {uri:?}");
        }
    }

    #[test]
    fn malformed_or_trailing_cbor_is_rejected() {
        let private_key = [1; 32];
        let envelope = Envelope::sign(sample_payload(&private_key), MAGIC, &private_key)
            .expect("signed envelope");
        let mut encoded = envelope.encode().expect("encode");
        encoded.push(0);
        assert!(Envelope::decode(&encoded).is_err());
    }
}
