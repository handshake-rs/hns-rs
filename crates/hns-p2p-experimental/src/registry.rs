use core::fmt;
use std::collections::BTreeSet;

use hns_encoding::{DecodeError, Decoder, Encoder};
use hns_primitives::RegistryFingerprint;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::assignment::Network;

pub const SHAKESCAPE_V1_REGISTRY_NAME: &str = "Shakescape Experimental Handshake P2P Registry";
pub const SHAKESCAPE_V1_REGISTRY_VERSION: u16 = 1;
pub const SHAKESCAPE_V1_REGISTRY_PROTOCOL_VERSION: u16 = 1;
/// Semantic version assigned to HIP-76 by the canonical Shakescape V1 registry.
pub const HIP_76_PROTOCOL_VERSION: u16 = 1;
pub const SHAKESCAPE_V1_WIRE_PROFILE: &str = "shakescape-v1";
const SHAKESCAPE_V1_REGISTRY_FINGERPRINT_BYTES: [u8; 32] = [
    0x04, 0xfc, 0xe3, 0xf1, 0x2b, 0x71, 0x7c, 0x42, 0x54, 0xbb, 0x66, 0xac, 0x07, 0x47, 0x4a, 0x6c,
    0x9f, 0x61, 0xbd, 0x29, 0x16, 0xef, 0xc1, 0x8e, 0xbf, 0xc7, 0x9d, 0xf8, 0x2a, 0x89, 0xa6, 0x6b,
];
pub const SHAKESCAPE_V1_REGISTRY_ID: ExperimentalRegistryId =
    ExperimentalRegistryId::new(SHAKESCAPE_V1_REGISTRY_FINGERPRINT_BYTES);
pub const SHAKESCAPE_V1_REGISTRY_FINGERPRINT: RegistryFingerprint =
    RegistryFingerprint::new(SHAKESCAPE_V1_REGISTRY_FINGERPRINT_BYTES);

pub const HNSR_PROFILE_REGISTRY_NAME: &str =
    "Shakescape Experimental HNSR Service Profile Registry";
pub const HNSR_PROFILE_REGISTRY_VERSION: u16 = 1;
pub const HNSR_PROFILE_REGISTRY_PROTOCOL_VERSION: u16 = 1;
pub const HNSR_PROFILE_WIRE_PROFILE: &str = "hnsr-service-profiles-v1";
const HNSR_PROFILE_REGISTRY_FINGERPRINT_BYTES: [u8; 32] = [
    0x59, 0xf4, 0x7a, 0xfa, 0x6e, 0x53, 0x6a, 0xfe, 0x78, 0x4b, 0xa6, 0x58, 0x23, 0xeb, 0x1a, 0x02,
    0x8f, 0xa0, 0xac, 0xe7, 0x2d, 0x7e, 0x72, 0x18, 0x88, 0xb4, 0xbe, 0x58, 0x6a, 0x68, 0x7a, 0xd2,
];
pub const HNSR_PROFILE_REGISTRY_ID: ExperimentalRegistryId =
    ExperimentalRegistryId::new(HNSR_PROFILE_REGISTRY_FINGERPRINT_BYTES);
pub const HNSR_PROFILE_REGISTRY_FINGERPRINT: RegistryFingerprint =
    RegistryFingerprint::new(HNSR_PROFILE_REGISTRY_FINGERPRINT_BYTES);

const REGISTRY_MAGIC: [u8; 4] = *b"SKR1";
const CANONICAL_FORMAT_VERSION: u16 = 1;
const MAX_REGISTRY_TEXT: usize = 256 * 1024;
const MAX_REGISTRY_BINARY: usize = 512 * 1024;
const MAX_ASSIGNMENTS: usize = 256;
const MAX_FIELD_LENGTH: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegistryDocument {
    pub registry: RegistryMetadata,
    #[serde(rename = "assignment")]
    pub assignments: Vec<RegistryAssignment>,
}

impl RegistryDocument {
    pub fn from_toml(input: &str) -> Result<Self, RegistryError> {
        if input.len() > MAX_REGISTRY_TEXT {
            return Err(RegistryError::DocumentTooLarge {
                actual: input.len(),
                maximum: MAX_REGISTRY_TEXT,
            });
        }
        let document: Self = toml::from_str(input)?;
        document.validate()?;
        Ok(document)
    }

    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, RegistryError> {
        if input.len() > MAX_REGISTRY_BINARY {
            return Err(RegistryError::DocumentTooLarge {
                actual: input.len(),
                maximum: MAX_REGISTRY_BINARY,
            });
        }
        let mut decoder = Decoder::new(input);
        let magic = decoder.read_array::<4>()?;
        if magic != REGISTRY_MAGIC {
            return Err(RegistryError::WrongMagic(magic));
        }
        let format_version = decoder.read_u16_le()?;
        if format_version != CANONICAL_FORMAT_VERSION {
            return Err(RegistryError::UnknownCanonicalFormat(format_version));
        }
        let registry_version = decoder.read_u16_le()?;
        let protocol_version = decoder.read_u16_le()?;
        let status = AssignmentStatus::try_from(decoder.read_u8()?)?;
        let name = read_string(&mut decoder)?;
        let owner = read_string(&mut decoder)?;
        let wire_profile = read_string(&mut decoder)?;
        let assignment_count = decoder.read_u16_le()? as usize;
        if assignment_count == 0 || assignment_count > MAX_ASSIGNMENTS {
            return Err(RegistryError::AssignmentCount(assignment_count));
        }

        let mut assignments = Vec::with_capacity(assignment_count);
        for _ in 0..assignment_count {
            let kind = AssignmentKind::try_from(decoder.read_u8()?)?;
            let status = AssignmentStatus::try_from(decoder.read_u8()?)?;
            let value = decoder.read_u64_le()?;
            let range_end = match decoder.read_u8()? {
                0 => None,
                1 => Some(decoder.read_u64_le()?),
                value => {
                    return Err(RegistryError::InvalidBoolean {
                        field: "range_end",
                        value,
                    });
                }
            };
            let entry_registry_version = decoder.read_u16_le()?;
            let entry_protocol_version = decoder.read_u16_le()?;
            let maximum_payload = decoder.read_u32_le()?;
            let semantic_name = read_string(&mut decoder)?;
            let entry_owner = read_string(&mut decoder)?;
            let source_proposal_url = read_string(&mut decoder)?;
            let source_implementation_url = read_string(&mut decoder)?;
            let security_classification = read_string(&mut decoder)?;
            let first_supported_release = read_string(&mut decoder)?;
            let deprecation_state = read_string(&mut decoder)?;
            let replacement_assignment = read_optional_string(&mut decoder)?;
            let network_count = decoder.read_u8()? as usize;
            if network_count == 0 || network_count > 4 {
                return Err(RegistryError::NetworkCount(network_count));
            }
            let mut network_applicability = Vec::with_capacity(network_count);
            for _ in 0..network_count {
                let byte = decoder.read_u8()?;
                let network =
                    Network::try_from(byte).map_err(|_| RegistryError::UnknownNetwork(byte))?;
                network_applicability.push(network);
            }
            assignments.push(RegistryAssignment {
                semantic_name,
                kind,
                value,
                range_end,
                registry_version: entry_registry_version,
                protocol_version: entry_protocol_version,
                status,
                owner: entry_owner,
                source_proposal_url,
                source_implementation_url,
                network_applicability,
                maximum_payload,
                security_classification,
                first_supported_release,
                deprecation_state,
                replacement_assignment,
            });
        }
        decoder.finish()?;

        let document = Self {
            registry: RegistryMetadata {
                name,
                version: registry_version,
                protocol_version,
                status,
                owner,
                wire_profile,
            },
            assignments,
        };
        document.validate()?;
        if document.canonical_bytes()? != input {
            return Err(RegistryError::NonCanonicalBinary);
        }
        Ok(document)
    }

    pub fn validate(&self) -> Result<(), RegistryError> {
        self.registry.validate()?;
        if self.assignments.is_empty() || self.assignments.len() > MAX_ASSIGNMENTS {
            return Err(RegistryError::AssignmentCount(self.assignments.len()));
        }
        for assignment in &self.assignments {
            assignment.validate(&self.registry)?;
        }
        for (index, left) in self.assignments.iter().enumerate() {
            for right in self.assignments.iter().skip(index + 1) {
                if left.kind == right.kind && left.value <= right.end() && right.value <= left.end()
                {
                    return Err(RegistryError::AssignmentCollision {
                        first: left.semantic_name.clone(),
                        second: right.semantic_name.clone(),
                    });
                }
                if left.semantic_name == right.semantic_name {
                    return Err(RegistryError::DuplicateSemanticName(
                        left.semantic_name.clone(),
                    ));
                }
            }
        }
        if self.registry.name == HNSR_PROFILE_REGISTRY_NAME {
            self.require_assignment(
                "hnsr-profile-hns-node-v1",
                AssignmentKind::ServiceProfile,
                1,
            )?;
            self.require_assignment("hnsr-profile-hns-web-v1", AssignmentKind::ServiceProfile, 2)?;
            self.require_assignment(
                "hnsr-profile-hns-chat-v1",
                AssignmentKind::ServiceProfile,
                3,
            )?;
            self.require_assignment(
                "hnsr-profile-shakescape-swap-v1",
                AssignmentKind::ServiceProfile,
                4,
            )?;
            self.require_assignment_range(
                "reserved-hnsr-profiles-0x0005-0xffff",
                AssignmentKind::ServiceProfile,
                5,
                u16::MAX as u64,
            )?;
            if self
                .assignments
                .iter()
                .any(|assignment| assignment.kind != AssignmentKind::ServiceProfile)
            {
                return Err(RegistryError::InvalidProfileRegistryAssignment);
            }
            return Ok(());
        }
        self.require_assignment(
            "hnsr-rendezvous-service",
            AssignmentKind::ServiceBit,
            0x0400_0000,
        )?;
        self.require_assignment(
            "hnsr-relay-service",
            AssignmentKind::ServiceBit,
            0x0800_0000,
        )?;
        self.require_assignment(
            "shakescape-extension-service",
            AssignmentKind::ServiceBit,
            0x1000_0000,
        )?;
        self.require_assignment("p2p-odoh-service", AssignmentKind::ServiceBit, 0x2000_0000)?;
        self.require_assignment(
            "p2p-dns-relay-service",
            AssignmentKind::ServiceBit,
            0x4000_0000,
        )?;
        self.require_assignment("getdnsrelay", AssignmentKind::PacketType, 0xf0)?;
        self.require_assignment("dnsrelay", AssignmentKind::PacketType, 0xf1)?;
        self.require_assignment("odns", AssignmentKind::PacketType, 0xf2)?;
        self.require_assignment("hnsr", AssignmentKind::PacketType, 0xf3)?;
        self.require_assignment("shakescape-ext", AssignmentKind::PacketType, 0xf4)?;
        self.require_assignment("registry-negotiation", AssignmentKind::ProtocolId, 0)?;
        self.require_assignment("atomic-name-marketplace", AssignmentKind::ProtocolId, 1)?;
        self.require_assignment("cross-chain-marketplace", AssignmentKind::ProtocolId, 2)?;
        self.require_assignment_range(
            "reserved-protocols-0x0003-0xffff",
            AssignmentKind::ProtocolId,
            3,
            u16::MAX as u64,
        )?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RegistryError> {
        self.validate()?;
        let mut assignments = self.assignments.clone();
        assignments.sort_by(|left, right| {
            (
                left.kind,
                left.value,
                left.end(),
                left.semantic_name.as_str(),
            )
                .cmp(&(
                    right.kind,
                    right.value,
                    right.end(),
                    right.semantic_name.as_str(),
                ))
        });

        let mut encoder = Encoder::with_capacity(4096);
        encoder.put_bytes(&REGISTRY_MAGIC);
        encoder.put_u16_le(CANONICAL_FORMAT_VERSION);
        encoder.put_u16_le(self.registry.version);
        encoder.put_u16_le(self.registry.protocol_version);
        encoder.put_u8(self.registry.status as u8);
        put_string(&mut encoder, &self.registry.name)?;
        put_string(&mut encoder, &self.registry.owner)?;
        put_string(&mut encoder, &self.registry.wire_profile)?;
        encoder.put_u16_le(
            u16::try_from(assignments.len())
                .map_err(|_| RegistryError::AssignmentCount(assignments.len()))?,
        );
        for assignment in assignments {
            encoder.put_u8(assignment.kind as u8);
            encoder.put_u8(assignment.status as u8);
            encoder.put_u64_le(assignment.value);
            if let Some(range_end) = assignment.range_end {
                encoder.put_u8(1);
                encoder.put_u64_le(range_end);
            } else {
                encoder.put_u8(0);
            }
            encoder.put_u16_le(assignment.registry_version);
            encoder.put_u16_le(assignment.protocol_version);
            encoder.put_u32_le(assignment.maximum_payload);
            put_string(&mut encoder, &assignment.semantic_name)?;
            put_string(&mut encoder, &assignment.owner)?;
            put_string(&mut encoder, &assignment.source_proposal_url)?;
            put_string(&mut encoder, &assignment.source_implementation_url)?;
            put_string(&mut encoder, &assignment.security_classification)?;
            put_string(&mut encoder, &assignment.first_supported_release)?;
            put_string(&mut encoder, &assignment.deprecation_state)?;
            put_optional_string(&mut encoder, assignment.replacement_assignment.as_deref())?;

            let mut networks = assignment.network_applicability;
            networks.sort_unstable();
            networks.dedup();
            encoder.put_u8(
                u8::try_from(networks.len())
                    .map_err(|_| RegistryError::NetworkCount(networks.len()))?,
            );
            for network in networks {
                encoder.put_u8(network as u8);
            }
        }
        Ok(encoder.into_bytes())
    }

    pub fn id(&self) -> Result<ExperimentalRegistryId, RegistryError> {
        let digest = Sha256::digest(self.canonical_bytes()?);
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Ok(ExperimentalRegistryId(bytes))
    }

    fn require_assignment(
        &self,
        semantic_name: &'static str,
        kind: AssignmentKind,
        value: u64,
    ) -> Result<(), RegistryError> {
        if self.assignments.iter().any(|assignment| {
            assignment.semantic_name == semantic_name
                && assignment.kind == kind
                && assignment.value == value
                && assignment.range_end.is_none()
        }) {
            Ok(())
        } else {
            Err(RegistryError::MissingRequiredAssignment {
                semantic_name,
                kind,
                value,
            })
        }
    }

    fn require_assignment_range(
        &self,
        semantic_name: &'static str,
        kind: AssignmentKind,
        value: u64,
        range_end: u64,
    ) -> Result<(), RegistryError> {
        if self.assignments.iter().any(|assignment| {
            assignment.semantic_name == semantic_name
                && assignment.kind == kind
                && assignment.value == value
                && assignment.range_end == Some(range_end)
                && assignment.status == AssignmentStatus::Reserved
        }) {
            Ok(())
        } else {
            Err(RegistryError::MissingRequiredAssignmentRange {
                semantic_name,
                kind,
                value,
                range_end,
            })
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegistryMetadata {
    pub name: String,
    pub version: u16,
    pub protocol_version: u16,
    pub status: AssignmentStatus,
    pub owner: String,
    pub wire_profile: String,
}

impl RegistryMetadata {
    fn validate(&self) -> Result<(), RegistryError> {
        validate_field("registry.name", &self.name)?;
        validate_field("registry.owner", &self.owner)?;
        validate_field("registry.wire_profile", &self.wire_profile)?;
        let expected_wire_profile = match (self.name.as_str(), self.version, self.protocol_version)
        {
            (
                SHAKESCAPE_V1_REGISTRY_NAME,
                SHAKESCAPE_V1_REGISTRY_VERSION,
                SHAKESCAPE_V1_REGISTRY_PROTOCOL_VERSION,
            ) => SHAKESCAPE_V1_WIRE_PROFILE,
            (
                HNSR_PROFILE_REGISTRY_NAME,
                HNSR_PROFILE_REGISTRY_VERSION,
                HNSR_PROFILE_REGISTRY_PROTOCOL_VERSION,
            ) => HNSR_PROFILE_WIRE_PROFILE,
            _ => {
                return Err(RegistryError::UnsupportedRegistryVersion {
                    registry: self.version,
                    protocol: self.protocol_version,
                });
            }
        };
        if self.status != AssignmentStatus::StableExperimental {
            return Err(RegistryError::InvalidRegistryStatus(self.status));
        }
        if self.wire_profile != expected_wire_profile {
            return Err(RegistryError::InvalidWireProfile(self.wire_profile.clone()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegistryAssignment {
    pub semantic_name: String,
    pub kind: AssignmentKind,
    pub value: u64,
    pub range_end: Option<u64>,
    pub registry_version: u16,
    pub protocol_version: u16,
    pub status: AssignmentStatus,
    pub owner: String,
    pub source_proposal_url: String,
    pub source_implementation_url: String,
    pub network_applicability: Vec<Network>,
    pub maximum_payload: u32,
    pub security_classification: String,
    pub first_supported_release: String,
    pub deprecation_state: String,
    pub replacement_assignment: Option<String>,
}

impl RegistryAssignment {
    pub const fn end(&self) -> u64 {
        match self.range_end {
            Some(end) => end,
            None => self.value,
        }
    }

    fn validate(&self, metadata: &RegistryMetadata) -> Result<(), RegistryError> {
        validate_field("semantic_name", &self.semantic_name)?;
        validate_field("owner", &self.owner)?;
        validate_field("source_proposal_url", &self.source_proposal_url)?;
        validate_field("source_implementation_url", &self.source_implementation_url)?;
        validate_field("security_classification", &self.security_classification)?;
        validate_field("first_supported_release", &self.first_supported_release)?;
        validate_field("deprecation_state", &self.deprecation_state)?;
        if let Some(replacement) = &self.replacement_assignment {
            validate_field("replacement_assignment", replacement)?;
        }
        if self.registry_version != metadata.version
            || self.protocol_version != metadata.protocol_version
        {
            return Err(RegistryError::EntryVersionMismatch(
                self.semantic_name.clone(),
            ));
        }
        if self.end() < self.value {
            return Err(RegistryError::ReversedRange(self.semantic_name.clone()));
        }
        let maximum = match self.kind {
            AssignmentKind::ServiceBit => u64::MAX,
            AssignmentKind::PacketType => u8::MAX as u64,
            AssignmentKind::ProtocolId | AssignmentKind::ServiceProfile => u16::MAX as u64,
        };
        if self.end() > maximum {
            return Err(RegistryError::ValueOutsideKind {
                semantic_name: self.semantic_name.clone(),
                value: self.end(),
                kind: self.kind,
            });
        }
        if self.kind == AssignmentKind::ServiceBit
            && (self.range_end.is_some() || self.value.count_ones() != 1)
        {
            return Err(RegistryError::InvalidServiceBit {
                semantic_name: self.semantic_name.clone(),
                value: self.value,
            });
        }
        if self.range_end.is_some() && self.status != AssignmentStatus::Reserved {
            return Err(RegistryError::NonReservedRange(self.semantic_name.clone()));
        }
        if self.network_applicability.is_empty() || self.network_applicability.len() > 4 {
            return Err(RegistryError::NetworkCount(
                self.network_applicability.len(),
            ));
        }
        let unique_networks: BTreeSet<_> = self.network_applicability.iter().copied().collect();
        if unique_networks.len() != self.network_applicability.len() {
            return Err(RegistryError::DuplicateNetwork(self.semantic_name.clone()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentKind {
    ServiceBit = 1,
    PacketType = 2,
    ProtocolId = 3,
    ServiceProfile = 4,
}

impl TryFrom<u8> for AssignmentKind {
    type Error = RegistryError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ServiceBit),
            2 => Ok(Self::PacketType),
            3 => Ok(Self::ProtocolId),
            4 => Ok(Self::ServiceProfile),
            _ => Err(RegistryError::UnknownAssignmentKind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[repr(u8)]
#[serde(rename_all = "kebab-case")]
pub enum AssignmentStatus {
    Experimental = 1,
    StableExperimental = 2,
    Deprecated = 3,
    OfficialAlias = 4,
    Retired = 5,
    Reserved = 6,
}

impl TryFrom<u8> for AssignmentStatus {
    type Error = RegistryError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Experimental),
            2 => Ok(Self::StableExperimental),
            3 => Ok(Self::Deprecated),
            4 => Ok(Self::OfficialAlias),
            5 => Ok(Self::Retired),
            6 => Ok(Self::Reserved),
            _ => Err(RegistryError::UnknownAssignmentStatus(value)),
        }
    }
}

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExperimentalRegistryId([u8; 32]);

impl ExperimentalRegistryId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for ExperimentalRegistryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ExperimentalRegistryId({self})")
    }
}

impl fmt::Display for ExperimentalRegistryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.0))
    }
}

impl From<ExperimentalRegistryId> for RegistryFingerprint {
    fn from(value: ExperimentalRegistryId) -> Self {
        Self::new(value.0)
    }
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("registry document is {actual} bytes; maximum is {maximum}")]
    DocumentTooLarge { actual: usize, maximum: usize },
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("wrong canonical registry magic {0:?}")]
    WrongMagic([u8; 4]),
    #[error("unsupported canonical registry format {0}")]
    UnknownCanonicalFormat(u16),
    #[error("unsupported registry version {registry} or protocol version {protocol}")]
    UnsupportedRegistryVersion { registry: u16, protocol: u16 },
    #[error("registry status must be stable-experimental, got {0:?}")]
    InvalidRegistryStatus(AssignmentStatus),
    #[error("wire profile does not match the registry version: {0}")]
    InvalidWireProfile(String),
    #[error("assignment count {0} is outside 1..=256")]
    AssignmentCount(usize),
    #[error("network count {0} is outside 1..=4")]
    NetworkCount(usize),
    #[error("unknown network identifier {0}")]
    UnknownNetwork(u8),
    #[error("unknown assignment kind {0}")]
    UnknownAssignmentKind(u8),
    #[error("unknown assignment status {0}")]
    UnknownAssignmentStatus(u8),
    #[error("invalid Boolean byte {value} for {field}")]
    InvalidBoolean { field: &'static str, value: u8 },
    #[error("field {0} is empty or exceeds the canonical bound")]
    InvalidField(&'static str),
    #[error("field is not valid UTF-8")]
    InvalidUtf8,
    #[error("assignment {0} does not use the registry's versions")]
    EntryVersionMismatch(String),
    #[error("assignment {0} has a reversed range")]
    ReversedRange(String),
    #[error("assignment {semantic_name} value {value:#x} is outside {kind:?}")]
    ValueOutsideKind {
        semantic_name: String,
        value: u64,
        kind: AssignmentKind,
    },
    #[error("assignment {semantic_name} value {value:#x} is not one service bit")]
    InvalidServiceBit { semantic_name: String, value: u64 },
    #[error("assignment range {0} is not reserved")]
    NonReservedRange(String),
    #[error("assignment {0} repeats a network")]
    DuplicateNetwork(String),
    #[error("assignments {first} and {second} collide")]
    AssignmentCollision { first: String, second: String },
    #[error("semantic assignment name {0} is duplicated")]
    DuplicateSemanticName(String),
    #[error("HNSR service-profile registry contains a non-profile assignment")]
    InvalidProfileRegistryAssignment,
    #[error("missing required {kind:?} assignment {semantic_name}={value:#x}")]
    MissingRequiredAssignment {
        semantic_name: &'static str,
        kind: AssignmentKind,
        value: u64,
    },
    #[error(
        "missing required {kind:?} assignment range {semantic_name}={value:#x}..={range_end:#x}"
    )]
    MissingRequiredAssignmentRange {
        semantic_name: &'static str,
        kind: AssignmentKind,
        value: u64,
        range_end: u64,
    },
    #[error("binary registry is valid but not in canonical order or form")]
    NonCanonicalBinary,
}

fn validate_field(field: &'static str, value: &str) -> Result<(), RegistryError> {
    if value.is_empty() || value.len() > MAX_FIELD_LENGTH {
        Err(RegistryError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn put_string(encoder: &mut Encoder, value: &str) -> Result<(), RegistryError> {
    validate_field("canonical string", value)?;
    let length =
        u16::try_from(value.len()).map_err(|_| RegistryError::InvalidField("canonical string"))?;
    encoder.put_u16_le(length);
    encoder.put_bytes(value.as_bytes());
    Ok(())
}

fn put_optional_string(encoder: &mut Encoder, value: Option<&str>) -> Result<(), RegistryError> {
    if let Some(value) = value {
        encoder.put_u8(1);
        put_string(encoder, value)?;
    } else {
        encoder.put_u8(0);
    }
    Ok(())
}

fn read_string(decoder: &mut Decoder<'_>) -> Result<String, RegistryError> {
    let length = decoder.read_u16_le()? as usize;
    if length == 0 || length > MAX_FIELD_LENGTH {
        return Err(RegistryError::InvalidField("canonical string"));
    }
    let bytes = decoder.read_bounded_vec(length, MAX_FIELD_LENGTH)?;
    String::from_utf8(bytes).map_err(|_| RegistryError::InvalidUtf8)
}

fn read_optional_string(decoder: &mut Decoder<'_>) -> Result<Option<String>, RegistryError> {
    match decoder.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(read_string(decoder)?)),
        value => Err(RegistryError::InvalidBoolean {
            field: "optional_string",
            value,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::SHAKESCAPE_EXTENSION_MAX_PACKET_PAYLOAD;
    use crate::negotiation::REGISTRY_NEGOTIATION_MAX_PAYLOAD;
    use hns_dns_relay_protocol::{
        MAX_DNS_RELAY_QUERY_BODY_SIZE, MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE,
        MAX_DNS_RELAY_RESPONSE_BODY_SIZE, MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE,
    };

    const REGISTRY_TOML: &str = include_str!("../registry/shakescape-experimental-v1.toml");
    const REGISTRY_BINARY: &[u8] = include_bytes!("../registry/shakescape-experimental-v1.bin");
    const REGISTRY_SHA256: &str = include_str!("../registry/shakescape-experimental-v1.sha256");
    const HNSR_PROFILE_TOML: &str = include_str!("../registry/hnsr-service-profiles-v1.toml");
    const HNSR_PROFILE_BINARY: &[u8] = include_bytes!("../registry/hnsr-service-profiles-v1.bin");
    const HNSR_PROFILE_SHA256: &str = include_str!("../registry/hnsr-service-profiles-v1.sha256");

    #[test]
    fn canonical_registry_artifacts_and_exports_have_one_stable_identity() {
        let registry = RegistryDocument::from_toml(REGISTRY_TOML).expect("valid registry");
        let binary = registry.canonical_bytes().expect("encodes");
        assert_eq!(binary, REGISTRY_BINARY);

        let decoded = RegistryDocument::from_canonical_bytes(REGISTRY_BINARY).expect("decodes");
        assert_eq!(decoded, registry);
        assert_eq!(
            registry.id().expect("hashes"),
            decoded.id().expect("hashes")
        );
        assert_eq!(
            registry.id().expect("hashes").to_string(),
            "04fce3f12b717c4254bb66ac07474a6c9f61bd2916efc18ebfc79df82a89a66b"
        );
        assert_eq!(registry.id().expect("hashes"), SHAKESCAPE_V1_REGISTRY_ID);
        assert_eq!(
            RegistryFingerprint::from(registry.id().expect("hashes")),
            SHAKESCAPE_V1_REGISTRY_FINGERPRINT
        );
        assert_eq!(registry.registry.name, SHAKESCAPE_V1_REGISTRY_NAME);
        assert_eq!(registry.registry.version, SHAKESCAPE_V1_REGISTRY_VERSION);
        assert_eq!(
            registry.registry.protocol_version,
            SHAKESCAPE_V1_REGISTRY_PROTOCOL_VERSION
        );
        assert_eq!(registry.registry.wire_profile, SHAKESCAPE_V1_WIRE_PROFILE);
        assert_eq!(
            REGISTRY_SHA256,
            format!("{SHAKESCAPE_V1_REGISTRY_ID}  shakescape-experimental-v1.bin\n")
        );
        let maximum_payload = |semantic_name: &str| {
            registry
                .assignments
                .iter()
                .find(|assignment| assignment.semantic_name == semantic_name)
                .map(|assignment| assignment.maximum_payload as usize)
                .expect("canonical assignment")
        };
        assert_eq!(
            maximum_payload("shakescape-ext"),
            SHAKESCAPE_EXTENSION_MAX_PACKET_PAYLOAD
        );
        assert_eq!(
            maximum_payload("registry-negotiation"),
            REGISTRY_NEGOTIATION_MAX_PAYLOAD
        );
        assert_eq!(
            maximum_payload("getdnsrelay"),
            MAX_DNS_RELAY_QUERY_BODY_SIZE
        );
        assert_eq!(
            maximum_payload("dnsrelay"),
            MAX_DNS_RELAY_RESPONSE_BODY_SIZE
        );
        assert_eq!(MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE, 4_106);
        assert_eq!(MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE, 65_546);
        for semantic_name in ["getdnsrelay", "dnsrelay"] {
            let assignment = registry
                .assignments
                .iter()
                .find(|assignment| assignment.semantic_name == semantic_name)
                .expect("canonical HIP-76 assignment");
            assert_eq!(assignment.protocol_version, HIP_76_PROTOCOL_VERSION);
        }
        let cross_chain = registry
            .assignments
            .iter()
            .find(|assignment| assignment.semantic_name == "cross-chain-marketplace")
            .expect("cross-chain assignment");
        assert_eq!(cross_chain.kind, AssignmentKind::ProtocolId);
        assert_eq!(cross_chain.value, 2);
        assert_eq!(cross_chain.range_end, None);
        assert_eq!(
            cross_chain.maximum_payload,
            crate::envelope::CROSS_CHAIN_MARKET_MAX_PAYLOAD as u32
        );
        assert_eq!(cross_chain.first_supported_release, "0.1.0");
        let reserved = registry
            .assignments
            .iter()
            .find(|assignment| assignment.semantic_name == "reserved-protocols-0x0003-0xffff")
            .expect("reserved protocol range");
        assert_eq!(
            (reserved.value, reserved.range_end),
            (3, Some(u16::MAX as u64))
        );
    }

    #[test]
    fn ordering_in_toml_does_not_affect_fingerprint() {
        let registry = RegistryDocument::from_toml(REGISTRY_TOML).expect("valid registry");
        let mut reordered = registry.clone();
        reordered.assignments.reverse();
        assert_eq!(
            registry.id().expect("hashes"),
            reordered.id().expect("hashes")
        );
    }

    #[test]
    fn canonical_hnsr_profile_registry_assigns_chat_without_changing_shakescape_identity() {
        let registry =
            RegistryDocument::from_toml(HNSR_PROFILE_TOML).expect("valid profile registry");
        assert_eq!(
            registry.canonical_bytes().expect("encodes"),
            HNSR_PROFILE_BINARY
        );
        assert_eq!(
            RegistryDocument::from_canonical_bytes(HNSR_PROFILE_BINARY).expect("decodes"),
            registry
        );
        assert_eq!(registry.id().expect("hashes"), HNSR_PROFILE_REGISTRY_ID);
        assert_eq!(
            RegistryFingerprint::from(registry.id().expect("hashes")),
            HNSR_PROFILE_REGISTRY_FINGERPRINT
        );
        assert_eq!(registry.registry.name, HNSR_PROFILE_REGISTRY_NAME);
        assert_eq!(registry.registry.version, HNSR_PROFILE_REGISTRY_VERSION);
        assert_eq!(
            registry.registry.protocol_version,
            HNSR_PROFILE_REGISTRY_PROTOCOL_VERSION
        );
        assert_eq!(registry.registry.wire_profile, HNSR_PROFILE_WIRE_PROFILE);
        assert_eq!(
            HNSR_PROFILE_SHA256,
            format!("{HNSR_PROFILE_REGISTRY_ID}  hnsr-service-profiles-v1.bin\n")
        );
        let chat = registry
            .assignments
            .iter()
            .find(|assignment| assignment.semantic_name == "hnsr-profile-hns-chat-v1")
            .expect("chat profile");
        assert_eq!(chat.kind, AssignmentKind::ServiceProfile);
        assert_eq!(chat.value, 3);
        assert_eq!(chat.maximum_payload, 8_192);
        let swap = registry
            .assignments
            .iter()
            .find(|assignment| assignment.semantic_name == "hnsr-profile-shakescape-swap-v1")
            .expect("Shakescape swap profile");
        assert_eq!(swap.kind, AssignmentKind::ServiceProfile);
        assert_eq!(swap.value, 4);
        assert_eq!(swap.maximum_payload, 16_384);
        assert_eq!(
            SHAKESCAPE_V1_REGISTRY_ID.to_string(),
            "04fce3f12b717c4254bb66ac07474a6c9f61bd2916efc18ebfc79df82a89a66b"
        );
    }

    #[test]
    fn collisions_and_wrong_versions_are_rejected() {
        let registry = RegistryDocument::from_toml(REGISTRY_TOML).expect("valid registry");
        let mut collision = registry.clone();
        collision.assignments[1].value = collision.assignments[0].value;
        assert!(matches!(
            collision.validate(),
            Err(RegistryError::AssignmentCollision { .. })
                | Err(RegistryError::MissingRequiredAssignment { .. })
        ));

        let mut wrong_version = registry;
        wrong_version.registry.version = 3;
        assert!(matches!(
            wrong_version.validate(),
            Err(RegistryError::UnsupportedRegistryVersion { .. })
        ));
    }
}
