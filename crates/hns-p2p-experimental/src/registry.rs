use core::fmt;
use std::collections::BTreeSet;

use hns_encoding::{DecodeError, Decoder, Encoder};
use hns_primitives::RegistryFingerprint;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::assignment::Network;

pub const DENUO_V1_REGISTRY_NAME: &str = "Denuo Experimental Handshake P2P Registry";
pub const DENUO_V1_REGISTRY_VERSION: u16 = 1;
pub const DENUO_V1_REGISTRY_PROTOCOL_VERSION: u16 = 1;
/// Semantic version assigned to HIP-76 by the canonical Denuo V1 registry.
pub const HIP_76_PROTOCOL_VERSION: u16 = 1;
pub const DENUO_V1_WIRE_PROFILE: &str = "denuo-v1";
const DENUO_V1_REGISTRY_FINGERPRINT_BYTES: [u8; 32] = [
    0x95, 0x77, 0x4d, 0xb0, 0x8c, 0x56, 0x9b, 0x36, 0xfa, 0x7b, 0x7e, 0x4a, 0x07, 0x19, 0x30, 0xf5,
    0x63, 0xb7, 0x25, 0x1f, 0xc3, 0x09, 0x34, 0xba, 0x98, 0x67, 0x32, 0x37, 0x9a, 0x6e, 0x54, 0x2d,
];
pub const DENUO_V1_REGISTRY_ID: ExperimentalRegistryId =
    ExperimentalRegistryId::new(DENUO_V1_REGISTRY_FINGERPRINT_BYTES);
pub const DENUO_V1_REGISTRY_FINGERPRINT: RegistryFingerprint =
    RegistryFingerprint::new(DENUO_V1_REGISTRY_FINGERPRINT_BYTES);

pub const DENUO_V2_REGISTRY_NAME: &str = "Denuo Experimental Handshake P2P Registry";
pub const DENUO_V2_REGISTRY_VERSION: u16 = 2;
pub const DENUO_V2_REGISTRY_PROTOCOL_VERSION: u16 = 1;
pub const DENUO_V2_WIRE_PROFILE: &str = "denuo-v2";
const DENUO_V2_REGISTRY_FINGERPRINT_BYTES: [u8; 32] = [
    0x73, 0x42, 0x26, 0xe8, 0x66, 0x43, 0x58, 0x21, 0xe4, 0x0b, 0xe7, 0xbd, 0xe8, 0x5f, 0xb1, 0x9d,
    0xd6, 0xeb, 0x86, 0x7c, 0x56, 0x20, 0xab, 0xb8, 0x34, 0x7a, 0xc8, 0xcd, 0x23, 0xda, 0x4f, 0x2c,
];
pub const DENUO_V2_REGISTRY_ID: ExperimentalRegistryId =
    ExperimentalRegistryId::new(DENUO_V2_REGISTRY_FINGERPRINT_BYTES);
pub const DENUO_V2_REGISTRY_FINGERPRINT: RegistryFingerprint =
    RegistryFingerprint::new(DENUO_V2_REGISTRY_FINGERPRINT_BYTES);

const REGISTRY_MAGIC: [u8; 4] = *b"DNR1";
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
            "denuo-extension-service",
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
        self.require_assignment("denuo-ext", AssignmentKind::PacketType, 0xf4)?;
        self.require_assignment("registry-negotiation", AssignmentKind::ProtocolId, 0)?;
        self.require_assignment("atomic-name-marketplace", AssignmentKind::ProtocolId, 1)?;
        match self.registry.version {
            DENUO_V1_REGISTRY_VERSION => self.require_assignment_range(
                "reserved-protocols-0x0002-0xffff",
                AssignmentKind::ProtocolId,
                2,
                u16::MAX as u64,
            )?,
            DENUO_V2_REGISTRY_VERSION => {
                self.require_assignment("cross-chain-marketplace", AssignmentKind::ProtocolId, 2)?;
                self.require_assignment_range(
                    "reserved-protocols-0x0003-0xffff",
                    AssignmentKind::ProtocolId,
                    3,
                    u16::MAX as u64,
                )?;
            }
            _ => unreachable!("registry metadata validation rejects unsupported versions"),
        }
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
        let expected_wire_profile = match (self.version, self.protocol_version) {
            (DENUO_V1_REGISTRY_VERSION, DENUO_V1_REGISTRY_PROTOCOL_VERSION) => {
                DENUO_V1_WIRE_PROFILE
            }
            (DENUO_V2_REGISTRY_VERSION, DENUO_V2_REGISTRY_PROTOCOL_VERSION) => {
                DENUO_V2_WIRE_PROFILE
            }
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
            AssignmentKind::ProtocolId => u16::MAX as u64,
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
}

impl TryFrom<u8> for AssignmentKind {
    type Error = RegistryError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ServiceBit),
            2 => Ok(Self::PacketType),
            3 => Ok(Self::ProtocolId),
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
    use crate::envelope::DENUO_EXTENSION_MAX_PACKET_PAYLOAD;
    use crate::negotiation::REGISTRY_NEGOTIATION_MAX_PAYLOAD;
    use hns_dns_relay_protocol::{
        MAX_DNS_RELAY_QUERY_BODY_SIZE, MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE,
        MAX_DNS_RELAY_RESPONSE_BODY_SIZE, MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE,
    };

    const REGISTRY_TOML: &str = include_str!("../registry/denuo-experimental-v1.toml");
    const REGISTRY_BINARY: &[u8] = include_bytes!("../registry/denuo-experimental-v1.bin");
    const REGISTRY_SHA256: &str = include_str!("../registry/denuo-experimental-v1.sha256");
    const REGISTRY_V2_TOML: &str = include_str!("../registry/denuo-experimental-v2.toml");
    const REGISTRY_V2_BINARY: &[u8] = include_bytes!("../registry/denuo-experimental-v2.bin");
    const REGISTRY_V2_SHA256: &str = include_str!("../registry/denuo-experimental-v2.sha256");

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
            "95774db08c569b36fa7b7e4a071930f563b7251fc30934ba986732379a6e542d"
        );
        assert_eq!(registry.id().expect("hashes"), DENUO_V1_REGISTRY_ID);
        assert_eq!(
            RegistryFingerprint::from(registry.id().expect("hashes")),
            DENUO_V1_REGISTRY_FINGERPRINT
        );
        assert_eq!(registry.registry.name, DENUO_V1_REGISTRY_NAME);
        assert_eq!(registry.registry.version, DENUO_V1_REGISTRY_VERSION);
        assert_eq!(
            registry.registry.protocol_version,
            DENUO_V1_REGISTRY_PROTOCOL_VERSION
        );
        assert_eq!(registry.registry.wire_profile, DENUO_V1_WIRE_PROFILE);
        assert_eq!(
            REGISTRY_SHA256,
            format!("{DENUO_V1_REGISTRY_ID}  denuo-experimental-v1.bin\n")
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
            maximum_payload("denuo-ext"),
            DENUO_EXTENSION_MAX_PACKET_PAYLOAD
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
    fn canonical_v2_artifacts_extend_v1_without_reassigning_it() {
        let v1 = RegistryDocument::from_toml(REGISTRY_TOML).expect("valid V1 registry");
        let v2 = RegistryDocument::from_toml(REGISTRY_V2_TOML).expect("valid V2 registry");
        assert_eq!(v2.canonical_bytes().expect("encodes"), REGISTRY_V2_BINARY);
        assert_eq!(
            RegistryDocument::from_canonical_bytes(REGISTRY_V2_BINARY).expect("decodes"),
            v2
        );
        assert_eq!(
            v2.id().expect("hashes").to_string(),
            "734226e866435821e40be7bde85fb19dd6eb867c5620abb8347ac8cd23da4f2c"
        );
        assert_eq!(v2.id().expect("hashes"), DENUO_V2_REGISTRY_ID);
        assert_eq!(
            RegistryFingerprint::from(v2.id().expect("hashes")),
            DENUO_V2_REGISTRY_FINGERPRINT
        );
        assert_eq!(v2.registry.name, DENUO_V2_REGISTRY_NAME);
        assert_eq!(v2.registry.version, DENUO_V2_REGISTRY_VERSION);
        assert_eq!(
            v2.registry.protocol_version,
            DENUO_V2_REGISTRY_PROTOCOL_VERSION
        );
        assert_eq!(v2.registry.wire_profile, DENUO_V2_WIRE_PROFILE);
        assert_eq!(
            REGISTRY_V2_SHA256,
            format!("{DENUO_V2_REGISTRY_ID}  denuo-experimental-v2.bin\n")
        );

        for old in v1
            .assignments
            .iter()
            .filter(|assignment| assignment.semantic_name != "reserved-protocols-0x0002-0xffff")
        {
            let retained = v2
                .assignments
                .iter()
                .find(|assignment| assignment.semantic_name == old.semantic_name)
                .expect("V1 assignment retained in V2");
            assert_eq!(retained.kind, old.kind);
            assert_eq!(retained.value, old.value);
            assert_eq!(retained.range_end, old.range_end);
            assert_eq!(retained.protocol_version, old.protocol_version);
            assert_eq!(retained.status, old.status);
            assert_eq!(retained.owner, old.owner);
            assert_eq!(retained.source_proposal_url, old.source_proposal_url);
            assert_eq!(
                retained.source_implementation_url,
                old.source_implementation_url
            );
            assert_eq!(retained.network_applicability, old.network_applicability);
            assert_eq!(retained.maximum_payload, old.maximum_payload);
            assert_eq!(
                retained.security_classification,
                old.security_classification
            );
            assert_eq!(
                retained.first_supported_release,
                old.first_supported_release
            );
            assert_eq!(retained.deprecation_state, old.deprecation_state);
            assert_eq!(retained.replacement_assignment, old.replacement_assignment);
            assert_eq!(retained.registry_version, DENUO_V2_REGISTRY_VERSION);
        }

        let cross_chain = v2
            .assignments
            .iter()
            .find(|assignment| assignment.semantic_name == "cross-chain-marketplace")
            .expect("V2 cross-chain assignment");
        assert_eq!(cross_chain.kind, AssignmentKind::ProtocolId);
        assert_eq!(cross_chain.value, 2);
        assert_eq!(cross_chain.range_end, None);
        assert_eq!(
            cross_chain.maximum_payload,
            crate::envelope::CROSS_CHAIN_MARKET_MAX_PAYLOAD as u32
        );
        assert_eq!(cross_chain.first_supported_release, "0.2.0");
        assert_eq!(
            cross_chain.source_implementation_url,
            "https://github.com/handshake-rs/hns-rs/tree/main/crates/hns-marketplace-protocol"
        );
        let reserved = v2
            .assignments
            .iter()
            .find(|assignment| assignment.semantic_name == "reserved-protocols-0x0003-0xffff")
            .expect("V2 reserved range");
        assert_eq!(
            (reserved.value, reserved.range_end),
            (3, Some(u16::MAX as u64))
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
