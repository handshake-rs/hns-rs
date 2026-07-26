use std::collections::BTreeSet;

use hns_encoding::{DecodeError, Decoder, Encoder};
use hns_primitives::RegistryFingerprint;
use thiserror::Error;

use crate::assignment::Network;
use crate::registry::{
    DENUO_V1_REGISTRY_FINGERPRINT, DENUO_V1_REGISTRY_PROTOCOL_VERSION, DENUO_V1_REGISTRY_VERSION,
};

const HELLO_MAGIC: [u8; 4] = *b"DNRN";
const HELLO_FORMAT_VERSION: u16 = 1;
const MAX_REGISTRY_VERSIONS: usize = 16;
const MAX_PROTOCOL_RANGES: usize = 64;

pub const REGISTRY_NEGOTIATION_PROTOCOL_ID: u16 = 0x0000;
pub const REGISTRY_NEGOTIATION_PROTOCOL_VERSION: u16 = DENUO_V1_REGISTRY_PROTOCOL_VERSION;
pub const REGISTRY_NEGOTIATION_MAX_PAYLOAD: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolRange {
    pub protocol_id: u16,
    pub minimum_version: u16,
    pub maximum_version: u16,
}

impl ProtocolRange {
    pub fn validate(self) -> Result<(), NegotiationError> {
        if self.minimum_version == 0 || self.minimum_version > self.maximum_version {
            return Err(NegotiationError::InvalidProtocolRange(self));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryHello {
    pub fingerprint: RegistryFingerprint,
    pub registry_versions: Vec<u16>,
    pub protocols: Vec<ProtocolRange>,
    pub maximum_receive_size: u32,
    pub maximum_live_requests: u16,
    pub network: Network,
    pub genesis_hash: [u8; 32],
    pub feature_flags: u64,
}

impl RegistryHello {
    pub fn denuo_v1(
        network: Network,
        genesis_hash: [u8; 32],
        mut protocols: Vec<ProtocolRange>,
        maximum_receive_size: u32,
        maximum_live_requests: u16,
        feature_flags: u64,
    ) -> Result<Self, NegotiationError> {
        if protocols
            .iter()
            .any(|protocol| protocol.protocol_id == REGISTRY_NEGOTIATION_PROTOCOL_ID)
        {
            return Err(NegotiationError::ManagedRegistryProtocol);
        }
        protocols.push(ProtocolRange {
            protocol_id: REGISTRY_NEGOTIATION_PROTOCOL_ID,
            minimum_version: REGISTRY_NEGOTIATION_PROTOCOL_VERSION,
            maximum_version: REGISTRY_NEGOTIATION_PROTOCOL_VERSION,
        });
        let hello = Self {
            fingerprint: DENUO_V1_REGISTRY_FINGERPRINT,
            registry_versions: vec![DENUO_V1_REGISTRY_VERSION],
            protocols,
            maximum_receive_size,
            maximum_live_requests,
            network,
            genesis_hash,
            feature_flags,
        };
        hello.validate()?;
        Ok(hello)
    }

    pub fn validate(&self) -> Result<(), NegotiationError> {
        if self.registry_versions.is_empty() || self.registry_versions.len() > MAX_REGISTRY_VERSIONS
        {
            return Err(NegotiationError::RegistryVersionCount(
                self.registry_versions.len(),
            ));
        }
        if self.protocols.len() > MAX_PROTOCOL_RANGES {
            return Err(NegotiationError::ProtocolCount(self.protocols.len()));
        }
        if self.maximum_receive_size == 0 || self.maximum_live_requests == 0 {
            return Err(NegotiationError::ZeroResourceLimit);
        }
        let registry_versions: BTreeSet<_> = self.registry_versions.iter().copied().collect();
        if registry_versions.len() != self.registry_versions.len() || registry_versions.contains(&0)
        {
            return Err(NegotiationError::DuplicateOrZeroRegistryVersion);
        }
        let protocol_ids: BTreeSet<_> = self
            .protocols
            .iter()
            .map(|protocol| protocol.protocol_id)
            .collect();
        if protocol_ids.len() != self.protocols.len() {
            return Err(NegotiationError::DuplicateProtocol);
        }
        for protocol in &self.protocols {
            protocol.validate()?;
        }
        let Some(registry_protocol) = self
            .protocols
            .iter()
            .find(|protocol| protocol.protocol_id == REGISTRY_NEGOTIATION_PROTOCOL_ID)
        else {
            return Err(NegotiationError::MissingRegistryProtocol);
        };
        if registry_protocol.minimum_version > REGISTRY_NEGOTIATION_PROTOCOL_VERSION
            || registry_protocol.maximum_version < REGISTRY_NEGOTIATION_PROTOCOL_VERSION
        {
            return Err(NegotiationError::UnsupportedRegistryProtocolRange(
                *registry_protocol,
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, NegotiationError> {
        self.validate()?;
        let mut versions = self.registry_versions.clone();
        versions.sort_unstable();
        let mut protocols = self.protocols.clone();
        protocols.sort_unstable();

        let mut encoder = Encoder::with_capacity(86 + versions.len() * 2 + protocols.len() * 6);
        encoder.put_bytes(&HELLO_MAGIC);
        encoder.put_u16_le(HELLO_FORMAT_VERSION);
        encoder.put_bytes(self.fingerprint.as_bytes());
        encoder.put_u8(u8::try_from(versions.len()).expect("bounded to 16"));
        for version in versions {
            encoder.put_u16_le(version);
        }
        encoder.put_u8(u8::try_from(protocols.len()).expect("bounded to 64"));
        for protocol in protocols {
            encoder.put_u16_le(protocol.protocol_id);
            encoder.put_u16_le(protocol.minimum_version);
            encoder.put_u16_le(protocol.maximum_version);
        }
        encoder.put_u32_le(self.maximum_receive_size);
        encoder.put_u16_le(self.maximum_live_requests);
        encoder.put_u8(self.network as u8);
        encoder.put_bytes(&self.genesis_hash);
        encoder.put_u64_le(self.feature_flags);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, NegotiationError> {
        let mut decoder = Decoder::new(input);
        let magic = decoder.read_array::<4>()?;
        if magic != HELLO_MAGIC {
            return Err(NegotiationError::WrongMagic(magic));
        }
        let format_version = decoder.read_u16_le()?;
        if format_version != HELLO_FORMAT_VERSION {
            return Err(NegotiationError::UnknownFormatVersion(format_version));
        }
        let fingerprint = RegistryFingerprint::new(decoder.read_array()?);
        let registry_count = decoder.read_u8()? as usize;
        if registry_count == 0 || registry_count > MAX_REGISTRY_VERSIONS {
            return Err(NegotiationError::RegistryVersionCount(registry_count));
        }
        let mut registry_versions = Vec::with_capacity(registry_count);
        for _ in 0..registry_count {
            registry_versions.push(decoder.read_u16_le()?);
        }
        let protocol_count = decoder.read_u8()? as usize;
        if protocol_count > MAX_PROTOCOL_RANGES {
            return Err(NegotiationError::ProtocolCount(protocol_count));
        }
        let mut protocols = Vec::with_capacity(protocol_count);
        for _ in 0..protocol_count {
            protocols.push(ProtocolRange {
                protocol_id: decoder.read_u16_le()?,
                minimum_version: decoder.read_u16_le()?,
                maximum_version: decoder.read_u16_le()?,
            });
        }
        let maximum_receive_size = decoder.read_u32_le()?;
        let maximum_live_requests = decoder.read_u16_le()?;
        let network_byte = decoder.read_u8()?;
        let network = Network::try_from(network_byte)
            .map_err(|_| NegotiationError::UnknownNetwork(network_byte))?;
        let genesis_hash = decoder.read_array()?;
        let feature_flags = decoder.read_u64_le()?;
        decoder.finish()?;

        let hello = Self {
            fingerprint,
            registry_versions,
            protocols,
            maximum_receive_size,
            maximum_live_requests,
            network,
            genesis_hash,
            feature_flags,
        };
        hello.validate()?;
        Ok(hello)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedRegistry {
    pub fingerprint: RegistryFingerprint,
    pub registry_version: u16,
    pub protocols: Vec<(u16, u16)>,
    pub maximum_send_size: u32,
    pub maximum_live_requests: u16,
    pub network: Network,
    pub genesis_hash: [u8; 32],
    pub feature_flags: u64,
}

impl NegotiatedRegistry {
    pub fn negotiate(
        local: &RegistryHello,
        remote: &RegistryHello,
    ) -> Result<Self, NegotiationError> {
        local.validate()?;
        remote.validate()?;
        if local.fingerprint != remote.fingerprint {
            return Err(NegotiationError::WrongFingerprint {
                expected: *local.fingerprint.as_bytes(),
                actual: *remote.fingerprint.as_bytes(),
            });
        }
        if local.network != remote.network {
            return Err(NegotiationError::WrongNetwork {
                local: local.network,
                remote: remote.network,
            });
        }
        if local.genesis_hash != remote.genesis_hash {
            return Err(NegotiationError::WrongGenesis);
        }

        let remote_versions: BTreeSet<_> = remote.registry_versions.iter().copied().collect();
        let registry_version = local
            .registry_versions
            .iter()
            .copied()
            .filter(|version| remote_versions.contains(version))
            .max()
            .ok_or(NegotiationError::NoCommonRegistry)?;

        let mut protocols = Vec::new();
        for local_protocol in &local.protocols {
            if let Some(remote_protocol) = remote
                .protocols
                .iter()
                .find(|candidate| candidate.protocol_id == local_protocol.protocol_id)
            {
                let minimum = local_protocol
                    .minimum_version
                    .max(remote_protocol.minimum_version);
                let maximum = local_protocol
                    .maximum_version
                    .min(remote_protocol.maximum_version);
                if minimum <= maximum {
                    let version = if local_protocol.protocol_id == REGISTRY_NEGOTIATION_PROTOCOL_ID
                    {
                        REGISTRY_NEGOTIATION_PROTOCOL_VERSION
                    } else {
                        maximum
                    };
                    protocols.push((local_protocol.protocol_id, version));
                }
            }
        }
        protocols.sort_unstable();
        if !protocols.contains(&(
            REGISTRY_NEGOTIATION_PROTOCOL_ID,
            REGISTRY_NEGOTIATION_PROTOCOL_VERSION,
        )) {
            return Err(NegotiationError::RegistryProtocolNotNegotiated);
        }

        Ok(Self {
            fingerprint: local.fingerprint,
            registry_version,
            protocols,
            maximum_send_size: local.maximum_receive_size.min(remote.maximum_receive_size),
            maximum_live_requests: local
                .maximum_live_requests
                .min(remote.maximum_live_requests),
            network: local.network,
            genesis_hash: local.genesis_hash,
            feature_flags: local.feature_flags & remote.feature_flags,
        })
    }

    pub fn supports(&self, protocol_id: u16, protocol_version: u16) -> bool {
        self.protocols.contains(&(protocol_id, protocol_version))
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NegotiationError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("wrong registry negotiation magic {0:?}")]
    WrongMagic([u8; 4]),
    #[error("unsupported registry negotiation format version {0}")]
    UnknownFormatVersion(u16),
    #[error("registry version count {0} is outside 1..=16")]
    RegistryVersionCount(usize),
    #[error("protocol count {0} exceeds 64")]
    ProtocolCount(usize),
    #[error("registry versions contain zero or a duplicate")]
    DuplicateOrZeroRegistryVersion,
    #[error("protocol identifiers contain a duplicate")]
    DuplicateProtocol,
    #[error("the canonical constructor manages registry negotiation protocol 0x0000")]
    ManagedRegistryProtocol,
    #[error("registry negotiation protocol 0x0000 version 1 is required")]
    MissingRegistryProtocol,
    #[error("registry negotiation protocol 0x0000 must include version 1, got {0:?}")]
    UnsupportedRegistryProtocolRange(ProtocolRange),
    #[error("registry negotiation protocol 0x0000 version 1 was not negotiated")]
    RegistryProtocolNotNegotiated,
    #[error("invalid protocol version range {0:?}")]
    InvalidProtocolRange(ProtocolRange),
    #[error("maximum receive size and live request count must be nonzero")]
    ZeroResourceLimit,
    #[error("unknown network identifier {0}")]
    UnknownNetwork(u8),
    #[error("registry fingerprints differ")]
    WrongFingerprint {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("network identities differ: local {local:?}, remote {remote:?}")]
    WrongNetwork { local: Network, remote: Network },
    #[error("genesis hashes differ")]
    WrongGenesis,
    #[error("no common registry version")]
    NoCommonRegistry,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello() -> RegistryHello {
        RegistryHello {
            fingerprint: RegistryFingerprint::new([7; 32]),
            registry_versions: vec![1, 2],
            protocols: vec![
                ProtocolRange {
                    protocol_id: 1,
                    minimum_version: 1,
                    maximum_version: 3,
                },
                ProtocolRange {
                    protocol_id: 0,
                    minimum_version: 1,
                    maximum_version: 1,
                },
            ],
            maximum_receive_size: 1_048_576,
            maximum_live_requests: 64,
            network: Network::Regtest,
            genesis_hash: [8; 32],
            feature_flags: 0b111,
        }
    }

    #[test]
    fn hello_is_deterministic_and_round_trips() {
        let first = hello().encode().expect("valid");
        let mut reordered = hello();
        reordered.registry_versions.reverse();
        reordered.protocols.reverse();
        assert_eq!(first, reordered.encode().expect("valid"));
        assert_eq!(RegistryHello::decode(&first).expect("valid"), {
            let mut canonical = hello();
            canonical.registry_versions.sort_unstable();
            canonical.protocols.sort_unstable();
            canonical
        });
    }

    #[test]
    fn canonical_constructor_owns_registry_identity_and_protocol() {
        let market = ProtocolRange {
            protocol_id: 1,
            minimum_version: 1,
            maximum_version: 1,
        };
        let hello = RegistryHello::denuo_v1(Network::Regtest, [8; 32], vec![market], 4096, 4, 3)
            .expect("canonical hello");
        assert_eq!(hello.fingerprint, DENUO_V1_REGISTRY_FINGERPRINT);
        assert_eq!(hello.registry_versions, vec![DENUO_V1_REGISTRY_VERSION]);
        assert!(hello.protocols.contains(&ProtocolRange {
            protocol_id: REGISTRY_NEGOTIATION_PROTOCOL_ID,
            minimum_version: REGISTRY_NEGOTIATION_PROTOCOL_VERSION,
            maximum_version: REGISTRY_NEGOTIATION_PROTOCOL_VERSION,
        }));
        assert_eq!(
            RegistryHello::denuo_v1(
                Network::Regtest,
                [8; 32],
                vec![ProtocolRange {
                    protocol_id: REGISTRY_NEGOTIATION_PROTOCOL_ID,
                    minimum_version: 1,
                    maximum_version: 1,
                }],
                4096,
                4,
                0,
            ),
            Err(NegotiationError::ManagedRegistryProtocol)
        );
    }

    #[test]
    fn registry_protocol_zero_version_one_is_mandatory() {
        let mut missing = hello();
        missing
            .protocols
            .retain(|protocol| protocol.protocol_id != REGISTRY_NEGOTIATION_PROTOCOL_ID);
        assert_eq!(
            missing.validate(),
            Err(NegotiationError::MissingRegistryProtocol)
        );

        let mut wrong_version = hello();
        let protocol = wrong_version
            .protocols
            .iter_mut()
            .find(|protocol| protocol.protocol_id == REGISTRY_NEGOTIATION_PROTOCOL_ID)
            .expect("fixture includes registry protocol");
        protocol.minimum_version = 2;
        protocol.maximum_version = 2;
        let unsupported = *protocol;
        assert_eq!(
            wrong_version.validate(),
            Err(NegotiationError::UnsupportedRegistryProtocolRange(
                unsupported
            ))
        );

        let local = hello();
        let mut forward_compatible = hello();
        let protocol = forward_compatible
            .protocols
            .iter_mut()
            .find(|protocol| protocol.protocol_id == REGISTRY_NEGOTIATION_PROTOCOL_ID)
            .expect("fixture includes registry protocol");
        protocol.maximum_version = 2;
        forward_compatible.validate().expect("v1 remains supported");
        let negotiated =
            NegotiatedRegistry::negotiate(&local, &forward_compatible).expect("selects v1");
        assert!(negotiated.supports(
            REGISTRY_NEGOTIATION_PROTOCOL_ID,
            REGISTRY_NEGOTIATION_PROTOCOL_VERSION
        ));
    }

    #[test]
    fn negotiation_selects_highest_common_semantic_versions() {
        let local = hello();
        let mut remote = hello();
        remote.registry_versions = vec![1];
        remote.protocols[0].minimum_version = 2;
        remote.maximum_receive_size = 4096;
        remote.maximum_live_requests = 3;
        remote.feature_flags = 0b101;
        let negotiated = NegotiatedRegistry::negotiate(&local, &remote).expect("compatible");
        assert_eq!(negotiated.registry_version, 1);
        assert_eq!(negotiated.protocols, vec![(0, 1), (1, 3)]);
        assert_eq!(negotiated.maximum_send_size, 4096);
        assert_eq!(negotiated.maximum_live_requests, 3);
        assert_eq!(negotiated.feature_flags, 0b101);
    }

    #[test]
    fn mismatch_is_scoped_to_experimental_negotiation() {
        let local = hello();
        let mut wrong_fingerprint = hello();
        wrong_fingerprint.fingerprint = RegistryFingerprint::new([9; 32]);
        assert!(matches!(
            NegotiatedRegistry::negotiate(&local, &wrong_fingerprint),
            Err(NegotiationError::WrongFingerprint { .. })
        ));

        let mut wrong_network = hello();
        wrong_network.network = Network::Mainnet;
        assert!(matches!(
            NegotiatedRegistry::negotiate(&local, &wrong_network),
            Err(NegotiationError::WrongNetwork { .. })
        ));
    }
}
