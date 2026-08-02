use core::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const HNSR_RENDEZVOUS_SERVICE: ServiceBit = ServiceBit::new(0x0400_0000);
pub const HNSR_RELAY_SERVICE: ServiceBit = ServiceBit::new(0x0800_0000);
pub const DENUO_EXTENSION_SERVICE: ServiceBit = ServiceBit::new(0x1000_0000);
pub const ODOH_SERVICE: ServiceBit = ServiceBit::new(0x2000_0000);
pub const DNS_RELAY_SERVICE: ServiceBit = ServiceBit::new(0x4000_0000);
pub const RESERVED_EXPERIMENTAL_SERVICE: ServiceBit = ServiceBit::new(0x8000_0000);

pub const DNS_RELAY_REQUEST_PACKET: PacketType = PacketType::new(0xf0);
pub const DNS_RELAY_RESPONSE_PACKET: PacketType = PacketType::new(0xf1);
pub const ODOH_PACKET: PacketType = PacketType::new(0xf2);
pub const HNSR_PACKET: PacketType = PacketType::new(0xf3);
pub const DENUO_EXTENSION_PACKET: PacketType = PacketType::new(0xf4);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServiceBit(u64);

impl ServiceBit {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub const fn is_single_bit(self) -> bool {
        self.0 != 0 && self.0.count_ones() == 1
    }
}

impl fmt::Display for ServiceBit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:016x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ServiceMask(u64);

impl ServiceMask {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub const fn contains(self, service: ServiceBit) -> bool {
        self.0 & service.0 == service.0
    }

    pub const fn with(self, service: ServiceBit) -> Self {
        Self(self.0 | service.0)
    }

    pub const fn without(self, service: ServiceBit) -> Self {
        Self(self.0 & !service.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PacketType(u8);

impl PacketType {
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u8 {
        self.0
    }
}

impl fmt::Display for PacketType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:02x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum Network {
    Mainnet = 0,
    Testnet = 1,
    Regtest = 2,
    Simnet = 3,
}

impl TryFrom<u8> for Network {
    type Error = AssignmentError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Mainnet),
            1 => Ok(Self::Testnet),
            2 => Ok(Self::Regtest),
            3 => Ok(Self::Simnet),
            _ => Err(AssignmentError::UnknownNetwork(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExperimentalWireProfile {
    DenuoV1,
    DenuoV2,
    LegacyDraftRegtest,
    Official(u16),
    Auto,
}

impl ExperimentalWireProfile {
    pub fn validate_for_network(
        self,
        network: Network,
        controlled_network: bool,
    ) -> Result<(), AssignmentError> {
        match self {
            Self::LegacyDraftRegtest if network != Network::Regtest && !controlled_network => {
                Err(AssignmentError::LegacyProfileProhibited(network))
            }
            Self::Official(version) => Err(AssignmentError::UnknownOfficialProfile(version)),
            Self::DenuoV1 | Self::DenuoV2 | Self::LegacyDraftRegtest | Self::Auto => Ok(()),
        }
    }

    pub const fn status_name(self) -> &'static str {
        match self {
            Self::DenuoV1 => "Denuo Experimental V1",
            Self::DenuoV2 => "Denuo Experimental V2",
            Self::LegacyDraftRegtest => "Legacy Draft Compatibility",
            Self::Official(_) => "Official Assignment Profile",
            Self::Auto => "Automatic Semantic Assignment Selection",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireAssignments {
    pub dns_relay_service: ServiceBit,
    pub dns_relay_request: PacketType,
    pub dns_relay_response: PacketType,
    pub odoh_service: ServiceBit,
    pub odoh_packet: PacketType,
    pub hnsr_rendezvous_service: ServiceBit,
    pub hnsr_relay_service: ServiceBit,
    pub hnsr_packet: PacketType,
    pub denuo_extension_service: ServiceBit,
    pub denuo_extension_packet: PacketType,
}

impl WireAssignments {
    pub const DENUO_V1: Self = Self {
        dns_relay_service: DNS_RELAY_SERVICE,
        dns_relay_request: DNS_RELAY_REQUEST_PACKET,
        dns_relay_response: DNS_RELAY_RESPONSE_PACKET,
        odoh_service: ODOH_SERVICE,
        odoh_packet: ODOH_PACKET,
        hnsr_rendezvous_service: HNSR_RENDEZVOUS_SERVICE,
        hnsr_relay_service: HNSR_RELAY_SERVICE,
        hnsr_packet: HNSR_PACKET,
        denuo_extension_service: DENUO_EXTENSION_SERVICE,
        denuo_extension_packet: DENUO_EXTENSION_PACKET,
    };

    /// Denuo V2 retains every V1 packet and service assignment.
    pub const DENUO_V2: Self = Self::DENUO_V1;

    pub fn for_profile(
        profile: ExperimentalWireProfile,
        network: Network,
        controlled_network: bool,
    ) -> Result<Self, AssignmentError> {
        profile.validate_for_network(network, controlled_network)?;
        match profile {
            ExperimentalWireProfile::DenuoV1
            | ExperimentalWireProfile::LegacyDraftRegtest
            | ExperimentalWireProfile::Auto => Ok(Self::DENUO_V1),
            ExperimentalWireProfile::DenuoV2 => Ok(Self::DENUO_V2),
            ExperimentalWireProfile::Official(version) => {
                Err(AssignmentError::UnknownOfficialProfile(version))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AssignmentError {
    #[error("legacy draft compatibility is prohibited on {0:?}")]
    LegacyProfileProhibited(Network),
    #[error("official assignment profile {0} is not registered")]
    UnknownOfficialProfile(u16),
    #[error("unknown network identifier {0}")]
    UnknownNetwork(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments_match_denuo_registry_v1_exactly() {
        assert_eq!(HNSR_RENDEZVOUS_SERVICE.value(), 0x0400_0000);
        assert_eq!(HNSR_RELAY_SERVICE.value(), 0x0800_0000);
        assert_eq!(DENUO_EXTENSION_SERVICE.value(), 0x1000_0000);
        assert_eq!(ODOH_SERVICE.value(), 0x2000_0000);
        assert_eq!(DNS_RELAY_SERVICE.value(), 0x4000_0000);
        assert_eq!(RESERVED_EXPERIMENTAL_SERVICE.value(), 0x8000_0000);
        assert_eq!(DNS_RELAY_REQUEST_PACKET.value(), 0xf0);
        assert_eq!(DNS_RELAY_RESPONSE_PACKET.value(), 0xf1);
        assert_eq!(ODOH_PACKET.value(), 0xf2);
        assert_eq!(HNSR_PACKET.value(), 0xf3);
        assert_eq!(DENUO_EXTENSION_PACKET.value(), 0xf4);
        assert_eq!(WireAssignments::DENUO_V2, WireAssignments::DENUO_V1);
        assert_eq!(
            WireAssignments::for_profile(ExperimentalWireProfile::DenuoV2, Network::Mainnet, false),
            Ok(WireAssignments::DENUO_V2)
        );
        assert_eq!(
            ExperimentalWireProfile::DenuoV2.status_name(),
            "Denuo Experimental V2"
        );
    }

    #[test]
    fn service_masks_are_unsigned_64_bit_values() {
        let mask = ServiceMask::default()
            .with(RESERVED_EXPERIMENTAL_SERVICE)
            .with(ServiceBit::new(1_u64 << 63));
        assert!(mask.contains(RESERVED_EXPERIMENTAL_SERVICE));
        assert!(mask.contains(ServiceBit::new(1_u64 << 63)));
        assert_eq!(mask.value(), 0x8000_0000_8000_0000);
        assert!(RESERVED_EXPERIMENTAL_SERVICE.value() > i32::MAX as u64);
    }

    #[test]
    fn legacy_profile_is_not_accepted_on_public_networks() {
        assert!(matches!(
            WireAssignments::for_profile(
                ExperimentalWireProfile::LegacyDraftRegtest,
                Network::Mainnet,
                false
            ),
            Err(AssignmentError::LegacyProfileProhibited(Network::Mainnet))
        ));
        assert!(
            WireAssignments::for_profile(
                ExperimentalWireProfile::LegacyDraftRegtest,
                Network::Regtest,
                false
            )
            .is_ok()
        );
    }
}
