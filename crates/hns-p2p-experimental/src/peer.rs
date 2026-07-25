use std::collections::BTreeSet;

use hns_primitives::RegistryFingerprint;
use thiserror::Error;

use crate::assignment::{
    DENUO_EXTENSION_PACKET, DENUO_EXTENSION_SERVICE, DNS_RELAY_REQUEST_PACKET,
    DNS_RELAY_RESPONSE_PACKET, DNS_RELAY_SERVICE, ExperimentalWireProfile, HNSR_PACKET,
    HNSR_RELAY_SERVICE, HNSR_RENDEZVOUS_SERVICE, Network, ODOH_PACKET, ODOH_SERVICE, PacketType,
    ServiceBit, ServiceMask,
};
use crate::negotiation::NegotiatedRegistry;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PeerProtocol {
    DnsRelay,
    ObliviousDns,
    Hnsr,
    DenuoExtension,
}

impl PeerProtocol {
    const fn required_service(self) -> ServiceBit {
        match self {
            Self::DnsRelay => DNS_RELAY_SERVICE,
            Self::ObliviousDns => ODOH_SERVICE,
            Self::Hnsr => HNSR_RENDEZVOUS_SERVICE,
            Self::DenuoExtension => DENUO_EXTENSION_SERVICE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExperimentalAdmission {
    OrdinaryHandshake,
    Experimental(PeerProtocol),
    ReservedPrivatePacket,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentalPeerState {
    profile: ExperimentalWireProfile,
    network: Network,
    genesis_hash: [u8; 32],
    expected_fingerprint: RegistryFingerprint,
    services: ServiceMask,
    established: bool,
    negotiated: Option<NegotiatedRegistry>,
    disabled: BTreeSet<PeerProtocol>,
}

impl ExperimentalPeerState {
    pub const fn new(
        profile: ExperimentalWireProfile,
        network: Network,
        genesis_hash: [u8; 32],
        expected_fingerprint: RegistryFingerprint,
        services: ServiceMask,
    ) -> Self {
        Self {
            profile,
            network,
            genesis_hash,
            expected_fingerprint,
            services,
            established: false,
            negotiated: None,
            disabled: BTreeSet::new(),
        }
    }

    pub fn mark_established(&mut self) {
        self.established = true;
    }

    pub fn install_negotiation(
        &mut self,
        negotiated: NegotiatedRegistry,
    ) -> Result<(), PeerProtocolError> {
        if !self.established {
            return Err(PeerProtocolError::ConnectionNotEstablished);
        }
        if negotiated.fingerprint != self.expected_fingerprint {
            return Err(PeerProtocolError::WrongFingerprint);
        }
        if negotiated.network != self.network {
            return Err(PeerProtocolError::WrongNetwork);
        }
        if negotiated.genesis_hash != self.genesis_hash {
            return Err(PeerProtocolError::WrongGenesis);
        }
        self.negotiated = Some(negotiated);
        Ok(())
    }

    pub fn admit_packet(
        &mut self,
        packet: PacketType,
    ) -> Result<ExperimentalAdmission, PeerProtocolError> {
        let Some(protocol) = protocol_for_packet(packet) else {
            if packet.value() >= 0xf5 {
                return Ok(ExperimentalAdmission::ReservedPrivatePacket);
            }
            return Ok(ExperimentalAdmission::OrdinaryHandshake);
        };
        if self.disabled.contains(&protocol) {
            return Err(PeerProtocolError::ProtocolDisabled(protocol));
        }
        if !self.established {
            self.disabled.insert(protocol);
            return Err(PeerProtocolError::ConnectionNotEstablished);
        }
        let required_service = required_service_for_packet(packet, protocol);
        if !self.services.contains(required_service) {
            self.disabled.insert(protocol);
            return Err(PeerProtocolError::PacketWithoutService {
                protocol,
                required_service,
            });
        }

        let requires_registry = matches!(
            self.profile,
            ExperimentalWireProfile::DenuoV1 | ExperimentalWireProfile::Auto
        );
        if requires_registry && protocol != PeerProtocol::DenuoExtension {
            if !self.services.contains(DENUO_EXTENSION_SERVICE) {
                self.disabled.insert(protocol);
                return Err(PeerProtocolError::MissingDenuoExtensionService(protocol));
            }
            let Some(negotiated) = &self.negotiated else {
                self.disabled.insert(protocol);
                return Err(PeerProtocolError::RegistryNotNegotiated(protocol));
            };
            if negotiated.fingerprint != self.expected_fingerprint {
                self.disabled.insert(protocol);
                return Err(PeerProtocolError::WrongFingerprint);
            }
        }
        Ok(ExperimentalAdmission::Experimental(protocol))
    }

    pub fn validate_advertisements(&self) -> Result<(), PeerProtocolError> {
        if !matches!(
            self.profile,
            ExperimentalWireProfile::DenuoV1 | ExperimentalWireProfile::Auto
        ) {
            return Ok(());
        }
        let advertises_private_role = self.services.contains(DNS_RELAY_SERVICE)
            || self.services.contains(ODOH_SERVICE)
            || self.services.contains(HNSR_RENDEZVOUS_SERVICE)
            || self.services.contains(HNSR_RELAY_SERVICE);
        if advertises_private_role && !self.services.contains(DENUO_EXTENSION_SERVICE) {
            return Err(PeerProtocolError::AdvertisedServiceWithoutRegistry);
        }
        Ok(())
    }

    pub fn is_disabled(&self, protocol: PeerProtocol) -> bool {
        self.disabled.contains(&protocol)
    }

    pub const fn ordinary_handshake_remains_available(&self) -> bool {
        true
    }
}

fn protocol_for_packet(packet: PacketType) -> Option<PeerProtocol> {
    match packet {
        DNS_RELAY_REQUEST_PACKET | DNS_RELAY_RESPONSE_PACKET => Some(PeerProtocol::DnsRelay),
        ODOH_PACKET => Some(PeerProtocol::ObliviousDns),
        HNSR_PACKET => Some(PeerProtocol::Hnsr),
        DENUO_EXTENSION_PACKET => Some(PeerProtocol::DenuoExtension),
        _ => None,
    }
}

fn required_service_for_packet(packet: PacketType, protocol: PeerProtocol) -> ServiceBit {
    if packet == HNSR_PACKET {
        HNSR_RENDEZVOUS_SERVICE
    } else {
        protocol.required_service()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PeerProtocolError {
    #[error("peer connection is not fully established")]
    ConnectionNotEstablished,
    #[error("experimental protocol {0:?} was disabled for this peer")]
    ProtocolDisabled(PeerProtocol),
    #[error("packet for {protocol:?} arrived without service {required_service}")]
    PacketWithoutService {
        protocol: PeerProtocol,
        required_service: ServiceBit,
    },
    #[error("peer advertises {0:?} without the Denuo extension service")]
    MissingDenuoExtensionService(PeerProtocol),
    #[error("peer advertises a private service without registry negotiation support")]
    AdvertisedServiceWithoutRegistry,
    #[error("registry negotiation has not completed for {0:?}")]
    RegistryNotNegotiated(PeerProtocol),
    #[error("registry fingerprint differs")]
    WrongFingerprint,
    #[error("network identity differs")]
    WrongNetwork,
    #[error("genesis identity differs")]
    WrongGenesis,
}

#[cfg(test)]
mod tests {
    use hns_primitives::RegistryFingerprint;

    use super::*;

    fn state(services: ServiceMask) -> ExperimentalPeerState {
        ExperimentalPeerState::new(
            ExperimentalWireProfile::DenuoV1,
            Network::Regtest,
            [2; 32],
            RegistryFingerprint::new([1; 32]),
            services,
        )
    }

    fn negotiated() -> NegotiatedRegistry {
        NegotiatedRegistry {
            fingerprint: RegistryFingerprint::new([1; 32]),
            registry_version: 1,
            protocols: vec![(0, 1)],
            maximum_send_size: 4096,
            maximum_live_requests: 8,
            network: Network::Regtest,
            genesis_hash: [2; 32],
            feature_flags: 0,
        }
    }

    #[test]
    fn denuo_packets_require_service_connection_and_registry() {
        let services = ServiceMask::default()
            .with(DNS_RELAY_SERVICE)
            .with(DENUO_EXTENSION_SERVICE);
        let mut peer = state(services);
        assert_eq!(
            peer.admit_packet(DNS_RELAY_REQUEST_PACKET),
            Err(PeerProtocolError::ConnectionNotEstablished)
        );

        let mut peer = state(services);
        peer.mark_established();
        assert_eq!(
            peer.admit_packet(DNS_RELAY_REQUEST_PACKET),
            Err(PeerProtocolError::RegistryNotNegotiated(
                PeerProtocol::DnsRelay
            ))
        );

        let mut peer = state(services);
        peer.mark_established();
        peer.install_negotiation(negotiated()).expect("matches");
        assert_eq!(
            peer.admit_packet(DNS_RELAY_REQUEST_PACKET),
            Ok(ExperimentalAdmission::Experimental(PeerProtocol::DnsRelay))
        );
    }

    #[test]
    fn packet_collision_disables_only_affected_experiment() {
        let services = ServiceMask::default().with(DENUO_EXTENSION_SERVICE);
        let mut peer = state(services);
        peer.mark_established();
        peer.install_negotiation(negotiated()).expect("matches");
        assert!(matches!(
            peer.admit_packet(ODOH_PACKET),
            Err(PeerProtocolError::PacketWithoutService {
                protocol: PeerProtocol::ObliviousDns,
                ..
            })
        ));
        assert!(peer.is_disabled(PeerProtocol::ObliviousDns));
        assert!(!peer.is_disabled(PeerProtocol::DnsRelay));
        assert!(peer.ordinary_handshake_remains_available());
        assert_eq!(
            peer.admit_packet(PacketType::new(1)),
            Ok(ExperimentalAdmission::OrdinaryHandshake)
        );
    }

    #[test]
    fn service_without_packet_support_is_detectable() {
        let peer = state(ServiceMask::default().with(DNS_RELAY_SERVICE));
        assert_eq!(
            peer.validate_advertisements(),
            Err(PeerProtocolError::AdvertisedServiceWithoutRegistry)
        );
    }

    #[test]
    fn reserved_private_packet_is_never_reinterpreted() {
        let mut peer = state(ServiceMask::default());
        assert_eq!(
            peer.admit_packet(PacketType::new(0xf5)),
            Ok(ExperimentalAdmission::ReservedPrivatePacket)
        );
    }
}
