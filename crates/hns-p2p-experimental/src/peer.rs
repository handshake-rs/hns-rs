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
use crate::policy::{DnsRelayOutputPolicy, DnsRelayRequesterPolicy};

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

    /// Admit a real outbound HIP-76 requester operation.
    ///
    /// `Auto` remains eligible only when a caller actually requests DNS work;
    /// this method never initiates work itself. The remote peer must advertise
    /// the HIP-76 output service and complete the selected registry handshake.
    pub fn admit_outbound_dns_relay_request(
        &mut self,
        requester_policy: DnsRelayRequesterPolicy,
    ) -> Result<ExperimentalAdmission, PeerProtocolError> {
        if requester_policy == DnsRelayRequesterPolicy::Disabled {
            return Err(PeerProtocolError::DnsRelayRequesterDisabled);
        }
        self.admit_remote_dns_relay_provider()
    }

    /// Admit an inbound HIP-76 request to a local DNS output backend.
    ///
    /// A requester does not advertise the provider service. Admission instead
    /// requires independent local provider opt-in, the corresponding local
    /// service advertisement, backend readiness, and canonical registry
    /// negotiation with the requester.
    pub fn admit_inbound_dns_relay_request(
        &mut self,
        local_services: ServiceMask,
        output_policy: DnsRelayOutputPolicy,
        backend_ready: bool,
    ) -> Result<ExperimentalAdmission, PeerProtocolError> {
        let protocol = PeerProtocol::DnsRelay;
        self.ensure_active_and_established(protocol)?;

        if !output_policy.is_enabled() {
            self.disabled.insert(protocol);
            return Err(PeerProtocolError::LocalDnsRelayProviderDisabled);
        }
        if !local_services.contains(DNS_RELAY_SERVICE) {
            self.disabled.insert(protocol);
            return Err(PeerProtocolError::LocalDnsRelayServiceNotAdvertised);
        }
        if !backend_ready {
            self.disabled.insert(protocol);
            return Err(PeerProtocolError::LocalDnsRelayBackendNotReady);
        }
        if self.requires_registry() && !local_services.contains(DENUO_EXTENSION_SERVICE) {
            self.disabled.insert(protocol);
            return Err(PeerProtocolError::LocalDnsRelayRegistryNotAdvertised);
        }

        self.ensure_registry_negotiated(protocol)?;
        Ok(ExperimentalAdmission::Experimental(protocol))
    }

    /// Compatibility admission for callers that predate direction-aware APIs.
    ///
    /// For HIP-76 only, this method interprets `getdnsrelay` as an outbound
    /// request and `dnsrelay` as an inbound response, matching its historical
    /// remote-provider check. Inbound requests must use
    /// [`Self::admit_inbound_dns_relay_request`]. Response correlation, request
    /// generation, and session direction remain the caller's responsibility.
    pub fn admit_packet(
        &mut self,
        packet: PacketType,
    ) -> Result<ExperimentalAdmission, PeerProtocolError> {
        if matches!(packet, DNS_RELAY_REQUEST_PACKET | DNS_RELAY_RESPONSE_PACKET) {
            return self.admit_remote_dns_relay_provider();
        }

        let Some(protocol) = protocol_for_packet(packet) else {
            if packet.value() >= 0xf5 {
                return Ok(ExperimentalAdmission::ReservedPrivatePacket);
            }
            return Ok(ExperimentalAdmission::OrdinaryHandshake);
        };
        self.ensure_active_and_established(protocol)?;
        let admits_service = if packet == HNSR_PACKET {
            self.services.contains(HNSR_RENDEZVOUS_SERVICE)
                || self.services.contains(HNSR_RELAY_SERVICE)
        } else {
            self.services.contains(protocol.required_service())
        };
        if !admits_service {
            self.disabled.insert(protocol);
            if packet == HNSR_PACKET {
                return Err(PeerProtocolError::HnsrPacketWithoutService);
            }
            return Err(PeerProtocolError::PacketWithoutService {
                protocol,
                required_service: protocol.required_service(),
            });
        }

        self.ensure_registry_negotiated(protocol)?;
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

    fn admit_remote_dns_relay_provider(
        &mut self,
    ) -> Result<ExperimentalAdmission, PeerProtocolError> {
        let protocol = PeerProtocol::DnsRelay;
        self.ensure_active_and_established(protocol)?;
        if !self.services.contains(DNS_RELAY_SERVICE) {
            self.disabled.insert(protocol);
            return Err(PeerProtocolError::PacketWithoutService {
                protocol,
                required_service: DNS_RELAY_SERVICE,
            });
        }
        self.ensure_registry_negotiated(protocol)?;
        Ok(ExperimentalAdmission::Experimental(protocol))
    }

    fn ensure_active_and_established(
        &mut self,
        protocol: PeerProtocol,
    ) -> Result<(), PeerProtocolError> {
        if self.disabled.contains(&protocol) {
            return Err(PeerProtocolError::ProtocolDisabled(protocol));
        }
        if !self.established {
            self.disabled.insert(protocol);
            return Err(PeerProtocolError::ConnectionNotEstablished);
        }
        Ok(())
    }

    fn ensure_registry_negotiated(
        &mut self,
        protocol: PeerProtocol,
    ) -> Result<(), PeerProtocolError> {
        if !self.requires_registry() || protocol == PeerProtocol::DenuoExtension {
            return Ok(());
        }
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
        Ok(())
    }

    const fn requires_registry(&self) -> bool {
        matches!(
            self.profile,
            ExperimentalWireProfile::DenuoV1 | ExperimentalWireProfile::Auto
        )
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
    #[error("HNSR packet arrived without a rendezvous or relay service")]
    HnsrPacketWithoutService,
    #[error("peer advertises {0:?} without the Denuo extension service")]
    MissingDenuoExtensionService(PeerProtocol),
    #[error("peer advertises a private service without registry negotiation support")]
    AdvertisedServiceWithoutRegistry,
    #[error("registry negotiation has not completed for {0:?}")]
    RegistryNotNegotiated(PeerProtocol),
    #[error("local HIP-76 requester policy is disabled")]
    DnsRelayRequesterDisabled,
    #[error("local HIP-76 output/provider role is not enabled")]
    LocalDnsRelayProviderDisabled,
    #[error("local HIP-76 output service is not advertised")]
    LocalDnsRelayServiceNotAdvertised,
    #[error("local HIP-76 output backend is not ready")]
    LocalDnsRelayBackendNotReady,
    #[error("local HIP-76 output service is advertised without Denuo registry support")]
    LocalDnsRelayRegistryNotAdvertised,
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

    fn ready_peer(services: ServiceMask) -> ExperimentalPeerState {
        let mut peer = state(services);
        peer.mark_established();
        peer.install_negotiation(negotiated()).expect("matches");
        peer
    }

    const fn dns_relay_output(enabled: bool) -> DnsRelayOutputPolicy {
        if enabled {
            DnsRelayOutputPolicy::opted_in()
        } else {
            DnsRelayOutputPolicy::disabled()
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
    fn outbound_request_requires_requester_eligibility_and_remote_provider() {
        let remote_provider = ServiceMask::default()
            .with(DNS_RELAY_SERVICE)
            .with(DENUO_EXTENSION_SERVICE);
        let mut peer = ready_peer(remote_provider);
        assert_eq!(
            peer.admit_outbound_dns_relay_request(DnsRelayRequesterPolicy::Auto),
            Ok(ExperimentalAdmission::Experimental(PeerProtocol::DnsRelay))
        );

        let mut peer = ready_peer(remote_provider);
        assert_eq!(
            peer.admit_outbound_dns_relay_request(DnsRelayRequesterPolicy::Disabled),
            Err(PeerProtocolError::DnsRelayRequesterDisabled)
        );
        assert!(!peer.is_disabled(PeerProtocol::DnsRelay));

        let mut peer = ready_peer(ServiceMask::default().with(DENUO_EXTENSION_SERVICE));
        assert!(matches!(
            peer.admit_outbound_dns_relay_request(DnsRelayRequesterPolicy::Required),
            Err(PeerProtocolError::PacketWithoutService {
                protocol: PeerProtocol::DnsRelay,
                required_service: DNS_RELAY_SERVICE,
            })
        ));
        assert!(peer.is_disabled(PeerProtocol::DnsRelay));
    }

    #[test]
    fn inbound_request_uses_local_provider_evidence_not_requester_service() {
        let requester_services = ServiceMask::default().with(DENUO_EXTENSION_SERVICE);
        let local_services = ServiceMask::default()
            .with(DNS_RELAY_SERVICE)
            .with(DENUO_EXTENSION_SERVICE);
        let mut peer = ready_peer(requester_services);
        assert_eq!(
            peer.admit_inbound_dns_relay_request(local_services, dns_relay_output(true), true,),
            Ok(ExperimentalAdmission::Experimental(PeerProtocol::DnsRelay))
        );
    }

    #[test]
    fn inbound_request_requires_opt_in_advertisement_and_ready_backend() {
        let requester_services = ServiceMask::default().with(DENUO_EXTENSION_SERVICE);
        let local_services = ServiceMask::default()
            .with(DNS_RELAY_SERVICE)
            .with(DENUO_EXTENSION_SERVICE);

        let mut peer = ready_peer(requester_services);
        assert_eq!(
            peer.admit_inbound_dns_relay_request(local_services, dns_relay_output(false), true,),
            Err(PeerProtocolError::LocalDnsRelayProviderDisabled)
        );

        let mut peer = ready_peer(requester_services);
        assert_eq!(
            peer.admit_inbound_dns_relay_request(
                ServiceMask::default().with(DENUO_EXTENSION_SERVICE),
                dns_relay_output(true),
                true,
            ),
            Err(PeerProtocolError::LocalDnsRelayServiceNotAdvertised)
        );

        let mut peer = ready_peer(requester_services);
        assert_eq!(
            peer.admit_inbound_dns_relay_request(local_services, dns_relay_output(true), false,),
            Err(PeerProtocolError::LocalDnsRelayBackendNotReady)
        );

        let mut peer = ready_peer(requester_services);
        assert_eq!(
            peer.admit_inbound_dns_relay_request(
                ServiceMask::default().with(DNS_RELAY_SERVICE),
                dns_relay_output(true),
                true,
            ),
            Err(PeerProtocolError::LocalDnsRelayRegistryNotAdvertised)
        );
        assert!(peer.is_disabled(PeerProtocol::DnsRelay));
        assert!(peer.ordinary_handshake_remains_available());
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
    fn hnsr_packet_accepts_either_negotiated_wire_role() {
        for service in [HNSR_RENDEZVOUS_SERVICE, HNSR_RELAY_SERVICE] {
            let services = ServiceMask::default()
                .with(DENUO_EXTENSION_SERVICE)
                .with(service);
            let mut peer = state(services);
            peer.mark_established();
            peer.install_negotiation(negotiated()).expect("matches");
            assert_eq!(
                peer.admit_packet(HNSR_PACKET),
                Ok(ExperimentalAdmission::Experimental(PeerProtocol::Hnsr))
            );
        }

        let mut peer = state(ServiceMask::default().with(DENUO_EXTENSION_SERVICE));
        peer.mark_established();
        peer.install_negotiation(negotiated()).expect("matches");
        assert_eq!(
            peer.admit_packet(HNSR_PACKET),
            Err(PeerProtocolError::HnsrPacketWithoutService)
        );
        assert!(peer.is_disabled(PeerProtocol::Hnsr));
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
