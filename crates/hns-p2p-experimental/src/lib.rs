#![doc = "Shakescape Experimental protocol registries and extension framing."]

pub mod assignment;
pub mod envelope;
pub mod negotiation;
pub mod peer;
pub mod policy;
pub mod registry;
pub mod request;

pub use assignment::{
    DNS_RELAY_REQUEST_PACKET, DNS_RELAY_RESPONSE_PACKET, DNS_RELAY_SERVICE,
    ExperimentalWireProfile, HNSR_PACKET, HNSR_RELAY_SERVICE, HNSR_RENDEZVOUS_SERVICE, Network,
    ODOH_PACKET, ODOH_SERVICE, PacketType, SHAKESCAPE_EXTENSION_PACKET,
    SHAKESCAPE_EXTENSION_SERVICE, ServiceBit, ServiceMask, WireAssignments,
};
pub use envelope::{
    ATOMIC_MARKET_MAX_PAYLOAD, ATOMIC_MARKET_PROTOCOL_ID, ATOMIC_MARKET_PROTOCOL_VERSION,
    CANCEL_DIRECT_OFFER_MESSAGE_TYPE, CROSS_CHAIN_MARKET_MAX_PAYLOAD,
    CROSS_CHAIN_MARKET_PROTOCOL_ID, CROSS_CHAIN_MARKET_PROTOCOL_VERSION,
    DEFAULT_MAX_SHAKESCAPE_PAYLOAD, DIRECT_OFFER_INVENTORY_MESSAGE_TYPE, DIRECT_OFFER_MESSAGE_TYPE,
    EnvelopeError, GET_DIRECT_OFFER_MESSAGE_TYPE, KnownMessage, ProtocolDisposition,
    REGISTRY_NEGOTIATION_MAX_PAYLOAD, REGISTRY_NEGOTIATION_PROTOCOL_ID,
    REGISTRY_NEGOTIATION_PROTOCOL_VERSION, RegistryEnvelopeError, SHAKESCAPE_ENVELOPE_MAGIC,
    SHAKESCAPE_ENVELOPE_OVERHEAD, SHAKESCAPE_EXTENSION_MAX_NESTED_PAYLOAD,
    SHAKESCAPE_EXTENSION_MAX_PACKET_PAYLOAD, SWAP_FUNDING_STATUS_MESSAGE_TYPE,
    SWAP_REDEEM_STATUS_MESSAGE_TYPE, SWAP_REFUND_STATUS_MESSAGE_TYPE,
    SWAP_SESSION_HELLO_MESSAGE_TYPE, SWAP_SESSION_PROPOSAL_MESSAGE_TYPE,
    SWAP_WATCH_READY_MESSAGE_TYPE, ShakescapeExtensionEnvelope, TAKE_DIRECT_OFFER_MESSAGE_TYPE,
};
pub use negotiation::{NegotiatedRegistry, NegotiationError, ProtocolRange, RegistryHello};
pub use peer::{ExperimentalAdmission, ExperimentalPeerState, PeerProtocol, PeerProtocolError};
#[allow(deprecated)]
pub use policy::{
    DnsRelayOutputPolicy, DnsRelayRequesterPolicy, HnsrPolicy, ObliviousDnsPolicy,
    OpaqueRelayRoles, OutputRoles, PolicyAction, PolicyController, PolicyTransition, ProviderRoles,
    TransportPolicy,
};
pub use registry::{
    AssignmentKind, AssignmentStatus, ExperimentalRegistryId, HIP_76_PROTOCOL_VERSION,
    HNSR_PROFILE_REGISTRY_FINGERPRINT, HNSR_PROFILE_REGISTRY_ID, HNSR_PROFILE_REGISTRY_NAME,
    HNSR_PROFILE_REGISTRY_PROTOCOL_VERSION, HNSR_PROFILE_REGISTRY_VERSION,
    HNSR_PROFILE_WIRE_PROFILE, RegistryAssignment, RegistryDocument, RegistryError,
    RegistryMetadata, SHAKESCAPE_V1_REGISTRY_FINGERPRINT, SHAKESCAPE_V1_REGISTRY_ID,
    SHAKESCAPE_V1_REGISTRY_NAME, SHAKESCAPE_V1_REGISTRY_PROTOCOL_VERSION,
    SHAKESCAPE_V1_REGISTRY_VERSION, SHAKESCAPE_V1_WIRE_PROFILE,
};
pub use request::{RequestTracker, RequestTrackerError};

/// Mandatory status label for every user-facing Shakescape assignment surface.
pub const EXPERIMENTAL_STATUS_LABEL: &str =
    "Shakescape Experimental V1 — Not an official Handshake protocol assignment";
