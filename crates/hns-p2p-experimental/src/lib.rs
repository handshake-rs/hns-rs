#![doc = "Denuo Experimental V1 protocol registry and extension framing."]

pub mod assignment;
pub mod envelope;
pub mod negotiation;
pub mod peer;
pub mod policy;
pub mod registry;
pub mod request;

pub use assignment::{
    DENUO_EXTENSION_PACKET, DENUO_EXTENSION_SERVICE, DNS_RELAY_REQUEST_PACKET,
    DNS_RELAY_RESPONSE_PACKET, DNS_RELAY_SERVICE, ExperimentalWireProfile, HNSR_PACKET,
    HNSR_RELAY_SERVICE, HNSR_RENDEZVOUS_SERVICE, Network, ODOH_PACKET, ODOH_SERVICE, PacketType,
    ServiceBit, ServiceMask, WireAssignments,
};
pub use envelope::{
    ATOMIC_MARKET_MAX_PAYLOAD, ATOMIC_MARKET_PROTOCOL_ID, DEFAULT_MAX_DENUO_PAYLOAD,
    DENUO_ENVELOPE_MAGIC, DENUO_ENVELOPE_OVERHEAD, DENUO_EXTENSION_MAX_NESTED_PAYLOAD,
    DENUO_EXTENSION_MAX_PACKET_PAYLOAD, DenuoExtensionEnvelope, EnvelopeError, KnownMessage,
    ProtocolDisposition, REGISTRY_NEGOTIATION_MAX_PAYLOAD, REGISTRY_NEGOTIATION_PROTOCOL_ID,
    REGISTRY_NEGOTIATION_PROTOCOL_VERSION, RegistryEnvelopeError,
};
pub use negotiation::{NegotiatedRegistry, NegotiationError, ProtocolRange, RegistryHello};
pub use peer::{ExperimentalAdmission, ExperimentalPeerState, PeerProtocol, PeerProtocolError};
pub use policy::{
    DnsRelayRequesterPolicy, HnsrPolicy, ObliviousDnsPolicy, PolicyAction, PolicyController,
    PolicyTransition, ProviderRoles, TransportPolicy,
};
pub use registry::{
    AssignmentKind, AssignmentStatus, DENUO_V1_REGISTRY_FINGERPRINT, DENUO_V1_REGISTRY_ID,
    DENUO_V1_REGISTRY_NAME, DENUO_V1_REGISTRY_PROTOCOL_VERSION, DENUO_V1_REGISTRY_VERSION,
    DENUO_V1_WIRE_PROFILE, ExperimentalRegistryId, RegistryAssignment, RegistryDocument,
    RegistryError, RegistryMetadata,
};
pub use request::{RequestTracker, RequestTrackerError};

/// Mandatory status label for every user-facing Denuo assignment surface.
pub const EXPERIMENTAL_STATUS_LABEL: &str =
    "Denuo Experimental V1 — Not an official Handshake protocol assignment";
