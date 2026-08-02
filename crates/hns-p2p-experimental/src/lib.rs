#![doc = "Denuo Experimental protocol registries and extension framing."]

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
    ATOMIC_MARKET_MAX_PAYLOAD, ATOMIC_MARKET_PROTOCOL_ID, CANCEL_MARKET_INTENT_MESSAGE_TYPE,
    CROSS_CHAIN_MARKET_MAX_PAYLOAD, CROSS_CHAIN_MARKET_PROTOCOL_ID, DEFAULT_MAX_DENUO_PAYLOAD,
    DENUO_ENVELOPE_MAGIC, DENUO_ENVELOPE_OVERHEAD, DENUO_EXTENSION_MAX_NESTED_PAYLOAD,
    DENUO_EXTENSION_MAX_PACKET_PAYLOAD, DenuoExtensionEnvelope, EnvelopeError,
    FILL_GRANT_MESSAGE_TYPE, GET_MARKET_INTENT_MESSAGE_TYPE, GET_PRICE_OBSERVATION_MESSAGE_TYPE,
    KnownMessage, MARKET_INTENT_INV_MESSAGE_TYPE, MARKET_INTENT_MESSAGE_TYPE,
    MATCH_REJECT_MESSAGE_TYPE, MATCH_REQUEST_MESSAGE_TYPE, PRICE_OBSERVATION_INV_MESSAGE_TYPE,
    PRICE_OBSERVATION_MESSAGE_TYPE, PRICE_ROUND_MESSAGE_TYPE, ProtocolDisposition,
    REGISTRY_NEGOTIATION_MAX_PAYLOAD, REGISTRY_NEGOTIATION_PROTOCOL_ID,
    REGISTRY_NEGOTIATION_PROTOCOL_VERSION, RegistryEnvelopeError, SWAP_FUNDING_STATUS_MESSAGE_TYPE,
    SWAP_REDEEM_STATUS_MESSAGE_TYPE, SWAP_REFUND_STATUS_MESSAGE_TYPE,
    SWAP_SESSION_HELLO_MESSAGE_TYPE,
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
    AssignmentKind, AssignmentStatus, DENUO_V1_REGISTRY_FINGERPRINT, DENUO_V1_REGISTRY_ID,
    DENUO_V1_REGISTRY_NAME, DENUO_V1_REGISTRY_PROTOCOL_VERSION, DENUO_V1_REGISTRY_VERSION,
    DENUO_V1_WIRE_PROFILE, DENUO_V2_REGISTRY_FINGERPRINT, DENUO_V2_REGISTRY_ID,
    DENUO_V2_REGISTRY_NAME, DENUO_V2_REGISTRY_PROTOCOL_VERSION, DENUO_V2_REGISTRY_VERSION,
    DENUO_V2_WIRE_PROFILE, ExperimentalRegistryId, HIP_76_PROTOCOL_VERSION, RegistryAssignment,
    RegistryDocument, RegistryError, RegistryMetadata,
};
pub use request::{RequestTracker, RequestTrackerError};

/// Mandatory status label for every user-facing Denuo assignment surface.
pub const EXPERIMENTAL_STATUS_LABEL: &str =
    "Denuo Experimental V1 — Not an official Handshake protocol assignment";

/// Mandatory status label for user-facing Denuo V2 assignment surfaces.
pub const DENUO_V2_EXPERIMENTAL_STATUS_LABEL: &str =
    "Denuo Experimental V2 — Not an official Handshake protocol assignment";
