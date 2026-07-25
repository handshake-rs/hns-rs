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
    DENUO_ENVELOPE_MAGIC, DENUO_ENVELOPE_OVERHEAD, DenuoExtensionEnvelope, EnvelopeError,
    KnownMessage, ProtocolDisposition,
};
pub use negotiation::{NegotiatedRegistry, NegotiationError, ProtocolRange, RegistryHello};
pub use peer::{ExperimentalAdmission, ExperimentalPeerState, PeerProtocol, PeerProtocolError};
pub use policy::{
    DnsRelayRequesterPolicy, HnsrPolicy, ObliviousDnsPolicy, PolicyAction, PolicyController,
    PolicyTransition, ProviderRoles, TransportPolicy,
};
pub use registry::{
    AssignmentKind, AssignmentStatus, ExperimentalRegistryId, RegistryAssignment, RegistryDocument,
    RegistryError, RegistryMetadata,
};
pub use request::{RequestTracker, RequestTrackerError};

/// Mandatory status label for every user-facing Denuo assignment surface.
pub const EXPERIMENTAL_STATUS_LABEL: &str =
    "Denuo Experimental V1 — Not an official Handshake protocol assignment";
