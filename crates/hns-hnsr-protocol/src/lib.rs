#![doc = "Runtime-independent wire types for draft HIP #78 HNSR."]

pub mod body;
pub mod circuit;
pub mod envelope;
pub mod named;
pub mod named_hrm;
mod persistent_routing;
pub mod record;
pub mod requester_hrm;
pub mod routing;
pub mod runtime;

pub use body::{
    AcceptBody, CloseBody, ConfirmBody, ConfirmedBody, DataBody, ErrorBody, FindNodeBody,
    GetRouteBody, HnsrErrorCode, IncomingBody, NodesBody, OpenBody, OpenedBody, PutResultBody,
    PutRouteBody, RenewBody, RoutesBody, SampleRoutesBody, WindowBody, WithdrawBody,
};
pub use circuit::{
    HnsrActionId, HnsrPeerId, HnsrRequester, HnsrRequesterConfig, HnsrRequesterEvent,
    HnsrRequesterSnapshot, HnsrRoute, HnsrRuntimeError, HnsrRuntimeStatus, OpaqueRelayConfig,
    OpaqueRelayRuntime, OpaqueRelaySnapshot, QueuedHnsrRoute,
};
pub use envelope::{HnsrOpcode, HnsrPacket};
pub use named::{NamedRoutePolicy, NamedRouteRecordV2, NamedRouteTrust, named_route_key};
pub use named::{OwnerBoundChatRouteTrust, verify_owner_bound_chat_route};
#[doc(hidden)]
pub use named_hrm::select_named_route_v3_uncommitted;
pub use named_hrm::{HrmNamedRoutePolicy, NamedRouteRecordV3, named_route_key_v3};
pub use persistent_routing::{
    LeasedPersistentRendezvousError, LeasedPersistentRendezvousService,
    LeasedPersistentRouteMutationError, NamedRouteV3Emission, NamedRouteV3GuardedCallbackError,
    NamedRouteV3LeaseContext, NamedRouteV3LeaseLost, NamedRouteV3LedgerExpectation,
    NamedRouteV3LedgerStorageState, NamedRouteV3OpenError, NamedRouteV3SoleOwnerLease,
    NamedRouteV3StorageNamespace,
};
pub use record::{
    EndpointDelegation, RelayTicket, ReserveRequest, RouteRecord, public_key, sign_withdrawal,
    verify_withdrawal,
};
pub use requester_hrm::{
    CurrentNamedRouteV3, HeldNamedRouteV3OperationLeases, HeldNamedRouteV3RequesterLease,
    NamedRouteV3LeaseAcquireError, NamedRouteV3LeaseScopeError, NamedRouteV3OperationLeaseWitness,
    NamedRouteV3RequesterExpectation, NamedRouteV3RequesterLeaseKey,
    NamedRouteV3RequesterLeaseWitness, NamedRouteV3RequesterOperationError,
    NamedRouteV3RequesterSnapshot, NamedRouteV3RequesterState, NamedRouteV3RequesterStorageState,
    ReconfirmedNamedRouteV3RequesterState,
};
pub use routing::{
    NamedRouteV3LedgerSnapshot, RendezvousContact, RouteRecordModel, RouteStore, RouteStoreLimits,
    compare_distance, rendezvous_node_id, route_key, sample_score,
};
pub use runtime::{
    ConfirmedReservation, EndpointReservation, HnsrService, RelayConfig, RelayLimits, RelayService,
    RendezvousService,
};

use hns_encoding::DecodeError;
use thiserror::Error;

pub const HNSR_RENDEZVOUS_SERVICE: u64 = 0x0400_0000;
pub const HNSR_RELAY_SERVICE: u64 = 0x0800_0000;
pub const HNSR_PACKET_TYPE: u8 = 0xf3;
pub const HNSR_VERSION: u8 = 1;
pub const HNS_NODE_V1: u16 = 1;
pub const HNS_WEB_V1: u16 = 2;
pub const HNS_CHAT_V1: u16 = hns_chat_protocol::HNS_CHAT_PROFILE_V1;

pub const MAX_PACKET_SIZE: usize = 65_535;
pub const MAX_RECORD_SIZE: usize = 8192;
pub const MAX_RECORDS_PER_KEY: usize = 16;
pub const MAX_STORED_RECORDS: usize = 50_000;
pub const MAX_CONTACTS: usize = 16;
pub const MAX_ROUTING_CONTACTS: usize = 2048;
pub const MAX_FIND_QUERIES: usize = 32;
pub const ROUTE_REPLICATION: usize = 8;
pub const MIN_ROUTE_STORES: usize = 3;
pub const MAX_DATA_SIZE: usize = 16_384;
pub const MAX_CIRCUIT_QUEUE: usize = 65_536;
pub const MIN_WINDOW: u32 = 16_384;
pub const DEFAULT_WINDOW: u32 = 65_536;
pub const MAX_WINDOW: u32 = 1_048_576;
pub const MAX_TICKET_LIFETIME: u64 = 7200;
pub const MAX_ROUTE_LIFETIME: u64 = 7200;
pub const MAX_DELEGATION_LIFETIME: u64 = 604_800;
pub const MAX_CIRCUITS: u16 = 32;
pub const MAX_SIGNATURE_SIZE: usize = 80;

#[derive(Debug, Error)]
pub enum HnsrProtocolError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("invalid HNSR value: {0}")]
    Invalid(&'static str),
    #[error("HNSR field length {actual} exceeds maximum {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("HNSR signature operation failed")]
    Cryptography,
    #[error("invalid owner-bound HNS Chat identity: {0}")]
    OwnerBinding(#[from] hns_chat_protocol::ChatProtocolError),
    #[error("HNSR route store capacity reached")]
    Capacity,
    #[error("HNSR signature verification rate limit reached")]
    VerificationRateLimited,
    #[error("stale HNSR endpoint-delegation or route sequence")]
    StaleSequence,
    #[error("conflicting canonical HNSR endpoint delegations or routes have the same sequence")]
    ConflictingSequence,
    #[error("corrupt HNSR named-route replay-ledger snapshot")]
    CorruptNamedRouteLedgerSnapshot,
    #[error("incompatible HNSR named-route replay-ledger snapshot")]
    IncompatibleNamedRouteLedgerSnapshot,
    #[error("HNSR named-route replay-ledger revision space exhausted")]
    NamedRouteLedgerRevisionExhausted,
    #[error("corrupt HNSR named-route requester snapshot")]
    CorruptNamedRouteRequesterSnapshot,
    #[error("incompatible HNSR named-route requester snapshot")]
    IncompatibleNamedRouteRequesterSnapshot,
    #[error("HNSR named-route requester revision space exhausted")]
    NamedRouteRequesterRevisionExhausted,
    #[error("HNSR trusted clock rollback detected")]
    ClockRollback,
}

pub(crate) fn is_zero(value: &[u8]) -> bool {
    value.iter().all(|byte| *byte == 0)
}
