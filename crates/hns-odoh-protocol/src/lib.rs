#![doc = "RFC 9230 records and draft HIP #77 Handshake transport messages."]

pub mod body;
pub mod config;
pub mod envelope;
pub mod message;

pub use body::{
    ClientQuery, GetConfigBody, ODOH_ROLE_CONFIG_CACHE, ODOH_ROLE_PROXY, ODOH_ROLE_TARGET,
    OdohCapabilities, OdohConfigBody, OdohErrorBody, OdohResponseBody, OdohStatus, TargetQuery,
};
pub use config::{DirectTargetLocator, OdohConfig, TargetConfigRecord};
pub use envelope::{OdnsPacket, OdohOpcode};
pub use message::{
    OdohMessage, OdohMessageType, OpenedQuery, QueryContext, decode_plaintext,
    derive_response_secrets, encode_plaintext, open_query, seal_query,
};

use hns_encoding::DecodeError;
use thiserror::Error;

pub const MAX_ODOH_QUERY_SIZE: usize = 8192;
pub const MAX_ODOH_RESPONSE_SIZE: usize = u16::MAX as usize;
pub const MAX_ODOH_PACKET_SIZE: usize = 12 + 4 + MAX_ODOH_RESPONSE_SIZE + 2 + 4096;
pub const MAX_ODOH_CONFIG_SIZE: usize = 16_384;
pub const MAX_OUTER_PADDING_SIZE: usize = 4096;
pub const MAX_ODOH_CONFIG_LIFETIME: u64 = 172_800;

#[derive(Debug, Error)]
pub enum OdohProtocolError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("invalid ODoH value: {0}")]
    Invalid(&'static str),
    #[error("ODoH field length {actual} exceeds maximum {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("ODoH cryptographic operation failed")]
    Cryptography,
    #[error("ODoH target configuration signature is invalid")]
    InvalidSignature,
}
