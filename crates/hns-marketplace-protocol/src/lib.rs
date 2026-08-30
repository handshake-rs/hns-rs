#![doc = "Canonical Handshake marketplace and bilateral cross-chain wire protocols."]

mod crypto;
mod denuo;
mod direct;
mod relay_acceptance;
mod swap;
mod types;

pub use denuo::*;
pub use direct::*;
pub use relay_acceptance::*;
pub use swap::*;
pub use types::*;

use thiserror::Error;

// Version 2 makes the maker-selected swap session identifier part of every
// signed direct offer. Version 1 let a taker supply an unrelated identifier,
// which could not be reconciled with the maker settlement key advertised by
// the offer.
pub const MARKETPLACE_PROTOCOL_VERSION: u16 = 2;

#[derive(Debug, Error)]
pub enum MarketplaceError {
    #[error(transparent)]
    Decode(#[from] hns_encoding::DecodeError),
    #[error(transparent)]
    Envelope(#[from] hns_p2p_experimental::EnvelopeError),
    #[error(transparent)]
    Swap(#[from] hns_swap::SwapError),
    #[error("unsupported marketplace protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("invalid marketplace field: {0}")]
    Invalid(&'static str),
    #[error("marketplace object is {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("marketplace arithmetic overflow")]
    ArithmeticOverflow,
    #[error("invalid or noncanonical marketplace signature")]
    InvalidSignature,
    #[error("signing key does not match the advertised public key")]
    SigningKeyMismatch,
    #[error("marketplace object is bound to another network")]
    NetworkMismatch,
    #[error("marketplace object is not valid until {created_at}; current time is {now}")]
    NotYetValid { created_at: u64, now: u64 },
    #[error("marketplace object expired at {expires_at}; current time is {now}")]
    Expired { expires_at: u64, now: u64 },
    #[error("marketplace object hash differs from its canonical fields")]
    HashMismatch,
    #[error("Denuo message type {message_type} is unknown for protocol {protocol_id}")]
    UnknownMessage { protocol_id: u16, message_type: u16 },
}

pub type Result<T> = core::result::Result<T, MarketplaceError>;

pub(crate) fn ensure_size(bytes: Vec<u8>, maximum: usize) -> Result<Vec<u8>> {
    if bytes.len() > maximum {
        Err(MarketplaceError::TooLarge {
            actual: bytes.len(),
            maximum,
        })
    } else {
        Ok(bytes)
    }
}
