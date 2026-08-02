#![doc = "Canonical Handshake marketplace and bilateral cross-chain wire protocols."]

mod crypto;
mod denuo;
mod market;
mod price;
mod swap;
mod types;

pub use denuo::*;
pub use market::*;
pub use price::*;
pub use swap::*;
pub use types::*;

use thiserror::Error;

pub const MARKETPLACE_PROTOCOL_VERSION: u16 = 1;

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
    #[error("price round has insufficient reporter or source quorum")]
    WeakQuorum,
    #[error("caller-supplied price reporter/source admission is invalid")]
    InvalidPriceAdmission,
    #[error("price round embeds a policy different from caller policy")]
    PricePolicyMismatch,
    #[error("price round contains a reporter not admitted by caller policy")]
    UnadmittedReporter,
    #[error("price round contains a source not admitted by caller policy")]
    UnadmittedSource,
    #[error("price round repeats a reporter")]
    DuplicateReporter,
    #[error("price round repeats a source")]
    DuplicateSource,
    #[error("price round canonical price differs from its deterministic median")]
    PriceMismatch,
    #[error("price round movement exceeds its circuit-breaker policy")]
    CircuitBreaker,
    #[error("price round does not link to the supplied previous round")]
    PreviousRoundMismatch,
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
