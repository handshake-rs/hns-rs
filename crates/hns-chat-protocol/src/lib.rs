#![doc = "Owner-bound HNS Chat identity and opaque HIP-78 mailbox values."]

mod binding;
mod owner;
mod wire;

pub use binding::{
    ChatIdentityBindingV1, ChatKeyMode, encode_chat_binding, parse_chat_binding,
    select_chat_binding, select_chat_binding_from_resource,
};
pub use owner::{
    ChatIdentityTrust, VerifiedOwnerBindingV1, owner_authority_record,
    resolve_compressed_owner_key, verify_current_owner_binding, xonly_from_compressed_public_key,
};
pub use wire::{
    ChatAcknowledgementV1, ChatEnvelopeV1, HNS_CHAT_WIRE_VERSION,
    MAX_CHAT_ACKNOWLEDGEMENT_SIZE, MAX_CHAT_ACKNOWLEDGEMENT_WIRE_SIZE,
    MAX_CHAT_CIPHERTEXT_SIZE, MAX_CHAT_ENVELOPE_SIZE, MAX_CHAT_EXPIRATION_WINDOW,
    validate_unique_message_ids,
};

use hns_encoding::DecodeError;
use thiserror::Error;

/// Canonical HNSA service name for owner-bound HNS Chat.
pub const HNS_CHAT_SERVICE_NAME: &str = "hns.chat";
/// Canonical HNSR service profile allocated by the HNSR profile registry.
pub const HNS_CHAT_PROFILE_V1: u16 = 3;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ChatProtocolError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("invalid HNS Chat value: {0}")]
    Invalid(&'static str),
    #[error("HNS Chat value is {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("hnschat resource binding is missing")]
    MissingBinding,
    #[error("multiple hnschat resource bindings are ambiguous")]
    AmbiguousBinding,
    #[error("current owner output is not a supported version-0 single-key program")]
    UnsupportedOwnerScript,
    #[error("hnschat x-only key does not control the current owner output")]
    StaleOwner,
    #[error("both x-only public-key parities match the current owner output")]
    AmbiguousOwnerKey,
    #[error("duplicate HNS Chat message identifier")]
    DuplicateMessageId,
}
