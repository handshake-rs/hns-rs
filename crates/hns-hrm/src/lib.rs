#![doc = "Deterministic objects and bounded validation for draft Handshake Resource Manifests."]
#![forbid(unsafe_code)]

pub mod cbor;
pub mod commitment;
pub mod model;
mod uri;
pub mod validation;

pub use cbor::{
    CborError, DecodeLimits, Value, decode_canonical, encode_canonical,
    encode_canonical_with_limits,
};
pub use commitment::{
    CommitmentError, CommitmentLimits, HrmCommitment, parse_txt_commitment, select_commitment,
};
pub use model::{
    ALGORITHM_SECP256K1_ECDSA, Controller, Delegation, Envelope, HrmModelError, Payload,
    ResourceAuthority, ResourceEntry, SignatureObject,
};
