#![doc = "Handshake name covenants, authenticated state, and resource values."]

mod name_state;
mod resource;

pub use name_state::{
    HSD_MAX_SAFE_INTEGER, MAX_NAME_STATE_SIZE, NameState, decode_name_state, encode_name_state,
};
pub use resource::{Resource, ResourceName, ResourceRecord};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_encoding::{Decoder, Encoder};
use hns_primitives::NameHash;
use sha3::{Digest, Sha3_256};
use thiserror::Error;

pub const MAX_COVENANT_ITEMS: usize = 1000;
pub const MAX_COVENANT_ITEM_SIZE: usize = 1_000_000;
pub const MAX_COVENANT_ENCODED_SIZE: usize = MAX_COVENANT_ITEM_SIZE + 9;
pub const MAX_NAME_SIZE: usize = 63;
pub const MAX_RESOURCE_SIZE: usize = 512;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CovenantKind {
    None,
    Claim,
    Open,
    Bid,
    Reveal,
    Redeem,
    Register,
    Update,
    Renew,
    Transfer,
    Finalize,
    Revoke,
    Unknown(u8),
}

impl CovenantKind {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Claim,
            2 => Self::Open,
            3 => Self::Bid,
            4 => Self::Reveal,
            5 => Self::Redeem,
            6 => Self::Register,
            7 => Self::Update,
            8 => Self::Renew,
            9 => Self::Transfer,
            10 => Self::Finalize,
            11 => Self::Revoke,
            value => Self::Unknown(value),
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Claim => 1,
            Self::Open => 2,
            Self::Bid => 3,
            Self::Reveal => 4,
            Self::Redeem => 5,
            Self::Register => 6,
            Self::Update => 7,
            Self::Renew => 8,
            Self::Transfer => 9,
            Self::Finalize => 10,
            Self::Revoke => 11,
            Self::Unknown(value) => value,
        }
    }

    pub const fn is_name(self) -> bool {
        !matches!(self, Self::None | Self::Unknown(_))
    }

    pub const fn is_linked(self) -> bool {
        matches!(
            self,
            Self::Reveal
                | Self::Redeem
                | Self::Register
                | Self::Update
                | Self::Renew
                | Self::Transfer
                | Self::Finalize
                | Self::Revoke
        )
    }

    pub const fn is_unspendable(self) -> bool {
        matches!(self, Self::Revoke)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Covenant {
    pub kind: CovenantKind,
    pub items: Vec<Vec<u8>>,
}

impl Covenant {
    pub fn encode(&self) -> Result<Vec<u8>, CovenantError> {
        let encoded_size = self.encoded_size()?;
        let mut encoder = Encoder::with_capacity(encoded_size);
        encoder.put_u8(self.kind.as_u8());
        encoder.put_compact_size(self.items.len() as u64);
        for item in &self.items {
            encoder.put_varbytes(item);
        }
        Ok(encoder.into_bytes())
    }

    pub fn encoded_size(&self) -> Result<usize, CovenantError> {
        if self.items.len() > MAX_COVENANT_ITEMS {
            return Err(CovenantError::TooLarge {
                actual: self.items.len(),
                maximum: MAX_COVENANT_ITEMS,
            });
        }
        let mut encoded_size = 1_usize
            .checked_add(compact_size_len(self.items.len() as u64))
            .ok_or(CovenantError::TooLarge {
                actual: usize::MAX,
                maximum: MAX_COVENANT_ENCODED_SIZE,
            })?;
        for item in &self.items {
            if item.len() > MAX_COVENANT_ITEM_SIZE {
                return Err(CovenantError::TooLarge {
                    actual: item.len(),
                    maximum: MAX_COVENANT_ITEM_SIZE,
                });
            }
            encoded_size = encoded_size
                .checked_add(compact_size_len(item.len() as u64))
                .and_then(|size| size.checked_add(item.len()))
                .ok_or(CovenantError::TooLarge {
                    actual: usize::MAX,
                    maximum: MAX_COVENANT_ENCODED_SIZE,
                })?;
            if encoded_size > MAX_COVENANT_ENCODED_SIZE {
                return Err(CovenantError::TooLarge {
                    actual: encoded_size,
                    maximum: MAX_COVENANT_ENCODED_SIZE,
                });
            }
        }
        Ok(encoded_size)
    }

    pub fn decode(input: &[u8]) -> Result<Self, CovenantError> {
        if input.len() > MAX_COVENANT_ENCODED_SIZE {
            return Err(CovenantError::TooLarge {
                actual: input.len(),
                maximum: MAX_COVENANT_ENCODED_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        let covenant = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(covenant)
    }

    pub fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, CovenantError> {
        Self::decode_from_with_limit(decoder, MAX_COVENANT_ENCODED_SIZE)
    }

    pub fn decode_from_with_limit(
        decoder: &mut Decoder<'_>,
        maximum_encoded_size: usize,
    ) -> Result<Self, CovenantError> {
        let maximum_encoded_size = maximum_encoded_size.min(MAX_COVENANT_ENCODED_SIZE);
        if maximum_encoded_size < 2 {
            return Err(CovenantError::TooLarge {
                actual: 2,
                maximum: maximum_encoded_size,
            });
        }
        let start = decoder.position();
        let kind = CovenantKind::from_u8(decoder.read_u8()?);
        let count = decoder.read_compact_usize(MAX_COVENANT_ITEMS, "covenant items")?;
        ensure_decode_budget(decoder, start, maximum_encoded_size)?;
        let mut items = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let length = decoder.read_compact_usize(MAX_COVENANT_ITEM_SIZE, "covenant item")?;
            let remaining = ensure_decode_budget(decoder, start, maximum_encoded_size)?;
            if length > remaining {
                return Err(CovenantError::TooLarge {
                    actual: decoder
                        .position()
                        .saturating_sub(start)
                        .saturating_add(length),
                    maximum: maximum_encoded_size,
                });
            }
            items.push(decoder.read_bounded_vec(length, remaining)?);
        }
        Ok(Self { kind, items })
    }

    pub fn encode_to(&self, encoder: &mut Encoder) -> Result<(), CovenantError> {
        self.validate_bounds()?;
        encoder.put_u8(self.kind.as_u8());
        encoder.put_compact_size(self.items.len() as u64);
        for item in &self.items {
            encoder.put_varbytes(item);
        }
        Ok(())
    }

    pub fn item(&self, index: usize) -> Option<&[u8]> {
        self.items.get(index).map(Vec::as_slice)
    }

    pub fn item_u8(&self, index: usize) -> Option<u8> {
        let item = self.item(index)?;
        (item.len() == 1).then_some(item[0])
    }

    pub fn item_u32(&self, index: usize) -> Option<u32> {
        Some(u32::from_le_bytes(self.item(index)?.try_into().ok()?))
    }

    pub fn item_u64(&self, index: usize) -> Option<u64> {
        Some(u64::from_le_bytes(self.item(index)?.try_into().ok()?))
    }

    pub fn item_name_hash(&self, index: usize) -> Option<NameHash> {
        Some(NameHash::new(self.item(index)?.try_into().ok()?))
    }

    fn validate_bounds(&self) -> Result<(), CovenantError> {
        self.encoded_size()?;
        Ok(())
    }
}

fn ensure_decode_budget(
    decoder: &Decoder<'_>,
    start: usize,
    maximum: usize,
) -> Result<usize, CovenantError> {
    let consumed = decoder.position().saturating_sub(start);
    if consumed > maximum {
        return Err(CovenantError::TooLarge {
            actual: consumed,
            maximum,
        });
    }
    Ok(maximum - consumed)
}

fn compact_size_len(value: u64) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

impl Default for Covenant {
    fn default() -> Self {
        Self {
            kind: CovenantKind::None,
            items: Vec::new(),
        }
    }
}

pub fn validate_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_SIZE {
        return false;
    }
    if matches!(
        name,
        b"example" | b"invalid" | b"local" | b"localhost" | b"test"
    ) {
        return false;
    }
    name.iter().copied().enumerate().all(|(index, byte)| {
        matches!(byte, b'0'..=b'9' | b'a'..=b'z')
            || matches!(byte, b'-' | b'_') && index != 0 && index + 1 != name.len()
    })
}

pub fn hash_name(name: &[u8]) -> Result<NameHash, CovenantError> {
    if !validate_name(name) {
        return Err(CovenantError::InvalidName);
    }
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, name);
    Ok(NameHash::new(hasher.finalize().into()))
}

pub fn blind_bid(value: u64, nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    Update::update(&mut hasher, &value.to_le_bytes());
    Update::update(&mut hasher, nonce);
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

#[derive(Debug, Error)]
pub enum CovenantError {
    #[error(transparent)]
    Decode(#[from] hns_encoding::DecodeError),
    #[error("covenant field length {actual} exceeds maximum {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid Handshake name")]
    InvalidName,
    #[error("unsupported Handshake resource version")]
    UnsupportedResourceVersion,
    #[error("unsupported Handshake resource record type {kind}")]
    UnsupportedResourceRecord { kind: u8 },
    #[error("invalid Handshake resource: {0}")]
    InvalidResource(&'static str),
    #[error("invalid Handshake name state: {0}")]
    InvalidNameState(&'static str),
    #[error("noncanonical Handshake name-state encoding")]
    NonCanonicalNameState,
    #[error("name-state name does not match its authenticated-tree key")]
    NameStateHashMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_assigned_covenant_types_round_trip() {
        for value in 0_u8..=11 {
            let covenant = Covenant {
                kind: CovenantKind::from_u8(value),
                items: vec![vec![value], vec![2; 253]],
            };
            let encoded = covenant.encode().expect("valid");
            assert_eq!(Covenant::decode(&encoded).expect("valid"), covenant);
        }
    }

    #[test]
    fn names_and_bid_commitments_match_hsd_vectors() {
        assert_eq!(
            hex::encode(hash_name(b"handshake").expect("valid").into_bytes()),
            "3aa2528576f96bd40fcff0bd6b60c44221d73c43b4e42d4b908ed20a93b8d1b6"
        );
        assert_eq!(
            hex::encode(hash_name(b"hsd").expect("valid").into_bytes()),
            "1adba96cde054383892a08bb53ab627fb2a2842914d53bc5312e4c69f5688de1"
        );
        for invalid in [
            b"".as_slice(),
            b"Example",
            b"-bad",
            b"bad-",
            b"local",
            b"name!",
        ] {
            assert!(!validate_name(invalid), "{invalid:?}");
        }
        assert_eq!(
            hex::encode(blind_bid(700, &[0x21; 32])),
            "c82876caf7bfa613c5b64bd421bbc35f8f0654bc645b340a56b0df0c09668f81"
        );
    }

    #[test]
    fn codec_matches_pinned_hsd_fixture() {
        let raw = hex::decode(
            "030220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa046e616d65",
        )
        .expect("hex");
        let covenant = Covenant::decode(&raw).expect("valid");
        assert_eq!(covenant.kind, CovenantKind::Bid);
        assert_eq!(covenant.items, vec![vec![0xaa; 32], b"name".to_vec()]);
        assert_eq!(covenant.encode().expect("valid"), raw);
    }

    #[test]
    fn parser_rejects_noncanonical_and_oversized_items() {
        assert!(Covenant::decode(&[0, 0xfd, 0, 0]).is_err());
        assert!(
            Covenant {
                kind: CovenantKind::None,
                items: vec![vec![0; MAX_COVENANT_ITEM_SIZE + 1]],
            }
            .encode()
            .is_err()
        );
        assert!(Resource::new(Vec::new()).is_err());
    }

    #[test]
    fn bounded_stream_decode_rejects_claimed_item_before_copying() {
        let encoded = [0, 1, 0xfd, 0xfd, 0];
        let mut decoder = Decoder::new(&encoded);
        assert!(matches!(
            Covenant::decode_from_with_limit(&mut decoder, 10),
            Err(CovenantError::TooLarge {
                actual: 258,
                maximum: 10
            })
        ));
    }
}
