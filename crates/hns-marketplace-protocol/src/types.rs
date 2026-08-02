use core::cmp::Ordering;

use hns_encoding::{Decoder, Encoder};
use hns_primitives::BlockHash;

use crate::{MARKETPLACE_PROTOCOL_VERSION, MarketplaceError, Result, ensure_size};

pub const MAX_PRIMITIVE_SIZE: usize = 256;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChainId(u16);

impl ChainId {
    pub const HANDSHAKE: Self = Self(1);
    pub const BITCOIN: Self = Self(2);
    pub const ETHEREUM: Self = Self(3);

    pub fn new(value: u16) -> Result<Self> {
        if value == 0 {
            Err(MarketplaceError::Invalid("zero chain identifier"))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }

    pub fn encode(self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(input);
        let value = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }

    pub(crate) fn encode_to(self, encoder: &mut Encoder) {
        encoder.put_u16_le(self.0);
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        Self::new(decoder.read_u16_le()?)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssetId {
    chain: ChainId,
    asset: u16,
}

impl AssetId {
    pub const HNS: Self = Self {
        chain: ChainId::HANDSHAKE,
        asset: 0,
    };
    pub const BTC: Self = Self {
        chain: ChainId::BITCOIN,
        asset: 0,
    };
    pub const ETH: Self = Self {
        chain: ChainId::ETHEREUM,
        asset: 0,
    };

    pub const fn new(chain: ChainId, asset: u16) -> Self {
        Self { chain, asset }
    }

    pub const fn chain(self) -> ChainId {
        self.chain
    }

    pub const fn asset(self) -> u16 {
        self.asset
    }

    pub fn encode(self) -> Vec<u8> {
        let mut encoder = Encoder::with_capacity(4);
        self.encode_to(&mut encoder);
        encoder.into_bytes()
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(input);
        let value = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }

    pub(crate) fn encode_to(self, encoder: &mut Encoder) {
        self.chain.encode_to(encoder);
        encoder.put_u16_le(self.asset);
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        Ok(Self::new(
            ChainId::decode_from(decoder)?,
            decoder.read_u16_le()?,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MarketPair {
    pub base: AssetId,
    pub quote: AssetId,
}

impl MarketPair {
    pub const HNS_BTC: Self = Self {
        base: AssetId::HNS,
        quote: AssetId::BTC,
    };
    pub const HNS_ETH: Self = Self {
        base: AssetId::HNS,
        quote: AssetId::ETH,
    };

    pub fn new(base: AssetId, quote: AssetId) -> Result<Self> {
        if base != AssetId::HNS || !matches!(quote, AssetId::BTC | AssetId::ETH) {
            return Err(MarketplaceError::Invalid(
                "market pair is not a canonical HNS/BTC or HNS/ETH pair",
            ));
        }
        Ok(Self { base, quote })
    }

    pub fn counterchain(self) -> Result<ChainId> {
        Self::new(self.base, self.quote)?;
        match (
            self.base.chain() == ChainId::HANDSHAKE,
            self.quote.chain() == ChainId::HANDSHAKE,
        ) {
            (true, false) => Ok(self.quote.chain()),
            (false, true) => Ok(self.base.chain()),
            _ => Err(MarketplaceError::Invalid(
                "market pair must contain exactly one Handshake asset",
            )),
        }
    }

    pub fn contains(self, asset: AssetId) -> bool {
        self.base == asset || self.quote == asset
    }

    pub fn other(self, asset: AssetId) -> Result<AssetId> {
        if asset == self.base {
            Ok(self.quote)
        } else if asset == self.quote {
            Ok(self.base)
        } else {
            Err(MarketplaceError::Invalid("asset is not in market pair"))
        }
    }

    pub fn encode(self) -> Result<Vec<u8>> {
        Self::new(self.base, self.quote)?;
        let mut encoder = Encoder::with_capacity(8);
        self.encode_to(&mut encoder);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(input);
        let value = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }

    pub(crate) fn encode_to(self, encoder: &mut Encoder) {
        self.base.encode_to(encoder);
        self.quote.encode_to(encoder);
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        Self::new(
            AssetId::decode_from(decoder)?,
            AssetId::decode_from(decoder)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AssetAmount(u128);

impl AssetAmount {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u128 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Result<Self> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(MarketplaceError::ArithmeticOverflow)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(MarketplaceError::ArithmeticOverflow)
    }

    pub fn encode(self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(input);
        let value = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }

    pub(crate) fn encode_to(self, encoder: &mut Encoder) {
        encoder.put_bytes(&self.0.to_le_bytes());
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        Ok(Self(u128::from_le_bytes(decoder.read_array()?)))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RationalPrice {
    numerator: u128,
    denominator: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rounding {
    Down,
    Up,
}

impl RationalPrice {
    pub fn new(numerator: u128, denominator: u128) -> Result<Self> {
        if numerator == 0 || denominator == 0 {
            return Err(MarketplaceError::Invalid(
                "price numerator and denominator must be nonzero",
            ));
        }
        let divisor = gcd(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    pub const fn numerator(self) -> u128 {
        self.numerator
    }

    pub const fn denominator(self) -> u128 {
        self.denominator
    }

    pub fn quote(self, base: AssetAmount, rounding: Rounding) -> Result<AssetAmount> {
        let product = base
            .get()
            .checked_mul(self.numerator)
            .ok_or(MarketplaceError::ArithmeticOverflow)?;
        let quotient = product / self.denominator;
        let remainder = product % self.denominator;
        if rounding == Rounding::Up && remainder != 0 {
            quotient
                .checked_add(1)
                .map(AssetAmount::new)
                .ok_or(MarketplaceError::ArithmeticOverflow)
        } else {
            Ok(AssetAmount::new(quotient))
        }
    }

    pub fn encode(self) -> Vec<u8> {
        let mut encoder = Encoder::with_capacity(32);
        self.encode_to(&mut encoder);
        encoder.into_bytes()
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(input);
        let value = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }

    pub(crate) fn encode_to(self, encoder: &mut Encoder) {
        encoder.put_bytes(&self.numerator.to_le_bytes());
        encoder.put_bytes(&self.denominator.to_le_bytes());
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        let numerator = u128::from_le_bytes(decoder.read_array()?);
        let denominator = u128::from_le_bytes(decoder.read_array()?);
        let canonical = Self::new(numerator, denominator)?;
        if canonical.numerator != numerator || canonical.denominator != denominator {
            return Err(MarketplaceError::Invalid("non-reduced rational price"));
        }
        Ok(canonical)
    }
}

impl Ord for RationalPrice {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_fractions(
            self.numerator,
            self.denominator,
            other.numerator,
            other.denominator,
        )
    }
}

impl PartialOrd for RationalPrice {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NetworkBinding {
    pub hns_magic: u32,
    pub hns_genesis: BlockHash,
    pub counterchain: ChainId,
    pub counterchain_network: u64,
    pub counterchain_genesis: [u8; 32],
}

impl NetworkBinding {
    pub fn validate(self) -> Result<()> {
        if self.hns_magic == 0
            || self.hns_genesis.as_bytes() == &[0; 32]
            || self.counterchain == ChainId::HANDSHAKE
            || self.counterchain_network == 0
            || self.counterchain_genesis == [0; 32]
        {
            return Err(MarketplaceError::Invalid("invalid network binding"));
        }
        Ok(())
    }

    pub fn validate_for_pair(self, pair: MarketPair) -> Result<()> {
        self.validate()?;
        if pair.counterchain()? != self.counterchain {
            return Err(MarketplaceError::Invalid(
                "network counterchain differs from market pair",
            ));
        }
        Ok(())
    }

    pub fn encode(self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(78);
        self.encode_to(&mut encoder);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(input);
        let value = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(value)
    }

    pub(crate) fn encode_to(self, encoder: &mut Encoder) {
        encoder.put_u32_le(self.hns_magic);
        encoder.put_bytes(self.hns_genesis.as_bytes());
        self.counterchain.encode_to(encoder);
        encoder.put_u64_le(self.counterchain_network);
        encoder.put_bytes(&self.counterchain_genesis);
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        let value = Self {
            hns_magic: decoder.read_u32_le()?,
            hns_genesis: BlockHash::new(decoder.read_array()?),
            counterchain: ChainId::decode_from(decoder)?,
            counterchain_network: decoder.read_u64_le()?,
            counterchain_genesis: decoder.read_array()?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChainAnchor {
    pub chain: ChainId,
    pub height: u64,
    pub block_hash: [u8; 32],
}

impl ChainAnchor {
    pub fn validate(self) -> Result<()> {
        if self.block_hash == [0; 32] {
            Err(MarketplaceError::Invalid("zero chain-anchor block hash"))
        } else {
            Ok(())
        }
    }

    pub(crate) fn encode_to(self, encoder: &mut Encoder) {
        self.chain.encode_to(encoder);
        encoder.put_u64_le(self.height);
        encoder.put_bytes(&self.block_hash);
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        Ok(Self {
            chain: ChainId::decode_from(decoder)?,
            height: decoder.read_u64_le()?,
            block_hash: decoder.read_array()?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedObjectHeader {
    pub version: u16,
    pub network: NetworkBinding,
    pub pair: MarketPair,
    pub signer_public_key: [u8; 33],
    pub sequence: u64,
    pub created_at: u64,
    pub expires_at: u64,
}

impl SignedObjectHeader {
    pub fn validate(&self) -> Result<()> {
        if self.version != MARKETPLACE_PROTOCOL_VERSION {
            return Err(MarketplaceError::UnsupportedVersion(self.version));
        }
        self.network.validate_for_pair(self.pair)?;
        crate::crypto::validate_public_key(&self.signer_public_key)?;
        if self.sequence == 0 || self.created_at >= self.expires_at {
            return Err(MarketplaceError::Invalid(
                "invalid sequence or validity interval",
            ));
        }
        Ok(())
    }

    pub fn validate_at(&self, expected_network: NetworkBinding, now: u64) -> Result<()> {
        self.validate()?;
        if self.network != expected_network {
            return Err(MarketplaceError::NetworkMismatch);
        }
        if now < self.created_at {
            return Err(MarketplaceError::NotYetValid {
                created_at: self.created_at,
                now,
            });
        }
        if now >= self.expires_at {
            return Err(MarketplaceError::Expired {
                expires_at: self.expires_at,
                now,
            });
        }
        Ok(())
    }

    pub(crate) fn encode_to(&self, encoder: &mut Encoder) {
        encoder.put_u16_le(self.version);
        self.network.encode_to(encoder);
        self.pair.encode_to(encoder);
        encoder.put_bytes(&self.signer_public_key);
        encoder.put_u64_le(self.sequence);
        encoder.put_u64_le(self.created_at);
        encoder.put_u64_le(self.expires_at);
    }

    pub(crate) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        let header = Self {
            version: decoder.read_u16_le()?,
            network: NetworkBinding::decode_from(decoder)?,
            pair: MarketPair::decode_from(decoder)?,
            signer_public_key: decoder.read_array()?,
            sequence: decoder.read_u64_le()?,
            created_at: decoder.read_u64_le()?,
            expires_at: decoder.read_u64_le()?,
        };
        header.validate()?;
        Ok(header)
    }
}

pub(crate) fn encode_nested(bytes: &[u8], encoder: &mut Encoder, maximum: usize) -> Result<()> {
    if bytes.len() > maximum {
        return Err(MarketplaceError::TooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    encoder.put_varbytes(bytes);
    Ok(())
}

pub(crate) fn decode_nested(
    decoder: &mut Decoder<'_>,
    maximum: usize,
    field: &'static str,
) -> Result<Vec<u8>> {
    Ok(decoder.read_varbytes(maximum, field)?)
}

pub(crate) fn encode_fixed_versioned<F>(maximum: usize, encode: F) -> Result<Vec<u8>>
where
    F: FnOnce(&mut Encoder) -> Result<()>,
{
    let mut encoder = Encoder::new();
    encode(&mut encoder)?;
    ensure_size(encoder.into_bytes(), maximum)
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let next = left % right;
        left = right;
        right = next;
    }
    left
}

fn compare_fractions(
    mut left_numerator: u128,
    mut left_denominator: u128,
    mut right_numerator: u128,
    mut right_denominator: u128,
) -> Ordering {
    let mut reverse = false;
    loop {
        let left_integer = left_numerator / left_denominator;
        let right_integer = right_numerator / right_denominator;
        let integer_order = left_integer.cmp(&right_integer);
        if integer_order != Ordering::Equal {
            return if reverse {
                integer_order.reverse()
            } else {
                integer_order
            };
        }

        let left_remainder = left_numerator % left_denominator;
        let right_remainder = right_numerator % right_denominator;
        let remainder_order = match (left_remainder == 0, right_remainder == 0) {
            (true, true) => return Ordering::Equal,
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => {
                left_numerator = left_denominator;
                left_denominator = left_remainder;
                right_numerator = right_denominator;
                right_denominator = right_remainder;
                reverse = !reverse;
                continue;
            }
        };
        return if reverse {
            remainder_order.reverse()
        } else {
            remainder_order
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_and_reduced_prices_are_canonical() {
        assert_eq!(hex::encode(ChainId::BITCOIN.encode()), "0200");
        assert_eq!(
            ChainId::decode(&ChainId::BITCOIN.encode()).unwrap(),
            ChainId::BITCOIN
        );
        assert!(ChainId::decode(&[0, 0]).is_err());
        assert_eq!(
            AssetId::decode(&AssetId::ETH.encode()).unwrap(),
            AssetId::ETH
        );
        assert_eq!(hex::encode(AssetId::HNS.encode()), "01000000");
        assert_eq!(
            MarketPair::decode(&MarketPair::HNS_BTC.encode().unwrap()).unwrap(),
            MarketPair::HNS_BTC
        );
        assert_eq!(
            hex::encode(MarketPair::HNS_BTC.encode().unwrap()),
            "0100000002000000"
        );
        assert!(MarketPair::new(AssetId::BTC, AssetId::ETH).is_err());
        assert!(MarketPair::new(AssetId::BTC, AssetId::HNS).is_err());
        let price = RationalPrice::new(6, 8).unwrap();
        assert_eq!((price.numerator(), price.denominator()), (3, 4));
        assert_eq!(RationalPrice::decode(&price.encode()).unwrap(), price);
        let mut noncanonical = Vec::new();
        noncanonical.extend_from_slice(&6_u128.to_le_bytes());
        noncanonical.extend_from_slice(&8_u128.to_le_bytes());
        assert!(RationalPrice::decode(&noncanonical).is_err());
        let amount = AssetAmount::new(u128::MAX);
        assert_eq!(AssetAmount::decode(&amount.encode()).unwrap(), amount);
        assert!(AssetAmount::decode(&amount.encode()[..15]).is_err());
        assert!(
            AssetAmount::new(0)
                .checked_sub(AssetAmount::new(1))
                .is_err()
        );
    }

    #[test]
    fn rational_comparison_and_rounding_do_not_use_floating_point() {
        let one_third = RationalPrice::new(1, 3).unwrap();
        let two_fifths = RationalPrice::new(2, 5).unwrap();
        assert!(one_third < two_fifths);
        assert_eq!(
            one_third
                .quote(AssetAmount::new(10), Rounding::Down)
                .unwrap()
                .get(),
            3
        );
        assert_eq!(
            one_third
                .quote(AssetAmount::new(10), Rounding::Up)
                .unwrap()
                .get(),
            4
        );
        assert!(
            RationalPrice::new(u128::MAX, 1)
                .unwrap()
                .quote(AssetAmount::new(2), Rounding::Down)
                .is_err()
        );
    }
}
