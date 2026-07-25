#![doc = "Canonical 236-byte Handshake headers and proof-of-work consensus."]

use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2b512, Blake2bVar, Digest as BlakeDigest};
use hns_encoding::{Decoder, Encoder};
use hns_primitives::{
    BlockHash, BlockTime, Chainwork, CompactTarget, Height, MerkleRoot, PowHash, PowMask,
    ReservedRoot, ShareHash, TreeRoot, WitnessRoot,
};
use sha3::{Digest as ShaDigest, Sha3_256};
use thiserror::Error;

pub const HEADER_SIZE: usize = 236;
pub const EXTRA_NONCE_SIZE: usize = 24;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub nonce: u32,
    pub time: BlockTime,
    pub previous_block: BlockHash,
    pub tree_root: TreeRoot,
    pub extra_nonce: [u8; EXTRA_NONCE_SIZE],
    pub reserved_root: ReservedRoot,
    pub witness_root: WitnessRoot,
    pub merkle_root: MerkleRoot,
    pub version: u32,
    pub bits: CompactTarget,
    pub mask: PowMask,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            nonce: 0,
            time: BlockTime::new(0),
            previous_block: BlockHash::default(),
            tree_root: TreeRoot::default(),
            extra_nonce: [0; EXTRA_NONCE_SIZE],
            reserved_root: ReservedRoot::default(),
            witness_root: WitnessRoot::default(),
            merkle_root: MerkleRoot::default(),
            version: 0,
            bits: CompactTarget::new(0),
            mask: PowMask::default(),
        }
    }
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut encoder = Encoder::with_capacity(HEADER_SIZE);
        encoder.put_u32_le(self.nonce);
        encoder.put_u64_le(self.time.get());
        encoder.put_bytes(self.previous_block.as_bytes());
        encoder.put_bytes(self.tree_root.as_bytes());
        encoder.put_bytes(&self.extra_nonce);
        encoder.put_bytes(self.reserved_root.as_bytes());
        encoder.put_bytes(self.witness_root.as_bytes());
        encoder.put_bytes(self.merkle_root.as_bytes());
        encoder.put_u32_le(self.version);
        encoder.put_u32_le(self.bits.get());
        encoder.put_bytes(self.mask.as_bytes());
        encoder
            .into_bytes()
            .try_into()
            .expect("header encoding is always 236 bytes")
    }

    pub fn decode(input: &[u8]) -> Result<Self, HeaderError> {
        if input.len() != HEADER_SIZE {
            return Err(HeaderError::InvalidLength {
                actual: input.len(),
            });
        }
        let mut decoder = Decoder::new(input);
        let header = Self {
            nonce: decoder.read_u32_le()?,
            time: BlockTime::new(decoder.read_u64_le()?),
            previous_block: BlockHash::new(decoder.read_array()?),
            tree_root: TreeRoot::new(decoder.read_array()?),
            extra_nonce: decoder.read_array()?,
            reserved_root: ReservedRoot::new(decoder.read_array()?),
            witness_root: WitnessRoot::new(decoder.read_array()?),
            merkle_root: MerkleRoot::new(decoder.read_array()?),
            version: decoder.read_u32_le()?,
            bits: CompactTarget::new(decoder.read_u32_le()?),
            mask: PowMask::new(decoder.read_array()?),
        };
        decoder.finish()?;
        Ok(header)
    }

    pub fn block_hash(&self) -> BlockHash {
        BlockHash::new(self.pow_hash().into_bytes())
    }

    pub fn subheader(&self) -> [u8; 128] {
        let mut encoder = Encoder::with_capacity(128);
        encoder.put_bytes(&self.extra_nonce);
        encoder.put_bytes(self.reserved_root.as_bytes());
        encoder.put_bytes(self.witness_root.as_bytes());
        encoder.put_bytes(self.merkle_root.as_bytes());
        encoder.put_u32_le(self.version);
        encoder.put_u32_le(self.bits.get());
        encoder
            .into_bytes()
            .try_into()
            .expect("subheader is always 128 bytes")
    }

    pub fn sub_hash(&self) -> [u8; 32] {
        blake2b_256(&[&self.subheader()])
    }

    pub fn mask_hash(&self) -> [u8; 32] {
        blake2b_256(&[self.previous_block.as_bytes(), self.mask.as_bytes()])
    }

    pub fn commit_hash(&self) -> [u8; 32] {
        blake2b_256(&[&self.sub_hash(), &self.mask_hash()])
    }

    pub fn preheader(&self) -> [u8; 128] {
        let mut encoder = Encoder::with_capacity(128);
        encoder.put_u32_le(self.nonce);
        encoder.put_u64_le(self.time.get());
        encoder.put_bytes(&self.padding::<20>());
        encoder.put_bytes(self.previous_block.as_bytes());
        encoder.put_bytes(self.tree_root.as_bytes());
        encoder.put_bytes(&self.commit_hash());
        encoder
            .into_bytes()
            .try_into()
            .expect("preheader is always 128 bytes")
    }

    pub fn share_hash(&self) -> ShareHash {
        let preheader = self.preheader();
        let left = blake2b_512(&preheader);
        let right = sha3_256(&[&preheader, &self.padding::<8>()]);
        ShareHash::new(blake2b_256(&[&left, &self.padding::<32>(), &right]))
    }

    pub fn pow_hash(&self) -> PowHash {
        let mut hash = self.share_hash().into_bytes();
        for (byte, mask) in hash.iter_mut().zip(self.mask.as_bytes()) {
            *byte ^= mask;
        }
        PowHash::new(hash)
    }

    pub fn verify_pow(&self) -> bool {
        DecodedTarget::from_compact(self.bits).is_met_by(self.pow_hash().as_bytes())
    }

    fn padding<const LENGTH: usize>(&self) -> [u8; LENGTH] {
        let mut output = [0_u8; LENGTH];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte =
                self.previous_block.as_bytes()[index % 32] ^ self.tree_root.as_bytes()[index % 32];
        }
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedTarget {
    bytes: [u8; 32],
    negative: bool,
    overflow: bool,
}

impl DecodedTarget {
    pub fn from_compact(bits: CompactTarget) -> Self {
        let bits = bits.get();
        if bits == 0 {
            return Self {
                bytes: [0; 32],
                negative: false,
                overflow: false,
            };
        }
        let exponent = (bits >> 24) as usize;
        let negative = bits & 0x0080_0000 != 0;
        let mantissa = bits & 0x007f_ffff;
        let mut bytes = [0_u8; 32];
        let mut overflow = false;
        if exponent <= 3 {
            let value = mantissa >> (8 * (3 - exponent));
            bytes[29..32].copy_from_slice(&value.to_be_bytes()[1..4]);
        } else {
            let mantissa_bytes = [
                ((mantissa >> 16) & 0xff) as u8,
                ((mantissa >> 8) & 0xff) as u8,
                (mantissa & 0xff) as u8,
            ];
            for (offset, byte) in mantissa_bytes.into_iter().enumerate() {
                let position = 32_isize - exponent as isize + offset as isize;
                if !(0..32).contains(&position) {
                    overflow |= byte != 0;
                } else {
                    bytes[position as usize] = byte;
                }
            }
        }
        Self {
            bytes,
            negative,
            overflow,
        }
    }

    pub const fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn is_valid(&self) -> bool {
        !self.negative && !self.overflow && self.bytes.iter().any(|byte| *byte != 0)
    }

    pub fn is_met_by(&self, hash: &[u8; 32]) -> bool {
        self.is_valid() && hash <= &self.bytes
    }

    pub fn proof(&self) -> Option<Chainwork> {
        if !self.is_valid() {
            return None;
        }
        U256::from_be_bytes(self.bytes)
            .work_for_target()
            .map(|work| Chainwork::from_be_bytes(work.to_be_bytes()))
    }

    pub fn to_compact(self) -> CompactTarget {
        let Some(first) = self.bytes.iter().position(|byte| *byte != 0) else {
            return CompactTarget::new(0);
        };
        let mut exponent = 32 - first;
        let mut mantissa = if exponent <= 3 {
            let mut value = 0_u32;
            for byte in &self.bytes[first..] {
                value = (value << 8) | u32::from(*byte);
            }
            value << (8 * (3 - exponent))
        } else {
            (u32::from(self.bytes[first]) << 16)
                | (u32::from(self.bytes[first + 1]) << 8)
                | u32::from(self.bytes[first + 2])
        };
        if mantissa & 0x0080_0000 != 0 {
            mantissa >>= 8;
            exponent += 1;
        }
        CompactTarget::new(((exponent as u32) << 24) | mantissa)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
    Simnet,
}

impl Network {
    pub const fn id(self) -> u8 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet => 1,
            Self::Regtest => 2,
            Self::Simnet => 3,
        }
    }

    pub const fn parameters(self) -> NetworkParameters {
        match self {
            Self::Mainnet => NetworkParameters {
                network: self,
                packet_magic: 0x5b6e_f2d3,
                port: 12_038,
                brontide_port: 44_806,
                pow: PowParameters {
                    limit: hex32(
                        "0000000000ffff00000000000000000000000000000000000000000000000000",
                    ),
                    bits: CompactTarget::new(0x1c00_ffff),
                    target_window: 144,
                    target_spacing: 600,
                    target_timespan: 86_400,
                    minimum_actual_timespan: 21_600,
                    maximum_actual_timespan: 345_600,
                    target_reset: false,
                    no_retargeting: false,
                },
                genesis_hash: BlockHash::new(hex32(
                    "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0",
                )),
                genesis_time: BlockTime::new(1_580_745_078),
            },
            Self::Testnet => NetworkParameters {
                network: self,
                packet_magic: 0xb152_0dd2,
                port: 13_038,
                brontide_port: 45_806,
                pow: PowParameters {
                    limit: hex32(
                        "00000000ffff0000000000000000000000000000000000000000000000000000",
                    ),
                    bits: CompactTarget::new(0x1d00_ffff),
                    target_window: 144,
                    target_spacing: 600,
                    target_timespan: 86_400,
                    minimum_actual_timespan: 21_600,
                    maximum_actual_timespan: 345_600,
                    target_reset: true,
                    no_retargeting: false,
                },
                genesis_hash: BlockHash::new(hex32(
                    "b1520dd24372f82ec94ebf8cf9d9b037d419c4aa3575d05dec70aedd1b427901",
                )),
                genesis_time: BlockTime::new(1_580_745_079),
            },
            Self::Regtest => NetworkParameters {
                network: self,
                packet_magic: 0xae38_95cf,
                port: 14_038,
                brontide_port: 46_806,
                pow: PowParameters {
                    limit: hex32(
                        "7fffff0000000000000000000000000000000000000000000000000000000000",
                    ),
                    bits: CompactTarget::new(0x207f_ffff),
                    target_window: 144,
                    target_spacing: 600,
                    target_timespan: 86_400,
                    minimum_actual_timespan: 21_600,
                    maximum_actual_timespan: 345_600,
                    target_reset: true,
                    no_retargeting: true,
                },
                genesis_hash: BlockHash::new(hex32(
                    "ae3895cf597eff05b19e02a70ceeeecb9dc72dbfe6504a50e9343a72f06a87c5",
                )),
                genesis_time: BlockTime::new(1_580_745_080),
            },
            Self::Simnet => NetworkParameters {
                network: self,
                packet_magic: 0x0e64_8edc,
                port: 15_038,
                brontide_port: 47_806,
                pow: PowParameters {
                    limit: hex32(
                        "7fffff0000000000000000000000000000000000000000000000000000000000",
                    ),
                    bits: CompactTarget::new(0x207f_ffff),
                    target_window: 144,
                    target_spacing: 600,
                    target_timespan: 86_400,
                    minimum_actual_timespan: 21_600,
                    maximum_actual_timespan: 345_600,
                    target_reset: false,
                    no_retargeting: false,
                },
                genesis_hash: BlockHash::new(hex32(
                    "0e648edc9cddb179014658061ea3f666a45cf44881877ae506e6babefbef6992",
                )),
                genesis_time: BlockTime::new(1_580_745_081),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PowParameters {
    pub limit: [u8; 32],
    pub bits: CompactTarget,
    pub target_window: u32,
    pub target_spacing: u32,
    pub target_timespan: u32,
    pub minimum_actual_timespan: u32,
    pub maximum_actual_timespan: u32,
    pub target_reset: bool,
    pub no_retargeting: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkParameters {
    pub network: Network,
    pub packet_magic: u32,
    pub port: u16,
    pub brontide_port: u16,
    pub pow: PowParameters,
    pub genesis_hash: BlockHash,
    pub genesis_time: BlockTime,
}

impl NetworkParameters {
    pub const fn genesis_header(self) -> Header {
        Header {
            nonce: 0,
            time: self.genesis_time,
            previous_block: BlockHash::new([0; 32]),
            tree_root: TreeRoot::new([0; 32]),
            extra_nonce: [0; EXTRA_NONCE_SIZE],
            reserved_root: ReservedRoot::new([0; 32]),
            witness_root: WitnessRoot::new(hex32(
                "1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351",
            )),
            merkle_root: MerkleRoot::new(hex32(
                "8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15",
            )),
            version: 0,
            bits: self.pow.bits,
            mask: PowMask::new([0; 32]),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DifficultyPoint {
    pub height: Height,
    pub time: BlockTime,
    pub bits: CompactTarget,
    pub chainwork: Chainwork,
}

pub fn expected_next_bits(
    parameters: PowParameters,
    next_time: BlockTime,
    previous: DifficultyPoint,
    first_suitable: Option<DifficultyPoint>,
    last_suitable: Option<DifficultyPoint>,
) -> Result<CompactTarget, HeaderError> {
    if parameters.no_retargeting {
        return Ok(parameters.bits);
    }
    if parameters.target_reset
        && next_time.get()
            > previous
                .time
                .get()
                .saturating_add(u64::from(parameters.target_spacing) * 2)
    {
        return Ok(parameters.bits);
    }
    if previous.height.get() < parameters.target_window.saturating_add(2) {
        if previous.bits != parameters.bits {
            return Err(HeaderError::InvalidDifficulty);
        }
        return Ok(parameters.bits);
    }
    retarget_bits(
        parameters,
        first_suitable.ok_or(HeaderError::MissingDifficultyPoint)?,
        last_suitable.ok_or(HeaderError::MissingDifficultyPoint)?,
    )
}

pub fn retarget_bits(
    parameters: PowParameters,
    first: DifficultyPoint,
    last: DifficultyPoint,
) -> Result<CompactTarget, HeaderError> {
    if last.height <= first.height {
        return Err(HeaderError::InvalidDifficulty);
    }
    let work_delta = last
        .chainwork
        .checked_sub(first.chainwork)
        .map_err(|_| HeaderError::InvalidDifficulty)?;
    let scaled_work = work_delta
        .checked_mul_u64(u64::from(parameters.target_spacing))
        .map_err(|_| HeaderError::InvalidDifficulty)?;
    let actual_timespan = last.time.get().saturating_sub(first.time.get()).clamp(
        u64::from(parameters.minimum_actual_timespan),
        u64::from(parameters.maximum_actual_timespan),
    );
    let work = scaled_work
        .checked_div_u64(actual_timespan)
        .map_err(|_| HeaderError::InvalidDifficulty)?;
    if work == Chainwork::ZERO {
        return Ok(parameters.bits);
    }
    let target = U256::from_be_bytes(work.to_be_bytes())
        .target_for_work()
        .ok_or(HeaderError::InvalidDifficulty)?;
    if target > U256::from_be_bytes(parameters.limit) {
        return Ok(parameters.bits);
    }
    Ok(DecodedTarget {
        bytes: target.to_be_bytes(),
        negative: false,
        overflow: false,
    }
    .to_compact())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeaderValidationContext {
    pub height: Height,
    pub previous_block: BlockHash,
    pub median_time: BlockTime,
    pub now: BlockTime,
    pub expected_bits: CompactTarget,
}

pub fn validate_header(
    parameters: NetworkParameters,
    header: &Header,
    context: HeaderValidationContext,
) -> Result<Chainwork, HeaderError> {
    let is_genesis = context.height.get() == 0;
    if is_genesis {
        if header != &parameters.genesis_header() || header.block_hash() != parameters.genesis_hash
        {
            return Err(HeaderError::WrongGenesis);
        }
    } else if header.previous_block != context.previous_block {
        return Err(HeaderError::WrongPreviousBlock);
    }
    if header.time <= context.median_time
        || header.time.get() > context.now.get().saturating_add(7200)
    {
        return Err(HeaderError::InvalidTime);
    }
    if header.bits != context.expected_bits {
        return Err(HeaderError::InvalidDifficulty);
    }
    let target = DecodedTarget::from_compact(header.bits);
    if !is_genesis && !target.is_met_by(header.pow_hash().as_bytes()) {
        return Err(HeaderError::InvalidProofOfWork);
    }
    target.proof().ok_or(HeaderError::InvalidProofOfWork)
}

#[derive(Debug, Error)]
pub enum HeaderError {
    #[error(transparent)]
    Decode(#[from] hns_encoding::DecodeError),
    #[error("Handshake header must be exactly 236 bytes, got {actual}")]
    InvalidLength { actual: usize },
    #[error("header does not match the selected network genesis")]
    WrongGenesis,
    #[error("header does not connect to the expected previous block")]
    WrongPreviousBlock,
    #[error("invalid header time")]
    InvalidTime,
    #[error("invalid header difficulty")]
    InvalidDifficulty,
    #[error("missing suitable difficulty point")]
    MissingDifficultyPoint,
    #[error("header proof of work does not meet target")]
    InvalidProofOfWork,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct U256([u8; 32]);

impl U256 {
    const ZERO: Self = Self([0; 32]);
    const ONE: Self = Self::from_u64(1);

    const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    const fn from_u64(value: u64) -> Self {
        let mut bytes = [0_u8; 32];
        let value = value.to_be_bytes();
        let mut index = 0;
        while index < 8 {
            bytes[24 + index] = value[index];
            index += 1;
        }
        Self(bytes)
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        let mut output = [0_u8; 32];
        let mut carry = 0_u16;
        for index in (0..32).rev() {
            let sum = u16::from(self.0[index]) + u16::from(other.0[index]) + carry;
            output[index] = sum as u8;
            carry = sum >> 8;
        }
        (carry == 0).then_some(Self(output))
    }

    fn work_for_target(self) -> Option<Self> {
        if self == Self::ZERO {
            return None;
        }
        let Some(divisor) = self.checked_add(Self::ONE) else {
            return Some(Self::ONE);
        };
        Self::divide_two_to_256(divisor)
    }

    fn target_for_work(self) -> Option<Self> {
        if self == Self::ZERO {
            return None;
        }
        if self == Self::ONE {
            return Some(Self([0xff; 32]));
        }
        Self::divide_two_to_256(self)?.checked_sub(Self::ONE)
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        (self >= other).then(|| self.wrapping_sub(other))
    }

    fn shift_left_one(&mut self) -> bool {
        let high = self.0[0] & 0x80 != 0;
        let mut carry = 0_u8;
        for byte in self.0.iter_mut().rev() {
            let next_carry = *byte >> 7;
            *byte = (*byte << 1) | carry;
            carry = next_carry;
        }
        high
    }

    fn wrapping_sub(self, other: Self) -> Self {
        let mut output = [0_u8; 32];
        let mut borrow = 0_i16;
        for index in (0..32).rev() {
            let difference = i16::from(self.0[index]) - i16::from(other.0[index]) - borrow;
            if difference < 0 {
                output[index] = (difference + 256) as u8;
                borrow = 1;
            } else {
                output[index] = difference as u8;
                borrow = 0;
            }
        }
        Self(output)
    }

    fn set_bit(&mut self, bit: usize) {
        self.0[31 - bit / 8] |= 1 << (bit % 8);
    }

    fn divide_two_to_256(divisor: Self) -> Option<Self> {
        if divisor <= Self::ONE {
            return None;
        }
        let mut remainder = Self::ZERO;
        let mut quotient = Self::ZERO;
        for bit in (0..=256).rev() {
            let high = remainder.shift_left_one();
            if bit == 256 {
                remainder.0[31] |= 1;
            }
            if high || remainder >= divisor {
                remainder = remainder.wrapping_sub(divisor);
                if bit < 256 {
                    quotient.set_bit(bit);
                }
            }
        }
        Some(quotient)
    }
}

fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    for part in parts {
        Update::update(&mut hasher, part);
    }
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

fn blake2b_512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    BlakeDigest::update(&mut hasher, input);
    hasher.finalize().into()
}

fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for part in parts {
        ShaDigest::update(&mut hasher, part);
    }
    hasher.finalize().into()
}

const fn hex32(value: &str) -> [u8; 32] {
    let bytes = value.as_bytes();
    assert!(bytes.len() == 64);
    let mut output = [0_u8; 32];
    let mut index = 0;
    while index < 32 {
        output[index] = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    output
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hexadecimal constant"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips_in_exact_hsd_order() {
        let raw = (0..HEADER_SIZE)
            .map(|index| index as u8)
            .collect::<Vec<_>>();
        let header = Header::decode(&raw).expect("valid");
        assert_eq!(header.nonce, 0x0302_0100);
        assert_eq!(header.time.get(), 0x0b0a_0908_0706_0504);
        assert_eq!(header.encode().as_slice(), raw);
    }

    #[test]
    fn network_genesis_hashes_match_hsd() {
        for network in [
            Network::Mainnet,
            Network::Testnet,
            Network::Regtest,
            Network::Simnet,
        ] {
            let parameters = network.parameters();
            let genesis = parameters.genesis_header();
            assert_eq!(genesis.block_hash(), parameters.genesis_hash);
            assert_eq!(
                validate_header(
                    parameters,
                    &genesis,
                    HeaderValidationContext {
                        height: Height::new(0),
                        previous_block: BlockHash::default(),
                        median_time: BlockTime::new(0),
                        now: genesis.time,
                        expected_bits: genesis.bits,
                    },
                )
                .expect("valid genesis"),
                DecodedTarget::from_compact(genesis.bits)
                    .proof()
                    .expect("work")
            );
        }
    }

    #[test]
    fn compact_targets_and_chainwork_match_hsd_boundaries() {
        for bits in [
            0x0112_0000,
            0x0201_2300,
            0x0312_3456,
            0x0412_3456,
            0x1d00_ffff,
            0x207f_ffff,
        ] {
            let compact = CompactTarget::new(bits);
            let target = DecodedTarget::from_compact(compact);
            assert!(target.is_valid());
            assert_eq!(target.to_compact(), compact);
        }
        assert_eq!(
            DecodedTarget::from_compact(CompactTarget::new(0x207f_ffff))
                .proof()
                .expect("proof")
                .to_be_bytes(),
            Chainwork::from_limbs_le([2, 0, 0, 0]).to_be_bytes()
        );
    }

    #[test]
    fn retarget_matches_pinned_hsd_half_timespan_vector() {
        let pow = Network::Mainnet.parameters().pow;
        let first = DifficultyPoint {
            height: Height::new(1000),
            time: BlockTime::new(1_000_000),
            bits: pow.bits,
            chainwork: Chainwork::from_be_bytes(hex32(
                "0000000000000000000000000000000000000000000000000123456789abcdef",
            )),
        };
        let last = DifficultyPoint {
            height: Height::new(first.height.get() + pow.target_window),
            time: BlockTime::new(first.time.get() + u64::from(pow.target_timespan / 2)),
            bits: pow.bits,
            chainwork: Chainwork::from_be_bytes(hex32(
                "0000000000000000000000000000000000000000000000000123d56819ac5def",
            )),
        };
        assert_eq!(
            retarget_bits(pow, first, last).expect("retarget"),
            CompactTarget::new(0x1b7f_ff80)
        );
    }

    #[test]
    fn validation_rejects_wrong_network_genesis() {
        let mainnet = Network::Mainnet.parameters();
        let testnet = Network::Testnet.parameters();
        let header = testnet.genesis_header();
        let context = HeaderValidationContext {
            height: Height::new(0),
            previous_block: BlockHash::default(),
            median_time: BlockTime::new(0),
            now: BlockTime::new(header.time.get()),
            expected_bits: header.bits,
        };
        assert!(matches!(
            validate_header(mainnet, &header, context),
            Err(HeaderError::WrongGenesis)
        ));
    }
}
