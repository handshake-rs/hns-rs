#![doc = "Canonical Handshake transaction, witness, address, and coin values."]

mod linkage;

pub use linkage::{CovenantLinkError, CovenantLinkSummary, verify_covenant_links};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_covenants::{Covenant, CovenantError};
use hns_encoding::{Decoder, Encoder};
use hns_primitives::{Dollarydoos, Height, TransactionHash};
use thiserror::Error;

pub const MAX_TRANSACTION_SIZE: usize = 1_000_000;
pub const MAX_WITNESS_ITEMS: usize = 1000;
pub const MAX_ADDRESS_HASH_SIZE: usize = 40;
pub const MIN_ADDRESS_HASH_SIZE: usize = 2;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Outpoint {
    pub transaction_hash: TransactionHash,
    pub index: u32,
}

impl Outpoint {
    pub const NULL: Self = Self {
        transaction_hash: TransactionHash::new([0; 32]),
        index: u32::MAX,
    };

    pub fn is_null(self) -> bool {
        self.index == u32::MAX && self.transaction_hash.into_bytes() == [0; 32]
    }

    pub fn encode(self) -> [u8; 36] {
        let mut encoder = Encoder::with_capacity(36);
        self.encode_to(&mut encoder);
        encoder
            .into_bytes()
            .try_into()
            .expect("outpoint encoding has a fixed length")
    }

    fn encode_to(self, encoder: &mut Encoder) {
        encoder.put_bytes(self.transaction_hash.as_bytes());
        encoder.put_u32_le(self.index);
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, TransactionError> {
        Ok(Self {
            transaction_hash: TransactionHash::new(decoder.read_array()?),
            index: decoder.read_u32_le()?,
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Witness {
    pub items: Vec<Vec<u8>>,
}

impl Witness {
    fn encode_to(&self, encoder: &mut Encoder) -> Result<(), TransactionError> {
        if self.items.len() > MAX_WITNESS_ITEMS {
            return Err(TransactionError::TooLarge {
                actual: self.items.len(),
                maximum: MAX_WITNESS_ITEMS,
            });
        }
        encoder.put_compact_size(self.items.len() as u64);
        for item in &self.items {
            if item.len() > MAX_TRANSACTION_SIZE {
                return Err(TransactionError::TooLarge {
                    actual: item.len(),
                    maximum: MAX_TRANSACTION_SIZE,
                });
            }
            encoder.put_varbytes(item);
        }
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, TransactionError> {
        let count = decoder.read_compact_usize(MAX_WITNESS_ITEMS, "witness items")?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(decoder.read_varbytes(MAX_TRANSACTION_SIZE, "witness item")?);
        }
        Ok(Self { items })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Input {
    pub previous_output: Outpoint,
    pub sequence: u32,
    pub witness: Witness,
}

impl Input {
    fn encode_base_to(&self, encoder: &mut Encoder) {
        self.previous_output.encode_to(encoder);
        encoder.put_u32_le(self.sequence);
    }

    fn decode_base_from(decoder: &mut Decoder<'_>) -> Result<Self, TransactionError> {
        Ok(Self {
            previous_output: Outpoint::decode_from(decoder)?,
            sequence: decoder.read_u32_le()?,
            witness: Witness::default(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address {
    pub version: u8,
    pub hash: Vec<u8>,
}

impl Address {
    pub fn new(version: u8, hash: Vec<u8>) -> Result<Self, TransactionError> {
        let address = Self { version, hash };
        address.validate()?;
        Ok(address)
    }

    pub const fn is_null_data(&self) -> bool {
        self.version == 31
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.version > 31 {
            return Err(TransactionError::InvalidAddress("version exceeds 31"));
        }
        if !(MIN_ADDRESS_HASH_SIZE..=MAX_ADDRESS_HASH_SIZE).contains(&self.hash.len()) {
            return Err(TransactionError::InvalidAddress(
                "hash length is outside 2..=40",
            ));
        }
        if self.version == 0 && !matches!(self.hash.len(), 20 | 32) {
            return Err(TransactionError::InvalidAddress(
                "version 0 program must be 20 or 32 bytes",
            ));
        }
        Ok(())
    }

    fn encode_to(&self, encoder: &mut Encoder) -> Result<(), TransactionError> {
        self.validate()?;
        encoder.put_u8(self.version);
        encoder.put_u8(self.hash.len() as u8);
        encoder.put_bytes(&self.hash);
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, TransactionError> {
        let version = decoder.read_u8()?;
        let length = decoder.read_u8()? as usize;
        let hash = decoder.read_bounded_vec(length, MAX_ADDRESS_HASH_SIZE)?;
        Self::new(version, hash)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Output {
    pub value: Dollarydoos,
    pub address: Address,
    pub covenant: Covenant,
}

impl Output {
    pub fn is_unspendable(&self) -> bool {
        self.address.is_null_data() || self.covenant.kind.is_unspendable()
    }

    pub fn encode(&self) -> Result<Vec<u8>, TransactionError> {
        let mut encoder = Encoder::new();
        self.encode_to(&mut encoder)?;
        Ok(encoder.into_bytes())
    }

    fn encode_to(&self, encoder: &mut Encoder) -> Result<(), TransactionError> {
        encoder.put_u64_le(self.value.get());
        self.address.encode_to(encoder)?;
        self.covenant.encode_to(encoder)?;
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, TransactionError> {
        Ok(Self {
            value: Dollarydoos::new(decoder.read_u64_le()?),
            address: Address::decode_from(decoder)?,
            covenant: Covenant::decode_from(decoder)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub locktime: u32,
}

impl Transaction {
    pub fn encode(&self) -> Result<Vec<u8>, TransactionError> {
        let base = self.base_encode()?;
        let witness = self.witness_encode()?;
        let size = base.len().saturating_add(witness.len());
        if size > MAX_TRANSACTION_SIZE {
            return Err(TransactionError::TooLarge {
                actual: size,
                maximum: MAX_TRANSACTION_SIZE,
            });
        }
        let mut output = Vec::with_capacity(size);
        output.extend(base);
        output.extend(witness);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, TransactionError> {
        if input.len() > MAX_TRANSACTION_SIZE {
            return Err(TransactionError::TooLarge {
                actual: input.len(),
                maximum: MAX_TRANSACTION_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        let version = decoder.read_u32_le()?;
        let input_count =
            decoder.read_compact_usize(MAX_TRANSACTION_SIZE / 40, "transaction inputs")?;
        let mut inputs = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            inputs.push(Input::decode_base_from(&mut decoder)?);
        }
        let output_count =
            decoder.read_compact_usize(MAX_TRANSACTION_SIZE / 12, "transaction outputs")?;
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(Output::decode_from(&mut decoder)?);
        }
        let locktime = decoder.read_u32_le()?;
        for input in &mut inputs {
            input.witness = Witness::decode_from(&mut decoder)?;
        }
        decoder.finish()?;
        Ok(Self {
            version,
            inputs,
            outputs,
            locktime,
        })
    }

    pub fn base_encode(&self) -> Result<Vec<u8>, TransactionError> {
        if self.inputs.len() > MAX_TRANSACTION_SIZE / 40
            || self.outputs.len() > MAX_TRANSACTION_SIZE / 12
        {
            return Err(TransactionError::TooLarge {
                actual: self.inputs.len().max(self.outputs.len()),
                maximum: MAX_TRANSACTION_SIZE / 12,
            });
        }
        let mut encoder = Encoder::new();
        encoder.put_u32_le(self.version);
        encoder.put_compact_size(self.inputs.len() as u64);
        for input in &self.inputs {
            input.encode_base_to(&mut encoder);
        }
        encoder.put_compact_size(self.outputs.len() as u64);
        for output in &self.outputs {
            output.encode_to(&mut encoder)?;
        }
        encoder.put_u32_le(self.locktime);
        let output = encoder.into_bytes();
        if output.len() > MAX_TRANSACTION_SIZE {
            return Err(TransactionError::TooLarge {
                actual: output.len(),
                maximum: MAX_TRANSACTION_SIZE,
            });
        }
        Ok(output)
    }

    pub fn witness_encode(&self) -> Result<Vec<u8>, TransactionError> {
        let mut encoder = Encoder::new();
        for input in &self.inputs {
            input.witness.encode_to(&mut encoder)?;
        }
        Ok(encoder.into_bytes())
    }

    pub fn transaction_hash(&self) -> Result<TransactionHash, TransactionError> {
        Ok(TransactionHash::new(blake2b_256(&self.base_encode()?)))
    }

    pub fn witness_hash(&self) -> Result<[u8; 32], TransactionError> {
        let transaction_hash = self.transaction_hash()?;
        let witness_data_hash = blake2b_256(&self.witness_encode()?);
        Ok(blake2b_256_many(&[
            transaction_hash.as_bytes(),
            &witness_data_hash,
        ]))
    }

    pub fn base_size(&self) -> Result<usize, TransactionError> {
        Ok(self.base_encode()?.len())
    }

    pub fn size(&self) -> Result<usize, TransactionError> {
        Ok(self.encode()?.len())
    }

    pub fn weight(&self) -> Result<usize, TransactionError> {
        let base = self.base_size()?;
        let witness = self.witness_encode()?.len();
        base.checked_mul(4)
            .and_then(|weight| weight.checked_add(witness))
            .ok_or(TransactionError::ArithmeticOverflow)
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].previous_output.is_null()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Coin {
    pub outpoint: Outpoint,
    pub value: Dollarydoos,
    pub height: Height,
    pub coinbase: bool,
    pub address: Address,
    pub covenant: Covenant,
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error(transparent)]
    Decode(#[from] hns_encoding::DecodeError),
    #[error(transparent)]
    Covenant(#[from] CovenantError),
    #[error("transaction field length {actual} exceeds maximum {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid Handshake address: {0}")]
    InvalidAddress(&'static str),
    #[error("transaction arithmetic overflow")]
    ArithmeticOverflow,
}

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    blake2b_256_many(&[input])
}

fn blake2b_256_many(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

#[cfg(test)]
mod tests {
    use hns_covenants::CovenantKind;

    use super::*;

    #[test]
    fn codec_and_hashes_match_pinned_hsd_fixture() {
        let raw = hex::decode(
            "0100000001080808080808080808080808080808080808080808080808080808080808080802000000feffffff012a0000000000000000140909090909090909090909090909090909090909020103616263630000000203010203020405",
        )
        .expect("hex");
        let transaction = Transaction::decode(&raw).expect("valid");
        assert_eq!(transaction.encode().expect("valid"), raw);
        assert_eq!(transaction.base_size().expect("valid"), 86);
        assert_eq!(transaction.size().expect("valid"), 94);
        assert_eq!(
            transaction.transaction_hash().expect("valid").to_string(),
            "420f91c753c7ad480b3359f47ccbcab9e058a59d15fcd5e10bec66e04a55f274"
        );
        assert_eq!(
            hex::encode(transaction.witness_hash().expect("valid")),
            "fba6fa32ac4b157d754c951d98d1e6e5e13c8d705a72621cd944e835597980a2"
        );
    }

    #[test]
    fn null_data_and_revoke_outputs_are_unspendable() {
        let spendable = Output {
            value: Dollarydoos::new(1),
            address: Address::new(0, vec![1; 20]).expect("address"),
            covenant: Covenant::default(),
        };
        assert!(!spendable.is_unspendable());
        let null_data = Output {
            address: Address::new(31, vec![2; 2]).expect("address"),
            ..spendable.clone()
        };
        assert!(null_data.is_unspendable());
        let revoke = Output {
            covenant: Covenant {
                kind: CovenantKind::Revoke,
                items: Vec::new(),
            },
            ..spendable
        };
        assert!(revoke.is_unspendable());
    }

    #[test]
    fn noncanonical_counts_and_trailing_bytes_fail_closed() {
        assert!(Transaction::decode(&[1, 0, 0, 0, 0xfd, 0, 0]).is_err());
        let transaction = Transaction {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            locktime: 0,
        };
        let mut encoded = transaction.encode().expect("valid");
        encoded.push(0);
        assert!(Transaction::decode(&encoded).is_err());
    }
}
