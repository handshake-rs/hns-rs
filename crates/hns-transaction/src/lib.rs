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
pub const MAX_TRANSACTION_RAW_SIZE: usize = 4_000_000;
pub const MAX_TRANSACTION_WEIGHT: usize = 4_000_000;
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
        self.encoded_size()?;
        encoder.put_compact_size(self.items.len() as u64);
        for item in &self.items {
            encoder.put_varbytes(item);
        }
        Ok(())
    }

    fn encoded_size(&self) -> Result<usize, TransactionError> {
        if self.items.len() > MAX_WITNESS_ITEMS {
            return Err(TransactionError::TooLarge {
                actual: self.items.len(),
                maximum: MAX_WITNESS_ITEMS,
            });
        }
        let mut size = compact_size_len(self.items.len() as u64);
        for item in &self.items {
            if item.len() > MAX_TRANSACTION_RAW_SIZE {
                return Err(TransactionError::TooLarge {
                    actual: item.len(),
                    maximum: MAX_TRANSACTION_RAW_SIZE,
                });
            }
            size = size
                .checked_add(compact_size_len(item.len() as u64))
                .and_then(|size| size.checked_add(item.len()))
                .ok_or(TransactionError::ArithmeticOverflow)?;
            if size > MAX_TRANSACTION_RAW_SIZE {
                return Err(TransactionError::TooLarge {
                    actual: size,
                    maximum: MAX_TRANSACTION_RAW_SIZE,
                });
            }
        }
        Ok(size)
    }

    fn decode_from(
        decoder: &mut Decoder<'_>,
        transaction_start: usize,
        maximum_transaction_size: usize,
    ) -> Result<Self, TransactionError> {
        let count = decoder.read_compact_usize(MAX_WITNESS_ITEMS, "witness items")?;
        remaining_decode_budget(decoder, transaction_start, maximum_transaction_size)?;
        let mut items = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            items.push(read_transaction_varbytes(
                decoder,
                transaction_start,
                maximum_transaction_size,
                "witness item",
            )?);
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

    fn decode_from(
        decoder: &mut Decoder<'_>,
        transaction_start: usize,
        maximum_transaction_size: usize,
    ) -> Result<Self, TransactionError> {
        let value = Dollarydoos::new(decoder.read_u64_le()?);
        let address = Address::decode_from(decoder)?;
        let remaining =
            remaining_decode_budget(decoder, transaction_start, maximum_transaction_size)?;
        let covenant = Covenant::decode_from_with_limit(decoder, remaining)?;
        remaining_decode_budget(decoder, transaction_start, maximum_transaction_size)?;
        Ok(Self {
            value,
            address,
            covenant,
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
        let (base_size, witness_size) = self.encoded_sizes()?;
        let base = self.base_encode()?;
        let witness = self.witness_encode()?;
        debug_assert_eq!(base.len(), base_size);
        debug_assert_eq!(witness.len(), witness_size);
        let size = base_size
            .checked_add(witness_size)
            .ok_or(TransactionError::ArithmeticOverflow)?;
        let mut output = Vec::with_capacity(size);
        output.extend(base);
        output.extend(witness);
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, TransactionError> {
        if input.len() > MAX_TRANSACTION_RAW_SIZE {
            return Err(TransactionError::TooLarge {
                actual: input.len(),
                maximum: MAX_TRANSACTION_RAW_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        let transaction = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(transaction)
    }

    pub fn decode_prefix(input: &[u8]) -> Result<(Self, usize), TransactionError> {
        let mut decoder = Decoder::new(input);
        let transaction = Self::decode_from(&mut decoder)?;
        Ok((transaction, decoder.position()))
    }

    pub fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, TransactionError> {
        let start = decoder.position();
        let version = decoder.read_u32_le()?;
        let input_count =
            decoder.read_compact_usize(MAX_TRANSACTION_SIZE / 40, "transaction inputs")?;
        remaining_decode_budget(decoder, start, MAX_TRANSACTION_SIZE)?;
        let mut inputs = Vec::with_capacity(input_count.min(1024));
        for _ in 0..input_count {
            inputs.push(Input::decode_base_from(decoder)?);
            remaining_decode_budget(decoder, start, MAX_TRANSACTION_SIZE)?;
        }
        let output_count =
            decoder.read_compact_usize(MAX_TRANSACTION_SIZE / 12, "transaction outputs")?;
        remaining_decode_budget(decoder, start, MAX_TRANSACTION_SIZE)?;
        let mut outputs = Vec::with_capacity(output_count.min(1024));
        for _ in 0..output_count {
            outputs.push(Output::decode_from(decoder, start, MAX_TRANSACTION_SIZE)?);
        }
        let locktime = decoder.read_u32_le()?;
        let base_size = decoder.position().saturating_sub(start);
        remaining_decode_budget(decoder, start, MAX_TRANSACTION_SIZE)?;
        let base_weight = base_size
            .checked_mul(4)
            .ok_or(TransactionError::ArithmeticOverflow)?;
        let maximum_transaction_size = base_size
            .checked_add(MAX_TRANSACTION_WEIGHT.checked_sub(base_weight).ok_or(
                TransactionError::TooLarge {
                    actual: base_weight,
                    maximum: MAX_TRANSACTION_WEIGHT,
                },
            )?)
            .ok_or(TransactionError::ArithmeticOverflow)?
            .min(MAX_TRANSACTION_RAW_SIZE);
        for input in &mut inputs {
            input.witness = Witness::decode_from(decoder, start, maximum_transaction_size)?;
        }
        let transaction = Self {
            version,
            inputs,
            outputs,
            locktime,
        };
        remaining_decode_budget(decoder, start, maximum_transaction_size)?;
        Ok(transaction)
    }

    pub fn base_encode(&self) -> Result<Vec<u8>, TransactionError> {
        let base_size = self.base_encoded_size()?;
        let mut encoder = Encoder::with_capacity(base_size);
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
        Ok(encoder.into_bytes())
    }

    pub fn witness_encode(&self) -> Result<Vec<u8>, TransactionError> {
        let witness_size = self.witness_encoded_size()?;
        let mut encoder = Encoder::with_capacity(witness_size);
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
        self.base_encoded_size()
    }

    pub fn size(&self) -> Result<usize, TransactionError> {
        let (base, witness) = self.encoded_sizes()?;
        base.checked_add(witness)
            .ok_or(TransactionError::ArithmeticOverflow)
    }

    pub fn weight(&self) -> Result<usize, TransactionError> {
        let (base, witness) = self.encoded_sizes()?;
        transaction_weight(base, witness)
    }

    pub fn is_coinbase(&self) -> bool {
        self.inputs
            .first()
            .is_some_and(|input| input.previous_output.is_null())
    }

    fn base_encoded_size(&self) -> Result<usize, TransactionError> {
        if self.inputs.len() > MAX_TRANSACTION_SIZE / 40
            || self.outputs.len() > MAX_TRANSACTION_SIZE / 12
        {
            return Err(TransactionError::TooLarge {
                actual: self.inputs.len().max(self.outputs.len()),
                maximum: MAX_TRANSACTION_SIZE / 12,
            });
        }
        let input_bytes = self
            .inputs
            .len()
            .checked_mul(40)
            .ok_or(TransactionError::ArithmeticOverflow)?;
        let mut size = 4_usize
            .checked_add(compact_size_len(self.inputs.len() as u64))
            .and_then(|size| size.checked_add(input_bytes))
            .and_then(|size| size.checked_add(compact_size_len(self.outputs.len() as u64)))
            .ok_or(TransactionError::ArithmeticOverflow)?;
        for output in &self.outputs {
            output.address.validate()?;
            let covenant_size = output.covenant.encoded_size()?;
            size = size
                .checked_add(8)
                .and_then(|size| size.checked_add(2))
                .and_then(|size| size.checked_add(output.address.hash.len()))
                .and_then(|size| size.checked_add(covenant_size))
                .ok_or(TransactionError::ArithmeticOverflow)?;
            if size > MAX_TRANSACTION_SIZE {
                return Err(TransactionError::TooLarge {
                    actual: size,
                    maximum: MAX_TRANSACTION_SIZE,
                });
            }
        }
        size = size
            .checked_add(4)
            .ok_or(TransactionError::ArithmeticOverflow)?;
        if size > MAX_TRANSACTION_SIZE {
            return Err(TransactionError::TooLarge {
                actual: size,
                maximum: MAX_TRANSACTION_SIZE,
            });
        }
        Ok(size)
    }

    fn witness_encoded_size(&self) -> Result<usize, TransactionError> {
        let mut size = 0_usize;
        for input in &self.inputs {
            size = size
                .checked_add(input.witness.encoded_size()?)
                .ok_or(TransactionError::ArithmeticOverflow)?;
            if size > MAX_TRANSACTION_RAW_SIZE {
                return Err(TransactionError::TooLarge {
                    actual: size,
                    maximum: MAX_TRANSACTION_RAW_SIZE,
                });
            }
        }
        Ok(size)
    }

    fn encoded_sizes(&self) -> Result<(usize, usize), TransactionError> {
        let base = self.base_encoded_size()?;
        let witness = self.witness_encoded_size()?;
        transaction_weight(base, witness)?;
        Ok((base, witness))
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

fn remaining_decode_budget(
    decoder: &Decoder<'_>,
    start: usize,
    maximum: usize,
) -> Result<usize, TransactionError> {
    let consumed = decoder.position().saturating_sub(start);
    if consumed > maximum {
        return Err(TransactionError::TooLarge {
            actual: consumed,
            maximum,
        });
    }
    Ok(maximum - consumed)
}

fn read_transaction_varbytes(
    decoder: &mut Decoder<'_>,
    transaction_start: usize,
    maximum_transaction_size: usize,
    field: &'static str,
) -> Result<Vec<u8>, TransactionError> {
    let length = decoder.read_compact_usize(MAX_TRANSACTION_RAW_SIZE, field)?;
    let remaining = remaining_decode_budget(decoder, transaction_start, maximum_transaction_size)?;
    if length > remaining {
        return Err(TransactionError::TooLarge {
            actual: decoder
                .position()
                .saturating_sub(transaction_start)
                .saturating_add(length),
            maximum: maximum_transaction_size,
        });
    }
    Ok(decoder.read_bounded_vec(length, remaining)?)
}

fn transaction_weight(base: usize, witness: usize) -> Result<usize, TransactionError> {
    let weight = base
        .checked_mul(4)
        .and_then(|weight| weight.checked_add(witness))
        .ok_or(TransactionError::ArithmeticOverflow)?;
    if weight > MAX_TRANSACTION_WEIGHT {
        return Err(TransactionError::TooLarge {
            actual: weight,
            maximum: MAX_TRANSACTION_WEIGHT,
        });
    }
    Ok(weight)
}

fn compact_size_len(value: u64) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
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
        let mut doubled = raw.clone();
        doubled.extend_from_slice(&raw);
        let (prefix, consumed) = Transaction::decode_prefix(&doubled).expect("valid prefix");
        assert_eq!(prefix, transaction);
        assert_eq!(consumed, raw.len());
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

    #[test]
    fn prefix_decode_rejects_oversized_witness_before_allocation() {
        let mut encoder = Encoder::new();
        encoder.put_u32_le(1);
        encoder.put_compact_size(1);
        encoder.put_bytes(&[0; 32]);
        encoder.put_u32_le(u32::MAX);
        encoder.put_u32_le(0);
        encoder.put_compact_size(0);
        encoder.put_u32_le(0);
        encoder.put_compact_size(1);
        encoder.put_compact_size(MAX_TRANSACTION_RAW_SIZE as u64);
        assert!(matches!(
            Transaction::decode_prefix(&encoder.into_bytes()),
            Err(TransactionError::TooLarge {
                actual: 4_000_056,
                maximum: 3_999_850
            })
        ));
    }

    #[test]
    fn witness_serialization_obeys_weight_not_base_size_limit() {
        let mut transaction = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint::NULL,
                sequence: 0,
                witness: Witness {
                    items: vec![vec![7; 1_100_000]],
                },
            }],
            outputs: Vec::new(),
            locktime: 0,
        };
        let encoded = transaction.encode().expect("under HSD weight limit");
        assert!(encoded.len() > MAX_TRANSACTION_SIZE);
        assert_eq!(Transaction::decode(&encoded).expect("valid"), transaction);

        transaction.inputs[0].witness.items[0] = vec![0; MAX_TRANSACTION_WEIGHT];
        assert!(matches!(
            transaction.encode(),
            Err(TransactionError::TooLarge {
                maximum: MAX_TRANSACTION_WEIGHT,
                ..
            })
        ));
    }
}
