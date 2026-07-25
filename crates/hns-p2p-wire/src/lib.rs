#![doc = "Bounded, runtime-independent codecs for standard Handshake P2P traffic."]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_encoding::{DecodeError, Decoder, Encoder};
use hns_header_consensus::{HEADER_SIZE, Header};
use hns_mining::{Block, validate_block_body};
use hns_primitives::{BlockHash, NameHash, TreeRoot};
use hns_transaction::Transaction;
use hns_urkel_proof::{HsdUrkelProof, UrkelError};
use thiserror::Error;

pub const PROTOCOL_VERSION: u32 = 3;
pub const MIN_PROTOCOL_VERSION: u32 = 1;
pub const SERVICE_NETWORK: u64 = 1;
pub const SERVICE_BLOOM: u64 = 1 << 1;
pub const FRAME_HEADER_SIZE: usize = 9;
pub const MAX_FRAME_PAYLOAD_SIZE: usize = 8_000_000;
pub const MAX_INVENTORY_ITEMS: usize = 50_000;
pub const MAX_LOCATOR_HASHES: usize = MAX_INVENTORY_ITEMS;
pub const MAX_HEADERS: usize = 2_000;
pub const MAX_ADDR_ITEMS: usize = 1_000;
pub const MAX_USER_AGENT_SIZE: usize = u8::MAX as usize;
pub const MAX_REJECT_REASON_SIZE: usize = u8::MAX as usize;
pub const MAX_COMPACT_BLOCK_TRANSACTIONS: usize = 16_662;
pub const NET_ADDRESS_SIZE: usize = 88;
pub const MAX_STREAM_BUFFER_SIZE: usize = 2 * (FRAME_HEADER_SIZE + MAX_FRAME_PAYLOAD_SIZE);

#[derive(Debug, Eq, Error, PartialEq)]
pub enum WireError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("network magic mismatch: expected {expected:#010x}, got {actual:#010x}")]
    NetworkMagicMismatch { expected: u32, actual: u32 },
    #[error("payload length {actual} exceeds the {maximum}-byte wire limit")]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[error("{context} count {actual} exceeds the limit {maximum}")]
    CountTooLarge {
        context: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("incomplete frame: need {needed} more byte(s)")]
    IncompleteFrame { needed: usize },
    #[error("invalid {context}: {reason}")]
    InvalidPacket {
        context: &'static str,
        reason: &'static str,
    },
    #[error("invalid transaction packet: {0}")]
    InvalidTransaction(String),
    #[error(transparent)]
    Urkel(#[from] UrkelError),
    #[error(transparent)]
    CompactBlock(#[from] CompactBlockError),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkMagic {
    Mainnet,
    Testnet,
    Regtest,
    Simnet,
}

impl NetworkMagic {
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Mainnet => 0x5b6e_f2d3,
            Self::Testnet => 0xb152_0dd2,
            Self::Regtest => 0xae38_95cf,
            Self::Simnet => 0x0e64_8edc,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PacketType {
    Version,
    Verack,
    Ping,
    Pong,
    GetAddr,
    Addr,
    Inv,
    GetData,
    NotFound,
    GetBlocks,
    GetHeaders,
    Headers,
    SendHeaders,
    Block,
    Tx,
    Reject,
    Mempool,
    FilterLoad,
    FilterAdd,
    FilterClear,
    MerkleBlock,
    FeeFilter,
    SendCmpct,
    CmpctBlock,
    GetBlockTxn,
    BlockTxn,
    GetProof,
    Proof,
    Claim,
    Airdrop,
    Unknown(u8),
}

impl PacketType {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Version => 0,
            Self::Verack => 1,
            Self::Ping => 2,
            Self::Pong => 3,
            Self::GetAddr => 4,
            Self::Addr => 5,
            Self::Inv => 6,
            Self::GetData => 7,
            Self::NotFound => 8,
            Self::GetBlocks => 9,
            Self::GetHeaders => 10,
            Self::Headers => 11,
            Self::SendHeaders => 12,
            Self::Block => 13,
            Self::Tx => 14,
            Self::Reject => 15,
            Self::Mempool => 16,
            Self::FilterLoad => 17,
            Self::FilterAdd => 18,
            Self::FilterClear => 19,
            Self::MerkleBlock => 20,
            Self::FeeFilter => 21,
            Self::SendCmpct => 22,
            Self::CmpctBlock => 23,
            Self::GetBlockTxn => 24,
            Self::BlockTxn => 25,
            Self::GetProof => 26,
            Self::Proof => 27,
            Self::Claim => 28,
            Self::Airdrop => 29,
            Self::Unknown(value) => value,
        }
    }

    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Version,
            1 => Self::Verack,
            2 => Self::Ping,
            3 => Self::Pong,
            4 => Self::GetAddr,
            5 => Self::Addr,
            6 => Self::Inv,
            7 => Self::GetData,
            8 => Self::NotFound,
            9 => Self::GetBlocks,
            10 => Self::GetHeaders,
            11 => Self::Headers,
            12 => Self::SendHeaders,
            13 => Self::Block,
            14 => Self::Tx,
            15 => Self::Reject,
            16 => Self::Mempool,
            17 => Self::FilterLoad,
            18 => Self::FilterAdd,
            19 => Self::FilterClear,
            20 => Self::MerkleBlock,
            21 => Self::FeeFilter,
            22 => Self::SendCmpct,
            23 => Self::CmpctBlock,
            24 => Self::GetBlockTxn,
            25 => Self::BlockTxn,
            26 => Self::GetProof,
            27 => Self::Proof,
            28 => Self::Claim,
            29 => Self::Airdrop,
            other => Self::Unknown(other),
        }
    }

    pub const fn carries_reject_hash(self) -> bool {
        matches!(self, Self::Block | Self::Tx | Self::Claim | Self::Airdrop)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InventoryKind {
    Transaction,
    Block,
    FilteredBlock,
    CompactBlock,
    Claim,
    Airdrop,
    Unknown(u32),
}

impl InventoryKind {
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Transaction => 1,
            Self::Block => 2,
            Self::FilteredBlock => 3,
            Self::CompactBlock => 4,
            Self::Claim => 5,
            Self::Airdrop => 6,
            Self::Unknown(value) => value,
        }
    }

    pub const fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Transaction,
            2 => Self::Block,
            3 => Self::FilteredBlock,
            4 => Self::CompactBlock,
            5 => Self::Claim,
            6 => Self::Airdrop,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Inventory {
    pub kind: InventoryKind,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetAddress {
    pub time: u64,
    pub services: u64,
    pub ip: [u8; 16],
    pub port: u16,
    pub key: [u8; 33],
}

impl NetAddress {
    pub fn from_socket_addr(address: SocketAddr, time: u64, services: u64) -> Self {
        let ip = match address.ip() {
            IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
            IpAddr::V6(ip) => ip.octets(),
        };
        Self {
            time,
            services,
            ip,
            port: address.port(),
            key: [0; 33],
        }
    }

    pub fn socket_addr(&self) -> SocketAddr {
        let ip = Ipv6Addr::from(self.ip);
        let ip = ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip));
        SocketAddr::new(ip, self.port)
    }

    pub fn encode(&self) -> [u8; NET_ADDRESS_SIZE] {
        let mut encoder = Encoder::with_capacity(NET_ADDRESS_SIZE);
        self.encode_to(&mut encoder);
        encoder
            .into_bytes()
            .try_into()
            .expect("network address encoding is always 88 bytes")
    }

    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        if input.len() != NET_ADDRESS_SIZE {
            return Err(WireError::InvalidPacket {
                context: "network address",
                reason: "the encoding must be exactly 88 bytes",
            });
        }
        let mut decoder = Decoder::new(input);
        let address = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(address)
    }

    fn encode_to(&self, encoder: &mut Encoder) {
        encoder.put_u64_le(self.time);
        // HSD writes only the low service word and a reserved zero high word.
        encoder.put_u32_le(self.services as u32);
        encoder.put_u32_le(0);
        encoder.put_u8(0);
        encoder.put_bytes(&self.ip);
        encoder.put_bytes(&[0; 20]);
        encoder.put_u16_le(self.port);
        encoder.put_bytes(&self.key);
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        let time = decoder.read_u64_le()?;
        let services = u64::from(decoder.read_u32_le()?);
        let _reserved_service_word = decoder.read_u32_le()?;
        let host_kind = decoder.read_u8()?;
        let host = decoder.read_array::<36>()?;
        let mut ip = [0; 16];
        if host_kind == 0 {
            ip.copy_from_slice(&host[..16]);
        }
        Ok(Self {
            time,
            services,
            ip,
            port: decoder.read_u16_le()?,
            key: decoder.read_array()?,
        })
    }
}

impl Default for NetAddress {
    fn default() -> Self {
        Self::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), 0, 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionPacket {
    pub version: u32,
    pub services: u64,
    pub time: u64,
    pub remote: NetAddress,
    pub nonce: [u8; 8],
    pub agent: String,
    pub height: u32,
    pub no_relay: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocatorPacket {
    pub locator: Vec<BlockHash>,
    pub stop: BlockHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectPacket {
    pub message: PacketType,
    pub code: u8,
    pub reason: String,
    pub hash: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetProofPacket {
    pub root: TreeRoot,
    pub key: NameHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofPacket {
    pub root: TreeRoot,
    pub key: NameHash,
    pub proof: HsdUrkelProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefilledTransaction {
    /// Differential index, matching HSD/BIP152 wire encoding.
    pub index: usize,
    pub transaction: Transaction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlock {
    pub header: Header,
    pub key_nonce: [u8; 8],
    pub short_ids: Vec<u64>,
    pub prefilled: Vec<PrefilledTransaction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlockRequest {
    pub block_hash: BlockHash,
    /// Absolute transaction indexes. The wire codec converts them to and from
    /// HSD/BIP152 differential indexes.
    pub indexes: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlockResponse {
    pub block_hash: BlockHash,
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, Debug)]
pub struct CompactBlockReconstruction {
    header: Header,
    available: Vec<Option<usize>>,
    transactions: Vec<Option<Transaction>>,
    short_id_indexes: HashMap<u64, usize>,
    filled: usize,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CompactBlockError {
    #[error("malformed compact block: {0}")]
    Malformed(String),
    #[error("compact block short-id collision: {0:#014x}")]
    ShortIdCollision(u64),
    #[error("compact block response hash does not match the pending block")]
    ResponseHashMismatch,
    #[error("compact block response has {actual} transactions; expected {expected}")]
    ResponseCountMismatch { expected: usize, actual: usize },
    #[error("compact block reconstruction is incomplete")]
    Incomplete,
    #[error("compact block transaction is malformed")]
    InvalidTransaction,
    #[error("compact block body does not match its committed roots or consensus shape")]
    InvalidBlockBody,
}

impl ProofPacket {
    pub fn verify(&self) -> Result<Option<Vec<u8>>, UrkelError> {
        self.proof.verify(self.root, self.key)
    }
}

impl CompactBlock {
    pub fn from_block_with_nonce(
        block: &Block,
        key_nonce: [u8; 8],
    ) -> Result<Self, CompactBlockError> {
        validate_block_body(block).map_err(|_| CompactBlockError::InvalidBlockBody)?;
        let mut compact = Self {
            header: block.header.clone(),
            key_nonce,
            short_ids: Vec::with_capacity(block.transactions.len().saturating_sub(1)),
            prefilled: Vec::with_capacity(usize::from(!block.transactions.is_empty())),
        };
        let siphash_key = compact.siphash_key();
        compact.short_ids = block
            .transactions
            .iter()
            .skip(1)
            .map(|transaction| {
                transaction
                    .witness_hash()
                    .map(|hash| Self::short_id_with_key(&hash, &siphash_key))
                    .map_err(|_| CompactBlockError::InvalidTransaction)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(coinbase) = block.transactions.first() {
            compact.prefilled.push(PrefilledTransaction {
                index: 0,
                transaction: coinbase.clone(),
            });
        }
        compact.validate_layout()?;
        Ok(compact)
    }

    pub fn hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    pub fn total_transactions(&self) -> usize {
        self.short_ids.len().saturating_add(self.prefilled.len())
    }

    pub fn short_id(&self, witness_hash: &[u8; 32]) -> u64 {
        Self::short_id_with_key(witness_hash, &self.siphash_key())
    }

    pub fn reconstruct(
        &self,
        mempool: &[Transaction],
    ) -> Result<CompactBlockReconstruction, CompactBlockError> {
        let total = self.validate_layout()?;
        let mut reconstruction = CompactBlockReconstruction {
            header: self.header.clone(),
            available: vec![None; total],
            transactions: Vec::with_capacity(total),
            short_id_indexes: HashMap::with_capacity(self.short_ids.len()),
            filled: 0,
        };

        let mut previous = None;
        for prefilled in &self.prefilled {
            let index = absolute_prefilled_index(previous, prefilled.index)?;
            previous = Some(index);
            reconstruction.insert(index, prefilled.transaction.clone())?;
        }

        let mut offset = 0_usize;
        for (relative, short_id) in self.short_ids.iter().copied().enumerate() {
            while reconstruction
                .available
                .get(relative.saturating_add(offset))
                .is_some_and(Option::is_some)
            {
                offset = offset.saturating_add(1);
            }
            let index = relative.checked_add(offset).ok_or_else(|| {
                CompactBlockError::Malformed("short-id index overflow".to_owned())
            })?;
            if index >= total {
                return Err(CompactBlockError::Malformed(
                    "short-id layout exceeds transaction count".to_owned(),
                ));
            }
            if reconstruction
                .short_id_indexes
                .insert(short_id, index)
                .is_some()
            {
                return Err(CompactBlockError::ShortIdCollision(short_id));
            }
        }
        reconstruction.fill_mempool(self, mempool)?;
        Ok(reconstruction)
    }

    fn siphash_key(&self) -> [u8; 16] {
        let header = self.header.encode();
        let hash = blake2b_256_many(&[header.as_slice(), self.key_nonce.as_slice()]);
        let mut key = [0_u8; 16];
        key.copy_from_slice(&hash[..16]);
        key
    }

    fn short_id_with_key(witness_hash: &[u8; 32], key: &[u8; 16]) -> u64 {
        siphash24(witness_hash, key) & 0x0000_ffff_ffff_ffff
    }

    fn validate_layout(&self) -> Result<usize, CompactBlockError> {
        let total = self.total_transactions();
        if total == 0 {
            return Err(CompactBlockError::Malformed(
                "empty short-id and prefilled vectors".to_owned(),
            ));
        }
        if total > MAX_COMPACT_BLOCK_TRANSACTIONS {
            return Err(CompactBlockError::Malformed(format!(
                "transaction count {total} exceeds {MAX_COMPACT_BLOCK_TRANSACTIONS}"
            )));
        }
        if self
            .short_ids
            .iter()
            .any(|short_id| *short_id > 0x0000_ffff_ffff_ffff)
        {
            return Err(CompactBlockError::Malformed(
                "short ID exceeds 48 bits".to_owned(),
            ));
        }

        let mut previous = None;
        for prefilled in &self.prefilled {
            let index = absolute_prefilled_index(previous, prefilled.index)?;
            if index >= total {
                return Err(CompactBlockError::Malformed(format!(
                    "prefilled index {index} exceeds transaction count {total}"
                )));
            }
            previous = Some(index);
        }
        Ok(total)
    }

    fn encode_to(&self, encoder: &mut Encoder) -> Result<(), WireError> {
        self.validate_layout()?;
        encoder.put_bytes(&self.header.encode());
        encoder.put_bytes(&self.key_nonce);
        encoder.put_compact_size(self.short_ids.len() as u64);
        for short_id in &self.short_ids {
            encoder.put_u32_le(*short_id as u32);
            encoder.put_u16_le((*short_id >> 32) as u16);
        }
        encoder.put_compact_size(self.prefilled.len() as u64);
        for prefilled in &self.prefilled {
            encoder.put_compact_size(prefilled.index as u64);
            encoder.put_bytes(
                &prefilled
                    .transaction
                    .encode()
                    .map_err(|error| WireError::InvalidTransaction(error.to_string()))?,
            );
        }
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        let header = Header::decode(decoder.read_slice(HEADER_SIZE)?).map_err(|_| {
            WireError::InvalidPacket {
                context: "compact block",
                reason: "the nested header is malformed",
            }
        })?;
        let key_nonce = decoder.read_array()?;
        let short_id_count = read_count(
            decoder,
            "compact-block short IDs",
            MAX_COMPACT_BLOCK_TRANSACTIONS,
        )?;
        let mut short_ids = Vec::with_capacity(short_id_count);
        for _ in 0..short_id_count {
            let low = u64::from(decoder.read_u32_le()?);
            let high = u64::from(decoder.read_u16_le()?);
            short_ids.push((high << 32) | low);
        }
        let maximum_prefilled = MAX_COMPACT_BLOCK_TRANSACTIONS.saturating_sub(short_id_count);
        let prefilled_count = read_count(
            decoder,
            "compact-block prefilled transactions",
            maximum_prefilled,
        )?;
        let total = short_id_count.saturating_add(prefilled_count);
        let mut prefilled = Vec::with_capacity(prefilled_count);
        let mut previous = None;
        for _ in 0..prefilled_count {
            let index = read_bounded_index(decoder, "compact-block prefilled index")?;
            let absolute = absolute_prefilled_index(previous, index)?;
            if absolute >= total {
                return Err(CompactBlockError::Malformed(format!(
                    "prefilled index {absolute} exceeds transaction count {total}"
                ))
                .into());
            }
            previous = Some(absolute);
            prefilled.push(PrefilledTransaction {
                index,
                transaction: Transaction::decode_from(decoder)
                    .map_err(|error| WireError::InvalidTransaction(error.to_string()))?,
            });
        }
        let compact = Self {
            header,
            key_nonce,
            short_ids,
            prefilled,
        };
        compact.validate_layout()?;
        Ok(compact)
    }
}

impl CompactBlockReconstruction {
    pub fn is_complete(&self) -> bool {
        self.filled == self.available.len()
    }

    pub fn missing_request(&self) -> CompactBlockRequest {
        CompactBlockRequest {
            block_hash: self.header.block_hash(),
            indexes: self
                .available
                .iter()
                .enumerate()
                .filter_map(|(index, transaction)| transaction.is_none().then_some(index))
                .collect(),
        }
    }

    pub fn fill_missing(
        &mut self,
        response: CompactBlockResponse,
    ) -> Result<(), CompactBlockError> {
        if response.block_hash != self.header.block_hash() {
            return Err(CompactBlockError::ResponseHashMismatch);
        }
        let missing = self.available.iter().filter(|item| item.is_none()).count();
        if response.transactions.len() != missing {
            return Err(CompactBlockError::ResponseCountMismatch {
                expected: missing,
                actual: response.transactions.len(),
            });
        }
        let indexes = self
            .available
            .iter()
            .enumerate()
            .filter_map(|(index, item)| item.is_none().then_some(index))
            .collect::<Vec<_>>();
        for (index, transaction) in indexes.into_iter().zip(response.transactions) {
            self.insert(index, transaction)?;
        }
        Ok(())
    }

    pub fn into_block(self) -> Result<Block, CompactBlockError> {
        if !self.is_complete() {
            return Err(CompactBlockError::Incomplete);
        }
        let mut resolved = self.transactions;
        let mut transactions = Vec::with_capacity(self.available.len());
        for item in self.available {
            let index = item.ok_or(CompactBlockError::Incomplete)?;
            let transaction = resolved
                .get_mut(index)
                .and_then(Option::take)
                .ok_or_else(|| {
                    CompactBlockError::Malformed(
                        "multiple compact-block slots reference one transaction".to_owned(),
                    )
                })?;
            transactions.push(transaction);
        }
        let block = Block {
            header: self.header,
            transactions,
        };
        validate_block_body(&block).map_err(|_| CompactBlockError::InvalidBlockBody)?;
        Ok(block)
    }

    fn fill_mempool(
        &mut self,
        compact: &CompactBlock,
        mempool: &[Transaction],
    ) -> Result<(), CompactBlockError> {
        if self.is_complete() {
            return Ok(());
        }
        let mut matched = HashSet::new();
        let siphash_key = compact.siphash_key();
        for transaction in mempool {
            let witness_hash = transaction
                .witness_hash()
                .map_err(|_| CompactBlockError::InvalidTransaction)?;
            let short_id = CompactBlock::short_id_with_key(&witness_hash, &siphash_key);
            let Some(index) = self.short_id_indexes.get(&short_id).copied() else {
                continue;
            };
            if !matched.insert(index) {
                if self.available[index].take().is_some() {
                    self.filled = self.filled.saturating_sub(1);
                }
                continue;
            }
            if self.available[index].is_none() {
                self.insert(index, transaction.clone())?;
            }
            if self.is_complete() {
                return Ok(());
            }
        }
        Ok(())
    }

    fn insert(&mut self, index: usize, transaction: Transaction) -> Result<(), CompactBlockError> {
        let slot = self.available.get_mut(index).ok_or_else(|| {
            CompactBlockError::Malformed(format!("transaction index {index} is out of bounds"))
        })?;
        if slot.is_some() {
            return Err(CompactBlockError::Malformed(format!(
                "transaction index {index} is filled more than once"
            )));
        }
        let resolved = self.transactions.len();
        self.transactions.push(Some(transaction));
        *slot = Some(resolved);
        self.filled = self.filled.saturating_add(1);
        Ok(())
    }
}

impl CompactBlockRequest {
    pub fn from_block(block: &Block, indexes: Vec<usize>) -> Self {
        Self {
            block_hash: block.header.block_hash(),
            indexes,
        }
    }

    fn encode_to(&self, encoder: &mut Encoder) -> Result<(), WireError> {
        validate_absolute_indexes(&self.indexes)?;
        encoder.put_bytes(self.block_hash.as_bytes());
        encoder.put_compact_size(self.indexes.len() as u64);
        for (position, index) in self.indexes.iter().copied().enumerate() {
            let differential = if position == 0 {
                index
            } else {
                index - self.indexes[position - 1] - 1
            };
            encoder.put_compact_size(differential as u64);
        }
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        let block_hash = BlockHash::new(decoder.read_array()?);
        let count = read_count(
            decoder,
            "compact-block requested indexes",
            MAX_COMPACT_BLOCK_TRANSACTIONS,
        )?;
        let mut indexes = Vec::with_capacity(count);
        let mut previous = None;
        for _ in 0..count {
            let differential = read_bounded_index(decoder, "compact-block requested index")?;
            let absolute = absolute_prefilled_index(previous, differential)?;
            indexes.push(absolute);
            previous = Some(absolute);
        }
        Ok(Self {
            block_hash,
            indexes,
        })
    }
}

impl CompactBlockResponse {
    pub fn from_block(
        block: &Block,
        request: &CompactBlockRequest,
    ) -> Result<Self, CompactBlockError> {
        validate_absolute_indexes(&request.indexes)?;
        if request.block_hash != block.header.block_hash() {
            return Err(CompactBlockError::ResponseHashMismatch);
        }
        let transactions = request
            .indexes
            .iter()
            .map(|index| {
                block.transactions.get(*index).cloned().ok_or_else(|| {
                    CompactBlockError::Malformed(format!(
                        "requested transaction index {index} is out of bounds"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            block_hash: request.block_hash,
            transactions,
        })
    }

    fn encode_to(&self, encoder: &mut Encoder) -> Result<(), WireError> {
        check_count(
            "compact-block response transactions",
            self.transactions.len(),
            MAX_COMPACT_BLOCK_TRANSACTIONS,
        )?;
        encoder.put_bytes(self.block_hash.as_bytes());
        encoder.put_compact_size(self.transactions.len() as u64);
        for transaction in &self.transactions {
            encoder.put_bytes(
                &transaction
                    .encode()
                    .map_err(|error| WireError::InvalidTransaction(error.to_string()))?,
            );
        }
        Ok(())
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        let block_hash = BlockHash::new(decoder.read_array()?);
        let count = read_count(
            decoder,
            "compact-block response transactions",
            MAX_COMPACT_BLOCK_TRANSACTIONS,
        )?;
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            transactions.push(
                Transaction::decode_from(decoder)
                    .map_err(|error| WireError::InvalidTransaction(error.to_string()))?,
            );
        }
        Ok(Self {
            block_hash,
            transactions,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    Version(VersionPacket),
    Verack,
    Ping([u8; 8]),
    Pong([u8; 8]),
    GetAddr,
    Addr(Vec<NetAddress>),
    Inv(Vec<Inventory>),
    GetData(Vec<Inventory>),
    NotFound(Vec<Inventory>),
    GetBlocks(LocatorPacket),
    GetHeaders(LocatorPacket),
    Headers(Vec<Header>),
    SendHeaders,
    Block(Block),
    Tx(Transaction),
    Reject(RejectPacket),
    Mempool,
    FilterLoad(Vec<u8>),
    FilterAdd(Vec<u8>),
    FilterClear,
    MerkleBlock(Vec<u8>),
    FeeFilter(i64),
    SendCmpct { mode: u8, version: u64 },
    CmpctBlock(CompactBlock),
    GetBlockTxn(CompactBlockRequest),
    BlockTxn(CompactBlockResponse),
    GetProof(GetProofPacket),
    Proof(ProofPacket),
    Claim(Vec<u8>),
    Airdrop(Vec<u8>),
    Unknown { packet_type: u8, payload: Vec<u8> },
}

impl Packet {
    pub const fn packet_type(&self) -> PacketType {
        match self {
            Self::Version(_) => PacketType::Version,
            Self::Verack => PacketType::Verack,
            Self::Ping(_) => PacketType::Ping,
            Self::Pong(_) => PacketType::Pong,
            Self::GetAddr => PacketType::GetAddr,
            Self::Addr(_) => PacketType::Addr,
            Self::Inv(_) => PacketType::Inv,
            Self::GetData(_) => PacketType::GetData,
            Self::NotFound(_) => PacketType::NotFound,
            Self::GetBlocks(_) => PacketType::GetBlocks,
            Self::GetHeaders(_) => PacketType::GetHeaders,
            Self::Headers(_) => PacketType::Headers,
            Self::SendHeaders => PacketType::SendHeaders,
            Self::Block(_) => PacketType::Block,
            Self::Tx(_) => PacketType::Tx,
            Self::Reject(_) => PacketType::Reject,
            Self::Mempool => PacketType::Mempool,
            Self::FilterLoad(_) => PacketType::FilterLoad,
            Self::FilterAdd(_) => PacketType::FilterAdd,
            Self::FilterClear => PacketType::FilterClear,
            Self::MerkleBlock(_) => PacketType::MerkleBlock,
            Self::FeeFilter(_) => PacketType::FeeFilter,
            Self::SendCmpct { .. } => PacketType::SendCmpct,
            Self::CmpctBlock(_) => PacketType::CmpctBlock,
            Self::GetBlockTxn(_) => PacketType::GetBlockTxn,
            Self::BlockTxn(_) => PacketType::BlockTxn,
            Self::GetProof(_) => PacketType::GetProof,
            Self::Proof(_) => PacketType::Proof,
            Self::Claim(_) => PacketType::Claim,
            Self::Airdrop(_) => PacketType::Airdrop,
            Self::Unknown { packet_type, .. } => PacketType::Unknown(*packet_type),
        }
    }

    pub fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        let mut encoder = Encoder::new();
        match self {
            Self::Version(packet) => encode_version(packet, &mut encoder)?,
            Self::Verack
            | Self::GetAddr
            | Self::SendHeaders
            | Self::Mempool
            | Self::FilterClear => {}
            Self::Ping(nonce) | Self::Pong(nonce) => encoder.put_bytes(nonce),
            Self::Addr(items) => {
                check_count("address", items.len(), MAX_ADDR_ITEMS)?;
                encoder.put_compact_size(items.len() as u64);
                for item in items {
                    item.encode_to(&mut encoder);
                }
            }
            Self::Inv(items) | Self::GetData(items) | Self::NotFound(items) => {
                encode_inventory(items, &mut encoder)?;
            }
            Self::GetBlocks(packet) | Self::GetHeaders(packet) => {
                check_count("locator", packet.locator.len(), MAX_LOCATOR_HASHES)?;
                encoder.put_compact_size(packet.locator.len() as u64);
                for hash in &packet.locator {
                    encoder.put_bytes(hash.as_bytes());
                }
                encoder.put_bytes(packet.stop.as_bytes());
            }
            Self::Headers(headers) => {
                check_count("header", headers.len(), MAX_HEADERS)?;
                encoder.put_compact_size(headers.len() as u64);
                for header in headers {
                    encoder.put_bytes(&header.encode());
                }
            }
            Self::Tx(transaction) => encoder.put_bytes(
                &transaction
                    .encode()
                    .map_err(|error| WireError::InvalidTransaction(error.to_string()))?,
            ),
            Self::Reject(packet) => encode_reject(packet, &mut encoder)?,
            Self::FeeFilter(rate) => encoder.put_u64_le(*rate as u64),
            Self::SendCmpct { mode, version } => {
                encoder.put_u8(*mode);
                encoder.put_u64_le(*version);
            }
            Self::GetProof(packet) => {
                encoder.put_bytes(packet.root.as_bytes());
                encoder.put_bytes(packet.key.as_bytes());
            }
            Self::Proof(packet) => {
                encoder.put_bytes(packet.root.as_bytes());
                encoder.put_bytes(packet.key.as_bytes());
                encoder.put_bytes(&packet.proof.encode()?);
            }
            Self::Block(block) => {
                encoder.put_bytes(&block.encode().map_err(|_| WireError::InvalidPacket {
                    context: "block",
                    reason: "the nested block is malformed",
                })?)
            }
            Self::CmpctBlock(block) => block.encode_to(&mut encoder)?,
            Self::GetBlockTxn(request) => request.encode_to(&mut encoder)?,
            Self::BlockTxn(response) => response.encode_to(&mut encoder)?,
            Self::FilterLoad(payload)
            | Self::FilterAdd(payload)
            | Self::MerkleBlock(payload)
            | Self::Claim(payload)
            | Self::Airdrop(payload)
            | Self::Unknown { payload, .. } => encoder.put_bytes(payload),
        }
        let payload = encoder.into_bytes();
        check_payload_size(payload.len())?;
        Ok(payload)
    }

    pub fn decode(packet_type: PacketType, payload: &[u8]) -> Result<Self, WireError> {
        check_payload_size(payload.len())?;
        if let PacketType::Unknown(packet_type) = packet_type {
            return Ok(Self::Unknown {
                packet_type,
                payload: payload.to_vec(),
            });
        }
        let mut decoder = Decoder::new(payload);
        let packet = match packet_type {
            PacketType::Version => Self::Version(decode_version(&mut decoder)?),
            PacketType::Verack => Self::Verack,
            PacketType::Ping => Self::Ping(decoder.read_array()?),
            PacketType::Pong => Self::Pong(decoder.read_array()?),
            PacketType::GetAddr => Self::GetAddr,
            PacketType::Addr => {
                let count = read_count(&mut decoder, "address", MAX_ADDR_ITEMS)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(NetAddress::decode_from(&mut decoder)?);
                }
                Self::Addr(items)
            }
            PacketType::Inv => Self::Inv(decode_inventory(&mut decoder)?),
            PacketType::GetData => Self::GetData(decode_inventory(&mut decoder)?),
            PacketType::NotFound => Self::NotFound(decode_inventory(&mut decoder)?),
            PacketType::GetBlocks | PacketType::GetHeaders => {
                let count = read_count(&mut decoder, "locator", MAX_LOCATOR_HASHES)?;
                let mut locator = Vec::with_capacity(count);
                for _ in 0..count {
                    locator.push(BlockHash::new(decoder.read_array()?));
                }
                let packet = LocatorPacket {
                    locator,
                    stop: BlockHash::new(decoder.read_array()?),
                };
                if packet_type == PacketType::GetBlocks {
                    Self::GetBlocks(packet)
                } else {
                    Self::GetHeaders(packet)
                }
            }
            PacketType::Headers => {
                let count = read_count(&mut decoder, "header", MAX_HEADERS)?;
                let mut headers = Vec::with_capacity(count);
                for _ in 0..count {
                    headers.push(Header::decode(decoder.read_slice(HEADER_SIZE)?).map_err(
                        |_| WireError::InvalidPacket {
                            context: "headers",
                            reason: "a nested header is malformed",
                        },
                    )?);
                }
                Self::Headers(headers)
            }
            PacketType::SendHeaders => Self::SendHeaders,
            PacketType::Block => {
                return Block::decode(payload).map(Self::Block).map_err(|_| {
                    WireError::InvalidPacket {
                        context: "block",
                        reason: "the nested block is malformed",
                    }
                });
            }
            PacketType::Tx => {
                let transaction = Transaction::decode(payload)
                    .map_err(|error| WireError::InvalidTransaction(error.to_string()))?;
                return Ok(Self::Tx(transaction));
            }
            PacketType::Reject => Self::Reject(decode_reject(&mut decoder)?),
            PacketType::Mempool => Self::Mempool,
            PacketType::FilterLoad => Self::FilterLoad(take_remaining(&mut decoder)?),
            PacketType::FilterAdd => Self::FilterAdd(take_remaining(&mut decoder)?),
            PacketType::FilterClear => Self::FilterClear,
            PacketType::MerkleBlock => Self::MerkleBlock(take_remaining(&mut decoder)?),
            PacketType::FeeFilter => Self::FeeFilter(decoder.read_u64_le()? as i64),
            PacketType::SendCmpct => Self::SendCmpct {
                mode: decoder.read_u8()?,
                version: decoder.read_u64_le()?,
            },
            PacketType::CmpctBlock => Self::CmpctBlock(CompactBlock::decode_from(&mut decoder)?),
            PacketType::GetBlockTxn => {
                Self::GetBlockTxn(CompactBlockRequest::decode_from(&mut decoder)?)
            }
            PacketType::BlockTxn => {
                Self::BlockTxn(CompactBlockResponse::decode_from(&mut decoder)?)
            }
            PacketType::GetProof => Self::GetProof(GetProofPacket {
                root: TreeRoot::new(decoder.read_array()?),
                key: NameHash::new(decoder.read_array()?),
            }),
            PacketType::Proof => {
                let root = TreeRoot::new(decoder.read_array()?);
                let key = NameHash::new(decoder.read_array()?);
                let raw = take_remaining(&mut decoder)?;
                Self::Proof(ProofPacket {
                    root,
                    key,
                    proof: HsdUrkelProof::decode_strict(&raw)?,
                })
            }
            PacketType::Claim => Self::Claim(take_remaining(&mut decoder)?),
            PacketType::Airdrop => Self::Airdrop(take_remaining(&mut decoder)?),
            PacketType::Unknown(_) => unreachable!("handled before decoder construction"),
        };
        decoder.finish()?;
        Ok(packet)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub packet_type: PacketType,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(packet_type: PacketType, payload: Vec<u8>) -> Result<Self, WireError> {
        check_payload_size(payload.len())?;
        Ok(Self {
            packet_type,
            payload,
        })
    }

    pub fn from_packet(packet: &Packet) -> Result<Self, WireError> {
        Self::new(packet.packet_type(), packet.encode_payload()?)
    }

    pub fn decode_packet(&self) -> Result<Packet, WireError> {
        Packet::decode(self.packet_type, &self.payload)
    }

    pub fn encode(&self, network: NetworkMagic) -> Result<Vec<u8>, WireError> {
        check_payload_size(self.payload.len())?;
        let length = u32::try_from(self.payload.len()).map_err(|_| WireError::PayloadTooLarge {
            actual: self.payload.len(),
            maximum: MAX_FRAME_PAYLOAD_SIZE,
        })?;
        let mut encoder =
            Encoder::with_capacity(FRAME_HEADER_SIZE.saturating_add(self.payload.len()));
        encoder.put_u32_le(network.as_u32());
        encoder.put_u8(self.packet_type.as_u8());
        encoder.put_u32_le(length);
        encoder.put_bytes(&self.payload);
        Ok(encoder.into_bytes())
    }

    pub fn decode_exact(network: NetworkMagic, input: &[u8]) -> Result<Self, WireError> {
        match decode_frame_prefix(network, input)? {
            Some((frame, consumed)) => {
                if consumed != input.len() {
                    return Err(DecodeError::TrailingBytes {
                        remaining: input.len() - consumed,
                    }
                    .into());
                }
                Ok(frame)
            }
            None => Err(WireError::IncompleteFrame {
                needed: bytes_needed_for_frame(input),
            }),
        }
    }
}

pub fn decode_frame_prefix(
    network: NetworkMagic,
    input: &[u8],
) -> Result<Option<(Frame, usize)>, WireError> {
    if input.len() < FRAME_HEADER_SIZE {
        return Ok(None);
    }
    let mut decoder = Decoder::new(&input[..FRAME_HEADER_SIZE]);
    let actual_magic = decoder.read_u32_le()?;
    if actual_magic != network.as_u32() {
        return Err(WireError::NetworkMagicMismatch {
            expected: network.as_u32(),
            actual: actual_magic,
        });
    }
    let packet_type = PacketType::from_u8(decoder.read_u8()?);
    let payload_length = decoder.read_u32_le()? as usize;
    decoder.finish()?;
    check_payload_size(payload_length)?;
    let frame_length = FRAME_HEADER_SIZE + payload_length;
    if input.len() < frame_length {
        return Ok(None);
    }
    Ok(Some((
        Frame {
            packet_type,
            payload: input[FRAME_HEADER_SIZE..frame_length].to_vec(),
        },
        frame_length,
    )))
}

#[derive(Clone, Debug)]
pub struct FrameDecoder {
    network: NetworkMagic,
    buffered: Vec<u8>,
}

impl FrameDecoder {
    pub const fn new(network: NetworkMagic) -> Self {
        Self {
            network,
            buffered: Vec::new(),
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.buffered.len()
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<Frame>, WireError> {
        let total =
            self.buffered
                .len()
                .checked_add(input.len())
                .ok_or(WireError::PayloadTooLarge {
                    actual: usize::MAX,
                    maximum: MAX_STREAM_BUFFER_SIZE,
                })?;
        if total > MAX_STREAM_BUFFER_SIZE {
            return Err(WireError::PayloadTooLarge {
                actual: total,
                maximum: MAX_STREAM_BUFFER_SIZE,
            });
        }
        self.buffered.extend_from_slice(input);
        let mut consumed = 0;
        let mut frames = Vec::new();
        while let Some((frame, length)) =
            decode_frame_prefix(self.network, &self.buffered[consumed..])?
        {
            consumed += length;
            frames.push(frame);
            if consumed == self.buffered.len() {
                break;
            }
        }
        if consumed != 0 {
            self.buffered.drain(..consumed);
        }
        Ok(frames)
    }
}

fn encode_version(packet: &VersionPacket, encoder: &mut Encoder) -> Result<(), WireError> {
    check_ascii_u8("version user agent", &packet.agent, MAX_USER_AGENT_SIZE)?;
    encoder.put_u32_le(packet.version);
    encoder.put_u32_le(packet.services as u32);
    encoder.put_u32_le(0);
    encoder.put_u64_le(packet.time);
    packet.remote.encode_to(encoder);
    encoder.put_bytes(&packet.nonce);
    encoder.put_u8(packet.agent.len() as u8);
    encoder.put_bytes(packet.agent.as_bytes());
    encoder.put_u32_le(packet.height);
    encoder.put_u8(u8::from(packet.no_relay));
    Ok(())
}

fn decode_version(decoder: &mut Decoder<'_>) -> Result<VersionPacket, WireError> {
    let version = decoder.read_u32_le()?;
    let services = u64::from(decoder.read_u32_le()?);
    let _reserved_service_word = decoder.read_u32_le()?;
    let time = decoder.read_u64_le()?;
    let remote = NetAddress::decode_from(decoder)?;
    let nonce = decoder.read_array()?;
    let agent_length = usize::from(decoder.read_u8()?);
    let agent = decode_hsd_ascii(decoder.read_slice(agent_length)?);
    let height = decoder.read_u32_le()?;
    // HSD treats exactly one as true and every other value as false.
    let no_relay = decoder.read_u8()? == 1;
    Ok(VersionPacket {
        version,
        services,
        time,
        remote,
        nonce,
        agent,
        height,
        no_relay,
    })
}

fn encode_inventory(items: &[Inventory], encoder: &mut Encoder) -> Result<(), WireError> {
    check_count("inventory", items.len(), MAX_INVENTORY_ITEMS)?;
    encoder.put_compact_size(items.len() as u64);
    for item in items {
        encoder.put_u32_le(item.kind.as_u32());
        encoder.put_bytes(&item.hash);
    }
    Ok(())
}

fn decode_inventory(decoder: &mut Decoder<'_>) -> Result<Vec<Inventory>, WireError> {
    let count = read_count(decoder, "inventory", MAX_INVENTORY_ITEMS)?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(Inventory {
            kind: InventoryKind::from_u32(decoder.read_u32_le()?),
            hash: decoder.read_array()?,
        });
    }
    Ok(items)
}

fn encode_reject(packet: &RejectPacket, encoder: &mut Encoder) -> Result<(), WireError> {
    check_ascii_u8("reject reason", &packet.reason, MAX_REJECT_REASON_SIZE)?;
    if packet.message.carries_reject_hash() != packet.hash.is_some() {
        return Err(WireError::InvalidPacket {
            context: "reject packet",
            reason: "hash presence does not match the rejected packet type",
        });
    }
    encoder.put_u8(packet.message.as_u8());
    encoder.put_u8(packet.code);
    encoder.put_u8(packet.reason.len() as u8);
    encoder.put_bytes(packet.reason.as_bytes());
    if let Some(hash) = packet.hash {
        encoder.put_bytes(&hash);
    }
    Ok(())
}

fn decode_reject(decoder: &mut Decoder<'_>) -> Result<RejectPacket, WireError> {
    let message = PacketType::from_u8(decoder.read_u8()?);
    let code = decoder.read_u8()?;
    let reason_length = usize::from(decoder.read_u8()?);
    let reason = decode_hsd_ascii(decoder.read_slice(reason_length)?);
    let hash = if message.carries_reject_hash() {
        Some(decoder.read_array()?)
    } else {
        None
    };
    Ok(RejectPacket {
        message,
        code,
        reason,
        hash,
    })
}

fn read_count(
    decoder: &mut Decoder<'_>,
    context: &'static str,
    maximum: usize,
) -> Result<usize, WireError> {
    let value = decoder.read_compact_size()?;
    let actual = usize::try_from(value).unwrap_or(usize::MAX);
    check_count(context, actual, maximum)?;
    Ok(actual)
}

fn read_bounded_index(
    decoder: &mut Decoder<'_>,
    context: &'static str,
) -> Result<usize, WireError> {
    let value = decoder.read_compact_size()?;
    let actual = usize::try_from(value).unwrap_or(usize::MAX);
    check_count(context, actual, u16::MAX as usize)?;
    Ok(actual)
}

fn absolute_prefilled_index(
    previous: Option<usize>,
    differential: usize,
) -> Result<usize, CompactBlockError> {
    match previous {
        Some(previous) => previous
            .checked_add(differential)
            .and_then(|index| index.checked_add(1))
            .filter(|index| *index <= u16::MAX as usize)
            .ok_or_else(|| CompactBlockError::Malformed("differential index overflow".to_owned())),
        None if differential <= u16::MAX as usize => Ok(differential),
        None => Err(CompactBlockError::Malformed(
            "first differential index exceeds u16".to_owned(),
        )),
    }
}

fn validate_absolute_indexes(indexes: &[usize]) -> Result<(), CompactBlockError> {
    if indexes.len() > MAX_COMPACT_BLOCK_TRANSACTIONS {
        return Err(CompactBlockError::Malformed(format!(
            "index count {} exceeds {MAX_COMPACT_BLOCK_TRANSACTIONS}",
            indexes.len()
        )));
    }
    let mut previous = None;
    for index in indexes.iter().copied() {
        if index > u16::MAX as usize {
            return Err(CompactBlockError::Malformed(format!(
                "transaction index {index} exceeds u16"
            )));
        }
        if previous.is_some_and(|previous| previous >= index) {
            return Err(CompactBlockError::Malformed(
                "absolute transaction indexes are not strictly increasing".to_owned(),
            ));
        }
        previous = Some(index);
    }
    Ok(())
}

fn check_count(context: &'static str, actual: usize, maximum: usize) -> Result<(), WireError> {
    if actual > maximum {
        return Err(WireError::CountTooLarge {
            context,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn check_payload_size(actual: usize) -> Result<(), WireError> {
    if actual > MAX_FRAME_PAYLOAD_SIZE {
        return Err(WireError::PayloadTooLarge {
            actual,
            maximum: MAX_FRAME_PAYLOAD_SIZE,
        });
    }
    Ok(())
}

fn check_ascii_u8(context: &'static str, value: &str, maximum: usize) -> Result<(), WireError> {
    if value.len() > maximum {
        return Err(WireError::CountTooLarge {
            context,
            actual: value.len(),
            maximum,
        });
    }
    if !value.is_ascii() {
        return Err(WireError::InvalidPacket {
            context,
            reason: "outbound text must be ASCII",
        });
    }
    Ok(())
}

fn decode_hsd_ascii(input: &[u8]) -> String {
    input.iter().map(|byte| char::from(byte & 0x7f)).collect()
}

fn take_remaining(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, WireError> {
    Ok(decoder.read_slice(decoder.remaining())?.to_vec())
}

fn blake2b_256_many(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output size");
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("output buffer has the requested size");
    output
}

fn siphash24(input: &[u8], key: &[u8; 16]) -> u64 {
    let key0 = u64::from_le_bytes(key[..8].try_into().expect("eight-byte key half"));
    let key1 = u64::from_le_bytes(key[8..].try_into().expect("eight-byte key half"));
    let mut state = [
        key0 ^ 0x736f_6d65_7073_6575,
        key1 ^ 0x646f_7261_6e64_6f6d,
        key0 ^ 0x6c79_6765_6e65_7261,
        key1 ^ 0x7465_6462_7974_6573,
    ];

    let mut chunks = input.chunks_exact(8);
    for chunk in &mut chunks {
        let message = u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"));
        state[3] ^= message;
        siphash_round(&mut state);
        siphash_round(&mut state);
        state[0] ^= message;
    }

    let mut tail = (input.len() as u64) << 56;
    for (offset, byte) in chunks.remainder().iter().copied().enumerate() {
        tail |= u64::from(byte) << (8 * offset);
    }
    state[3] ^= tail;
    siphash_round(&mut state);
    siphash_round(&mut state);
    state[0] ^= tail;
    state[2] ^= 0xff;
    for _ in 0..4 {
        siphash_round(&mut state);
    }
    state[0] ^ state[1] ^ state[2] ^ state[3]
}

fn siphash_round(state: &mut [u64; 4]) {
    state[0] = state[0].wrapping_add(state[1]);
    state[1] = state[1].rotate_left(13);
    state[1] ^= state[0];
    state[0] = state[0].rotate_left(32);
    state[2] = state[2].wrapping_add(state[3]);
    state[3] = state[3].rotate_left(16);
    state[3] ^= state[2];
    state[0] = state[0].wrapping_add(state[3]);
    state[3] = state[3].rotate_left(21);
    state[3] ^= state[0];
    state[2] = state[2].wrapping_add(state[1]);
    state[1] = state[1].rotate_left(17);
    state[1] ^= state[2];
    state[2] = state[2].rotate_left(32);
}

fn bytes_needed_for_frame(input: &[u8]) -> usize {
    if input.len() < FRAME_HEADER_SIZE {
        return FRAME_HEADER_SIZE - input.len();
    }
    let payload_length =
        u32::from_le_bytes(input[5..9].try_into().expect("frame length field")) as usize;
    FRAME_HEADER_SIZE
        .saturating_add(payload_length)
        .saturating_sub(input.len())
}

#[cfg(test)]
mod tests {
    use hns_transaction::{Address, Input, Outpoint, Output, Witness};

    use super::*;

    const VERSION_PAYLOAD: &str = "03000000010000000000000006050403020100000403020100000000efcdab89000000000000000000000000000000ffff000000000000000000000000000000000000000000000000d6360211111111111111111111111111111111111111111111111111111111111111110102030405060708132f687372642d6f7261636c653a302e312e302f40e2010001";
    const VERSION_FRAME: &str = "d3f26e5b008d00000003000000010000000000000006050403020100000403020100000000efcdab89000000000000000000000000000000ffff000000000000000000000000000000000000000000000000d6360211111111111111111111111111111111111111111111111111111111111111110102030405060708132f687372642d6f7261636c653a302e312e302f40e2010001";
    const HEADER_PAYLOAD: &str = "017856341206050403020100000101010101010101010101010101010101010101010101010101010101010101040404040404040404040404040404040404040404040404040404040404040406060606060606060606060606060606060606060606060605050505050505050505050505050505050505050505050505050505050505050303030303030303030303030303030303030303030303030303030303030303020202020202020202020202020202020202020202020202020202020202020207000000ffff001d0707070707070707070707070707070707070707070707070707070707070707";
    const CMPCTBLOCK_PAYLOAD: &str = "7856341206050403020100000101010101010101010101010101010101010101010101010101010101010101040404040404040404040404040404040404040404040404040404040404040406060606060606060606060606060606060606060606060605050505050505050505050505050505050505050505050505050505050505050303030303030303030303030303030303030303030303030303030303030303020202020202020202020202020202020202020202020202020202020202020207000000ffff001d0707070707070707070707070707070707070707070707070707070707070707010203040506070802d8451ace6e01662b3c2ef01b0100010000000101010101010101010101010101010101010101010101010101010101010101010100000001ffffff01e9030000000000000014000000000000000000000000000000000000000000000100000001020102";
    const GETBLOCKTXN_PAYLOAD: &str =
        "e6c0e40f86adaaa4c2cf6e1be9525a8bb440fd5d4caad2e28f0cec6368d5a879020100";
    const BLOCKTXN_PAYLOAD: &str = "e6c0e40f86adaaa4c2cf6e1be9525a8bb440fd5d4caad2e28f0cec6368d5a87902020000000102020202020202020202020202020202020202020202020202020202020202020200000002ffffff01ea030000000000000014000000000000000000000000000000000000000000000200000001020203030000000103030303030303030303030303030303030303030303030303030303030303030300000003ffffff01eb030000000000000014000000000000000000000000000000000000000000000300000001020304";

    fn decode_hex(value: &str) -> Vec<u8> {
        hex::decode(value).expect("valid fixture hex")
    }

    fn valid_compact_source() -> Block {
        let coinbase = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint::NULL,
                sequence: 1,
                witness: Witness {
                    items: vec![b"hns-rs".to_vec(), vec![0; 8], vec![0; 8]],
                },
            }],
            outputs: vec![Output {
                value: 1_000_u64.into(),
                address: Address::new(0, vec![1; 20]).unwrap(),
                covenant: Default::default(),
            }],
            locktime: 1,
        };
        let coinbase_hash = coinbase.transaction_hash().unwrap();
        let spend = |index: u32| Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    transaction_hash: coinbase_hash,
                    index,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: u64::from(900 - index).into(),
                address: Address::new(0, vec![index as u8 + 2; 20]).unwrap(),
                covenant: Default::default(),
            }],
            locktime: 0,
        };
        let transactions = vec![coinbase, spend(0), spend(1)];
        let header = Header {
            merkle_root: hns_mining::block_merkle_root(&transactions).unwrap(),
            witness_root: hns_mining::block_witness_root(&transactions).unwrap(),
            ..Header::default()
        };
        let block = Block {
            header,
            transactions,
        };
        validate_block_body(&block).unwrap();
        block
    }

    #[test]
    fn packet_type_assignments_match_hsd() {
        let expected = [
            PacketType::Version,
            PacketType::Verack,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::GetAddr,
            PacketType::Addr,
            PacketType::Inv,
            PacketType::GetData,
            PacketType::NotFound,
            PacketType::GetBlocks,
            PacketType::GetHeaders,
            PacketType::Headers,
            PacketType::SendHeaders,
            PacketType::Block,
            PacketType::Tx,
            PacketType::Reject,
            PacketType::Mempool,
            PacketType::FilterLoad,
            PacketType::FilterAdd,
            PacketType::FilterClear,
            PacketType::MerkleBlock,
            PacketType::FeeFilter,
            PacketType::SendCmpct,
            PacketType::CmpctBlock,
            PacketType::GetBlockTxn,
            PacketType::BlockTxn,
            PacketType::GetProof,
            PacketType::Proof,
            PacketType::Claim,
            PacketType::Airdrop,
        ];
        for (value, packet_type) in expected.into_iter().enumerate() {
            assert_eq!(packet_type.as_u8(), value as u8);
            assert_eq!(PacketType::from_u8(value as u8), packet_type);
        }
        assert_eq!(PacketType::from_u8(254), PacketType::Unknown(254));
    }

    #[test]
    fn all_network_ping_frames_match_hsd() {
        let fixtures = [
            (
                NetworkMagic::Mainnet,
                "0102030405060708",
                "d3f26e5b02080000000102030405060708",
            ),
            (
                NetworkMagic::Testnet,
                "4242424242424242",
                "d20d52b102080000004242424242424242",
            ),
            (
                NetworkMagic::Regtest,
                "4343434343434343",
                "cf9538ae02080000004343434343434343",
            ),
            (
                NetworkMagic::Simnet,
                "4444444444444444",
                "dc8e640e02080000004444444444444444",
            ),
        ];
        for (network, payload, encoded) in fixtures {
            let frame = Frame::new(PacketType::Ping, decode_hex(payload)).unwrap();
            assert_eq!(frame.encode(network).unwrap(), decode_hex(encoded));
            assert_eq!(
                Frame::decode_exact(network, &decode_hex(encoded)).unwrap(),
                frame
            );
        }
    }

    #[test]
    fn version_packet_matches_hsd_and_preserves_decode_quirks() {
        let frame = Frame::decode_exact(NetworkMagic::Mainnet, &decode_hex(VERSION_FRAME)).unwrap();
        assert_eq!(frame.payload, decode_hex(VERSION_PAYLOAD));
        let Packet::Version(version) = frame.decode_packet().unwrap() else {
            panic!("expected version packet");
        };
        assert_eq!(version.version, 3);
        assert_eq!(version.services, 1);
        assert_eq!(version.time, 0x0000_0102_0304_0506);
        assert_eq!(version.remote.time, 0x0102_0304);
        assert_eq!(version.remote.services, 0x89ab_cdef);
        assert_eq!(version.remote.port, 14_038);
        assert_eq!(version.agent, "/hsrd-oracle:0.1.0/");
        assert_eq!(version.height, 123_456);
        assert!(version.no_relay);
        assert_eq!(
            Frame::from_packet(&Packet::Version(version))
                .unwrap()
                .encode(NetworkMagic::Mainnet)
                .unwrap(),
            decode_hex(VERSION_FRAME)
        );

        let mut noncanonical = decode_hex(VERSION_PAYLOAD);
        *noncanonical.last_mut().unwrap() = 2;
        let Packet::Version(version) = Packet::decode(PacketType::Version, &noncanonical).unwrap()
        else {
            panic!("expected version packet");
        };
        assert!(!version.no_relay);

        let agent_offset = noncanonical.len() - 1 - 4 - 19;
        noncanonical[agent_offset] = 0x80;
        noncanonical[agent_offset + 1] = 0xff;
        let Packet::Version(version) = Packet::decode(PacketType::Version, &noncanonical).unwrap()
        else {
            panic!("expected version packet");
        };
        assert_eq!(version.agent.as_bytes()[..2], [0, 0x7f]);
    }

    #[test]
    fn address_normalization_and_inventory_match_hsd() {
        let unsupported = decode_hex(concat!(
            "7b0000000000000007000000ddccbbaa09",
            "555555555555555555555555555555555555555555555555555555555555555555555555",
            "d636222222222222222222222222222222222222222222222222222222222222222222"
        ));
        let address = NetAddress::decode(&unsupported).unwrap();
        assert_eq!(address.ip, [0; 16]);
        assert_eq!(address.services, 7);
        let canonical = decode_hex(concat!(
            "7b00000000000000070000000000000000",
            "000000000000000000000000000000000000000000000000000000000000000000000000",
            "d636222222222222222222222222222222222222222222222222222222222222222222"
        ));
        assert_eq!(address.encode(), canonical.as_slice());

        let payload = decode_hex(
            "02020000002121212121212121212121212121212121212121212121212121212121212121efbeedfe2222222222222222222222222222222222222222222222222222222222222222",
        );
        let Packet::Inv(items) = Packet::decode(PacketType::Inv, &payload).unwrap() else {
            panic!("expected inventory packet");
        };
        assert_eq!(items[0].kind, InventoryKind::Block);
        assert_eq!(items[1].kind, InventoryKind::Unknown(0xfeed_beef));
        assert_eq!(Packet::Inv(items).encode_payload().unwrap(), payload);
    }

    #[test]
    fn locators_headers_reject_and_filters_match_hsd() {
        let locator = decode_hex(
            "02313131313131313131313131313131313131313131313131313131313131313132323232323232323232323232323232323232323232323232323232323232323333333333333333333333333333333333333333333333333333333333333333",
        );
        let packet = Packet::decode(PacketType::GetHeaders, &locator).unwrap();
        assert_eq!(packet.encode_payload().unwrap(), locator);

        let headers = decode_hex(HEADER_PAYLOAD);
        let packet = Packet::decode(PacketType::Headers, &headers).unwrap();
        assert_eq!(packet.encode_payload().unwrap(), headers);

        let reject = decode_hex(concat!(
            "0d10096261642d626c6f636b",
            "5151515151515151515151515151515151515151515151515151515151515151"
        ));
        let packet = Packet::decode(PacketType::Reject, &reject).unwrap();
        assert_eq!(packet.encode_payload().unwrap(), reject);

        let fee = decode_hex("7929edffffffffff");
        assert_eq!(
            Packet::decode(PacketType::FeeFilter, &fee).unwrap(),
            Packet::FeeFilter(-1_234_567)
        );
        let compact = decode_hex("010200000000000000");
        assert_eq!(
            Packet::decode(PacketType::SendCmpct, &compact)
                .unwrap()
                .encode_payload()
                .unwrap(),
            compact
        );
    }

    #[test]
    fn syntactic_block_packet_matches_hsd_fixture() {
        let payload = vec![0; HEADER_SIZE + 1];
        let packet = Packet::decode(PacketType::Block, &payload).unwrap();
        assert_eq!(packet.encode_payload().unwrap(), payload);
        let Packet::Block(block) = packet else {
            panic!("expected block packet");
        };
        assert!(block.transactions.is_empty());
    }

    #[test]
    fn compact_block_packets_match_hsd_and_reconstruct() {
        let compact_payload = decode_hex(CMPCTBLOCK_PAYLOAD);
        let Packet::CmpctBlock(compact) =
            Packet::decode(PacketType::CmpctBlock, &compact_payload).unwrap()
        else {
            panic!("expected compact block");
        };
        assert_eq!(compact.total_transactions(), 3);
        assert_eq!(
            Packet::CmpctBlock(compact.clone())
                .encode_payload()
                .unwrap(),
            compact_payload
        );

        let request_payload = decode_hex(GETBLOCKTXN_PAYLOAD);
        let Packet::GetBlockTxn(request) =
            Packet::decode(PacketType::GetBlockTxn, &request_payload).unwrap()
        else {
            panic!("expected compact-block request");
        };
        assert_eq!(request.block_hash, compact.hash());
        assert_eq!(request.indexes, [1, 2]);
        assert_eq!(
            Packet::GetBlockTxn(request.clone())
                .encode_payload()
                .unwrap(),
            request_payload
        );

        let response_payload = decode_hex(BLOCKTXN_PAYLOAD);
        let Packet::BlockTxn(response) =
            Packet::decode(PacketType::BlockTxn, &response_payload).unwrap()
        else {
            panic!("expected compact-block response");
        };
        assert_eq!(response.block_hash, compact.hash());
        assert_eq!(response.transactions.len(), 2);
        assert_eq!(
            Packet::BlockTxn(response.clone()).encode_payload().unwrap(),
            response_payload
        );

        let mut reconstruction = compact.reconstruct(&[]).unwrap();
        assert!(!reconstruction.is_complete());
        assert_eq!(reconstruction.missing_request(), request);
        reconstruction.fill_missing(response).unwrap();
        assert!(reconstruction.is_complete());
        assert!(matches!(
            reconstruction.into_block(),
            Err(CompactBlockError::InvalidBlockBody)
        ));
    }

    #[test]
    fn compact_block_codecs_reject_ambiguous_or_malformed_data() {
        let Packet::CmpctBlock(mut compact) =
            Packet::decode(PacketType::CmpctBlock, &decode_hex(CMPCTBLOCK_PAYLOAD)).unwrap()
        else {
            panic!("expected compact block");
        };
        compact.short_ids[1] = compact.short_ids[0];
        assert!(matches!(
            compact.reconstruct(&[]),
            Err(CompactBlockError::ShortIdCollision(_))
        ));

        let request = CompactBlockRequest {
            block_hash: compact.hash(),
            indexes: vec![2, 2],
        };
        assert!(matches!(
            Packet::GetBlockTxn(request).encode_payload(),
            Err(WireError::CompactBlock(CompactBlockError::Malformed(_)))
        ));

        let block = valid_compact_source();
        let valid_compact =
            CompactBlock::from_block_with_nonce(&block, [1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let mut reconstruction = valid_compact.reconstruct(&[]).unwrap();
        let request = reconstruction.missing_request();
        let mut response = CompactBlockResponse::from_block(&block, &request).unwrap();
        response.transactions[0].outputs[0].value = 0_u64.into();
        reconstruction.fill_missing(response).unwrap();
        assert!(matches!(
            reconstruction.into_block(),
            Err(CompactBlockError::InvalidBlockBody)
        ));

        let mut wrong_request = request;
        wrong_request.block_hash = BlockHash::new([0xff; 32]);
        assert!(matches!(
            CompactBlockResponse::from_block(&block, &wrong_request),
            Err(CompactBlockError::ResponseHashMismatch)
        ));

        let mut trailing = decode_hex(GETBLOCKTXN_PAYLOAD);
        trailing.push(0);
        assert!(matches!(
            Packet::decode(PacketType::GetBlockTxn, &trailing),
            Err(WireError::Decode(DecodeError::TrailingBytes {
                remaining: 1
            }))
        ));
    }

    #[test]
    fn compact_block_reconstruction_validates_the_final_body() {
        let block = valid_compact_source();
        let compact =
            CompactBlock::from_block_with_nonce(&block, [8, 7, 6, 5, 4, 3, 2, 1]).unwrap();
        let mut reconstruction = compact
            .reconstruct(std::slice::from_ref(&block.transactions[1]))
            .unwrap();
        assert_eq!(reconstruction.missing_request().indexes, [2]);
        let response =
            CompactBlockResponse::from_block(&block, &reconstruction.missing_request()).unwrap();
        reconstruction.fill_missing(response).unwrap();
        assert_eq!(reconstruction.into_block().unwrap(), block);
    }

    #[test]
    fn proof_transport_verifies_and_rejects_trailing_bytes() {
        let proof = HsdUrkelProof::decode_strict(&[0, 0, 0, 0]).unwrap();
        let packet = Packet::Proof(ProofPacket {
            root: TreeRoot::new([0; 32]),
            key: NameHash::new([7; 32]),
            proof,
        });
        let payload = packet.encode_payload().unwrap();
        let decoded = Packet::decode(PacketType::Proof, &payload).unwrap();
        assert_eq!(decoded, packet);
        let Packet::Proof(proof) = decoded else {
            panic!("expected proof packet");
        };
        assert_eq!(proof.verify().unwrap(), None);

        let mut trailing = payload;
        trailing.push(0);
        assert!(matches!(
            Packet::decode(PacketType::Proof, &trailing),
            Err(WireError::Urkel(UrkelError::TrailingBytes(1)))
        ));
    }

    #[test]
    fn framing_is_incremental_and_bounded() {
        let first = decode_hex("cf9538ae02080000004343434343434343");
        let second = decode_hex("cf9538ae02080000004444444444444444");
        let mut decoder = FrameDecoder::new(NetworkMagic::Regtest);
        assert!(decoder.push(&first[..5]).unwrap().is_empty());
        assert_eq!(decoder.buffered_len(), 5);
        let mut remainder = first[5..].to_vec();
        remainder.extend_from_slice(&second);
        let frames = decoder.push(&remainder).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(decoder.buffered_len(), 0);

        let mut wrong_magic = first;
        wrong_magic[..4].copy_from_slice(&0_u32.to_le_bytes());
        assert!(matches!(
            Frame::decode_exact(NetworkMagic::Regtest, &wrong_magic),
            Err(WireError::NetworkMagicMismatch { .. })
        ));

        let oversized = [
            &NetworkMagic::Regtest.as_u32().to_le_bytes()[..],
            &[PacketType::Ping.as_u8()],
            &(MAX_FRAME_PAYLOAD_SIZE as u32 + 1).to_le_bytes(),
        ]
        .concat();
        assert!(matches!(
            Frame::decode_exact(NetworkMagic::Regtest, &oversized),
            Err(WireError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn strict_packet_decoders_reject_trailing_and_noncanonical_counts() {
        assert!(matches!(
            Packet::decode(PacketType::Ping, &[0; 9]),
            Err(WireError::Decode(DecodeError::TrailingBytes {
                remaining: 1
            }))
        ));
        assert!(matches!(
            Packet::decode(PacketType::Inv, &[0xfd, 1, 0]),
            Err(WireError::Decode(DecodeError::InvalidValue { .. }))
        ));
        let oversized_count = [0xfd, 0x51, 0xc3];
        assert!(matches!(
            Packet::decode(PacketType::Headers, &oversized_count),
            Err(WireError::CountTooLarge { .. })
        ));
    }
}
