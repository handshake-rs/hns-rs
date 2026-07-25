#![doc = "Bounded, runtime-independent codecs for standard Handshake P2P traffic."]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hns_encoding::{DecodeError, Decoder, Encoder};
use hns_header_consensus::{HEADER_SIZE, Header};
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

impl ProofPacket {
    pub fn verify(&self) -> Result<Option<Vec<u8>>, UrkelError> {
        self.proof.verify(self.root, self.key)
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
    Block(Vec<u8>),
    Tx(Transaction),
    Reject(RejectPacket),
    Mempool,
    FilterLoad(Vec<u8>),
    FilterAdd(Vec<u8>),
    FilterClear,
    MerkleBlock(Vec<u8>),
    FeeFilter(i64),
    SendCmpct { mode: u8, version: u64 },
    CmpctBlock(Vec<u8>),
    GetBlockTxn(Vec<u8>),
    BlockTxn(Vec<u8>),
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
            Self::Block(payload)
            | Self::FilterLoad(payload)
            | Self::FilterAdd(payload)
            | Self::MerkleBlock(payload)
            | Self::CmpctBlock(payload)
            | Self::GetBlockTxn(payload)
            | Self::BlockTxn(payload)
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
            PacketType::Block => Self::Block(take_remaining(&mut decoder)?),
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
            PacketType::CmpctBlock => Self::CmpctBlock(take_remaining(&mut decoder)?),
            PacketType::GetBlockTxn => Self::GetBlockTxn(take_remaining(&mut decoder)?),
            PacketType::BlockTxn => Self::BlockTxn(take_remaining(&mut decoder)?),
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
    use super::*;

    const VERSION_PAYLOAD: &str = "03000000010000000000000006050403020100000403020100000000efcdab89000000000000000000000000000000ffff000000000000000000000000000000000000000000000000d6360211111111111111111111111111111111111111111111111111111111111111110102030405060708132f687372642d6f7261636c653a302e312e302f40e2010001";
    const VERSION_FRAME: &str = "d3f26e5b008d00000003000000010000000000000006050403020100000403020100000000efcdab89000000000000000000000000000000ffff000000000000000000000000000000000000000000000000d6360211111111111111111111111111111111111111111111111111111111111111110102030405060708132f687372642d6f7261636c653a302e312e302f40e2010001";
    const HEADER_PAYLOAD: &str = "017856341206050403020100000101010101010101010101010101010101010101010101010101010101010101040404040404040404040404040404040404040404040404040404040404040406060606060606060606060606060606060606060606060605050505050505050505050505050505050505050505050505050505050505050303030303030303030303030303030303030303030303030303030303030303020202020202020202020202020202020202020202020202020202020202020207000000ffff001d0707070707070707070707070707070707070707070707070707070707070707";

    fn decode_hex(value: &str) -> Vec<u8> {
        hex::decode(value).expect("valid fixture hex")
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
