use hns_encoding::{DecodeError, Decoder, Encoder};
use thiserror::Error;

use crate::negotiation::{NegotiationError, RegistryHello};
pub use crate::negotiation::{
    REGISTRY_NEGOTIATION_MAX_PAYLOAD, REGISTRY_NEGOTIATION_PROTOCOL_ID,
    REGISTRY_NEGOTIATION_PROTOCOL_VERSION,
};
use crate::registry::{
    DENUO_V1_REGISTRY_FINGERPRINT, DENUO_V1_REGISTRY_VERSION, DENUO_V2_REGISTRY_FINGERPRINT,
    DENUO_V2_REGISTRY_VERSION,
};

pub const DENUO_ENVELOPE_MAGIC: [u8; 4] = *b"DNU1";
pub const DENUO_ENVELOPE_OVERHEAD: usize = 26;
pub const DENUO_EXTENSION_MAX_PACKET_PAYLOAD: usize = 1_048_576;
pub const DENUO_EXTENSION_MAX_NESTED_PAYLOAD: usize =
    DENUO_EXTENSION_MAX_PACKET_PAYLOAD - DENUO_ENVELOPE_OVERHEAD;
pub const DEFAULT_MAX_DENUO_PAYLOAD: usize = DENUO_EXTENSION_MAX_NESTED_PAYLOAD;
pub const ATOMIC_MARKET_PROTOCOL_ID: u16 = 0x0001;
pub const ATOMIC_MARKET_PROTOCOL_VERSION: u16 = 1;
pub const ATOMIC_MARKET_MAX_PAYLOAD: usize = DENUO_EXTENSION_MAX_NESTED_PAYLOAD;
pub const CROSS_CHAIN_MARKET_PROTOCOL_ID: u16 = 0x0002;
pub const CROSS_CHAIN_MARKET_PROTOCOL_VERSION: u16 = 1;
pub const CROSS_CHAIN_MARKET_MAX_PAYLOAD: usize = 512 * 1024;

pub const MARKET_INTENT_INV_MESSAGE_TYPE: u16 = 1;
pub const GET_MARKET_INTENT_MESSAGE_TYPE: u16 = 2;
pub const MARKET_INTENT_MESSAGE_TYPE: u16 = 3;
pub const CANCEL_MARKET_INTENT_MESSAGE_TYPE: u16 = 4;
pub const PRICE_OBSERVATION_INV_MESSAGE_TYPE: u16 = 5;
pub const GET_PRICE_OBSERVATION_MESSAGE_TYPE: u16 = 6;
pub const PRICE_OBSERVATION_MESSAGE_TYPE: u16 = 7;
pub const PRICE_ROUND_MESSAGE_TYPE: u16 = 8;
pub const MATCH_REQUEST_MESSAGE_TYPE: u16 = 9;
pub const FILL_GRANT_MESSAGE_TYPE: u16 = 10;
pub const MATCH_REJECT_MESSAGE_TYPE: u16 = 11;
pub const SWAP_SESSION_HELLO_MESSAGE_TYPE: u16 = 12;
pub const SWAP_FUNDING_STATUS_MESSAGE_TYPE: u16 = 13;
pub const SWAP_REDEEM_STATUS_MESSAGE_TYPE: u16 = 14;
pub const SWAP_REFUND_STATUS_MESSAGE_TYPE: u16 = 15;

const REGISTRY_HELLO_MESSAGE_TYPE: u16 = 1;
const REGISTRY_HELLO_ACK_MESSAGE_TYPE: u16 = 2;
const REGISTRY_REJECT_MESSAGE_TYPE: u16 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoExtensionEnvelope {
    pub registry_version: u16,
    pub protocol_id: u16,
    pub protocol_version: u16,
    pub message_type: u16,
    pub flags: u16,
    pub request_id: u64,
    pub payload: Vec<u8>,
}

impl DenuoExtensionEnvelope {
    pub fn registry_hello(
        request_id: u64,
        hello: &RegistryHello,
    ) -> Result<Self, RegistryEnvelopeError> {
        Self::registry_message(
            DENUO_V1_REGISTRY_VERSION,
            REGISTRY_HELLO_MESSAGE_TYPE,
            request_id,
            hello,
        )
    }

    pub fn registry_hello_ack(
        request_id: u64,
        hello: &RegistryHello,
    ) -> Result<Self, RegistryEnvelopeError> {
        Self::registry_message(
            DENUO_V1_REGISTRY_VERSION,
            REGISTRY_HELLO_ACK_MESSAGE_TYPE,
            request_id,
            hello,
        )
    }

    pub fn registry_hello_v2(
        request_id: u64,
        hello: &RegistryHello,
    ) -> Result<Self, RegistryEnvelopeError> {
        Self::registry_message(
            DENUO_V2_REGISTRY_VERSION,
            REGISTRY_HELLO_MESSAGE_TYPE,
            request_id,
            hello,
        )
    }

    pub fn registry_hello_ack_v2(
        request_id: u64,
        hello: &RegistryHello,
    ) -> Result<Self, RegistryEnvelopeError> {
        Self::registry_message(
            DENUO_V2_REGISTRY_VERSION,
            REGISTRY_HELLO_ACK_MESSAGE_TYPE,
            request_id,
            hello,
        )
    }

    pub fn decode_registry_hello(
        input: &[u8],
    ) -> Result<(u64, RegistryHello), RegistryEnvelopeError> {
        Self::decode_registry_message(
            input,
            DENUO_V1_REGISTRY_VERSION,
            KnownMessage::RegistryHello,
        )
    }

    pub fn decode_registry_hello_ack(
        input: &[u8],
    ) -> Result<(u64, RegistryHello), RegistryEnvelopeError> {
        Self::decode_registry_message(
            input,
            DENUO_V1_REGISTRY_VERSION,
            KnownMessage::RegistryHelloAck,
        )
    }

    pub fn decode_registry_hello_v2(
        input: &[u8],
    ) -> Result<(u64, RegistryHello), RegistryEnvelopeError> {
        Self::decode_registry_message(
            input,
            DENUO_V2_REGISTRY_VERSION,
            KnownMessage::RegistryHello,
        )
    }

    pub fn decode_registry_hello_ack_v2(
        input: &[u8],
    ) -> Result<(u64, RegistryHello), RegistryEnvelopeError> {
        Self::decode_registry_message(
            input,
            DENUO_V2_REGISTRY_VERSION,
            KnownMessage::RegistryHelloAck,
        )
    }

    pub fn encode_canonical(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.encode(DENUO_EXTENSION_MAX_NESTED_PAYLOAD)
    }

    pub fn decode_canonical(input: &[u8]) -> Result<Self, EnvelopeError> {
        if input.len() > DENUO_EXTENSION_MAX_PACKET_PAYLOAD {
            return Err(EnvelopeError::PacketTooLarge {
                actual: input.len(),
                maximum: DENUO_EXTENSION_MAX_PACKET_PAYLOAD,
            });
        }
        Self::decode(input, DENUO_EXTENSION_MAX_NESTED_PAYLOAD)
    }

    pub fn encode(&self, maximum_payload: usize) -> Result<Vec<u8>, EnvelopeError> {
        self.validate_size(maximum_payload)?;
        self.classify()?;
        let payload_length =
            u32::try_from(self.payload.len()).map_err(|_| EnvelopeError::PayloadTooLarge {
                actual: self.payload.len(),
                maximum: maximum_payload.min(u32::MAX as usize),
            })?;
        let mut encoder = Encoder::with_capacity(DENUO_ENVELOPE_OVERHEAD + self.payload.len());
        encoder.put_bytes(&DENUO_ENVELOPE_MAGIC);
        encoder.put_u16_le(self.registry_version);
        encoder.put_u16_le(self.protocol_id);
        encoder.put_u16_le(self.protocol_version);
        encoder.put_u16_le(self.message_type);
        encoder.put_u16_le(self.flags);
        encoder.put_u64_le(self.request_id);
        encoder.put_u32_le(payload_length);
        encoder.put_bytes(&self.payload);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8], maximum_payload: usize) -> Result<Self, EnvelopeError> {
        let mut decoder = Decoder::new(input);
        let magic = decoder.read_array::<4>()?;
        if magic != DENUO_ENVELOPE_MAGIC {
            return Err(EnvelopeError::WrongMagic(magic));
        }
        let registry_version = decoder.read_u16_le()?;
        let protocol_id = decoder.read_u16_le()?;
        let protocol_version = decoder.read_u16_le()?;
        let message_type = decoder.read_u16_le()?;
        let flags = decoder.read_u16_le()?;
        let request_id = decoder.read_u64_le()?;
        let payload_length = decoder.read_u32_le()? as usize;
        if payload_length > maximum_payload {
            return Err(EnvelopeError::PayloadTooLarge {
                actual: payload_length,
                maximum: maximum_payload,
            });
        }
        if payload_length != decoder.remaining() {
            return Err(EnvelopeError::LengthMismatch {
                declared: payload_length,
                available: decoder.remaining(),
            });
        }
        let payload = decoder.read_bounded_vec(payload_length, maximum_payload)?;
        decoder.finish()?;
        let envelope = Self {
            registry_version,
            protocol_id,
            protocol_version,
            message_type,
            flags,
            request_id,
            payload,
        };
        envelope.classify()?;
        Ok(envelope)
    }

    pub fn classify(&self) -> Result<ProtocolDisposition, EnvelopeError> {
        if self.registry_version == DENUO_V1_REGISTRY_VERSION
            && self.protocol_id == CROSS_CHAIN_MARKET_PROTOCOL_ID
        {
            return Err(EnvelopeError::ProtocolUnavailable {
                registry_version: self.registry_version,
                protocol_id: self.protocol_id,
            });
        }
        let supported_protocol_version = match self.protocol_id {
            REGISTRY_NEGOTIATION_PROTOCOL_ID => Some(REGISTRY_NEGOTIATION_PROTOCOL_VERSION),
            ATOMIC_MARKET_PROTOCOL_ID => Some(ATOMIC_MARKET_PROTOCOL_VERSION),
            CROSS_CHAIN_MARKET_PROTOCOL_ID
                if self.registry_version == DENUO_V2_REGISTRY_VERSION =>
            {
                Some(CROSS_CHAIN_MARKET_PROTOCOL_VERSION)
            }
            _ => None,
        };
        if let Some(expected) = supported_protocol_version {
            if self.protocol_version != expected {
                return Ok(ProtocolDisposition::UnknownProtocol {
                    protocol_id: self.protocol_id,
                    protocol_version: self.protocol_version,
                });
            }
            if self.flags != 0 {
                return Err(EnvelopeError::UnsupportedFlags {
                    protocol_id: self.protocol_id,
                    protocol_version: self.protocol_version,
                    flags: self.flags,
                });
            }
        }
        let known = match (self.registry_version, self.protocol_id, self.message_type) {
            (_, REGISTRY_NEGOTIATION_PROTOCOL_ID, REGISTRY_HELLO_MESSAGE_TYPE) => {
                Some(KnownMessage::RegistryHello)
            }
            (_, REGISTRY_NEGOTIATION_PROTOCOL_ID, REGISTRY_HELLO_ACK_MESSAGE_TYPE) => {
                Some(KnownMessage::RegistryHelloAck)
            }
            (_, REGISTRY_NEGOTIATION_PROTOCOL_ID, REGISTRY_REJECT_MESSAGE_TYPE) => {
                Some(KnownMessage::RegistryReject)
            }
            (_, ATOMIC_MARKET_PROTOCOL_ID, 1) => Some(KnownMessage::MarketHello),
            (_, ATOMIC_MARKET_PROTOCOL_ID, 2) => Some(KnownMessage::GetOfferInventory),
            (_, ATOMIC_MARKET_PROTOCOL_ID, 3) => Some(KnownMessage::OfferInventory),
            (_, ATOMIC_MARKET_PROTOCOL_ID, 4) => Some(KnownMessage::GetOffers),
            (_, ATOMIC_MARKET_PROTOCOL_ID, 5) => Some(KnownMessage::Offers),
            (_, ATOMIC_MARKET_PROTOCOL_ID, 6) => Some(KnownMessage::GetOffer),
            (_, ATOMIC_MARKET_PROTOCOL_ID, 7) => Some(KnownMessage::Offer),
            (_, ATOMIC_MARKET_PROTOCOL_ID, 8) => Some(KnownMessage::OfferTombstone),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                MARKET_INTENT_INV_MESSAGE_TYPE,
            ) => Some(KnownMessage::MarketIntentInventory),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                GET_MARKET_INTENT_MESSAGE_TYPE,
            ) => Some(KnownMessage::GetMarketIntent),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                MARKET_INTENT_MESSAGE_TYPE,
            ) => Some(KnownMessage::MarketIntent),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                CANCEL_MARKET_INTENT_MESSAGE_TYPE,
            ) => Some(KnownMessage::CancelMarketIntent),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                PRICE_OBSERVATION_INV_MESSAGE_TYPE,
            ) => Some(KnownMessage::PriceObservationInventory),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                GET_PRICE_OBSERVATION_MESSAGE_TYPE,
            ) => Some(KnownMessage::GetPriceObservation),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                PRICE_OBSERVATION_MESSAGE_TYPE,
            ) => Some(KnownMessage::PriceObservation),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                PRICE_ROUND_MESSAGE_TYPE,
            ) => Some(KnownMessage::PriceRound),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                MATCH_REQUEST_MESSAGE_TYPE,
            ) => Some(KnownMessage::MatchRequest),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                FILL_GRANT_MESSAGE_TYPE,
            ) => Some(KnownMessage::FillGrant),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                MATCH_REJECT_MESSAGE_TYPE,
            ) => Some(KnownMessage::MatchReject),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                SWAP_SESSION_HELLO_MESSAGE_TYPE,
            ) => Some(KnownMessage::SwapSessionHello),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                SWAP_FUNDING_STATUS_MESSAGE_TYPE,
            ) => Some(KnownMessage::SwapFundingStatus),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                SWAP_REDEEM_STATUS_MESSAGE_TYPE,
            ) => Some(KnownMessage::SwapRedeemStatus),
            (
                DENUO_V2_REGISTRY_VERSION,
                CROSS_CHAIN_MARKET_PROTOCOL_ID,
                SWAP_REFUND_STATUS_MESSAGE_TYPE,
            ) => Some(KnownMessage::SwapRefundStatus),
            (_, REGISTRY_NEGOTIATION_PROTOCOL_ID, _) | (_, ATOMIC_MARKET_PROTOCOL_ID, _) => {
                return Err(EnvelopeError::UnknownMessage {
                    protocol_id: self.protocol_id,
                    message_type: self.message_type,
                });
            }
            (DENUO_V2_REGISTRY_VERSION, CROSS_CHAIN_MARKET_PROTOCOL_ID, _) => {
                return Err(EnvelopeError::UnknownMessage {
                    protocol_id: self.protocol_id,
                    message_type: self.message_type,
                });
            }
            _ => None,
        };

        if let Some(message) = known {
            if message.requires_request_id() && self.request_id == 0 {
                return Err(EnvelopeError::ZeroRequestId {
                    protocol_id: self.protocol_id,
                    message_type: self.message_type,
                });
            }
            Ok(ProtocolDisposition::Known(message))
        } else {
            Ok(ProtocolDisposition::UnknownProtocol {
                protocol_id: self.protocol_id,
                protocol_version: self.protocol_version,
            })
        }
    }

    fn validate_size(&self, maximum_payload: usize) -> Result<(), EnvelopeError> {
        if self.payload.len() > maximum_payload || self.payload.len() > u32::MAX as usize {
            return Err(EnvelopeError::PayloadTooLarge {
                actual: self.payload.len(),
                maximum: maximum_payload.min(u32::MAX as usize),
            });
        }
        Ok(())
    }

    fn registry_message(
        registry_version: u16,
        message_type: u16,
        request_id: u64,
        hello: &RegistryHello,
    ) -> Result<Self, RegistryEnvelopeError> {
        validate_registry_identity(registry_version, hello)?;
        let payload = hello.encode()?;
        if payload.len() > REGISTRY_NEGOTIATION_MAX_PAYLOAD {
            return Err(EnvelopeError::PayloadTooLarge {
                actual: payload.len(),
                maximum: REGISTRY_NEGOTIATION_MAX_PAYLOAD,
            }
            .into());
        }
        let envelope = Self {
            registry_version,
            protocol_id: REGISTRY_NEGOTIATION_PROTOCOL_ID,
            protocol_version: REGISTRY_NEGOTIATION_PROTOCOL_VERSION,
            message_type,
            flags: 0,
            request_id,
            payload,
        };
        envelope.classify()?;
        Ok(envelope)
    }

    fn decode_registry_message(
        input: &[u8],
        expected_registry_version: u16,
        expected: KnownMessage,
    ) -> Result<(u64, RegistryHello), RegistryEnvelopeError> {
        if input.len() > DENUO_EXTENSION_MAX_PACKET_PAYLOAD {
            return Err(EnvelopeError::PacketTooLarge {
                actual: input.len(),
                maximum: DENUO_EXTENSION_MAX_PACKET_PAYLOAD,
            }
            .into());
        }
        let envelope = Self::decode(input, REGISTRY_NEGOTIATION_MAX_PAYLOAD)?;
        if envelope.registry_version != expected_registry_version {
            return Err(RegistryEnvelopeError::WrongRegistryVersion(
                envelope.registry_version,
            ));
        }
        if envelope.protocol_id != REGISTRY_NEGOTIATION_PROTOCOL_ID
            || envelope.protocol_version != REGISTRY_NEGOTIATION_PROTOCOL_VERSION
        {
            return Err(RegistryEnvelopeError::WrongProtocol {
                protocol_id: envelope.protocol_id,
                protocol_version: envelope.protocol_version,
            });
        }
        if envelope.flags != 0 {
            return Err(RegistryEnvelopeError::UnsupportedFlags(envelope.flags));
        }
        let ProtocolDisposition::Known(actual) = envelope.classify()? else {
            return Err(RegistryEnvelopeError::WrongProtocol {
                protocol_id: envelope.protocol_id,
                protocol_version: envelope.protocol_version,
            });
        };
        if actual != expected {
            return Err(RegistryEnvelopeError::UnexpectedMessage { expected, actual });
        }
        let hello = RegistryHello::decode(&envelope.payload)?;
        validate_registry_identity(expected_registry_version, &hello)?;
        Ok((envelope.request_id, hello))
    }
}

fn validate_registry_identity(
    registry_version: u16,
    hello: &RegistryHello,
) -> Result<(), RegistryEnvelopeError> {
    let expected_fingerprint = match registry_version {
        DENUO_V1_REGISTRY_VERSION => DENUO_V1_REGISTRY_FINGERPRINT,
        DENUO_V2_REGISTRY_VERSION => DENUO_V2_REGISTRY_FINGERPRINT,
        _ => {
            return Err(RegistryEnvelopeError::WrongRegistryVersion(
                registry_version,
            ));
        }
    };
    if hello.fingerprint != expected_fingerprint
        || hello.registry_versions.as_slice() != [registry_version]
    {
        return Err(RegistryEnvelopeError::RegistryIdentityMismatch { registry_version });
    }
    if registry_version == DENUO_V1_REGISTRY_VERSION
        && hello
            .protocols
            .iter()
            .any(|protocol| protocol.protocol_id == CROSS_CHAIN_MARKET_PROTOCOL_ID)
    {
        return Err(EnvelopeError::ProtocolUnavailable {
            registry_version,
            protocol_id: CROSS_CHAIN_MARKET_PROTOCOL_ID,
        }
        .into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownMessage {
    RegistryHello,
    RegistryHelloAck,
    RegistryReject,
    MarketHello,
    GetOfferInventory,
    OfferInventory,
    GetOffers,
    Offers,
    GetOffer,
    Offer,
    OfferTombstone,
    MarketIntentInventory,
    GetMarketIntent,
    MarketIntent,
    CancelMarketIntent,
    PriceObservationInventory,
    GetPriceObservation,
    PriceObservation,
    PriceRound,
    MatchRequest,
    FillGrant,
    MatchReject,
    SwapSessionHello,
    SwapFundingStatus,
    SwapRedeemStatus,
    SwapRefundStatus,
}

impl KnownMessage {
    pub const fn requires_request_id(self) -> bool {
        !matches!(
            self,
            Self::RegistryReject
                | Self::MarketHello
                | Self::OfferTombstone
                | Self::MarketIntentInventory
                | Self::CancelMarketIntent
                | Self::PriceObservationInventory
                | Self::PriceRound
                | Self::SwapFundingStatus
                | Self::SwapRedeemStatus
                | Self::SwapRefundStatus
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolDisposition {
    Known(KnownMessage),
    UnknownProtocol {
        protocol_id: u16,
        protocol_version: u16,
    },
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EnvelopeError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("wrong Denuo envelope magic {0:?}")]
    WrongMagic([u8; 4]),
    #[error("payload length {actual} exceeds maximum {maximum}")]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[error("DENUO_EXT packet payload is {actual} bytes; maximum is {maximum}")]
    PacketTooLarge { actual: usize, maximum: usize },
    #[error("declared payload length {declared} does not match {available} available bytes")]
    LengthMismatch { declared: usize, available: usize },
    #[error("unknown message type {message_type:#06x} for known protocol {protocol_id:#06x}")]
    UnknownMessage { protocol_id: u16, message_type: u16 },
    #[error("protocol {protocol_id:#06x} is unavailable in registry version {registry_version}")]
    ProtocolUnavailable {
        registry_version: u16,
        protocol_id: u16,
    },
    #[error(
        "protocol {protocol_id:#06x} version {protocol_version} uses unsupported flags {flags:#06x}"
    )]
    UnsupportedFlags {
        protocol_id: u16,
        protocol_version: u16,
        flags: u16,
    },
    #[error(
        "request ID is zero for correlated protocol {protocol_id:#06x} message {message_type:#06x}"
    )]
    ZeroRequestId { protocol_id: u16, message_type: u16 },
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistryEnvelopeError {
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
    #[error(transparent)]
    Negotiation(#[from] NegotiationError),
    #[error("registry envelope uses unexpected registry version {0}")]
    WrongRegistryVersion(u16),
    #[error("registry hello identity does not match registry version {registry_version}")]
    RegistryIdentityMismatch { registry_version: u16 },
    #[error(
        "registry envelope uses protocol {protocol_id:#06x} version {protocol_version}; expected 0x0000 version 1"
    )]
    WrongProtocol {
        protocol_id: u16,
        protocol_version: u16,
    },
    #[error("registry envelope uses unsupported flags {0:#06x}")]
    UnsupportedFlags(u16),
    #[error("expected registry message {expected:?}, got {actual:?}")]
    UnexpectedMessage {
        expected: KnownMessage,
        actual: KnownMessage,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assignment::Network;

    fn envelope() -> DenuoExtensionEnvelope {
        DenuoExtensionEnvelope {
            registry_version: 1,
            protocol_id: ATOMIC_MARKET_PROTOCOL_ID,
            protocol_version: 1,
            message_type: 6,
            flags: 0,
            request_id: 7,
            payload: vec![0xaa, 0xbb],
        }
    }

    #[test]
    fn envelope_round_trip_and_exact_vector() {
        let encoded = envelope().encode(1024).expect("valid");
        assert_eq!(
            hex::encode(&encoded),
            "444e553101000100010006000000070000000000000002000000aabb"
        );
        assert_eq!(
            DenuoExtensionEnvelope::decode(&encoded, 1024).expect("valid"),
            envelope()
        );
    }

    #[test]
    fn rejects_truncation_trailing_bytes_and_oversized_payloads() {
        let encoded = envelope().encode(1024).expect("valid");
        assert!(matches!(
            DenuoExtensionEnvelope::decode(&encoded[..encoded.len() - 1], 1024),
            Err(EnvelopeError::LengthMismatch { .. })
        ));

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            DenuoExtensionEnvelope::decode(&trailing, 1024),
            Err(EnvelopeError::LengthMismatch { .. })
        ));

        assert!(matches!(
            DenuoExtensionEnvelope::decode(&encoded, 1),
            Err(EnvelopeError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn preserves_unknown_protocol_but_rejects_unknown_known_message() {
        let mut unknown_protocol = envelope();
        unknown_protocol.protocol_id = 0x1234;
        unknown_protocol.message_type = 0xffff;
        assert_eq!(
            unknown_protocol.classify(),
            Ok(ProtocolDisposition::UnknownProtocol {
                protocol_id: 0x1234,
                protocol_version: 1
            })
        );

        let mut unknown_message = envelope();
        unknown_message.message_type = 99;
        assert!(matches!(
            unknown_message.classify(),
            Err(EnvelopeError::UnknownMessage { .. })
        ));
    }

    #[test]
    fn known_classification_requires_exact_protocol_version_and_zero_flags() {
        let mut future_version = envelope();
        future_version.protocol_version += 1;
        assert_eq!(
            future_version.classify(),
            Ok(ProtocolDisposition::UnknownProtocol {
                protocol_id: ATOMIC_MARKET_PROTOCOL_ID,
                protocol_version: 2,
            })
        );

        let mut flagged = envelope();
        flagged.flags = 1;
        assert!(matches!(
            flagged.classify(),
            Err(EnvelopeError::UnsupportedFlags {
                protocol_id: ATOMIC_MARKET_PROTOCOL_ID,
                protocol_version: ATOMIC_MARKET_PROTOCOL_VERSION,
                flags: 1,
            })
        ));
    }

    #[test]
    fn correlated_requests_reject_zero_request_id() {
        let mut invalid = envelope();
        invalid.request_id = 0;
        assert!(matches!(
            invalid.encode(1024),
            Err(EnvelopeError::ZeroRequestId { .. })
        ));
    }

    fn registry_hello() -> RegistryHello {
        RegistryHello::denuo_v1(Network::Regtest, [8; 32], Vec::new(), 4096, 4, 3)
            .expect("canonical registry hello")
    }

    fn registry_hello_v2() -> RegistryHello {
        RegistryHello::denuo_v2(Network::Regtest, [8; 32], Vec::new(), 4096, 4, 3)
            .expect("canonical V2 registry hello")
    }

    #[test]
    fn typed_registry_hello_and_ack_round_trip_without_private_numbers() {
        let hello = registry_hello();
        let hello_envelope =
            DenuoExtensionEnvelope::registry_hello(7, &hello).expect("typed hello");
        let hello_wire = hello_envelope.encode_canonical().expect("bounded envelope");
        assert_eq!(
            DenuoExtensionEnvelope::decode_registry_hello(&hello_wire),
            Ok((7, hello.clone()))
        );

        let ack_envelope =
            DenuoExtensionEnvelope::registry_hello_ack(7, &hello).expect("typed ack");
        let ack_wire = ack_envelope.encode_canonical().expect("bounded envelope");
        assert_eq!(
            DenuoExtensionEnvelope::decode_registry_hello_ack(&ack_wire),
            Ok((7, hello))
        );
        assert!(matches!(
            DenuoExtensionEnvelope::decode_registry_hello(&ack_wire),
            Err(RegistryEnvelopeError::UnexpectedMessage {
                expected: KnownMessage::RegistryHello,
                actual: KnownMessage::RegistryHelloAck,
            })
        ));
    }

    #[test]
    fn typed_v2_registry_hello_and_ack_round_trip() {
        let hello = registry_hello_v2();
        let hello_envelope =
            DenuoExtensionEnvelope::registry_hello_v2(9, &hello).expect("typed V2 hello");
        assert_eq!(hello_envelope.registry_version, DENUO_V2_REGISTRY_VERSION);
        let hello_wire = hello_envelope.encode_canonical().expect("bounded envelope");
        assert_eq!(
            DenuoExtensionEnvelope::decode_registry_hello_v2(&hello_wire),
            Ok((9, hello.clone()))
        );
        assert!(matches!(
            DenuoExtensionEnvelope::decode_registry_hello(&hello_wire),
            Err(RegistryEnvelopeError::WrongRegistryVersion(
                DENUO_V2_REGISTRY_VERSION
            ))
        ));

        let ack_envelope =
            DenuoExtensionEnvelope::registry_hello_ack_v2(9, &hello).expect("typed V2 ack");
        let ack_wire = ack_envelope.encode_canonical().expect("bounded envelope");
        assert_eq!(
            DenuoExtensionEnvelope::decode_registry_hello_ack_v2(&ack_wire),
            Ok((9, hello))
        );

        assert!(matches!(
            DenuoExtensionEnvelope::registry_hello_v2(9, &registry_hello()),
            Err(RegistryEnvelopeError::RegistryIdentityMismatch {
                registry_version: DENUO_V2_REGISTRY_VERSION
            })
        ));

        let v1_with_v2_protocol = RegistryHello::denuo_v1(
            Network::Regtest,
            [8; 32],
            vec![crate::ProtocolRange {
                protocol_id: CROSS_CHAIN_MARKET_PROTOCOL_ID,
                minimum_version: 1,
                maximum_version: 1,
            }],
            4096,
            4,
            3,
        )
        .expect("generic hello remains structurally valid");
        assert!(matches!(
            DenuoExtensionEnvelope::registry_hello(9, &v1_with_v2_protocol),
            Err(RegistryEnvelopeError::Envelope(
                EnvelopeError::ProtocolUnavailable {
                    registry_version: DENUO_V1_REGISTRY_VERSION,
                    protocol_id: CROSS_CHAIN_MARKET_PROTOCOL_ID,
                }
            ))
        ));
    }

    #[test]
    fn cross_chain_messages_are_known_only_in_registry_v2() {
        let messages = [
            (
                MARKET_INTENT_INV_MESSAGE_TYPE,
                KnownMessage::MarketIntentInventory,
            ),
            (
                GET_MARKET_INTENT_MESSAGE_TYPE,
                KnownMessage::GetMarketIntent,
            ),
            (MARKET_INTENT_MESSAGE_TYPE, KnownMessage::MarketIntent),
            (
                CANCEL_MARKET_INTENT_MESSAGE_TYPE,
                KnownMessage::CancelMarketIntent,
            ),
            (
                PRICE_OBSERVATION_INV_MESSAGE_TYPE,
                KnownMessage::PriceObservationInventory,
            ),
            (
                GET_PRICE_OBSERVATION_MESSAGE_TYPE,
                KnownMessage::GetPriceObservation,
            ),
            (
                PRICE_OBSERVATION_MESSAGE_TYPE,
                KnownMessage::PriceObservation,
            ),
            (PRICE_ROUND_MESSAGE_TYPE, KnownMessage::PriceRound),
            (MATCH_REQUEST_MESSAGE_TYPE, KnownMessage::MatchRequest),
            (FILL_GRANT_MESSAGE_TYPE, KnownMessage::FillGrant),
            (MATCH_REJECT_MESSAGE_TYPE, KnownMessage::MatchReject),
            (
                SWAP_SESSION_HELLO_MESSAGE_TYPE,
                KnownMessage::SwapSessionHello,
            ),
            (
                SWAP_FUNDING_STATUS_MESSAGE_TYPE,
                KnownMessage::SwapFundingStatus,
            ),
            (
                SWAP_REDEEM_STATUS_MESSAGE_TYPE,
                KnownMessage::SwapRedeemStatus,
            ),
            (
                SWAP_REFUND_STATUS_MESSAGE_TYPE,
                KnownMessage::SwapRefundStatus,
            ),
        ];
        for (message_type, expected) in messages {
            let envelope = DenuoExtensionEnvelope {
                registry_version: DENUO_V2_REGISTRY_VERSION,
                protocol_id: CROSS_CHAIN_MARKET_PROTOCOL_ID,
                protocol_version: 1,
                message_type,
                flags: 0,
                request_id: 1,
                payload: Vec::new(),
            };
            assert_eq!(
                envelope.classify(),
                Ok(ProtocolDisposition::Known(expected))
            );
        }

        let v1_reserved = DenuoExtensionEnvelope {
            registry_version: DENUO_V1_REGISTRY_VERSION,
            protocol_id: CROSS_CHAIN_MARKET_PROTOCOL_ID,
            protocol_version: 1,
            message_type: MARKET_INTENT_INV_MESSAGE_TYPE,
            flags: 0,
            request_id: 0,
            payload: Vec::new(),
        };
        assert_eq!(
            v1_reserved.classify(),
            Err(EnvelopeError::ProtocolUnavailable {
                registry_version: DENUO_V1_REGISTRY_VERSION,
                protocol_id: CROSS_CHAIN_MARKET_PROTOCOL_ID,
            })
        );
        assert!(matches!(
            v1_reserved.encode_canonical(),
            Err(EnvelopeError::ProtocolUnavailable { .. })
        ));

        let v2_inventory = DenuoExtensionEnvelope {
            registry_version: DENUO_V2_REGISTRY_VERSION,
            ..v1_reserved.clone()
        };
        let mut mislabeled_v1_wire = v2_inventory
            .encode_canonical()
            .expect("V2 inventory envelope");
        mislabeled_v1_wire[4..6].copy_from_slice(&DENUO_V1_REGISTRY_VERSION.to_le_bytes());
        assert!(matches!(
            DenuoExtensionEnvelope::decode_canonical(&mislabeled_v1_wire),
            Err(EnvelopeError::ProtocolUnavailable {
                registry_version: DENUO_V1_REGISTRY_VERSION,
                protocol_id: CROSS_CHAIN_MARKET_PROTOCOL_ID,
            })
        ));

        let mut atomic_v2 = envelope();
        atomic_v2.registry_version = DENUO_V2_REGISTRY_VERSION;
        assert_eq!(
            atomic_v2.classify(),
            Ok(ProtocolDisposition::Known(KnownMessage::GetOffer))
        );

        let mut unknown_v2 = v1_reserved;
        unknown_v2.registry_version = DENUO_V2_REGISTRY_VERSION;
        unknown_v2.message_type = 16;
        assert!(matches!(
            unknown_v2.classify(),
            Err(EnvelopeError::UnknownMessage {
                protocol_id: CROSS_CHAIN_MARKET_PROTOCOL_ID,
                message_type: 16,
            })
        ));
    }

    #[test]
    fn typed_registry_envelopes_enforce_identity_correlation_and_bound() {
        let hello = registry_hello();
        assert!(matches!(
            DenuoExtensionEnvelope::registry_hello(0, &hello),
            Err(RegistryEnvelopeError::Envelope(
                EnvelopeError::ZeroRequestId { .. }
            ))
        ));

        let mut wrong_version =
            DenuoExtensionEnvelope::registry_hello(1, &hello).expect("typed hello");
        wrong_version.protocol_version = 2;
        let wrong_version_wire = wrong_version
            .encode_canonical()
            .expect("generic envelope remains structurally valid");
        assert_eq!(
            DenuoExtensionEnvelope::decode_registry_hello(&wrong_version_wire),
            Err(RegistryEnvelopeError::WrongProtocol {
                protocol_id: REGISTRY_NEGOTIATION_PROTOCOL_ID,
                protocol_version: 2,
            })
        );

        let mut oversized = DenuoExtensionEnvelope::registry_hello(2, &hello).expect("typed hello");
        oversized
            .payload
            .resize(REGISTRY_NEGOTIATION_MAX_PAYLOAD + 1, 0);
        let oversized_wire = oversized
            .encode_canonical()
            .expect("fits outer Denuo bound");
        assert!(matches!(
            DenuoExtensionEnvelope::decode_registry_hello(&oversized_wire),
            Err(RegistryEnvelopeError::Envelope(
                EnvelopeError::PayloadTooLarge {
                    maximum: REGISTRY_NEGOTIATION_MAX_PAYLOAD,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn unknown_registry_message_is_rejected_as_known_protocol() {
        let mut invalid =
            DenuoExtensionEnvelope::registry_hello(1, &registry_hello()).expect("typed hello");
        invalid.message_type = 99;
        assert!(matches!(
            invalid.classify(),
            Err(EnvelopeError::UnknownMessage {
                protocol_id: REGISTRY_NEGOTIATION_PROTOCOL_ID,
                message_type: 99,
            })
        ));
    }

    #[test]
    fn canonical_outer_and_nested_payload_bounds_are_exact() {
        assert_eq!(
            DENUO_EXTENSION_MAX_NESTED_PAYLOAD + DENUO_ENVELOPE_OVERHEAD,
            DENUO_EXTENSION_MAX_PACKET_PAYLOAD
        );
        let mut boundary = DenuoExtensionEnvelope {
            registry_version: DENUO_V1_REGISTRY_VERSION,
            protocol_id: 0x1234,
            protocol_version: 1,
            message_type: 0xffff,
            flags: 0,
            request_id: 0,
            payload: vec![0; DENUO_EXTENSION_MAX_NESTED_PAYLOAD],
        };
        let encoded = boundary.encode_canonical().expect("exact boundary");
        assert_eq!(encoded.len(), DENUO_EXTENSION_MAX_PACKET_PAYLOAD);
        assert_eq!(
            DenuoExtensionEnvelope::decode_canonical(&encoded),
            Ok(boundary.clone())
        );

        boundary.payload.push(0);
        assert_eq!(
            boundary.encode_canonical(),
            Err(EnvelopeError::PayloadTooLarge {
                actual: DENUO_EXTENSION_MAX_NESTED_PAYLOAD + 1,
                maximum: DENUO_EXTENSION_MAX_NESTED_PAYLOAD,
            })
        );
        let oversized_packet = boundary
            .encode(DENUO_EXTENSION_MAX_NESTED_PAYLOAD + 1)
            .expect("generic encoder accepts its explicit nested bound");
        assert_eq!(
            DenuoExtensionEnvelope::decode_canonical(&oversized_packet),
            Err(EnvelopeError::PacketTooLarge {
                actual: DENUO_EXTENSION_MAX_PACKET_PAYLOAD + 1,
                maximum: DENUO_EXTENSION_MAX_PACKET_PAYLOAD,
            })
        );
    }
}
