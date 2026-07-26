use hns_encoding::{DecodeError, Decoder, Encoder};
use thiserror::Error;

use crate::negotiation::{NegotiationError, RegistryHello};
pub use crate::negotiation::{
    REGISTRY_NEGOTIATION_MAX_PAYLOAD, REGISTRY_NEGOTIATION_PROTOCOL_ID,
    REGISTRY_NEGOTIATION_PROTOCOL_VERSION,
};
use crate::registry::DENUO_V1_REGISTRY_VERSION;

pub const DENUO_ENVELOPE_MAGIC: [u8; 4] = *b"DNU1";
pub const DENUO_ENVELOPE_OVERHEAD: usize = 26;
pub const DENUO_EXTENSION_MAX_PACKET_PAYLOAD: usize = 1_048_576;
pub const DENUO_EXTENSION_MAX_NESTED_PAYLOAD: usize =
    DENUO_EXTENSION_MAX_PACKET_PAYLOAD - DENUO_ENVELOPE_OVERHEAD;
pub const DEFAULT_MAX_DENUO_PAYLOAD: usize = DENUO_EXTENSION_MAX_NESTED_PAYLOAD;
pub const ATOMIC_MARKET_PROTOCOL_ID: u16 = 0x0001;
pub const ATOMIC_MARKET_MAX_PAYLOAD: usize = DENUO_EXTENSION_MAX_NESTED_PAYLOAD;

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
        Self::registry_message(REGISTRY_HELLO_MESSAGE_TYPE, request_id, hello)
    }

    pub fn registry_hello_ack(
        request_id: u64,
        hello: &RegistryHello,
    ) -> Result<Self, RegistryEnvelopeError> {
        Self::registry_message(REGISTRY_HELLO_ACK_MESSAGE_TYPE, request_id, hello)
    }

    pub fn decode_registry_hello(
        input: &[u8],
    ) -> Result<(u64, RegistryHello), RegistryEnvelopeError> {
        Self::decode_registry_message(input, KnownMessage::RegistryHello)
    }

    pub fn decode_registry_hello_ack(
        input: &[u8],
    ) -> Result<(u64, RegistryHello), RegistryEnvelopeError> {
        Self::decode_registry_message(input, KnownMessage::RegistryHelloAck)
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
        let known = match (self.protocol_id, self.message_type) {
            (REGISTRY_NEGOTIATION_PROTOCOL_ID, REGISTRY_HELLO_MESSAGE_TYPE) => {
                Some(KnownMessage::RegistryHello)
            }
            (REGISTRY_NEGOTIATION_PROTOCOL_ID, REGISTRY_HELLO_ACK_MESSAGE_TYPE) => {
                Some(KnownMessage::RegistryHelloAck)
            }
            (REGISTRY_NEGOTIATION_PROTOCOL_ID, REGISTRY_REJECT_MESSAGE_TYPE) => {
                Some(KnownMessage::RegistryReject)
            }
            (ATOMIC_MARKET_PROTOCOL_ID, 1) => Some(KnownMessage::MarketHello),
            (ATOMIC_MARKET_PROTOCOL_ID, 2) => Some(KnownMessage::GetOfferInventory),
            (ATOMIC_MARKET_PROTOCOL_ID, 3) => Some(KnownMessage::OfferInventory),
            (ATOMIC_MARKET_PROTOCOL_ID, 4) => Some(KnownMessage::GetOffers),
            (ATOMIC_MARKET_PROTOCOL_ID, 5) => Some(KnownMessage::Offers),
            (ATOMIC_MARKET_PROTOCOL_ID, 6) => Some(KnownMessage::GetOffer),
            (ATOMIC_MARKET_PROTOCOL_ID, 7) => Some(KnownMessage::Offer),
            (ATOMIC_MARKET_PROTOCOL_ID, 8) => Some(KnownMessage::OfferTombstone),
            (REGISTRY_NEGOTIATION_PROTOCOL_ID, _) | (ATOMIC_MARKET_PROTOCOL_ID, _) => {
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
        message_type: u16,
        request_id: u64,
        hello: &RegistryHello,
    ) -> Result<Self, RegistryEnvelopeError> {
        let payload = hello.encode()?;
        if payload.len() > REGISTRY_NEGOTIATION_MAX_PAYLOAD {
            return Err(EnvelopeError::PayloadTooLarge {
                actual: payload.len(),
                maximum: REGISTRY_NEGOTIATION_MAX_PAYLOAD,
            }
            .into());
        }
        let envelope = Self {
            registry_version: DENUO_V1_REGISTRY_VERSION,
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
        if envelope.registry_version != DENUO_V1_REGISTRY_VERSION {
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
        Ok((envelope.request_id, hello))
    }
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
}

impl KnownMessage {
    pub const fn requires_request_id(self) -> bool {
        !matches!(
            self,
            Self::RegistryReject | Self::MarketHello | Self::OfferTombstone
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
    #[error("registry envelope uses registry version {0}; expected version 1")]
    WrongRegistryVersion(u16),
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
            flags: 0x0201,
            request_id: 7,
            payload: vec![0xaa, 0xbb],
        }
    }

    #[test]
    fn envelope_round_trip_and_exact_vector() {
        let encoded = envelope().encode(1024).expect("valid");
        assert_eq!(
            hex::encode(&encoded),
            "444e553101000100010006000102070000000000000002000000aabb"
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
