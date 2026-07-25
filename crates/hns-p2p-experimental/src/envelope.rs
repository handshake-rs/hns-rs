use hns_encoding::{DecodeError, Decoder, Encoder};
use thiserror::Error;

pub const DENUO_ENVELOPE_MAGIC: [u8; 4] = *b"DNU1";
pub const DENUO_ENVELOPE_OVERHEAD: usize = 26;
pub const DEFAULT_MAX_DENUO_PAYLOAD: usize = 1024 * 1024;
pub const REGISTRY_NEGOTIATION_PROTOCOL_ID: u16 = 0x0000;
pub const ATOMIC_MARKET_PROTOCOL_ID: u16 = 0x0001;

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
            (REGISTRY_NEGOTIATION_PROTOCOL_ID, 1) => Some(KnownMessage::RegistryHello),
            (REGISTRY_NEGOTIATION_PROTOCOL_ID, 2) => Some(KnownMessage::RegistryHelloAck),
            (REGISTRY_NEGOTIATION_PROTOCOL_ID, 3) => Some(KnownMessage::RegistryReject),
            (ATOMIC_MARKET_PROTOCOL_ID, 1) => Some(KnownMessage::MarketHello),
            (ATOMIC_MARKET_PROTOCOL_ID, 2) => Some(KnownMessage::GetOfferInventory),
            (ATOMIC_MARKET_PROTOCOL_ID, 3) => Some(KnownMessage::OfferInventory),
            (ATOMIC_MARKET_PROTOCOL_ID, 4) => Some(KnownMessage::GetOffers),
            (ATOMIC_MARKET_PROTOCOL_ID, 5) => Some(KnownMessage::Offers),
            (ATOMIC_MARKET_PROTOCOL_ID, 6) => Some(KnownMessage::GetOffer),
            (ATOMIC_MARKET_PROTOCOL_ID, 7) => Some(KnownMessage::Offer),
            (ATOMIC_MARKET_PROTOCOL_ID, 8) => Some(KnownMessage::OfferTombstone),
            (REGISTRY_NEGOTIATION_PROTOCOL_ID | ATOMIC_MARKET_PROTOCOL_ID, _) => {
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
    #[error("declared payload length {declared} does not match {available} available bytes")]
    LengthMismatch { declared: usize, available: usize },
    #[error("unknown message type {message_type:#06x} for known protocol {protocol_id:#06x}")]
    UnknownMessage { protocol_id: u16, message_type: u16 },
    #[error(
        "request ID is zero for correlated protocol {protocol_id:#06x} message {message_type:#06x}"
    )]
    ZeroRequestId { protocol_id: u16, message_type: u16 },
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
