use std::collections::HashSet;

use hns_encoding::{Decoder, Encoder};
use k256::ecdsa::VerifyingKey;

use crate::ChatProtocolError;

const VERSION: u8 = 1;
const MAX_CHAT_ENVELOPE_SIZE: usize = 8_282;
const MAX_CHAT_ACK_WIRE_SIZE: usize = 2_098;

pub const MAX_CHAT_CIPHERTEXT_SIZE: usize = 8 * 1024;
pub const MAX_CHAT_ACKNOWLEDGEMENT_SIZE: usize = 2 * 1024;
pub const MAX_CHAT_EXPIRATION_WINDOW: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatEnvelopeV1 {
    pub message_id: [u8; 32],
    pub recipient_public_key: [u8; 32],
    pub created_at: u64,
    pub expires_at: u64,
    pub gift_wrap: Vec<u8>,
}

impl ChatEnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ChatProtocolError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(81_usize.saturating_add(self.gift_wrap.len()));
        encoder.put_u8(VERSION);
        encoder.put_bytes(&self.message_id);
        encoder.put_bytes(&self.recipient_public_key);
        encoder.put_u64_le(self.created_at);
        encoder.put_u64_le(self.expires_at);
        encoder.put_varbytes(&self.gift_wrap);
        let encoded = encoder.into_bytes();
        if encoded.len() > MAX_CHAT_ENVELOPE_SIZE {
            return Err(ChatProtocolError::TooLarge {
                actual: encoded.len(),
                maximum: MAX_CHAT_ENVELOPE_SIZE,
            });
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ChatProtocolError> {
        if input.len() > MAX_CHAT_ENVELOPE_SIZE {
            return Err(ChatProtocolError::TooLarge {
                actual: input.len(),
                maximum: MAX_CHAT_ENVELOPE_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        if decoder.read_u8()? != VERSION {
            return Err(ChatProtocolError::Invalid(
                "unsupported chat envelope version",
            ));
        }
        let envelope = Self {
            message_id: decoder.read_array()?,
            recipient_public_key: decoder.read_array()?,
            created_at: decoder.read_u64_le()?,
            expires_at: decoder.read_u64_le()?,
            gift_wrap: decoder.read_varbytes(MAX_CHAT_CIPHERTEXT_SIZE, "NIP-59 gift wrap")?,
        };
        decoder.finish()?;
        envelope.validate()?;
        Ok(envelope)
    }

    fn validate(&self) -> Result<(), ChatProtocolError> {
        if self.message_id.iter().all(|byte| *byte == 0) {
            return Err(ChatProtocolError::Invalid("message identifier is zero"));
        }
        if self.recipient_public_key.iter().all(|byte| *byte == 0) {
            return Err(ChatProtocolError::Invalid("recipient public key is zero"));
        }
        let mut recipient = [0_u8; 33];
        recipient[0] = 0x02;
        recipient[1..].copy_from_slice(&self.recipient_public_key);
        if VerifyingKey::from_sec1_bytes(&recipient).is_err() {
            return Err(ChatProtocolError::Invalid(
                "recipient public key is not a valid x-only secp256k1 key",
            ));
        }
        if self.created_at == 0
            || self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_CHAT_EXPIRATION_WINDOW
        {
            return Err(ChatProtocolError::Invalid(
                "message timestamps are noncanonical or exceed retention",
            ));
        }
        if self.gift_wrap.is_empty() {
            return Err(ChatProtocolError::Invalid("NIP-59 gift wrap is empty"));
        }
        if self.gift_wrap.len() > MAX_CHAT_CIPHERTEXT_SIZE {
            return Err(ChatProtocolError::TooLarge {
                actual: self.gift_wrap.len(),
                maximum: MAX_CHAT_CIPHERTEXT_SIZE,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatAcknowledgementV1 {
    pub message_id: [u8; 32],
    pub received_at: u64,
    pub encrypted_receipt: Vec<u8>,
}

impl ChatAcknowledgementV1 {
    pub fn encode(&self) -> Result<Vec<u8>, ChatProtocolError> {
        self.validate()?;
        let mut encoder =
            Encoder::with_capacity(42_usize.saturating_add(self.encrypted_receipt.len()));
        encoder.put_u8(VERSION);
        encoder.put_bytes(&self.message_id);
        encoder.put_u64_le(self.received_at);
        encoder.put_varbytes(&self.encrypted_receipt);
        let encoded = encoder.into_bytes();
        if encoded.len() > MAX_CHAT_ACK_WIRE_SIZE {
            return Err(ChatProtocolError::TooLarge {
                actual: encoded.len(),
                maximum: MAX_CHAT_ACK_WIRE_SIZE,
            });
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ChatProtocolError> {
        if input.len() > MAX_CHAT_ACK_WIRE_SIZE {
            return Err(ChatProtocolError::TooLarge {
                actual: input.len(),
                maximum: MAX_CHAT_ACK_WIRE_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        if decoder.read_u8()? != VERSION {
            return Err(ChatProtocolError::Invalid(
                "unsupported acknowledgement version",
            ));
        }
        let acknowledgement = Self {
            message_id: decoder.read_array()?,
            received_at: decoder.read_u64_le()?,
            encrypted_receipt: decoder
                .read_varbytes(MAX_CHAT_ACKNOWLEDGEMENT_SIZE, "encrypted acknowledgement")?,
        };
        decoder.finish()?;
        acknowledgement.validate()?;
        Ok(acknowledgement)
    }

    fn validate(&self) -> Result<(), ChatProtocolError> {
        if self.message_id.iter().all(|byte| *byte == 0) {
            return Err(ChatProtocolError::Invalid("message identifier is zero"));
        }
        if self.received_at == 0 {
            return Err(ChatProtocolError::Invalid(
                "acknowledgement timestamp is zero",
            ));
        }
        if self.encrypted_receipt.is_empty() {
            return Err(ChatProtocolError::Invalid(
                "encrypted acknowledgement is empty",
            ));
        }
        if self.encrypted_receipt.len() > MAX_CHAT_ACKNOWLEDGEMENT_SIZE {
            return Err(ChatProtocolError::TooLarge {
                actual: self.encrypted_receipt.len(),
                maximum: MAX_CHAT_ACKNOWLEDGEMENT_SIZE,
            });
        }
        Ok(())
    }
}

pub fn validate_unique_message_ids(envelopes: &[ChatEnvelopeV1]) -> Result<(), ChatProtocolError> {
    let mut identifiers = HashSet::with_capacity(envelopes.len());
    for envelope in envelopes {
        envelope.validate()?;
        if !identifiers.insert(envelope.message_id) {
            return Err(ChatProtocolError::DuplicateMessageId);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> ChatEnvelopeV1 {
        ChatEnvelopeV1 {
            message_id: [1; 32],
            recipient_public_key: hex::decode(
                "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917",
            )
            .expect("hex")
            .try_into()
            .expect("x-only key"),
            created_at: 1_700_000_000,
            expires_at: 1_700_000_600,
            gift_wrap: br#"{\"kind\":1059,\"content\":\"opaque\"}"#.to_vec(),
        }
    }

    #[test]
    fn opaque_envelope_and_acknowledgement_round_trip_strictly() {
        let envelope = envelope();
        let encoded = envelope.encode().expect("encode");
        assert_eq!(ChatEnvelopeV1::decode(&encoded).expect("decode"), envelope);
        let acknowledgement = ChatAcknowledgementV1 {
            message_id: envelope.message_id,
            received_at: envelope.created_at + 10,
            encrypted_receipt: b"opaque receipt".to_vec(),
        };
        let encoded = acknowledgement.encode().expect("encode");
        assert_eq!(
            ChatAcknowledgementV1::decode(&encoded).expect("decode"),
            acknowledgement
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(ChatAcknowledgementV1::decode(&trailing).is_err());
    }

    #[test]
    fn limits_timestamps_and_duplicates_fail_closed() {
        let mut invalid = envelope();
        invalid.expires_at = invalid.created_at + MAX_CHAT_EXPIRATION_WINDOW + 1;
        assert!(invalid.encode().is_err());
        invalid = envelope();
        invalid.gift_wrap = vec![0; MAX_CHAT_CIPHERTEXT_SIZE + 1];
        assert!(invalid.encode().is_err());
        invalid = envelope();
        invalid.recipient_public_key = [0xff; 32];
        assert!(invalid.encode().is_err());
        let first = envelope();
        let second = first.clone();
        assert_eq!(
            validate_unique_message_ids(&[first, second]),
            Err(ChatProtocolError::DuplicateMessageId)
        );
    }
}
