use hns_encoding::{Decoder, Encoder};

use crate::config::{DirectTargetLocator, TargetConfigRecord};
use crate::message::{OdohMessage, OdohMessageType};
use crate::{
    MAX_ODOH_CONFIG_SIZE, MAX_ODOH_QUERY_SIZE, MAX_ODOH_RESPONSE_SIZE, MAX_OUTER_PADDING_SIZE,
    OdohProtocolError,
};

pub const ODOH_ROLE_PROXY: u8 = 1;
pub const ODOH_ROLE_TARGET: u8 = 2;
pub const ODOH_ROLE_CONFIG_CACHE: u8 = 4;
const ODOH_ROLE_MASK: u8 = ODOH_ROLE_PROXY | ODOH_ROLE_TARGET | ODOH_ROLE_CONFIG_CACHE;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdohCapabilities {
    pub roles: u8,
    pub max_client_query: u16,
    pub max_target_response: u32,
    pub max_live_per_connection: u16,
    pub max_config_size: u16,
    pub preferred_query_bucket: u16,
    pub preferred_response_bucket: u16,
}

impl OdohCapabilities {
    pub fn encode(&self) -> Result<Vec<u8>, OdohProtocolError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(15);
        encoder.put_u8(self.roles);
        encoder.put_u16_le(self.max_client_query);
        encoder.put_u32_le(self.max_target_response);
        encoder.put_u16_le(self.max_live_per_connection);
        encoder.put_u16_le(self.max_config_size);
        encoder.put_u16_le(self.preferred_query_bucket);
        encoder.put_u16_le(self.preferred_response_bucket);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, OdohProtocolError> {
        if input.len() != 15 {
            return Err(OdohProtocolError::Invalid(
                "invalid P2P ODoH capabilities length",
            ));
        }
        let mut decoder = Decoder::new(input);
        let capabilities = Self {
            roles: decoder.read_u8()?,
            max_client_query: decoder.read_u16_le()?,
            max_target_response: decoder.read_u32_le()?,
            max_live_per_connection: decoder.read_u16_le()?,
            max_config_size: decoder.read_u16_le()?,
            preferred_query_bucket: decoder.read_u16_le()?,
            preferred_response_bucket: decoder.read_u16_le()?,
        };
        decoder.finish()?;
        capabilities.validate()?;
        Ok(capabilities)
    }

    fn validate(&self) -> Result<(), OdohProtocolError> {
        if self.roles == 0 || self.roles & !ODOH_ROLE_MASK != 0 {
            return Err(OdohProtocolError::Invalid(
                "invalid P2P ODoH capability roles",
            ));
        }
        if !(256..=MAX_ODOH_QUERY_SIZE as u16).contains(&self.max_client_query)
            || !(512..=MAX_ODOH_RESPONSE_SIZE as u32).contains(&self.max_target_response)
            || !(1..=256).contains(&self.max_live_per_connection)
            || !(128..=MAX_ODOH_CONFIG_SIZE as u16).contains(&self.max_config_size)
        {
            return Err(OdohProtocolError::Invalid(
                "invalid P2P ODoH capability limit",
            ));
        }
        validate_bucket(self.preferred_query_bucket)?;
        validate_bucket(self.preferred_response_bucket)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetConfigBody {
    pub locator: DirectTargetLocator,
    pub allow_cached: bool,
}

impl GetConfigBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut output = self.locator.encode();
        output.push(u8::from(self.allow_cached));
        output
    }

    pub fn decode(input: &[u8], allow_private: bool) -> Result<Self, OdohProtocolError> {
        let mut decoder = Decoder::new(input);
        let locator = DirectTargetLocator::decode_from(&mut decoder, allow_private)?;
        if decoder.remaining() != 1 {
            return Err(OdohProtocolError::Invalid("invalid GETCONFIG body"));
        }
        let allow_cached = match decoder.read_u8()? {
            0 => false,
            1 => true,
            _ => {
                return Err(OdohProtocolError::Invalid("invalid GETCONFIG cache flag"));
            }
        };
        decoder.finish()?;
        Ok(Self {
            locator,
            allow_cached,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdohConfigBody {
    pub record: Vec<u8>,
}

impl OdohConfigBody {
    pub fn new(record: Vec<u8>) -> Result<Self, OdohProtocolError> {
        validate_nonempty_size(
            &record,
            MAX_ODOH_CONFIG_SIZE,
            "invalid CONFIG record length",
        )?;
        Ok(Self { record })
    }

    pub fn encode(&self) -> Result<Vec<u8>, OdohProtocolError> {
        validate_nonempty_size(
            &self.record,
            MAX_ODOH_CONFIG_SIZE,
            "invalid CONFIG record length",
        )?;
        let length = u16::try_from(self.record.len()).map_err(|_| OdohProtocolError::TooLarge {
            actual: self.record.len(),
            maximum: u16::MAX as usize,
        })?;
        let mut encoder = Encoder::with_capacity(2 + self.record.len());
        encoder.put_u16_le(length);
        encoder.put_bytes(&self.record);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, OdohProtocolError> {
        let mut decoder = Decoder::new(input);
        let length = decoder.read_u16_le()? as usize;
        if length == 0 || length > MAX_ODOH_CONFIG_SIZE || decoder.remaining() != length {
            return Err(OdohProtocolError::Invalid("invalid CONFIG record length"));
        }
        let record = decoder.read_bounded_vec(length, MAX_ODOH_CONFIG_SIZE)?;
        decoder.finish()?;
        Ok(Self { record })
    }

    pub fn decode_and_verify_record(
        &self,
        expected_locator: &DirectTargetLocator,
        expected_network_magic: u32,
        now: u64,
        allow_private: bool,
    ) -> Result<TargetConfigRecord, OdohProtocolError> {
        TargetConfigRecord::decode_and_verify(
            &self.record,
            expected_locator,
            expected_network_magic,
            now,
            allow_private,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientQuery {
    pub locator: DirectTargetLocator,
    pub config_id: [u8; 32],
    pub message: OdohMessage,
    pub padding: Vec<u8>,
}

impl ClientQuery {
    pub fn encode(&self) -> Result<Vec<u8>, OdohProtocolError> {
        ensure_message_type(&self.message, OdohMessageType::Query)?;
        let message = self.message.encode()?;
        validate_nonempty_size(
            &message,
            MAX_ODOH_QUERY_SIZE,
            "invalid CLIENT_QUERY message length",
        )?;
        validate_padding(&self.padding)?;
        let locator = self.locator.encode();
        let mut encoder =
            Encoder::with_capacity(locator.len() + 32 + 2 + message.len() + 2 + self.padding.len());
        encoder.put_bytes(&locator);
        encoder.put_bytes(&self.config_id);
        encoder.put_u16_le(message.len() as u16);
        encoder.put_bytes(&message);
        put_padding(&mut encoder, &self.padding);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8], allow_private: bool) -> Result<Self, OdohProtocolError> {
        let mut decoder = Decoder::new(input);
        let locator = DirectTargetLocator::decode_from(&mut decoder, allow_private)?;
        let config_id = decoder.read_array()?;
        let message = read_message(&mut decoder, MAX_ODOH_QUERY_SIZE, OdohMessageType::Query)?;
        let padding = read_padding(&mut decoder)?;
        decoder.finish()?;
        Ok(Self {
            locator,
            config_id,
            message,
            padding,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetQuery {
    pub config_id: [u8; 32],
    pub message: OdohMessage,
    pub padding: Vec<u8>,
}

impl TargetQuery {
    pub fn encode(&self) -> Result<Vec<u8>, OdohProtocolError> {
        ensure_message_type(&self.message, OdohMessageType::Query)?;
        let message = self.message.encode()?;
        validate_nonempty_size(
            &message,
            MAX_ODOH_QUERY_SIZE,
            "invalid TARGET_QUERY message length",
        )?;
        validate_padding(&self.padding)?;
        let mut encoder = Encoder::with_capacity(32 + 2 + message.len() + 2 + self.padding.len());
        encoder.put_bytes(&self.config_id);
        encoder.put_u16_le(message.len() as u16);
        encoder.put_bytes(&message);
        put_padding(&mut encoder, &self.padding);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, OdohProtocolError> {
        let mut decoder = Decoder::new(input);
        let config_id = decoder.read_array()?;
        let message = read_message(&mut decoder, MAX_ODOH_QUERY_SIZE, OdohMessageType::Query)?;
        let padding = read_padding(&mut decoder)?;
        decoder.finish()?;
        Ok(Self {
            config_id,
            message,
            padding,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdohResponseBody {
    pub message: OdohMessage,
    pub padding: Vec<u8>,
}

impl OdohResponseBody {
    pub fn encode(&self) -> Result<Vec<u8>, OdohProtocolError> {
        ensure_message_type(&self.message, OdohMessageType::Response)?;
        let message = self.message.encode()?;
        validate_nonempty_size(
            &message,
            MAX_ODOH_RESPONSE_SIZE,
            "invalid ODoH response length",
        )?;
        validate_padding(&self.padding)?;
        let mut encoder = Encoder::with_capacity(4 + message.len() + 2 + self.padding.len());
        encoder.put_u32_le(message.len() as u32);
        encoder.put_bytes(&message);
        put_padding(&mut encoder, &self.padding);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, OdohProtocolError> {
        let mut decoder = Decoder::new(input);
        let length = decoder.read_u32_le()? as usize;
        if length == 0 || length > MAX_ODOH_RESPONSE_SIZE || decoder.remaining() < length + 2 {
            return Err(OdohProtocolError::Invalid("invalid ODoH response length"));
        }
        let message = OdohMessage::decode(decoder.read_slice(length)?)?;
        ensure_message_type(&message, OdohMessageType::Response)?;
        let padding = read_padding(&mut decoder)?;
        decoder.finish()?;
        Ok(Self { message, padding })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OdohStatus {
    Refused = 0,
    Unsupported = 1,
    Busy = 2,
    InvalidOuter = 3,
    TargetUnreachable = 4,
    TargetTimeout = 5,
    ConfigUnknown = 6,
    ConfigExpired = 7,
    TargetFailure = 8,
    ResponseTooLarge = 9,
    RateLimited = 10,
    Cancelled = 11,
    InternalError = 12,
}

impl TryFrom<u8> for OdohStatus {
    type Error = OdohProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Refused),
            1 => Ok(Self::Unsupported),
            2 => Ok(Self::Busy),
            3 => Ok(Self::InvalidOuter),
            4 => Ok(Self::TargetUnreachable),
            5 => Ok(Self::TargetTimeout),
            6 => Ok(Self::ConfigUnknown),
            7 => Ok(Self::ConfigExpired),
            8 => Ok(Self::TargetFailure),
            9 => Ok(Self::ResponseTooLarge),
            10 => Ok(Self::RateLimited),
            11 => Ok(Self::Cancelled),
            12 => Ok(Self::InternalError),
            _ => Err(OdohProtocolError::Invalid("unknown P2P ODoH error status")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OdohErrorBody {
    pub status: OdohStatus,
    pub retry_after: u32,
    pub error_class: u16,
}

impl OdohErrorBody {
    pub fn encode(self) -> Vec<u8> {
        let mut encoder = Encoder::with_capacity(7);
        encoder.put_u8(self.status as u8);
        encoder.put_u32_le(self.retry_after);
        encoder.put_u16_le(self.error_class);
        encoder.into_bytes()
    }

    pub fn decode(input: &[u8]) -> Result<Self, OdohProtocolError> {
        if input.len() != 7 {
            return Err(OdohProtocolError::Invalid("invalid P2P ODoH error body"));
        }
        let mut decoder = Decoder::new(input);
        let error = Self {
            status: OdohStatus::try_from(decoder.read_u8()?)?,
            retry_after: decoder.read_u32_le()?,
            error_class: decoder.read_u16_le()?,
        };
        decoder.finish()?;
        Ok(error)
    }
}

fn read_message(
    decoder: &mut Decoder<'_>,
    maximum: usize,
    expected_type: OdohMessageType,
) -> Result<OdohMessage, OdohProtocolError> {
    let length = decoder.read_u16_le()? as usize;
    if length == 0 || length > maximum || decoder.remaining() < length + 2 {
        return Err(OdohProtocolError::Invalid("invalid ODoH query length"));
    }
    let message = OdohMessage::decode(decoder.read_slice(length)?)?;
    ensure_message_type(&message, expected_type)?;
    Ok(message)
}

fn ensure_message_type(
    message: &OdohMessage,
    expected: OdohMessageType,
) -> Result<(), OdohProtocolError> {
    if message.message_type != expected {
        return Err(OdohProtocolError::Invalid(
            "unexpected RFC 9230 message type",
        ));
    }
    Ok(())
}

fn put_padding(encoder: &mut Encoder, padding: &[u8]) {
    encoder.put_u16_le(padding.len() as u16);
    encoder.put_bytes(padding);
}

fn read_padding(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, OdohProtocolError> {
    let length = decoder.read_u16_le()? as usize;
    if length > MAX_OUTER_PADDING_SIZE || decoder.remaining() != length {
        return Err(OdohProtocolError::Invalid("invalid outer-padding length"));
    }
    let padding = decoder.read_bounded_vec(length, MAX_OUTER_PADDING_SIZE)?;
    validate_padding(&padding)?;
    Ok(padding)
}

fn validate_padding(padding: &[u8]) -> Result<(), OdohProtocolError> {
    if padding.len() > MAX_OUTER_PADDING_SIZE {
        return Err(OdohProtocolError::TooLarge {
            actual: padding.len(),
            maximum: MAX_OUTER_PADDING_SIZE,
        });
    }
    if padding.iter().any(|byte| *byte != 0) {
        return Err(OdohProtocolError::Invalid("outer padding is nonzero"));
    }
    Ok(())
}

fn validate_nonempty_size(
    value: &[u8],
    maximum: usize,
    message: &'static str,
) -> Result<(), OdohProtocolError> {
    if value.is_empty() {
        return Err(OdohProtocolError::Invalid(message));
    }
    if value.len() > maximum {
        return Err(OdohProtocolError::TooLarge {
            actual: value.len(),
            maximum,
        });
    }
    Ok(())
}

fn validate_bucket(bucket: u16) -> Result<(), OdohProtocolError> {
    if bucket != 0 && (!(128..=4096).contains(&bucket) || !bucket.is_power_of_two()) {
        return Err(OdohProtocolError::Invalid(
            "invalid P2P ODoH padding bucket",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn locator() -> DirectTargetLocator {
        DirectTargetLocator::new(
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .expect("hex")
                .try_into()
                .expect("33 bytes"),
            "127.0.0.1:14039"
                .parse::<SocketAddr>()
                .expect("socket address"),
            true,
        )
        .expect("valid locator")
    }

    fn message(message_type: OdohMessageType) -> OdohMessage {
        OdohMessage::new(message_type, Vec::new(), vec![0xaa]).expect("valid message")
    }

    #[test]
    fn capabilities_match_hsd_encoding_and_reject_invalid_limits() {
        let capabilities = OdohCapabilities {
            roles: ODOH_ROLE_PROXY | ODOH_ROLE_TARGET,
            max_client_query: 8192,
            max_target_response: 65_535,
            max_live_per_connection: 256,
            max_config_size: 16_384,
            preferred_query_bucket: 512,
            preferred_response_bucket: 1024,
        };
        let encoded = capabilities.encode().expect("valid");
        assert_eq!(hex::encode(&encoded), "030020ffff00000001004000020004");
        assert_eq!(
            OdohCapabilities::decode(&encoded).expect("valid"),
            capabilities
        );

        let mut invalid = capabilities;
        invalid.roles = 0;
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn hsd_body_examples_round_trip_strictly() {
        let get_config = GetConfigBody {
            locator: locator(),
            allow_cached: true,
        };
        assert_eq!(
            GetConfigBody::decode(&get_config.encode(), true).expect("valid"),
            get_config
        );

        let client = ClientQuery {
            locator: locator(),
            config_id: [2; 32],
            message: message(OdohMessageType::Query),
            padding: Vec::new(),
        };
        assert_eq!(
            ClientQuery::decode(&client.encode().expect("valid"), true).expect("valid"),
            client
        );

        let target = TargetQuery {
            config_id: [2; 32],
            message: message(OdohMessageType::Query),
            padding: vec![0; 128],
        };
        assert_eq!(
            TargetQuery::decode(&target.encode().expect("valid")).expect("valid"),
            target
        );

        let response = OdohResponseBody {
            message: message(OdohMessageType::Response),
            padding: Vec::new(),
        };
        assert_eq!(
            OdohResponseBody::decode(&response.encode().expect("valid")).expect("valid"),
            response
        );

        let error = OdohErrorBody {
            status: OdohStatus::Busy,
            retry_after: 2,
            error_class: 0,
        };
        assert_eq!(
            OdohErrorBody::decode(&error.encode()).expect("valid"),
            error
        );
    }

    #[test]
    fn nonzero_and_trailing_outer_padding_fail_closed() {
        let target = TargetQuery {
            config_id: [2; 32],
            message: message(OdohMessageType::Query),
            padding: vec![0; 8],
        };
        let mut encoded = target.encode().expect("valid");
        *encoded.last_mut().expect("padding") = 1;
        assert!(TargetQuery::decode(&encoded).is_err());
        encoded.push(0);
        assert!(TargetQuery::decode(&encoded).is_err());
    }
}
