use hns_encoding::{Decoder, Encoder};

use crate::record::{ReserveRequest, decode_signature, encode_signature};
use crate::routing::RendezvousContact;
use crate::{
    HNS_NODE_V1, HnsrProtocolError, MAX_CONTACTS, MAX_DATA_SIZE, MAX_PACKET_SIZE, MAX_RECORD_SIZE,
    MAX_WINDOW, MIN_WINDOW, is_zero,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum HnsrErrorCode {
    Normal = 0,
    Refused = 1,
    Unsupported = 2,
    Busy = 3,
    Invalid = 4,
    NotFound = 5,
    Expired = 6,
    Capacity = 7,
    Timeout = 8,
    Protocol = 9,
    Internal = 10,
    EndpointGone = 11,
    AuthenticationFailed = 12,
    FlowControl = 13,
    RateLimited = 14,
    Shutdown = 15,
    ProfileDisabled = 16,
    ByteLimit = 17,
}

impl TryFrom<u16> for HnsrErrorCode {
    type Error = HnsrProtocolError;

    fn try_from(value: u16) -> Result<Self, HnsrProtocolError> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::Refused),
            2 => Ok(Self::Unsupported),
            3 => Ok(Self::Busy),
            4 => Ok(Self::Invalid),
            5 => Ok(Self::NotFound),
            6 => Ok(Self::Expired),
            7 => Ok(Self::Capacity),
            8 => Ok(Self::Timeout),
            9 => Ok(Self::Protocol),
            10 => Ok(Self::Internal),
            11 => Ok(Self::EndpointGone),
            12 => Ok(Self::AuthenticationFailed),
            13 => Ok(Self::FlowControl),
            14 => Ok(Self::RateLimited),
            15 => Ok(Self::Shutdown),
            16 => Ok(Self::ProfileDisabled),
            17 => Ok(Self::ByteLimit),
            _ => Err(HnsrProtocolError::Invalid("unknown HNSR error code")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindNodeBody {
    pub target: [u8; 32],
    pub maximum: u8,
}

impl FindNodeBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        validate_maximum(self.maximum)?;
        let mut encoder = Encoder::with_capacity(33);
        encoder.put_bytes(&self.target);
        encoder.put_u8(self.maximum);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            target: decoder.read_array()?,
            maximum: decoder.read_u8()?,
        };
        decoder.finish()?;
        validate_maximum(body.maximum)?;
        Ok(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodesBody {
    pub contacts: Vec<RendezvousContact>,
}

impl NodesBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        if self.contacts.len() > MAX_CONTACTS {
            return Err(HnsrProtocolError::TooLarge {
                actual: self.contacts.len(),
                maximum: MAX_CONTACTS,
            });
        }
        let mut encoder = Encoder::with_capacity(1 + self.contacts.len() * 100);
        encoder.put_u8(self.contacts.len() as u8);
        for contact in &self.contacts {
            encoder.put_bytes(&contact.encode()?);
        }
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let count = decoder.read_u8()? as usize;
        if count > MAX_CONTACTS {
            return Err(HnsrProtocolError::Invalid(
                "too many HNSR rendezvous contacts",
            ));
        }
        let mut contacts = Vec::with_capacity(count);
        for _ in 0..count {
            contacts.push(RendezvousContact::read_from(&mut decoder)?);
        }
        decoder.finish()?;
        Ok(Self { contacts })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PutRouteBody {
    pub route_key: [u8; 32],
    pub record: Vec<u8>,
}

impl PutRouteBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        validate_record(&self.record)?;
        let mut encoder = Encoder::with_capacity(34 + self.record.len());
        encoder.put_bytes(&self.route_key);
        encoder.put_u16_le(self.record.len() as u16);
        encoder.put_bytes(&self.record);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let route_key = decoder.read_array()?;
        let length = decoder.read_u16_le()? as usize;
        if length == 0 || length > MAX_RECORD_SIZE || decoder.remaining() != length {
            return Err(HnsrProtocolError::Invalid("invalid HNSR put-route length"));
        }
        let record = decoder.read_bounded_vec(length, MAX_RECORD_SIZE)?;
        decoder.finish()?;
        Ok(Self { route_key, record })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PutResultBody {
    pub status: u16,
    pub stored_until: u64,
}

impl PutResultBody {
    pub fn encode(self) -> Vec<u8> {
        let mut encoder = Encoder::with_capacity(10);
        encoder.put_u16_le(self.status);
        encoder.put_u64_le(self.stored_until);
        encoder.into_bytes()
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            status: decoder.read_u16_le()?,
            stored_until: decoder.read_u64_le()?,
        };
        decoder.finish()?;
        Ok(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetRouteBody {
    pub route_key: [u8; 32],
    pub maximum_records: u8,
}

impl GetRouteBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        validate_maximum(self.maximum_records)?;
        let mut encoder = Encoder::with_capacity(33);
        encoder.put_bytes(&self.route_key);
        encoder.put_u8(self.maximum_records);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            route_key: decoder.read_array()?,
            maximum_records: decoder.read_u8()?,
        };
        decoder.finish()?;
        validate_maximum(body.maximum_records)?;
        Ok(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutesBody {
    pub records: Vec<Vec<u8>>,
}

impl RoutesBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        if self.records.len() > MAX_CONTACTS {
            return Err(HnsrProtocolError::TooLarge {
                actual: self.records.len(),
                maximum: MAX_CONTACTS,
            });
        }
        let mut size = 1_usize;
        for record in &self.records {
            validate_record(record)?;
            size = size.saturating_add(2 + record.len());
        }
        if size > MAX_PACKET_SIZE - 12 {
            return Err(HnsrProtocolError::TooLarge {
                actual: size,
                maximum: MAX_PACKET_SIZE - 12,
            });
        }
        let mut encoder = Encoder::with_capacity(size);
        encoder.put_u8(self.records.len() as u8);
        for record in &self.records {
            encoder.put_u16_le(record.len() as u16);
            encoder.put_bytes(record);
        }
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let count = decoder.read_u8()? as usize;
        if count > MAX_CONTACTS {
            return Err(HnsrProtocolError::Invalid("too many HNSR route records"));
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let length = decoder.read_u16_le()? as usize;
            if length == 0 || length > MAX_RECORD_SIZE {
                return Err(HnsrProtocolError::Invalid(
                    "invalid returned HNSR record length",
                ));
            }
            records.push(decoder.read_bounded_vec(length, MAX_RECORD_SIZE)?);
        }
        decoder.finish()?;
        Ok(Self { records })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleRoutesBody {
    pub maximum_records: u8,
    pub random_seed: [u8; 32],
}

impl SampleRoutesBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        validate_maximum(self.maximum_records)?;
        if is_zero(&self.random_seed) {
            return Err(HnsrProtocolError::Invalid("HNSR sample seed is zero"));
        }
        let mut encoder = Encoder::with_capacity(33);
        encoder.put_u8(self.maximum_records);
        encoder.put_bytes(&self.random_seed);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            maximum_records: decoder.read_u8()?,
            random_seed: decoder.read_array()?,
        };
        decoder.finish()?;
        body.encode()?;
        Ok(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewBody {
    pub previous_reservation_id: [u8; 16],
    pub request: ReserveRequest,
}

impl RenewBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        if is_zero(&self.previous_reservation_id) {
            return Err(HnsrProtocolError::Invalid(
                "previous HNSR reservation ID is zero",
            ));
        }
        let request = self.request.encode()?;
        let mut encoder = Encoder::with_capacity(16 + request.len());
        encoder.put_bytes(&self.previous_reservation_id);
        encoder.put_bytes(&request);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let previous_reservation_id = decoder.read_array()?;
        let request = ReserveRequest::decode(decoder.read_slice(decoder.remaining())?)?;
        decoder.finish()?;
        if is_zero(&previous_reservation_id) {
            return Err(HnsrProtocolError::Invalid(
                "previous HNSR reservation ID is zero",
            ));
        }
        Ok(Self {
            previous_reservation_id,
            request,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmBody {
    pub reservation_id: [u8; 16],
    pub endpoint_signature: Vec<u8>,
}

impl ConfirmBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        if is_zero(&self.reservation_id) {
            return Err(HnsrProtocolError::Invalid("HNSR reservation ID is zero"));
        }
        let mut encoder = Encoder::with_capacity(17 + self.endpoint_signature.len());
        encoder.put_bytes(&self.reservation_id);
        encode_signature(&mut encoder, &self.endpoint_signature, false)?;
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            reservation_id: decoder.read_array()?,
            endpoint_signature: decode_signature(&mut decoder, false)?,
        };
        decoder.finish()?;
        if is_zero(&body.reservation_id) {
            return Err(HnsrProtocolError::Invalid("HNSR reservation ID is zero"));
        }
        Ok(body)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfirmedBody {
    pub reservation_id: [u8; 16],
    pub ticket_id: [u8; 32],
    pub expires_at: u64,
}

impl ConfirmedBody {
    pub fn encode(self) -> Result<Vec<u8>, HnsrProtocolError> {
        if is_zero(&self.reservation_id) || is_zero(&self.ticket_id) {
            return Err(HnsrProtocolError::Invalid(
                "zero HNSR confirmation identifier",
            ));
        }
        let mut encoder = Encoder::with_capacity(56);
        encoder.put_bytes(&self.reservation_id);
        encoder.put_bytes(&self.ticket_id);
        encoder.put_u64_le(self.expires_at);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            reservation_id: decoder.read_array()?,
            ticket_id: decoder.read_array()?,
            expires_at: decoder.read_u64_le()?,
        };
        decoder.finish()?;
        if is_zero(&body.reservation_id) || is_zero(&body.ticket_id) {
            return Err(HnsrProtocolError::Invalid(
                "zero HNSR confirmation identifier",
            ));
        }
        Ok(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawBody {
    pub reservation_id: [u8; 16],
    pub ticket_id: [u8; 32],
    pub signature: Vec<u8>,
}

impl WithdrawBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        if is_zero(&self.reservation_id) || is_zero(&self.ticket_id) {
            return Err(HnsrProtocolError::Invalid(
                "zero HNSR withdrawal identifier",
            ));
        }
        let mut encoder = Encoder::with_capacity(49 + self.signature.len());
        encoder.put_bytes(&self.reservation_id);
        encoder.put_bytes(&self.ticket_id);
        encode_signature(&mut encoder, &self.signature, false)?;
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            reservation_id: decoder.read_array()?,
            ticket_id: decoder.read_array()?,
            signature: decode_signature(&mut decoder, false)?,
        };
        decoder.finish()?;
        if is_zero(&body.reservation_id) || is_zero(&body.ticket_id) {
            return Err(HnsrProtocolError::Invalid(
                "zero HNSR withdrawal identifier",
            ));
        }
        Ok(body)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenBody {
    pub ticket_id: [u8; 32],
    pub reservation_id: [u8; 16],
    pub endpoint_key: [u8; 33],
    pub profile: u16,
    pub requester_nonce: [u8; 16],
    pub initial_window: u32,
}

impl OpenBody {
    pub fn encode(self) -> Result<Vec<u8>, HnsrProtocolError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(103);
        encoder.put_bytes(&self.ticket_id);
        encoder.put_bytes(&self.reservation_id);
        encoder.put_bytes(&self.endpoint_key);
        encoder.put_u16_le(self.profile);
        encoder.put_bytes(&self.requester_nonce);
        encoder.put_u32_le(self.initial_window);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            ticket_id: decoder.read_array()?,
            reservation_id: decoder.read_array()?,
            endpoint_key: decoder.read_array()?,
            profile: decoder.read_u16_le()?,
            requester_nonce: decoder.read_array()?,
            initial_window: decoder.read_u32_le()?,
        };
        decoder.finish()?;
        body.validate()?;
        Ok(body)
    }

    fn validate(&self) -> Result<(), HnsrProtocolError> {
        validate_circuit_values(
            &self.ticket_id,
            &self.reservation_id,
            &self.endpoint_key,
            self.profile,
            &self.requester_nonce,
            self.initial_window,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IncomingBody {
    pub ticket_id: [u8; 32],
    pub open_request_id: [u8; 8],
    pub profile: u16,
    pub requester_nonce: [u8; 16],
    pub initial_window: u32,
}

impl IncomingBody {
    pub fn encode(self) -> Result<Vec<u8>, HnsrProtocolError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(62);
        encoder.put_bytes(&self.ticket_id);
        encoder.put_bytes(&self.open_request_id);
        encoder.put_u16_le(self.profile);
        encoder.put_bytes(&self.requester_nonce);
        encoder.put_u32_le(self.initial_window);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            ticket_id: decoder.read_array()?,
            open_request_id: decoder.read_array()?,
            profile: decoder.read_u16_le()?,
            requester_nonce: decoder.read_array()?,
            initial_window: decoder.read_u32_le()?,
        };
        decoder.finish()?;
        body.validate()?;
        Ok(body)
    }

    fn validate(&self) -> Result<(), HnsrProtocolError> {
        if is_zero(&self.ticket_id)
            || is_zero(&self.open_request_id)
            || self.profile != HNS_NODE_V1
            || is_zero(&self.requester_nonce)
            || !(MIN_WINDOW..=MAX_WINDOW).contains(&self.initial_window)
        {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSR incoming parameters",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptBody {
    pub accepted_window: u32,
    pub endpoint_nonce: [u8; 16],
}

impl AcceptBody {
    pub fn encode(self) -> Result<Vec<u8>, HnsrProtocolError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(20);
        encoder.put_u32_le(self.accepted_window);
        encoder.put_bytes(&self.endpoint_nonce);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            accepted_window: decoder.read_u32_le()?,
            endpoint_nonce: decoder.read_array()?,
        };
        decoder.finish()?;
        body.validate()?;
        Ok(body)
    }

    fn validate(&self) -> Result<(), HnsrProtocolError> {
        if !(MIN_WINDOW..=MAX_WINDOW).contains(&self.accepted_window)
            || is_zero(&self.endpoint_nonce)
        {
            return Err(HnsrProtocolError::Invalid("invalid HNSR accept response"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenedBody {
    pub circuit_id: [u8; 8],
    pub accepted_window: u32,
    pub endpoint_nonce: [u8; 16],
}

impl OpenedBody {
    pub fn encode(self) -> Result<Vec<u8>, HnsrProtocolError> {
        if is_zero(&self.circuit_id) {
            return Err(HnsrProtocolError::Invalid("HNSR circuit ID is zero"));
        }
        AcceptBody {
            accepted_window: self.accepted_window,
            endpoint_nonce: self.endpoint_nonce,
        }
        .validate()?;
        let mut encoder = Encoder::with_capacity(28);
        encoder.put_bytes(&self.circuit_id);
        encoder.put_u32_le(self.accepted_window);
        encoder.put_bytes(&self.endpoint_nonce);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            circuit_id: decoder.read_array()?,
            accepted_window: decoder.read_u32_le()?,
            endpoint_nonce: decoder.read_array()?,
        };
        decoder.finish()?;
        body.encode()?;
        Ok(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataBody {
    pub bytes: Vec<u8>,
}

impl DataBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_DATA_SIZE {
            return Err(HnsrProtocolError::Invalid("invalid HNSR DATA size"));
        }
        Ok(self.bytes.clone())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let body = Self {
            bytes: input.to_vec(),
        };
        body.encode()?;
        Ok(body)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowBody {
    pub credit_delta: u32,
}

impl WindowBody {
    pub fn encode(self) -> Result<Vec<u8>, HnsrProtocolError> {
        if self.credit_delta == 0 || self.credit_delta > MAX_WINDOW {
            return Err(HnsrProtocolError::Invalid("invalid HNSR window credit"));
        }
        let mut encoder = Encoder::with_capacity(4);
        encoder.put_u32_le(self.credit_delta);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let body = Self {
            credit_delta: decoder.read_u32_le()?,
        };
        decoder.finish()?;
        body.encode()?;
        Ok(body)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseBody {
    pub reason: u16,
    pub detail: String,
}

impl CloseBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        encode_reason_detail(self.reason, &self.detail)
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let (reason, detail) = decode_reason_detail(input)?;
        Ok(Self { reason, detail })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorBody {
    pub reason: u16,
    pub detail: String,
}

impl ErrorBody {
    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        encode_reason_detail(self.reason, &self.detail)
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let (reason, detail) = decode_reason_detail(input)?;
        if reason <= HnsrErrorCode::ByteLimit as u16 {
            let _ = HnsrErrorCode::try_from(reason)?;
        }
        Ok(Self { reason, detail })
    }
}

fn validate_maximum(maximum: u8) -> Result<(), HnsrProtocolError> {
    if maximum == 0 || maximum as usize > MAX_CONTACTS {
        return Err(HnsrProtocolError::Invalid(
            "invalid HNSR rendezvous result limit",
        ));
    }
    Ok(())
}

fn validate_record(record: &[u8]) -> Result<(), HnsrProtocolError> {
    if record.is_empty() || record.len() > MAX_RECORD_SIZE {
        return Err(HnsrProtocolError::TooLarge {
            actual: record.len(),
            maximum: MAX_RECORD_SIZE,
        });
    }
    Ok(())
}

fn validate_circuit_values(
    ticket_id: &[u8; 32],
    reservation_id: &[u8; 16],
    endpoint_key: &[u8; 33],
    profile: u16,
    requester_nonce: &[u8; 16],
    initial_window: u32,
) -> Result<(), HnsrProtocolError> {
    if is_zero(ticket_id)
        || is_zero(reservation_id)
        || public_key_invalid(endpoint_key)
        || profile != HNS_NODE_V1
        || is_zero(requester_nonce)
        || !(MIN_WINDOW..=MAX_WINDOW).contains(&initial_window)
    {
        return Err(HnsrProtocolError::Invalid("invalid HNSR open parameters"));
    }
    Ok(())
}

fn public_key_invalid(key: &[u8; 33]) -> bool {
    k256::ecdsa::VerifyingKey::from_sec1_bytes(key).is_err()
}

fn encode_reason_detail(reason: u16, detail: &str) -> Result<Vec<u8>, HnsrProtocolError> {
    let bytes = detail.as_bytes();
    if bytes.len() > 128 {
        return Err(HnsrProtocolError::TooLarge {
            actual: bytes.len(),
            maximum: 128,
        });
    }
    let mut encoder = Encoder::with_capacity(3 + bytes.len());
    encoder.put_u16_le(reason);
    encoder.put_u8(bytes.len() as u8);
    encoder.put_bytes(bytes);
    Ok(encoder.into_bytes())
}

fn decode_reason_detail(input: &[u8]) -> Result<(u16, String), HnsrProtocolError> {
    let mut decoder = Decoder::new(input);
    let reason = decoder.read_u16_le()?;
    let length = decoder.read_u8()? as usize;
    if length > 128 || decoder.remaining() != length {
        return Err(HnsrProtocolError::Invalid("invalid HNSR diagnostic detail"));
    }
    let detail = std::str::from_utf8(decoder.read_slice(length)?)
        .map_err(|_| HnsrProtocolError::Invalid("HNSR detail is not UTF-8"))?
        .to_owned();
    decoder.finish()?;
    Ok((reason, detail))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_size_circuit_bodies_round_trip() {
        let endpoint_key =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .expect("hex")
                .try_into()
                .expect("33 bytes");
        let open = OpenBody {
            ticket_id: [1; 32],
            reservation_id: [2; 16],
            endpoint_key,
            profile: HNS_NODE_V1,
            requester_nonce: [3; 16],
            initial_window: MIN_WINDOW,
        };
        let encoded = open.encode().expect("valid");
        assert_eq!(encoded.len(), 103);
        assert_eq!(OpenBody::decode(&encoded).expect("valid"), open);

        let opened = OpenedBody {
            circuit_id: [4; 8],
            accepted_window: MIN_WINDOW,
            endpoint_nonce: [5; 16],
        };
        let encoded = opened.encode().expect("valid");
        assert_eq!(encoded.len(), 28);
        assert_eq!(OpenedBody::decode(&encoded).expect("valid"), opened);
    }

    #[test]
    fn route_and_diagnostic_lists_are_bounded() {
        let routes = RoutesBody {
            records: vec![vec![1], vec![2; MAX_RECORD_SIZE]],
        };
        assert_eq!(
            RoutesBody::decode(&routes.encode().expect("valid")).expect("valid"),
            routes
        );
        assert!(
            RoutesBody {
                records: vec![vec![1]; MAX_CONTACTS + 1]
            }
            .encode()
            .is_err()
        );
        assert!(
            ErrorBody {
                reason: 1,
                detail: "x".repeat(129)
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn flow_control_values_fail_closed() {
        assert!(WindowBody { credit_delta: 0 }.encode().is_err());
        assert!(
            DataBody {
                bytes: vec![0; MAX_DATA_SIZE + 1]
            }
            .encode()
            .is_err()
        );
        let mut malformed = CloseBody {
            reason: 1,
            detail: "closed".to_owned(),
        }
        .encode()
        .expect("valid");
        malformed.push(0);
        assert!(CloseBody::decode(&malformed).is_err());
    }
}
