#![doc = "Wire-compatible, allocation-bounded messages for draft HIP #76."]

use hns_encoding::{DecodeError, Decoder, Encoder};
use thiserror::Error;

/// Maximum DNS message body carried by a HIP-76 request.
pub const MAX_DNS_RELAY_QUERY_BODY_SIZE: usize = 4 * 1024;
/// Maximum DNS message body carried by a successful HIP-76 response.
pub const MAX_DNS_RELAY_RESPONSE_BODY_SIZE: usize = u16::MAX as usize;
/// Maximum complete `getdnsrelay` payload: request ID, body length, and body.
pub const MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE: usize = 8 + 2 + MAX_DNS_RELAY_QUERY_BODY_SIZE;
/// Maximum complete `dnsrelay` payload: request ID, status, body length, and body.
pub const MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE: usize = 8 + 1 + 2 + MAX_DNS_RELAY_RESPONSE_BODY_SIZE;

/// Compatibility alias for the maximum HIP-76 query body size.
pub const MAX_DNS_RELAY_QUERY_SIZE: usize = MAX_DNS_RELAY_QUERY_BODY_SIZE;
/// Compatibility alias for the maximum HIP-76 response body size.
pub const MAX_DNS_RELAY_RESPONSE_SIZE: usize = MAX_DNS_RELAY_RESPONSE_BODY_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DnsRelayStatus {
    Ok = 0,
    Refused = 1,
    Unsupported = 2,
    Busy = 3,
    InvalidQuery = 4,
    ResolverUnavailable = 5,
    Timeout = 6,
    InternalError = 7,
}

impl TryFrom<u8> for DnsRelayStatus {
    type Error = DnsRelayProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Refused),
            2 => Ok(Self::Unsupported),
            3 => Ok(Self::Busy),
            4 => Ok(Self::InvalidQuery),
            5 => Ok(Self::ResolverUnavailable),
            6 => Ok(Self::Timeout),
            7 => Ok(Self::InternalError),
            _ => Err(DnsRelayProtocolError::UnknownStatus(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetDnsRelay {
    pub request_id: u64,
    pub query: Vec<u8>,
}

impl GetDnsRelay {
    pub fn new(request_id: u64, query: Vec<u8>) -> Result<Self, DnsRelayProtocolError> {
        let message = Self { request_id, query };
        message.validate()?;
        Ok(message)
    }

    pub fn encode(&self) -> Result<Vec<u8>, DnsRelayProtocolError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(10 + self.query.len());
        encoder.put_u64_le(self.request_id);
        encoder.put_u16_le(
            u16::try_from(self.query.len())
                .map_err(|_| DnsRelayProtocolError::QueryTooLarge(self.query.len()))?,
        );
        encoder.put_bytes(&self.query);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, DnsRelayProtocolError> {
        let mut decoder = Decoder::new(input);
        let request_id = decoder.read_u64_le()?;
        if request_id == 0 {
            return Err(DnsRelayProtocolError::ZeroRequestId);
        }
        let query_length = decoder.read_u16_le()? as usize;
        if query_length > MAX_DNS_RELAY_QUERY_BODY_SIZE {
            return Err(DnsRelayProtocolError::QueryTooLarge(query_length));
        }
        let query = decoder.read_bounded_vec(query_length, MAX_DNS_RELAY_QUERY_BODY_SIZE)?;
        decoder.finish()?;
        Self::new(request_id, query)
    }

    fn validate(&self) -> Result<(), DnsRelayProtocolError> {
        if self.request_id == 0 {
            return Err(DnsRelayProtocolError::ZeroRequestId);
        }
        if self.query.is_empty() {
            return Err(DnsRelayProtocolError::EmptyQuery);
        }
        if self.query.len() > MAX_DNS_RELAY_QUERY_BODY_SIZE {
            return Err(DnsRelayProtocolError::QueryTooLarge(self.query.len()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRelay {
    pub request_id: u64,
    pub status: DnsRelayStatus,
    pub response: Vec<u8>,
}

impl DnsRelay {
    pub fn new(
        request_id: u64,
        status: DnsRelayStatus,
        response: Vec<u8>,
    ) -> Result<Self, DnsRelayProtocolError> {
        let message = Self {
            request_id,
            status,
            response,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn encode(&self) -> Result<Vec<u8>, DnsRelayProtocolError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(11 + self.response.len());
        encoder.put_u64_le(self.request_id);
        encoder.put_u8(self.status as u8);
        encoder.put_u16_le(
            u16::try_from(self.response.len())
                .map_err(|_| DnsRelayProtocolError::ResponseTooLarge(self.response.len()))?,
        );
        encoder.put_bytes(&self.response);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, DnsRelayProtocolError> {
        let mut decoder = Decoder::new(input);
        let request_id = decoder.read_u64_le()?;
        if request_id == 0 {
            return Err(DnsRelayProtocolError::ZeroRequestId);
        }
        let status = DnsRelayStatus::try_from(decoder.read_u8()?)?;
        let response_length = decoder.read_u16_le()? as usize;
        if response_length > MAX_DNS_RELAY_RESPONSE_BODY_SIZE {
            return Err(DnsRelayProtocolError::ResponseTooLarge(response_length));
        }
        let response =
            decoder.read_bounded_vec(response_length, MAX_DNS_RELAY_RESPONSE_BODY_SIZE)?;
        decoder.finish()?;
        Self::new(request_id, status, response)
    }

    fn validate(&self) -> Result<(), DnsRelayProtocolError> {
        if self.request_id == 0 {
            return Err(DnsRelayProtocolError::ZeroRequestId);
        }
        if self.response.len() > MAX_DNS_RELAY_RESPONSE_BODY_SIZE {
            return Err(DnsRelayProtocolError::ResponseTooLarge(self.response.len()));
        }
        match (self.status, self.response.is_empty()) {
            (DnsRelayStatus::Ok, true) => Err(DnsRelayProtocolError::EmptySuccess),
            (DnsRelayStatus::Ok, false) | (_, true) => Ok(()),
            (_, false) => Err(DnsRelayProtocolError::ErrorHasBody),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DnsRelayProtocolError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("request ID must be nonzero")]
    ZeroRequestId,
    #[error("DNS relay query must not be empty")]
    EmptyQuery,
    #[error("DNS relay query length {0} exceeds 4096 bytes")]
    QueryTooLarge(usize),
    #[error("DNS relay response length {0} exceeds 65535 bytes")]
    ResponseTooLarge(usize),
    #[error("unknown DNS relay status {0}")]
    UnknownStatus(u8),
    #[error("successful DNS relay response has no DNS message")]
    EmptySuccess,
    #[error("DNS relay error status has a response body")]
    ErrorHasBody,
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_BASIC: &str = "08070605040302012a00123401100001000000000001037777770972656c617974657374000001000100002904d0000080000000";
    const RESPONSE_OK: &str = "0807060504030201003a00123481b00001000100000001037777770972656c6179746573740000010001c00c000100010000003c0004c000020100002904d0000080000000";
    const RESPONSE_ERROR: &str = "0807060504030201030000";

    #[test]
    fn exact_draft_vectors_round_trip() {
        let request_wire = hex::decode(REQUEST_BASIC).expect("hex");
        let request = GetDnsRelay::decode(&request_wire).expect("valid");
        assert_eq!(request.request_id, 0x0102_0304_0506_0708);
        assert_eq!(request.encode().expect("valid"), request_wire);

        let response_wire = hex::decode(RESPONSE_OK).expect("hex");
        let response = DnsRelay::decode(&response_wire).expect("valid");
        assert_eq!(response.status, DnsRelayStatus::Ok);
        assert_eq!(response.encode().expect("valid"), response_wire);

        let error_wire = hex::decode(RESPONSE_ERROR).expect("hex");
        let response = DnsRelay::decode(&error_wire).expect("valid");
        assert_eq!(response.status, DnsRelayStatus::Busy);
        assert!(response.response.is_empty());
        assert_eq!(response.encode().expect("valid"), error_wire);
    }

    #[test]
    fn request_parser_rejects_zero_id_lengths_and_trailing_bytes() {
        let zero_id = hex::decode("0000000000000000030000").expect("hex");
        assert_eq!(
            GetDnsRelay::decode(&zero_id),
            Err(DnsRelayProtocolError::ZeroRequestId)
        );

        let malformed = hex::decode(
            "08070605040302012b00123401100001000000000001037777770972656c617974657374000001000100002904d0000080000000",
        )
        .expect("hex");
        assert!(matches!(
            GetDnsRelay::decode(&malformed),
            Err(DnsRelayProtocolError::Decode(
                DecodeError::UnexpectedEnd { .. }
            ))
        ));

        let trailing = hex::decode(
            "08070605040302012a00123401100001000000000001037777770972656c617974657374000001000100002904d0000080000000ff",
        )
        .expect("hex");
        assert!(matches!(
            GetDnsRelay::decode(&trailing),
            Err(DnsRelayProtocolError::Decode(
                DecodeError::TrailingBytes { .. }
            ))
        ));
    }

    #[test]
    fn response_parser_rejects_unknown_status_and_body_mismatch() {
        let unknown = hex::decode("0807060504030201ff0000").expect("hex");
        assert_eq!(
            DnsRelay::decode(&unknown),
            Err(DnsRelayProtocolError::UnknownStatus(0xff))
        );
        assert_eq!(
            DnsRelay::new(1, DnsRelayStatus::Ok, Vec::new()),
            Err(DnsRelayProtocolError::EmptySuccess)
        );
        assert_eq!(
            DnsRelay::new(1, DnsRelayStatus::Busy, vec![1]),
            Err(DnsRelayProtocolError::ErrorHasBody)
        );
    }

    #[test]
    fn allocation_bounds_are_enforced_at_both_limits() {
        let request =
            GetDnsRelay::new(1, vec![0; MAX_DNS_RELAY_QUERY_BODY_SIZE]).expect("maximum request");
        assert_eq!(
            request.encode().expect("valid").len(),
            MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE
        );
        assert_eq!(MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE, 4_106);
        assert_eq!(
            GetDnsRelay::new(1, vec![0; MAX_DNS_RELAY_QUERY_BODY_SIZE + 1]),
            Err(DnsRelayProtocolError::QueryTooLarge(
                MAX_DNS_RELAY_QUERY_BODY_SIZE + 1
            ))
        );

        let response = DnsRelay::new(
            1,
            DnsRelayStatus::Ok,
            vec![0; MAX_DNS_RELAY_RESPONSE_BODY_SIZE],
        )
        .expect("maximum response");
        assert_eq!(
            response.encode().expect("valid").len(),
            MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE
        );
        assert_eq!(MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE, 65_546);
        assert_eq!(MAX_DNS_RELAY_QUERY_SIZE, MAX_DNS_RELAY_QUERY_BODY_SIZE);
        assert_eq!(
            MAX_DNS_RELAY_RESPONSE_SIZE,
            MAX_DNS_RELAY_RESPONSE_BODY_SIZE
        );
    }
}
