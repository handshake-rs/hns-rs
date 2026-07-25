use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_encoding::{Decoder, Encoder};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::{
    HNS_NODE_V1, HnsrProtocolError, MAX_CIRCUITS, MAX_DELEGATION_LIFETIME, MAX_RECORD_SIZE,
    MAX_ROUTE_LIFETIME, MAX_SIGNATURE_SIZE, MAX_TICKET_LIFETIME, is_zero,
};

const RESERVE_DOMAIN: &[u8] = b"HNSR-RESERVE-V1\0";
const RENEW_DOMAIN: &[u8] = b"HNSR-RENEW-V1\0";
const TICKET_RELAY_DOMAIN: &[u8] = b"HNSR-RELAY-TICKET-V1\0";
const TICKET_ENDPOINT_DOMAIN: &[u8] = b"HNSR-RELAY-CONFIRM-V1\0";
const DELEGATION_DOMAIN: &[u8] = b"HNSR-ENDPOINT-DELEGATION-V1\0";
const ROUTE_DOMAIN: &[u8] = b"HNSR-ROUTE-RECORD-V1\0";
const WITHDRAW_DOMAIN: &[u8] = b"HNSR-WITHDRAW-V1\0";

const RELAY_TICKET_UNSIGNED_SIZE: usize = 145;
const ENDPOINT_DELEGATION_UNSIGNED_SIZE: usize = 102;
const RESERVE_UNSIGNED_SIZE: usize = 65;

pub fn public_key(private_key: &[u8; 32]) -> Result<[u8; 33], HnsrProtocolError> {
    let signing_key = signing_key(private_key)?;
    let encoded = signing_key.verifying_key().to_encoded_point(true);
    encoded
        .as_bytes()
        .try_into()
        .map_err(|_| HnsrProtocolError::Cryptography)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveRequest {
    pub endpoint_key: [u8; 33],
    pub profile: u16,
    pub lifetime: u32,
    pub max_circuits: u16,
    pub max_bytes: u64,
    pub nonce: [u8; 16],
    pub signature: Vec<u8>,
}

impl ReserveRequest {
    pub fn encode_unsigned(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        validate_public_key(&self.endpoint_key)?;
        if is_zero(&self.nonce) {
            return Err(HnsrProtocolError::Invalid("HNSR reservation nonce is zero"));
        }
        let mut encoder = Encoder::with_capacity(RESERVE_UNSIGNED_SIZE);
        encoder.put_bytes(&self.endpoint_key);
        encoder.put_u16_le(self.profile);
        encoder.put_u32_le(self.lifetime);
        encoder.put_u16_le(self.max_circuits);
        encoder.put_u64_le(self.max_bytes);
        encoder.put_bytes(&self.nonce);
        Ok(encoder.into_bytes())
    }

    pub fn validate_limits(&self) -> Result<(), HnsrProtocolError> {
        if self.profile != HNS_NODE_V1
            || !(300..=MAX_TICKET_LIFETIME as u32).contains(&self.lifetime)
            || !(1..=MAX_CIRCUITS).contains(&self.max_circuits)
            || self.max_bytes == 0
        {
            return Err(HnsrProtocolError::Invalid(
                "HNSR reservation exceeds protocol limits",
            ));
        }
        Ok(())
    }

    pub fn sign(
        &mut self,
        network_magic: u32,
        relay_key: &[u8; 33],
        context_id: &[u8; 8],
        private_key: &[u8; 32],
    ) -> Result<(), HnsrProtocolError> {
        let data = self.signature_data(network_magic, relay_key, context_id)?;
        self.signature = sign(RESERVE_DOMAIN, &[&data], private_key)?;
        Ok(())
    }

    pub fn verify(
        &self,
        network_magic: u32,
        relay_key: &[u8; 33],
        context_id: &[u8; 8],
    ) -> Result<(), HnsrProtocolError> {
        let data = self.signature_data(network_magic, relay_key, context_id)?;
        verify(
            RESERVE_DOMAIN,
            &[&data],
            &self.signature,
            &self.endpoint_key,
        )
    }

    pub fn sign_renewal(
        &mut self,
        network_magic: u32,
        relay_key: &[u8; 33],
        context_id: &[u8; 8],
        reservation_id: &[u8; 16],
        private_key: &[u8; 32],
    ) -> Result<(), HnsrProtocolError> {
        let data = self.renewal_data(network_magic, relay_key, context_id, reservation_id)?;
        self.signature = sign(RENEW_DOMAIN, &[&data], private_key)?;
        Ok(())
    }

    pub fn verify_renewal(
        &self,
        network_magic: u32,
        relay_key: &[u8; 33],
        context_id: &[u8; 8],
        reservation_id: &[u8; 16],
    ) -> Result<(), HnsrProtocolError> {
        let data = self.renewal_data(network_magic, relay_key, context_id, reservation_id)?;
        verify(RENEW_DOMAIN, &[&data], &self.signature, &self.endpoint_key)
    }

    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut encoder = Encoder::with_capacity(unsigned.len() + 1 + self.signature.len());
        encoder.put_bytes(&unsigned);
        encode_signature(&mut encoder, &self.signature, false)?;
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let request = Self {
            endpoint_key: decoder.read_array()?,
            profile: decoder.read_u16_le()?,
            lifetime: decoder.read_u32_le()?,
            max_circuits: decoder.read_u16_le()?,
            max_bytes: decoder.read_u64_le()?,
            nonce: decoder.read_array()?,
            signature: decode_signature(&mut decoder, false)?,
        };
        decoder.finish()?;
        request.encode_unsigned()?;
        Ok(request)
    }

    fn signature_data(
        &self,
        network_magic: u32,
        relay_key: &[u8; 33],
        context_id: &[u8; 8],
    ) -> Result<Vec<u8>, HnsrProtocolError> {
        validate_public_key(relay_key)?;
        if is_zero(context_id) {
            return Err(HnsrProtocolError::Invalid("HNSR context ID is zero"));
        }
        let unsigned = self.encode_unsigned()?;
        let mut data = Vec::with_capacity(4 + 33 + 8 + unsigned.len());
        data.extend(network_magic.to_le_bytes());
        data.extend(relay_key);
        data.extend(context_id);
        data.extend(unsigned);
        Ok(data)
    }

    fn renewal_data(
        &self,
        network_magic: u32,
        relay_key: &[u8; 33],
        context_id: &[u8; 8],
        reservation_id: &[u8; 16],
    ) -> Result<Vec<u8>, HnsrProtocolError> {
        if is_zero(reservation_id) {
            return Err(HnsrProtocolError::Invalid("HNSR reservation ID is zero"));
        }
        let base = self.signature_data(network_magic, relay_key, context_id)?;
        let unsigned_offset = 4 + 33 + 8;
        let mut data = Vec::with_capacity(base.len() + 16);
        data.extend(&base[..unsigned_offset]);
        data.extend(reservation_id);
        data.extend(&base[unsigned_offset..]);
        Ok(data)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayTicket {
    pub network_magic: u32,
    pub profile: u16,
    pub transport: u8,
    pub host_type: u8,
    pub host: [u8; 16],
    pub port: u16,
    pub relay_key: [u8; 33],
    pub endpoint_key: [u8; 33],
    pub reservation_id: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
    pub max_active_circuits: u16,
    pub max_bytes_per_circuit: u64,
    pub max_total_bytes: u64,
    pub flags: u16,
    pub relay_signature: Vec<u8>,
    pub endpoint_signature: Vec<u8>,
}

impl RelayTicket {
    pub fn encode_unsigned(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        validate_public_key(&self.relay_key)?;
        validate_public_key(&self.endpoint_key)?;
        if is_zero(&self.reservation_id) {
            return Err(HnsrProtocolError::Invalid("HNSR reservation ID is zero"));
        }
        let mut encoder = Encoder::with_capacity(RELAY_TICKET_UNSIGNED_SIZE);
        encoder.put_u8(1);
        encoder.put_u32_le(self.network_magic);
        encoder.put_u16_le(self.profile);
        encoder.put_u8(self.transport);
        encoder.put_u8(self.host_type);
        encoder.put_bytes(&self.host);
        encoder.put_u16_le(self.port);
        encoder.put_bytes(&self.relay_key);
        encoder.put_bytes(&self.endpoint_key);
        encoder.put_bytes(&self.reservation_id);
        encoder.put_u64_le(self.issued_at);
        encoder.put_u64_le(self.expires_at);
        encoder.put_u16_le(self.max_active_circuits);
        encoder.put_u64_le(self.max_bytes_per_circuit);
        encoder.put_u64_le(self.max_total_bytes);
        encoder.put_u16_le(self.flags);
        Ok(encoder.into_bytes())
    }

    pub fn sign_relay(&mut self, private_key: &[u8; 32]) -> Result<(), HnsrProtocolError> {
        let unsigned = self.encode_unsigned()?;
        self.relay_signature = sign(TICKET_RELAY_DOMAIN, &[&unsigned], private_key)?;
        Ok(())
    }

    pub fn verify_relay(&self) -> Result<(), HnsrProtocolError> {
        let unsigned = self.encode_unsigned()?;
        verify(
            TICKET_RELAY_DOMAIN,
            &[&unsigned],
            &self.relay_signature,
            &self.relay_key,
        )
    }

    pub fn sign_endpoint(&mut self, private_key: &[u8; 32]) -> Result<(), HnsrProtocolError> {
        self.verify_relay()?;
        let unsigned = self.encode_unsigned()?;
        self.endpoint_signature = sign(
            TICKET_ENDPOINT_DOMAIN,
            &[&unsigned, &self.relay_signature],
            private_key,
        )?;
        Ok(())
    }

    pub fn verify_endpoint(&self) -> Result<(), HnsrProtocolError> {
        let unsigned = self.encode_unsigned()?;
        verify(
            TICKET_ENDPOINT_DOMAIN,
            &[&unsigned, &self.relay_signature],
            &self.endpoint_signature,
            &self.endpoint_key,
        )
    }

    pub fn verify(
        &self,
        expected_network_magic: u32,
        now: u64,
        allow_private: bool,
    ) -> Result<(), HnsrProtocolError> {
        if self.network_magic != expected_network_magic
            || self.profile != HNS_NODE_V1
            || self.transport != 0
            || self.flags != 0
            || self.relay_key == self.endpoint_key
            || !(1..=MAX_CIRCUITS).contains(&self.max_active_circuits)
            || self.max_bytes_per_circuit == 0
            || self.max_total_bytes < self.max_bytes_per_circuit
            || self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_TICKET_LIFETIME
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(HnsrProtocolError::Invalid("invalid HNSR relay ticket"));
        }
        validate_host(self.host_type, &self.host, self.port, allow_private)?;
        self.verify_relay()?;
        self.verify_endpoint()
    }

    pub fn id(&self) -> Result<[u8; 32], HnsrProtocolError> {
        Ok(blake2b_256(&[&self.encode()?]))
    }

    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut encoder = Encoder::with_capacity(
            unsigned.len() + 2 + self.relay_signature.len() + self.endpoint_signature.len(),
        );
        encoder.put_bytes(&unsigned);
        encode_signature(&mut encoder, &self.relay_signature, false)?;
        encode_signature(&mut encoder, &self.endpoint_signature, true)?;
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let ticket = Self::read_from(&mut decoder)?;
        decoder.finish()?;
        Ok(ticket)
    }

    pub(crate) fn read_from(decoder: &mut Decoder<'_>) -> Result<Self, HnsrProtocolError> {
        if decoder.read_u8()? != 1 {
            return Err(HnsrProtocolError::Invalid(
                "unsupported HNSR ticket version",
            ));
        }
        let ticket = Self {
            network_magic: decoder.read_u32_le()?,
            profile: decoder.read_u16_le()?,
            transport: decoder.read_u8()?,
            host_type: decoder.read_u8()?,
            host: decoder.read_array()?,
            port: decoder.read_u16_le()?,
            relay_key: decoder.read_array()?,
            endpoint_key: decoder.read_array()?,
            reservation_id: decoder.read_array()?,
            issued_at: decoder.read_u64_le()?,
            expires_at: decoder.read_u64_le()?,
            max_active_circuits: decoder.read_u16_le()?,
            max_bytes_per_circuit: decoder.read_u64_le()?,
            max_total_bytes: decoder.read_u64_le()?,
            flags: decoder.read_u16_le()?,
            relay_signature: decode_signature(decoder, false)?,
            endpoint_signature: decode_signature(decoder, true)?,
        };
        ticket.encode_unsigned()?;
        Ok(ticket)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointDelegation {
    pub authorization_id: [u8; 32],
    pub endpoint_key: [u8; 33],
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub max_active_circuits: u16,
    pub max_bytes_per_circuit: u64,
    pub flags: u16,
    pub signature: Vec<u8>,
}

impl EndpointDelegation {
    pub fn encode_unsigned(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        validate_public_key(&self.endpoint_key)?;
        let mut encoder = Encoder::with_capacity(ENDPOINT_DELEGATION_UNSIGNED_SIZE);
        encoder.put_u8(1);
        encoder.put_bytes(&self.authorization_id);
        encoder.put_bytes(&self.endpoint_key);
        encoder.put_u64_le(self.sequence);
        encoder.put_u64_le(self.issued_at);
        encoder.put_u64_le(self.expires_at);
        encoder.put_u16_le(self.max_active_circuits);
        encoder.put_u64_le(self.max_bytes_per_circuit);
        encoder.put_u16_le(self.flags);
        Ok(encoder.into_bytes())
    }

    pub fn sign(
        &mut self,
        network_magic: u32,
        private_key: &[u8; 32],
    ) -> Result<(), HnsrProtocolError> {
        let unsigned = self.encode_unsigned()?;
        self.signature = sign(
            DELEGATION_DOMAIN,
            &[&network_magic.to_le_bytes(), &unsigned],
            private_key,
        )?;
        Ok(())
    }

    pub fn verify(&self, network_magic: u32, now: u64) -> Result<(), HnsrProtocolError> {
        if !is_zero(&self.authorization_id)
            || self.sequence == 0
            || self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_DELEGATION_LIFETIME
            || now < self.issued_at
            || now >= self.expires_at
            || !(1..=MAX_CIRCUITS).contains(&self.max_active_circuits)
            || self.max_bytes_per_circuit == 0
            || self.flags != 0
        {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSR endpoint delegation",
            ));
        }
        let unsigned = self.encode_unsigned()?;
        verify(
            DELEGATION_DOMAIN,
            &[&network_magic.to_le_bytes(), &unsigned],
            &self.signature,
            &self.endpoint_key,
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut encoder = Encoder::with_capacity(unsigned.len() + 1 + self.signature.len());
        encoder.put_bytes(&unsigned);
        encode_signature(&mut encoder, &self.signature, false)?;
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        if decoder.read_u8()? != 1 {
            return Err(HnsrProtocolError::Invalid(
                "unsupported HNSR delegation version",
            ));
        }
        let delegation = Self {
            authorization_id: decoder.read_array()?,
            endpoint_key: decoder.read_array()?,
            sequence: decoder.read_u64_le()?,
            issued_at: decoder.read_u64_le()?,
            expires_at: decoder.read_u64_le()?,
            max_active_circuits: decoder.read_u16_le()?,
            max_bytes_per_circuit: decoder.read_u64_le()?,
            flags: decoder.read_u16_le()?,
            signature: decode_signature(&mut decoder, false)?,
        };
        decoder.finish()?;
        delegation.encode_unsigned()?;
        Ok(delegation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRecord {
    pub route_key: [u8; 32],
    pub profile: u16,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub authorization: Vec<u8>,
    pub delegation: EndpointDelegation,
    pub tickets: Vec<RelayTicket>,
    pub endpoint_signature: Vec<u8>,
}

impl RouteRecord {
    pub fn encode_unsigned(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        if self.profile != HNS_NODE_V1
            || self.authorization.len() > u16::MAX as usize
            || self.tickets.is_empty()
            || self.tickets.len() > 8
        {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSR route record fields",
            ));
        }
        let delegation = self.delegation.encode()?;
        if delegation.len() > u16::MAX as usize {
            return Err(HnsrProtocolError::TooLarge {
                actual: delegation.len(),
                maximum: u16::MAX as usize,
            });
        }
        let mut encoded_tickets = Vec::with_capacity(self.tickets.len());
        let mut size = 65 + self.authorization.len() + delegation.len();
        for ticket in &self.tickets {
            let encoded = ticket.encode()?;
            size = size.saturating_add(encoded.len());
            encoded_tickets.push(encoded);
        }
        if size > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: size,
                maximum: MAX_RECORD_SIZE,
            });
        }
        let mut encoder = Encoder::with_capacity(size);
        encoder.put_u8(1);
        encoder.put_u8(0);
        encoder.put_bytes(&self.route_key);
        encoder.put_u16_le(self.profile);
        encoder.put_u64_le(self.sequence);
        encoder.put_u64_le(self.issued_at);
        encoder.put_u64_le(self.expires_at);
        encoder.put_u16_le(self.authorization.len() as u16);
        encoder.put_bytes(&self.authorization);
        encoder.put_u16_le(delegation.len() as u16);
        encoder.put_bytes(&delegation);
        encoder.put_u8(encoded_tickets.len() as u8);
        for ticket in encoded_tickets {
            encoder.put_bytes(&ticket);
        }
        Ok(encoder.into_bytes())
    }

    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<(), HnsrProtocolError> {
        let unsigned = self.encode_unsigned()?;
        self.endpoint_signature = sign(ROUTE_DOMAIN, &[&unsigned], private_key)?;
        Ok(())
    }

    pub fn verify(
        &self,
        network_magic: u32,
        now: u64,
        allow_private: bool,
    ) -> Result<(), HnsrProtocolError> {
        if self.profile != HNS_NODE_V1
            || self.sequence == 0
            || self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at) > MAX_ROUTE_LIFETIME
            || now < self.issued_at
            || now >= self.expires_at
            || self.tickets.is_empty()
            || self.tickets.len() > 8
            || self.route_key
                != crate::routing::route_key(network_magic, &self.delegation.endpoint_key)?
        {
            return Err(HnsrProtocolError::Invalid("invalid HNSR route record"));
        }
        self.delegation.verify(network_magic, now)?;
        if self.delegation.expires_at < self.expires_at {
            return Err(HnsrProtocolError::Invalid(
                "HNSR delegation expires before route",
            ));
        }
        for ticket in &self.tickets {
            if ticket.endpoint_key != self.delegation.endpoint_key
                || ticket.profile != self.profile
                || ticket.expires_at < self.expires_at
            {
                return Err(HnsrProtocolError::Invalid(
                    "HNSR route ticket binding mismatch",
                ));
            }
            ticket.verify(network_magic, now, allow_private)?;
        }
        let unsigned = self.encode_unsigned()?;
        verify(
            ROUTE_DOMAIN,
            &[&unsigned],
            &self.endpoint_signature,
            &self.delegation.endpoint_key,
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        let unsigned = self.encode_unsigned()?;
        let mut encoder =
            Encoder::with_capacity(unsigned.len() + 1 + self.endpoint_signature.len());
        encoder.put_bytes(&unsigned);
        encode_signature(&mut encoder, &self.endpoint_signature, false)?;
        let output = encoder.into_bytes();
        if output.len() > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: output.len(),
                maximum: MAX_RECORD_SIZE,
            });
        }
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        if input.is_empty() || input.len() > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: input.len(),
                maximum: MAX_RECORD_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        if decoder.read_u8()? != 1 {
            return Err(HnsrProtocolError::Invalid("unsupported HNSR route version"));
        }
        if decoder.read_u8()? != 0 {
            return Err(HnsrProtocolError::Invalid(
                "unsupported HNSR route authority",
            ));
        }
        let route_key = decoder.read_array()?;
        let profile = decoder.read_u16_le()?;
        let sequence = decoder.read_u64_le()?;
        let issued_at = decoder.read_u64_le()?;
        let expires_at = decoder.read_u64_le()?;
        let authorization_length = decoder.read_u16_le()? as usize;
        let authorization = decoder.read_bounded_vec(authorization_length, MAX_RECORD_SIZE)?;
        let delegation_length = decoder.read_u16_le()? as usize;
        if delegation_length == 0 || delegation_length > MAX_RECORD_SIZE {
            return Err(HnsrProtocolError::Invalid("invalid HNSR delegation length"));
        }
        let delegation = EndpointDelegation::decode(decoder.read_slice(delegation_length)?)?;
        let ticket_count = decoder.read_u8()? as usize;
        if !(1..=8).contains(&ticket_count) {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSR route ticket count",
            ));
        }
        let mut tickets = Vec::with_capacity(ticket_count);
        for _ in 0..ticket_count {
            tickets.push(RelayTicket::read_from(&mut decoder)?);
        }
        let endpoint_signature = decode_signature(&mut decoder, false)?;
        decoder.finish()?;
        let record = Self {
            route_key,
            profile,
            sequence,
            issued_at,
            expires_at,
            authorization,
            delegation,
            tickets,
            endpoint_signature,
        };
        record.encode_unsigned()?;
        Ok(record)
    }
}

pub fn sign_withdrawal(
    network_magic: u32,
    relay_key: &[u8; 33],
    context_id: &[u8; 8],
    reservation_id: &[u8; 16],
    ticket_id: &[u8; 32],
    private_key: &[u8; 32],
) -> Result<Vec<u8>, HnsrProtocolError> {
    let data = withdrawal_data(
        network_magic,
        relay_key,
        context_id,
        reservation_id,
        ticket_id,
    )?;
    sign(WITHDRAW_DOMAIN, &[&data], private_key)
}

pub fn verify_withdrawal(
    network_magic: u32,
    relay_key: &[u8; 33],
    context_id: &[u8; 8],
    reservation_id: &[u8; 16],
    ticket_id: &[u8; 32],
    signature: &[u8],
    endpoint_key: &[u8; 33],
) -> Result<(), HnsrProtocolError> {
    let data = withdrawal_data(
        network_magic,
        relay_key,
        context_id,
        reservation_id,
        ticket_id,
    )?;
    verify(WITHDRAW_DOMAIN, &[&data], signature, endpoint_key)
}

pub(crate) fn encode_signature(
    encoder: &mut Encoder,
    signature: &[u8],
    allow_empty: bool,
) -> Result<(), HnsrProtocolError> {
    if (!allow_empty && signature.is_empty()) || signature.len() > MAX_SIGNATURE_SIZE {
        return Err(HnsrProtocolError::Invalid("invalid HNSR signature length"));
    }
    encoder.put_u8(signature.len() as u8);
    encoder.put_bytes(signature);
    Ok(())
}

pub(crate) fn decode_signature(
    decoder: &mut Decoder<'_>,
    allow_empty: bool,
) -> Result<Vec<u8>, HnsrProtocolError> {
    let length = decoder.read_u8()? as usize;
    if (!allow_empty && length == 0) || length > MAX_SIGNATURE_SIZE {
        return Err(HnsrProtocolError::Invalid("invalid HNSR signature length"));
    }
    Ok(decoder.read_bounded_vec(length, MAX_SIGNATURE_SIZE)?)
}

pub(crate) fn validate_host(
    host_type: u8,
    host: &[u8; 16],
    port: u16,
    allow_private: bool,
) -> Result<(), HnsrProtocolError> {
    if port == 0 || !matches!(host_type, 1 | 2) {
        return Err(HnsrProtocolError::Invalid("invalid HNSR relay address"));
    }
    if allow_private {
        return Ok(());
    }
    let address = match host_type {
        1 if host[..10] == [0; 10] && host[10..12] == [0xff, 0xff] => {
            IpAddr::V4(Ipv4Addr::new(host[12], host[13], host[14], host[15]))
        }
        2 => IpAddr::V6(Ipv6Addr::from(*host)),
        _ => {
            return Err(HnsrProtocolError::Invalid(
                "noncanonical HNSR host encoding",
            ));
        }
    };
    if !is_publicly_routable(address) {
        return Err(HnsrProtocolError::Invalid(
            "HNSR address is not publicly routable",
        ));
    }
    Ok(())
}

pub(crate) fn validate_public_key(key: &[u8; 33]) -> Result<(), HnsrProtocolError> {
    VerifyingKey::from_sec1_bytes(key)
        .map(|_| ())
        .map_err(|_| HnsrProtocolError::Invalid("invalid HNSR peer key"))
}

pub(crate) fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
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

fn sign(
    domain: &[u8],
    parts: &[&[u8]],
    private_key: &[u8; 32],
) -> Result<Vec<u8>, HnsrProtocolError> {
    let key = signing_key(private_key)?;
    let mut digest_parts = Vec::with_capacity(parts.len() + 1);
    digest_parts.push(domain);
    digest_parts.extend(parts);
    let digest = blake2b_256(&digest_parts);
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|_| HnsrProtocolError::Cryptography)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    Ok(signature.to_der().as_bytes().to_vec())
}

fn verify(
    domain: &[u8],
    parts: &[&[u8]],
    signature: &[u8],
    public_key: &[u8; 33],
) -> Result<(), HnsrProtocolError> {
    validate_public_key(public_key)?;
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_SIZE {
        return Err(HnsrProtocolError::Invalid("invalid HNSR signature length"));
    }
    let signature = Signature::from_der(signature).map_err(|_| HnsrProtocolError::Cryptography)?;
    if signature.normalize_s().is_some() {
        return Err(HnsrProtocolError::Cryptography);
    }
    let mut digest_parts = Vec::with_capacity(parts.len() + 1);
    digest_parts.push(domain);
    digest_parts.extend(parts);
    let digest = blake2b_256(&digest_parts);
    VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| HnsrProtocolError::Cryptography)?
        .verify_prehash(&digest, &signature)
        .map_err(|_| HnsrProtocolError::Cryptography)
}

fn signing_key(private_key: &[u8; 32]) -> Result<SigningKey, HnsrProtocolError> {
    let private = Zeroizing::new(*private_key);
    SigningKey::from_bytes((&*private).into()).map_err(|_| HnsrProtocolError::Cryptography)
}

fn withdrawal_data(
    network_magic: u32,
    relay_key: &[u8; 33],
    context_id: &[u8; 8],
    reservation_id: &[u8; 16],
    ticket_id: &[u8; 32],
) -> Result<Vec<u8>, HnsrProtocolError> {
    validate_public_key(relay_key)?;
    if is_zero(context_id) || is_zero(reservation_id) || is_zero(ticket_id) {
        return Err(HnsrProtocolError::Invalid(
            "zero HNSR withdrawal identifier",
        ));
    }
    let mut data = Vec::with_capacity(4 + 33 + 8 + 16 + 32);
    data.extend(network_magic.to_le_bytes());
    data.extend(relay_key);
    data.extend(context_id);
    data.extend(reservation_id);
    data.extend(ticket_id);
    Ok(data)
}

fn is_publicly_routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_broadcast()
                || address.is_documentation()
                || address.is_multicast()
                || address.is_unspecified()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && matches!(octets[1], 18 | 19))
                || octets[0] >= 240)
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_publicly_routable(IpAddr::V4(mapped));
            }
            let segments = address.segments();
            !(address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || segments[0] & 0xfe00 == 0xfc00
                || segments[0] & 0xffc0 == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::route_key;

    const MAGIC: u32 = 2_922_943_951;

    fn keys() -> ([u8; 32], [u8; 33], [u8; 32], [u8; 33]) {
        let endpoint_private = [1; 32];
        let relay_private = [2; 32];
        (
            endpoint_private,
            public_key(&endpoint_private).expect("key"),
            relay_private,
            public_key(&relay_private).expect("key"),
        )
    }

    fn ticket(now: u64) -> (RelayTicket, [u8; 32]) {
        let (endpoint_private, endpoint_key, relay_private, relay_key) = keys();
        let mut ticket = RelayTicket {
            network_magic: MAGIC,
            profile: HNS_NODE_V1,
            transport: 0,
            host_type: 1,
            host: [0; 16],
            port: 14_039,
            relay_key,
            endpoint_key,
            reservation_id: [3; 16],
            issued_at: now,
            expires_at: now + 1800,
            max_active_circuits: 8,
            max_bytes_per_circuit: 1_048_576,
            max_total_bytes: 8_388_608,
            flags: 0,
            relay_signature: Vec::new(),
            endpoint_signature: Vec::new(),
        };
        ticket.sign_relay(&relay_private).expect("sign");
        ticket.sign_endpoint(&endpoint_private).expect("sign");
        (ticket, endpoint_private)
    }

    #[test]
    fn reservation_signatures_bind_network_relay_context_and_renewal() {
        let (endpoint_private, endpoint_key, _, relay_key) = keys();
        let context = [4; 8];
        let mut request = ReserveRequest {
            endpoint_key,
            profile: HNS_NODE_V1,
            lifetime: 1800,
            max_circuits: 8,
            max_bytes: 1_048_576,
            nonce: [5; 16],
            signature: Vec::new(),
        };
        request
            .sign(MAGIC, &relay_key, &context, &endpoint_private)
            .expect("sign");
        let decoded = ReserveRequest::decode(&request.encode().expect("valid")).expect("valid");
        decoded.verify(MAGIC, &relay_key, &context).expect("valid");
        assert!(decoded.verify(MAGIC + 1, &relay_key, &context).is_err());

        request
            .sign_renewal(MAGIC, &relay_key, &context, &[6; 16], &endpoint_private)
            .expect("sign");
        request
            .verify_renewal(MAGIC, &relay_key, &context, &[6; 16])
            .expect("valid");
        assert!(
            request
                .verify_renewal(MAGIC, &relay_key, &context, &[7; 16])
                .is_err()
        );
    }

    #[test]
    fn complete_unnamed_route_authorization_chain_round_trips() {
        let now = 1_700_000_000;
        let (ticket, endpoint_private) = ticket(now);
        let mut delegation = EndpointDelegation {
            authorization_id: [0; 32],
            endpoint_key: ticket.endpoint_key,
            sequence: 1,
            issued_at: now,
            expires_at: now + 900,
            max_active_circuits: 8,
            max_bytes_per_circuit: 1_048_576,
            flags: 0,
            signature: Vec::new(),
        };
        delegation.sign(MAGIC, &endpoint_private).expect("sign");
        let mut record = RouteRecord {
            route_key: route_key(MAGIC, &ticket.endpoint_key).expect("key"),
            profile: HNS_NODE_V1,
            sequence: 1,
            issued_at: now,
            expires_at: now + 900,
            authorization: Vec::new(),
            delegation,
            tickets: vec![ticket],
            endpoint_signature: Vec::new(),
        };
        record.sign(&endpoint_private).expect("sign");
        let encoded = record.encode().expect("valid");
        let decoded = RouteRecord::decode(&encoded).expect("valid");
        decoded.verify(MAGIC, now, true).expect("valid");
        assert_eq!(decoded, record);
    }

    #[test]
    fn wrong_network_expiry_and_high_s_fail_closed() {
        let now = 1_700_000_000;
        let (mut ticket, _) = ticket(now);
        ticket.verify(MAGIC, now, true).expect("valid");
        assert!(ticket.verify(MAGIC + 1, now, true).is_err());
        assert!(ticket.verify(MAGIC, now + 1800, true).is_err());

        let signature = Signature::from_der(&ticket.relay_signature).expect("DER");
        let (r, _) = signature.split_bytes();
        let high = Signature::from_scalars(r, (-signature.s()).to_bytes()).expect("signature");
        ticket.relay_signature = high.to_der().as_bytes().to_vec();
        assert!(ticket.verify_relay().is_err());
    }
}
