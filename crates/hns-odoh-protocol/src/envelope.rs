use hns_encoding::{Decoder, Encoder};

use crate::{MAX_ODOH_PACKET_SIZE, OdohProtocolError};

const ODOH_VERSION: u8 = 1;
const ODNS_HEADER_SIZE: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OdohOpcode {
    GetCaps = 0,
    Caps = 1,
    GetConfig = 2,
    Config = 3,
    ClientQuery = 4,
    TargetQuery = 5,
    TargetResponse = 6,
    ClientResponse = 7,
    Cancel = 8,
    Error = 9,
}

impl TryFrom<u8> for OdohOpcode {
    type Error = OdohProtocolError;

    fn try_from(value: u8) -> Result<Self, OdohProtocolError> {
        match value {
            0 => Ok(Self::GetCaps),
            1 => Ok(Self::Caps),
            2 => Ok(Self::GetConfig),
            3 => Ok(Self::Config),
            4 => Ok(Self::ClientQuery),
            5 => Ok(Self::TargetQuery),
            6 => Ok(Self::TargetResponse),
            7 => Ok(Self::ClientResponse),
            8 => Ok(Self::Cancel),
            9 => Ok(Self::Error),
            _ => Err(OdohProtocolError::Invalid("unknown ODNS opcode")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdnsPacket {
    pub opcode: OdohOpcode,
    pub request_id: u64,
    pub body: Vec<u8>,
}

impl OdnsPacket {
    pub fn new(
        opcode: OdohOpcode,
        request_id: u64,
        body: Vec<u8>,
    ) -> Result<Self, OdohProtocolError> {
        let packet = Self {
            opcode,
            request_id,
            body,
        };
        packet.validate()?;
        Ok(packet)
    }

    pub fn encode(&self) -> Result<Vec<u8>, OdohProtocolError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(ODNS_HEADER_SIZE + self.body.len());
        encoder.put_u8(ODOH_VERSION);
        encoder.put_u8(self.opcode as u8);
        encoder.put_u16_le(0);
        encoder.put_u64_le(self.request_id);
        encoder.put_bytes(&self.body);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, OdohProtocolError> {
        if input.len() > MAX_ODOH_PACKET_SIZE {
            return Err(OdohProtocolError::TooLarge {
                actual: input.len(),
                maximum: MAX_ODOH_PACKET_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        if decoder.read_u8()? != ODOH_VERSION {
            return Err(OdohProtocolError::Invalid("unsupported ODNS version"));
        }
        let opcode = OdohOpcode::try_from(decoder.read_u8()?)?;
        if decoder.read_u16_le()? != 0 {
            return Err(OdohProtocolError::Invalid(
                "ODNS reserved flags are nonzero",
            ));
        }
        let request_id = decoder.read_u64_le()?;
        if request_id == 0 {
            return Err(OdohProtocolError::Invalid("ODNS request ID is zero"));
        }
        let body = decoder.read_bounded_vec(decoder.remaining(), MAX_ODOH_PACKET_SIZE - 12)?;
        decoder.finish()?;
        Self::new(opcode, request_id, body)
    }

    fn validate(&self) -> Result<(), OdohProtocolError> {
        if self.request_id == 0 {
            return Err(OdohProtocolError::Invalid("ODNS request ID is zero"));
        }
        let total = ODNS_HEADER_SIZE.saturating_add(self.body.len());
        if total > MAX_ODOH_PACKET_SIZE {
            return Err(OdohProtocolError::TooLarge {
                actual: total,
                maximum: MAX_ODOH_PACKET_SIZE,
            });
        }
        match self.opcode {
            OdohOpcode::GetCaps if !self.body.is_empty() => {
                Err(OdohProtocolError::Invalid("GETCAPS body must be empty"))
            }
            OdohOpcode::Cancel
                if self.body.len() != 1 || self.body.first().copied().unwrap_or(4) > 3 =>
            {
                Err(OdohProtocolError::Invalid("invalid CANCEL reason"))
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odns_envelope_round_trips_and_rejects_reserved_bits() {
        let packet =
            OdnsPacket::new(OdohOpcode::Caps, 0x0102_0304_0506_0708, vec![2, 3]).expect("valid");
        let encoded = packet.encode().expect("valid");
        assert_eq!(hex::encode(&encoded), "0101000008070605040302010203");
        assert_eq!(OdnsPacket::decode(&encoded).expect("valid"), packet);

        let mut flags = encoded;
        flags[2] = 1;
        assert!(OdnsPacket::decode(&flags).is_err());
        assert!(OdnsPacket::new(OdohOpcode::GetCaps, 0, Vec::new()).is_err());
    }

    #[test]
    fn cancel_and_getcaps_have_strict_bodies() {
        assert!(OdnsPacket::new(OdohOpcode::GetCaps, 1, vec![0]).is_err());
        assert!(OdnsPacket::new(OdohOpcode::Cancel, 1, vec![]).is_err());
        assert!(OdnsPacket::new(OdohOpcode::Cancel, 1, vec![4]).is_err());
        assert!(OdnsPacket::new(OdohOpcode::Cancel, 1, vec![3]).is_ok());
    }
}
