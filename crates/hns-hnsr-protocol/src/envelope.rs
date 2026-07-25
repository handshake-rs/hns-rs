use hns_encoding::{Decoder, Encoder};

use crate::{HNSR_VERSION, HnsrProtocolError, MAX_PACKET_SIZE, is_zero};

const HNSR_HEADER_SIZE: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HnsrOpcode {
    FindNode = 0,
    Nodes = 1,
    PutRoute = 2,
    PutResult = 3,
    GetRoute = 4,
    Routes = 5,
    SampleRoutes = 6,
    Reserve = 7,
    Offer = 8,
    Confirm = 9,
    Confirmed = 10,
    Renew = 11,
    Withdraw = 12,
    Open = 13,
    Incoming = 14,
    Accept = 15,
    Opened = 16,
    Data = 17,
    Window = 18,
    Close = 19,
    Error = 20,
}

impl TryFrom<u8> for HnsrOpcode {
    type Error = HnsrProtocolError;

    fn try_from(value: u8) -> Result<Self, HnsrProtocolError> {
        match value {
            0 => Ok(Self::FindNode),
            1 => Ok(Self::Nodes),
            2 => Ok(Self::PutRoute),
            3 => Ok(Self::PutResult),
            4 => Ok(Self::GetRoute),
            5 => Ok(Self::Routes),
            6 => Ok(Self::SampleRoutes),
            7 => Ok(Self::Reserve),
            8 => Ok(Self::Offer),
            9 => Ok(Self::Confirm),
            10 => Ok(Self::Confirmed),
            11 => Ok(Self::Renew),
            12 => Ok(Self::Withdraw),
            13 => Ok(Self::Open),
            14 => Ok(Self::Incoming),
            15 => Ok(Self::Accept),
            16 => Ok(Self::Opened),
            17 => Ok(Self::Data),
            18 => Ok(Self::Window),
            19 => Ok(Self::Close),
            20 => Ok(Self::Error),
            _ => Err(HnsrProtocolError::Invalid("unknown HNSR opcode")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsrPacket {
    pub opcode: HnsrOpcode,
    pub context_id: [u8; 8],
    pub body: Vec<u8>,
}

impl HnsrPacket {
    pub fn new(
        opcode: HnsrOpcode,
        context_id: [u8; 8],
        body: Vec<u8>,
    ) -> Result<Self, HnsrProtocolError> {
        let packet = Self {
            opcode,
            context_id,
            body,
        };
        packet.validate()?;
        Ok(packet)
    }

    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(HNSR_HEADER_SIZE + self.body.len());
        encoder.put_u8(HNSR_VERSION);
        encoder.put_u8(self.opcode as u8);
        encoder.put_u16_le(0);
        encoder.put_bytes(&self.context_id);
        encoder.put_bytes(&self.body);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        if input.len() > MAX_PACKET_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: input.len(),
                maximum: MAX_PACKET_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        if decoder.read_u8()? != HNSR_VERSION {
            return Err(HnsrProtocolError::Invalid("unknown HNSR version"));
        }
        let opcode = HnsrOpcode::try_from(decoder.read_u8()?)?;
        if decoder.read_u16_le()? != 0 {
            return Err(HnsrProtocolError::Invalid("reserved HNSR flags are set"));
        }
        let context_id = decoder.read_array()?;
        let body =
            decoder.read_bounded_vec(decoder.remaining(), MAX_PACKET_SIZE - HNSR_HEADER_SIZE)?;
        decoder.finish()?;
        Self::new(opcode, context_id, body)
    }

    fn validate(&self) -> Result<(), HnsrProtocolError> {
        let total = HNSR_HEADER_SIZE.saturating_add(self.body.len());
        if total > MAX_PACKET_SIZE {
            return Err(HnsrProtocolError::TooLarge {
                actual: total,
                maximum: MAX_PACKET_SIZE,
            });
        }
        if is_zero(&self.context_id) && self.opcode != HnsrOpcode::SampleRoutes {
            return Err(HnsrProtocolError::Invalid("HNSR context ID is zero"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_hsd_envelope_round_trip() {
        let packet = HnsrPacket::new(
            HnsrOpcode::Data,
            [1, 2, 3, 4, 5, 6, 7, 8],
            hex::decode("deadbeef").expect("hex"),
        )
        .expect("valid");
        let encoded = packet.encode().expect("valid");
        assert_eq!(hex::encode(&encoded), "011100000102030405060708deadbeef");
        assert_eq!(HnsrPacket::decode(&encoded).expect("valid"), packet);
    }

    #[test]
    fn malformed_envelopes_fail_closed() {
        let raw = HnsrPacket::new(HnsrOpcode::Data, [1; 8], vec![1])
            .expect("valid")
            .encode()
            .expect("valid");
        assert!(HnsrPacket::decode(&raw[..11]).is_err());
        let mut invalid = raw.clone();
        invalid[0] = 2;
        assert!(HnsrPacket::decode(&invalid).is_err());
        invalid = raw.clone();
        invalid[2] = 1;
        assert!(HnsrPacket::decode(&invalid).is_err());
        invalid = raw;
        invalid[4..12].fill(0);
        assert!(HnsrPacket::decode(&invalid).is_err());
    }
}
