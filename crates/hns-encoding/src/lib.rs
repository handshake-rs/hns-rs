#![doc = "Little-endian wire encoding with allocation bounds and complete-input checks."]

use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DecodeError {
    #[error("unexpected end of input at byte {offset}; needed {needed} more byte(s)")]
    UnexpectedEnd { offset: usize, needed: usize },
    #[error("length {actual} exceeds configured maximum {maximum}")]
    LengthExceedsBound { actual: usize, maximum: usize },
    #[error("{remaining} trailing byte(s) remain")]
    TrailingBytes { remaining: usize },
    #[error("invalid value for {field}: {reason}")]
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct Decoder<'input> {
    input: &'input [u8],
    position: usize,
}

impl<'input> Decoder<'input> {
    pub const fn new(input: &'input [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub const fn position(&self) -> usize {
        self.position
    }

    pub const fn remaining(&self) -> usize {
        self.input.len() - self.position
    }

    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_array::<1>()?[0])
    }

    pub fn read_u16_le(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    pub fn read_u32_le(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    pub fn read_u64_le(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    pub fn read_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], DecodeError> {
        let bytes = self.read_slice(LENGTH)?;
        let mut output = [0_u8; LENGTH];
        output.copy_from_slice(bytes);
        Ok(output)
    }

    pub fn read_slice(&mut self, length: usize) -> Result<&'input [u8], DecodeError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(DecodeError::LengthExceedsBound {
                actual: usize::MAX,
                maximum: self.remaining(),
            })?;
        if end > self.input.len() {
            return Err(DecodeError::UnexpectedEnd {
                offset: self.position,
                needed: end - self.input.len(),
            });
        }
        let bytes = &self.input[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    pub fn read_bounded_vec(
        &mut self,
        length: usize,
        maximum: usize,
    ) -> Result<Vec<u8>, DecodeError> {
        if length > maximum {
            return Err(DecodeError::LengthExceedsBound {
                actual: length,
                maximum,
            });
        }
        Ok(self.read_slice(length)?.to_vec())
    }

    pub fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes {
                remaining: self.remaining(),
            })
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub fn put_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn put_u16_le(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn put_u32_le(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn put_u64_le(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn put_bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_little_endian() {
        let mut encoder = Encoder::new();
        encoder.put_u8(1);
        encoder.put_u16_le(0x0302);
        encoder.put_u32_le(0x0706_0504);
        encoder.put_u64_le(0x0f0e_0d0c_0b0a_0908);

        let bytes = encoder.into_bytes();
        assert_eq!(bytes, (1_u8..=15).collect::<Vec<_>>());

        let mut decoder = Decoder::new(&bytes);
        assert_eq!(decoder.read_u8(), Ok(1));
        assert_eq!(decoder.read_u16_le(), Ok(0x0302));
        assert_eq!(decoder.read_u32_le(), Ok(0x0706_0504));
        assert_eq!(decoder.read_u64_le(), Ok(0x0f0e_0d0c_0b0a_0908));
        assert_eq!(decoder.finish(), Ok(()));
    }

    #[test]
    fn rejects_truncation_trailing_bytes_and_oversized_allocation() {
        let mut truncated = Decoder::new(&[1, 2, 3]);
        assert!(matches!(
            truncated.read_u32_le(),
            Err(DecodeError::UnexpectedEnd { .. })
        ));

        let mut trailing = Decoder::new(&[1, 2]);
        assert_eq!(trailing.read_u8(), Ok(1));
        assert_eq!(
            trailing.finish(),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        );

        let mut bounded = Decoder::new(&[0; 4]);
        assert_eq!(
            bounded.read_bounded_vec(4, 3),
            Err(DecodeError::LengthExceedsBound {
                actual: 4,
                maximum: 3
            })
        );
        assert_eq!(bounded.position(), 0);
    }
}
