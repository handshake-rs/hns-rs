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

    pub fn read_compact_size(&mut self) -> Result<u64, DecodeError> {
        match self.read_u8()? {
            value @ 0x00..=0xfc => Ok(u64::from(value)),
            0xfd => {
                let value = u64::from(self.read_u16_le()?);
                if value < 0xfd {
                    return Err(DecodeError::InvalidValue {
                        field: "compact size",
                        reason: "noncanonical u16 encoding",
                    });
                }
                Ok(value)
            }
            0xfe => {
                let value = u64::from(self.read_u32_le()?);
                if value <= u64::from(u16::MAX) {
                    return Err(DecodeError::InvalidValue {
                        field: "compact size",
                        reason: "noncanonical u32 encoding",
                    });
                }
                Ok(value)
            }
            0xff => {
                let value = self.read_u64_le()?;
                if value <= u64::from(u32::MAX) {
                    return Err(DecodeError::InvalidValue {
                        field: "compact size",
                        reason: "noncanonical u64 encoding",
                    });
                }
                Ok(value)
            }
        }
    }

    pub fn read_compact_usize(
        &mut self,
        maximum: usize,
        _field: &'static str,
    ) -> Result<usize, DecodeError> {
        let value = self.read_compact_size()?;
        let value = usize::try_from(value).map_err(|_| DecodeError::LengthExceedsBound {
            actual: usize::MAX,
            maximum,
        })?;
        if value > maximum {
            return Err(DecodeError::LengthExceedsBound {
                actual: value,
                maximum,
            });
        }
        Ok(value)
    }

    pub fn read_varbytes(
        &mut self,
        maximum: usize,
        field: &'static str,
    ) -> Result<Vec<u8>, DecodeError> {
        let length = self.read_compact_usize(maximum, field)?;
        self.read_bounded_vec(length, maximum)
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

    pub fn put_compact_size(&mut self, value: u64) {
        match value {
            0x00..=0xfc => self.put_u8(value as u8),
            0xfd..=0xffff => {
                self.put_u8(0xfd);
                self.put_u16_le(value as u16);
            }
            0x1_0000..=0xffff_ffff => {
                self.put_u8(0xfe);
                self.put_u32_le(value as u32);
            }
            _ => {
                self.put_u8(0xff);
                self.put_u64_le(value);
            }
        }
    }

    pub fn put_varbytes(&mut self, value: &[u8]) {
        self.put_compact_size(value.len() as u64);
        self.put_bytes(value);
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

    #[test]
    fn compact_sizes_are_minimal_and_bounded() {
        for value in [
            0,
            0xfc,
            0xfd,
            u64::from(u16::MAX),
            u64::from(u16::MAX) + 1,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            u64::MAX,
        ] {
            let mut encoder = Encoder::new();
            encoder.put_compact_size(value);
            let bytes = encoder.into_bytes();
            let mut decoder = Decoder::new(&bytes);
            assert_eq!(decoder.read_compact_size(), Ok(value));
            assert_eq!(decoder.finish(), Ok(()));
        }
        assert!(Decoder::new(&[0xfd, 0xfc, 0]).read_compact_size().is_err());
        assert!(Decoder::new(&[4]).read_compact_usize(3, "items").is_err());
    }
}
