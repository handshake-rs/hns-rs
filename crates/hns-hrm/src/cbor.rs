//! Strict deterministic-CBOR subset used by HRM objects.
//!
//! HRM maps use non-negative assigned integer keys. Values support every
//! primitive needed by HRM and profile maps while deliberately rejecting
//! tags, floating-point values, undefined/simple values, indefinite lengths,
//! duplicate keys, and trailing bytes.

use thiserror::Error;

/// One deterministic HRM CBOR value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Unsigned(u64),
    /// A negative integer in the complete CBOR range `-1-u64::MAX..=-1`.
    Negative(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// A map with strictly increasing non-negative integer keys.
    Map(Vec<(u64, Value)>),
    Bool(bool),
    Null,
}

/// Allocation and recursion limits applied before encoding or decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeLimits {
    pub max_depth: usize,
    pub max_items: usize,
    pub max_bytes: usize,
    pub max_array_len: usize,
    pub max_map_len: usize,
    pub max_string_bytes: usize,
}

impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            // Every decoded item or map key consumes at least one input byte.
            // Matching the byte cap therefore admits every item layout that
            // can otherwise fit in a default-sized HRM envelope.
            max_items: 1_048_576,
            max_bytes: 1_048_576,
            max_array_len: 4_096,
            max_map_len: 4_096,
            max_string_bytes: 1_048_576,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CborError {
    #[error("invalid deterministic-CBOR limits: {0}")]
    InvalidLimits(&'static str),
    #[error("deterministic-CBOR input is empty")]
    Empty,
    #[error("deterministic-CBOR input exceeds the byte limit")]
    TooLarge,
    #[error("truncated deterministic-CBOR input")]
    Truncated,
    #[error("non-preferred deterministic-CBOR integer or length")]
    NonPreferred,
    #[error("unsupported CBOR major type or additional information")]
    Unsupported,
    #[error("floating-point values are forbidden in HRM CBOR")]
    Float,
    #[error("indefinite-length values are forbidden in HRM CBOR")]
    Indefinite,
    #[error("deterministic-CBOR text is not valid UTF-8")]
    Utf8,
    #[error("deterministic-CBOR nesting exceeds the depth limit")]
    Depth,
    #[error("deterministic-CBOR item count exceeds the limit")]
    Items,
    #[error("deterministic-CBOR container exceeds its element limit")]
    Container,
    #[error("deterministic-CBOR string exceeds its byte limit")]
    String,
    #[error("HRM CBOR map keys must be strictly increasing unsigned integers")]
    MapKey,
    #[error("negative value is outside the CBOR integer range")]
    NegativeRange,
    #[error("trailing bytes follow the top-level deterministic-CBOR item")]
    Trailing,
}

/// Encode a value in RFC 8949 preferred deterministic form under the default
/// HRM allocation and recursion limits.
pub fn encode_canonical(value: &Value) -> Result<Vec<u8>, CborError> {
    encode_canonical_with_limits(value, DecodeLimits::default())
}

/// Encode a value in RFC 8949 preferred deterministic form under explicit
/// allocation and recursion limits.
pub fn encode_canonical_with_limits(
    value: &Value,
    limits: DecodeLimits,
) -> Result<Vec<u8>, CborError> {
    validate_limits(limits)?;
    let mut encoder = Encoder {
        output: Vec::new(),
        limits,
        items: 0,
    };
    encoder.value(value, 1)?;
    Ok(encoder.output)
}

/// Decode one complete canonical value within explicit allocation bounds.
pub fn decode_canonical(input: &[u8], limits: DecodeLimits) -> Result<Value, CborError> {
    validate_limits(limits)?;
    if input.is_empty() {
        return Err(CborError::Empty);
    }
    if input.len() > limits.max_bytes {
        return Err(CborError::TooLarge);
    }
    let mut decoder = Decoder {
        input,
        position: 0,
        limits,
        items: 0,
    };
    let value = decoder.value(1)?;
    if decoder.position != input.len() {
        return Err(CborError::Trailing);
    }
    if encode_canonical_with_limits(&value, limits)?.as_slice() != input {
        return Err(CborError::NonPreferred);
    }
    Ok(value)
}

fn validate_limits(limits: DecodeLimits) -> Result<(), CborError> {
    if limits.max_depth == 0 {
        return Err(CborError::InvalidLimits("max_depth must be nonzero"));
    }
    if limits.max_items == 0 {
        return Err(CborError::InvalidLimits("max_items must be nonzero"));
    }
    if limits.max_bytes == 0 {
        return Err(CborError::InvalidLimits("max_bytes must be nonzero"));
    }
    Ok(())
}

fn encode_head(major: u8, argument: u64, output: &mut Vec<u8>) {
    let prefix = major << 5;
    match argument {
        0..=23 => output.push(prefix | argument as u8),
        24..=0xff => {
            output.push(prefix | 24);
            output.push(argument as u8);
        }
        0x100..=0xffff => {
            output.push(prefix | 25);
            output.extend_from_slice(&(argument as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(prefix | 26);
            output.extend_from_slice(&(argument as u32).to_be_bytes());
        }
        _ => {
            output.push(prefix | 27);
            output.extend_from_slice(&argument.to_be_bytes());
        }
    }
}

struct Encoder {
    output: Vec<u8>,
    limits: DecodeLimits,
    items: usize,
}

impl Encoder {
    fn value(&mut self, value: &Value, depth: usize) -> Result<(), CborError> {
        if depth > self.limits.max_depth {
            return Err(CborError::Depth);
        }
        self.bump_item()?;
        match value {
            Value::Unsigned(value) => self.head(0, *value)?,
            Value::Negative(value) => {
                if *value >= 0 {
                    return Err(CborError::NegativeRange);
                }
                let magnitude = (-1_i128)
                    .checked_sub(*value)
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or(CborError::NegativeRange)?;
                self.head(1, magnitude)?;
            }
            Value::Bytes(bytes) => {
                self.string_len(bytes.len())?;
                self.head(2, bytes.len().try_into().map_err(|_| CborError::TooLarge)?)?;
                self.extend(bytes)?;
            }
            Value::Text(text) => {
                self.string_len(text.len())?;
                self.head(3, text.len().try_into().map_err(|_| CborError::TooLarge)?)?;
                self.extend(text.as_bytes())?;
            }
            Value::Array(values) => {
                if values.len() > self.limits.max_array_len {
                    return Err(CborError::Container);
                }
                self.ensure_future_items(values.len())?;
                self.head(4, values.len().try_into().map_err(|_| CborError::TooLarge)?)?;
                for value in values {
                    self.value(value, depth + 1)?;
                }
            }
            Value::Map(fields) => {
                if fields.len() > self.limits.max_map_len {
                    return Err(CborError::Container);
                }
                self.ensure_future_items(fields.len().saturating_mul(2))?;
                let mut previous = None;
                for (key, _) in fields {
                    if previous.is_some_and(|previous| previous >= *key) {
                        return Err(CborError::MapKey);
                    }
                    previous = Some(*key);
                }
                self.head(5, fields.len().try_into().map_err(|_| CborError::TooLarge)?)?;
                for (key, value) in fields {
                    self.bump_item()?;
                    self.head(0, *key)?;
                    self.value(value, depth + 1)?;
                }
            }
            Value::Bool(false) => self.push(0xf4)?,
            Value::Bool(true) => self.push(0xf5)?,
            Value::Null => self.push(0xf6)?,
        }
        Ok(())
    }

    fn string_len(&self, length: usize) -> Result<(), CborError> {
        if length > self.limits.max_string_bytes {
            return Err(CborError::String);
        }
        Ok(())
    }

    fn ensure_future_items(&self, additional: usize) -> Result<(), CborError> {
        if self.items.saturating_add(additional) > self.limits.max_items {
            return Err(CborError::Items);
        }
        Ok(())
    }

    fn bump_item(&mut self) -> Result<(), CborError> {
        self.items = self.items.saturating_add(1);
        if self.items > self.limits.max_items {
            return Err(CborError::Items);
        }
        Ok(())
    }

    fn head(&mut self, major: u8, argument: u64) -> Result<(), CborError> {
        let mut bytes = Vec::with_capacity(9);
        encode_head(major, argument, &mut bytes);
        self.extend(&bytes)
    }

    fn push(&mut self, byte: u8) -> Result<(), CborError> {
        if self.output.len() == self.limits.max_bytes {
            return Err(CborError::TooLarge);
        }
        self.output.push(byte);
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), CborError> {
        let new_len = self
            .output
            .len()
            .checked_add(bytes.len())
            .ok_or(CborError::TooLarge)?;
        if new_len > self.limits.max_bytes {
            return Err(CborError::TooLarge);
        }
        self.output.extend_from_slice(bytes);
        Ok(())
    }
}

struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
    limits: DecodeLimits,
    items: usize,
}

impl Decoder<'_> {
    fn value(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > self.limits.max_depth {
            return Err(CborError::Depth);
        }
        self.bump_item()?;
        let initial = self.byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        match major {
            0 => Ok(Value::Unsigned(self.argument(additional)?)),
            1 => {
                let magnitude = self.argument(additional)?;
                Ok(Value::Negative(-1_i128 - i128::from(magnitude)))
            }
            2 => {
                let length = self.string_length(additional)?;
                Ok(Value::Bytes(self.slice(length)?.to_vec()))
            }
            3 => {
                let length = self.string_length(additional)?;
                let text = std::str::from_utf8(self.slice(length)?)
                    .map_err(|_| CborError::Utf8)?
                    .to_owned();
                Ok(Value::Text(text))
            }
            4 => {
                let length = self.container_length(additional, self.limits.max_array_len)?;
                self.ensure_future_items(length)?;
                let mut values = Vec::with_capacity(length.min(1_024));
                for _ in 0..length {
                    values.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(values))
            }
            5 => {
                let length = self.container_length(additional, self.limits.max_map_len)?;
                self.ensure_future_items(length.saturating_mul(2))?;
                let mut fields = Vec::with_capacity(length.min(1_024));
                let mut previous = None;
                for _ in 0..length {
                    self.bump_item()?;
                    let initial = self.byte()?;
                    if initial >> 5 != 0 {
                        return Err(CborError::MapKey);
                    }
                    let key = self.argument(initial & 0x1f)?;
                    if previous.is_some_and(|previous| previous >= key) {
                        return Err(CborError::MapKey);
                    }
                    previous = Some(key);
                    fields.push((key, self.value(depth + 1)?));
                }
                Ok(Value::Map(fields))
            }
            6 => Err(CborError::Unsupported),
            7 => match additional {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                25..=27 => Err(CborError::Float),
                31 => Err(CborError::Indefinite),
                _ => Err(CborError::Unsupported),
            },
            _ => Err(CborError::Unsupported),
        }
    }

    fn argument(&mut self, additional: u8) -> Result<u64, CborError> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.byte()?);
                if value < 24 {
                    return Err(CborError::NonPreferred);
                }
                Ok(value)
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.array()?));
                if value <= 0xff {
                    return Err(CborError::NonPreferred);
                }
                Ok(value)
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.array()?));
                if value <= 0xffff {
                    return Err(CborError::NonPreferred);
                }
                Ok(value)
            }
            27 => {
                let value = u64::from_be_bytes(self.array()?);
                if value <= 0xffff_ffff {
                    return Err(CborError::NonPreferred);
                }
                Ok(value)
            }
            31 => Err(CborError::Indefinite),
            _ => Err(CborError::Unsupported),
        }
    }

    fn string_length(&mut self, additional: u8) -> Result<usize, CborError> {
        let length: usize = self
            .argument(additional)?
            .try_into()
            .map_err(|_| CborError::String)?;
        if length > self.limits.max_string_bytes {
            return Err(CborError::String);
        }
        Ok(length)
    }

    fn container_length(&mut self, additional: u8, maximum: usize) -> Result<usize, CborError> {
        let length: usize = self
            .argument(additional)?
            .try_into()
            .map_err(|_| CborError::Container)?;
        if length > maximum {
            return Err(CborError::Container);
        }
        Ok(length)
    }

    fn ensure_future_items(&self, additional: usize) -> Result<(), CborError> {
        if self.items.saturating_add(additional) > self.limits.max_items {
            return Err(CborError::Items);
        }
        Ok(())
    }

    fn bump_item(&mut self) -> Result<(), CborError> {
        self.items = self.items.saturating_add(1);
        if self.items > self.limits.max_items {
            return Err(CborError::Items);
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        let byte = *self.input.get(self.position).ok_or(CborError::Truncated)?;
        self.position += 1;
        Ok(byte)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        self.slice(N)?.try_into().map_err(|_| CborError::Truncated)
    }

    fn slice(&mut self, length: usize) -> Result<&[u8], CborError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CborError::Truncated)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(CborError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> DecodeLimits {
        DecodeLimits {
            max_depth: 8,
            max_items: 64,
            max_bytes: 1_024,
            max_array_len: 16,
            max_map_len: 16,
            max_string_bytes: 128,
        }
    }

    #[test]
    fn preferred_integer_boundaries_round_trip() {
        for (value, expected) in [
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65_535, "19ffff"),
            (65_536, "1a00010000"),
            (u64::MAX, "1bffffffffffffffff"),
        ] {
            let encoded = encode_canonical(&Value::Unsigned(value)).expect("encode");
            assert_eq!(hex::encode(&encoded), expected);
            assert_eq!(
                decode_canonical(&encoded, limits()),
                Ok(Value::Unsigned(value))
            );
        }
    }

    #[test]
    fn negative_bool_null_strings_arrays_and_maps_round_trip() {
        let value = Value::Map(vec![
            (0, Value::Negative(-1)),
            (1, Value::Negative(-18_446_744_073_709_551_616_i128)),
            (2, Value::Bool(true)),
            (3, Value::Null),
            (4, Value::Bytes(vec![0, 1, 2])),
            (5, Value::Text("HRM ✓".to_owned())),
            (
                6,
                Value::Array(vec![Value::Unsigned(1), Value::Bool(false)]),
            ),
        ]);
        let encoded = encode_canonical(&value).expect("encode");
        assert_eq!(decode_canonical(&encoded, limits()), Ok(value));
    }

    #[test]
    fn nonpreferred_indefinite_float_tag_simple_and_trailing_fail() {
        for (bytes, error) in [
            (&[0x18, 0x17][..], CborError::NonPreferred),
            (&[0x19, 0x00, 0xff], CborError::NonPreferred),
            (&[0x5f, 0xff], CborError::Indefinite),
            (&[0x9f, 0xff], CborError::Indefinite),
            (&[0xf9, 0, 0], CborError::Float),
            (&[0xc0, 0], CborError::Unsupported),
            (&[0xf7], CborError::Unsupported),
            (&[0, 0], CborError::Trailing),
        ] {
            assert_eq!(decode_canonical(bytes, limits()), Err(error));
        }
    }

    #[test]
    fn invalid_utf8_and_map_key_order_fail() {
        assert_eq!(
            decode_canonical(&[0x61, 0xff], limits()),
            Err(CborError::Utf8)
        );
        assert_eq!(
            decode_canonical(&[0xa2, 0x01, 0x00, 0x00, 0x00], limits()),
            Err(CborError::MapKey)
        );
        assert_eq!(
            decode_canonical(&[0xa2, 0x00, 0x00, 0x00, 0x01], limits()),
            Err(CborError::MapKey)
        );
        assert_eq!(
            decode_canonical(&[0xa1, 0x20, 0x00], limits()),
            Err(CborError::MapKey)
        );
        assert_eq!(
            encode_canonical(&Value::Map(vec![
                (1, Value::Unsigned(0)),
                (0, Value::Unsigned(0)),
            ])),
            Err(CborError::MapKey)
        );
    }

    #[test]
    fn allocation_depth_and_item_limits_apply_before_container_allocation() {
        let mut restricted = limits();
        restricted.max_array_len = 1;
        assert_eq!(
            decode_canonical(&[0x82, 0, 0], restricted),
            Err(CborError::Container)
        );

        restricted = limits();
        restricted.max_items = 2;
        assert_eq!(
            decode_canonical(&[0x82, 0, 0], restricted),
            Err(CborError::Items)
        );

        restricted = limits();
        restricted.max_depth = 1;
        assert_eq!(
            decode_canonical(&[0x81, 0x80], restricted),
            Err(CborError::Depth)
        );

        restricted = limits();
        restricted.max_string_bytes = 1;
        assert_eq!(
            decode_canonical(&[0x42, 0, 0], restricted),
            Err(CborError::String)
        );
    }

    #[test]
    fn encoder_enforces_the_same_depth_item_container_string_and_byte_limits() {
        let nested = Value::Array(vec![Value::Array(vec![Value::Unsigned(0)])]);
        let mut restricted = limits();
        restricted.max_depth = 2;
        assert_eq!(
            encode_canonical_with_limits(&nested, restricted),
            Err(CborError::Depth)
        );

        restricted = limits();
        restricted.max_items = 2;
        assert_eq!(
            encode_canonical_with_limits(
                &Value::Array(vec![Value::Unsigned(0), Value::Unsigned(1)]),
                restricted,
            ),
            Err(CborError::Items)
        );

        restricted = limits();
        restricted.max_array_len = 1;
        assert_eq!(
            encode_canonical_with_limits(
                &Value::Array(vec![Value::Unsigned(0), Value::Unsigned(1)]),
                restricted,
            ),
            Err(CborError::Container)
        );

        restricted = limits();
        restricted.max_string_bytes = 1;
        assert_eq!(
            encode_canonical_with_limits(&Value::Bytes(vec![0, 1]), restricted),
            Err(CborError::String)
        );

        restricted = limits();
        restricted.max_bytes = 1;
        assert_eq!(
            encode_canonical_with_limits(&Value::Bytes(vec![0]), restricted),
            Err(CborError::TooLarge)
        );
    }

    #[test]
    fn negative_encoder_rejects_nonnegative_and_out_of_range_values() {
        assert_eq!(
            encode_canonical(&Value::Negative(0)),
            Err(CborError::NegativeRange)
        );
        assert_eq!(
            encode_canonical(&Value::Negative(-18_446_744_073_709_551_617_i128)),
            Err(CborError::NegativeRange)
        );
    }
}
