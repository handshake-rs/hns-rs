#![doc = "Strongly typed, allocation-free Handshake protocol values."]

use core::fmt;

use thiserror::Error;

macro_rules! semantic_bytes {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $size]);

        impl $name {
            pub const LENGTH: usize = $size;

            pub const fn new(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }

            pub const fn into_bytes(self) -> [u8; $size] {
                self.0
            }

            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }

            pub fn from_hex(value: &str) -> Result<Self, HexValueError> {
                let mut bytes = [0_u8; $size];
                hex::decode_to_slice(value, &mut bytes).map_err(|_| HexValueError::InvalidHex {
                    expected_bytes: $size,
                })?;
                Ok(Self(bytes))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&hex::encode(self.0))
            }
        }

        impl From<[u8; $size]> for $name {
            fn from(bytes: [u8; $size]) -> Self {
                Self(bytes)
            }
        }
    };
}

macro_rules! semantic_integer {
    ($name:ident, $inner:ty) => {
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name($inner);

        impl $name {
            pub const fn new(value: $inner) -> Self {
                Self(value)
            }

            pub const fn get(self) -> $inner {
                self.0
            }
        }

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HexValueError {
    #[error("invalid hexadecimal value; expected exactly {expected_bytes} bytes")]
    InvalidHex { expected_bytes: usize },
}

semantic_bytes!(BlockHash, 32);
semantic_bytes!(TransactionHash, 32);
semantic_bytes!(NameHash, 32);
semantic_bytes!(TreeRoot, 32);
semantic_bytes!(MerkleRoot, 32);
semantic_bytes!(WitnessRoot, 32);
semantic_bytes!(ScriptHash, 32);
semantic_bytes!(OfferId, 32);
semantic_bytes!(PeerIdentity, 33);
semantic_bytes!(RegistryFingerprint, 32);

semantic_integer!(Height, u32);
semantic_integer!(BlockTime, u64);
semantic_integer!(Dollarydoos, u64);
semantic_integer!(CompactTarget, u32);
semantic_integer!(RequestId, u64);
semantic_integer!(EventSequence, u64);
semantic_integer!(PolicyGeneration, u64);

impl RequestId {
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ArithmeticError {
    #[error("numeric overflow")]
    Overflow,
    #[error("numeric underflow")]
    Underflow,
}

impl Dollarydoos {
    pub fn checked_add(self, other: Self) -> Result<Self, ArithmeticError> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(ArithmeticError::Overflow)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, ArithmeticError> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(ArithmeticError::Underflow)
    }
}

/// Unsigned 256-bit chainwork in little-endian 64-bit limbs.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Chainwork([u64; 4]);

impl Chainwork {
    pub const ZERO: Self = Self([0; 4]);

    pub const fn from_limbs_le(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    pub const fn limbs_le(self) -> [u64; 4] {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Result<Self, ArithmeticError> {
        let mut output = [0_u64; 4];
        let mut carry = false;
        for (index, output_limb) in output.iter_mut().enumerate() {
            let (sum, first_carry) = self.0[index].overflowing_add(other.0[index]);
            let (sum, second_carry) = sum.overflowing_add(u64::from(carry));
            *output_limb = sum;
            carry = first_carry || second_carry;
        }
        if carry {
            Err(ArithmeticError::Overflow)
        } else {
            Ok(Self(output))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_hashes_do_not_interchange() {
        let block = BlockHash::new([7; 32]);
        let transaction = TransactionHash::new([7; 32]);
        assert_eq!(block.as_bytes(), transaction.as_bytes());
        assert_eq!(block.to_string().len(), 64);
    }

    #[test]
    fn chainwork_addition_carries_and_detects_overflow() {
        let left = Chainwork::from_limbs_le([u64::MAX, 1, 0, 0]);
        let right = Chainwork::from_limbs_le([1, 2, 0, 0]);
        assert_eq!(
            left.checked_add(right).expect("fits").limbs_le(),
            [0, 4, 0, 0]
        );
        assert_eq!(
            Chainwork::from_limbs_le([u64::MAX; 4]).checked_add(right),
            Err(ArithmeticError::Overflow)
        );
    }

    #[test]
    fn amounts_never_use_floating_point() {
        assert_eq!(
            Dollarydoos::new(2)
                .checked_add(Dollarydoos::new(3))
                .expect("fits")
                .get(),
            5
        );
        assert_eq!(
            Dollarydoos::new(0).checked_sub(Dollarydoos::new(1)),
            Err(ArithmeticError::Underflow)
        );
    }
}
