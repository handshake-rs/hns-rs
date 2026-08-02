#![doc = "Strongly typed, allocation-free Handshake protocol values."]

use core::{cmp::Ordering, fmt};

use thiserror::Error;

macro_rules! semantic_bytes {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $size]);

        impl Default for $name {
            fn default() -> Self {
                Self([0; $size])
            }
        }

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
semantic_bytes!(ReservedRoot, 32);
semantic_bytes!(PowMask, 32);
semantic_bytes!(ShareHash, 32);
semantic_bytes!(PowHash, 32);
semantic_bytes!(ScriptHash, 32);
semantic_bytes!(OfferId, 32);
semantic_bytes!(PeerIdentity, 33);
semantic_bytes!(RegistryFingerprint, 32);

/// Canonical Handshake transaction output reference.
///
/// The all-zero transaction hash paired with `u32::MAX` is HSD's null
/// outpoint. Name-state ownership and transaction inputs intentionally share
/// this type so an authenticated owner cannot be detached from its output
/// index by an adapter-specific representation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Outpoint {
    /// Internal little-endian transaction hash bytes used by Handshake wire
    /// encodings and HSD's name tree.
    pub transaction_hash: TransactionHash,
    /// Zero-based output index, or `u32::MAX` only for the null sentinel.
    pub index: u32,
}

impl Outpoint {
    pub const NULL: Self = Self {
        transaction_hash: TransactionHash::new([0; 32]),
        index: u32::MAX,
    };

    /// Whether this is HSD's exact null-outpoint sentinel.
    pub fn is_null(self) -> bool {
        self.index == u32::MAX && self.transaction_hash.into_bytes() == [0; 32]
    }

    /// Encode the fixed-width transaction-input representation.
    ///
    /// NameState values use the same hash but compact-size encode the index;
    /// that distinct encoding is owned by `hns-covenants`.
    pub fn encode(self) -> [u8; 36] {
        let mut encoded = [0_u8; 36];
        encoded[..32].copy_from_slice(self.transaction_hash.as_bytes());
        encoded[32..].copy_from_slice(&self.index.to_le_bytes());
        encoded
    }
}

impl Default for Outpoint {
    fn default() -> Self {
        Self::NULL
    }
}

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
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Chainwork([u64; 4]);

impl Chainwork {
    pub const ZERO: Self = Self([0; 4]);

    pub const fn from_limbs_le(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    pub const fn limbs_le(self) -> [u64; 4] {
        self.0
    }

    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0_u64; 4];
        for (index, limb) in limbs.iter_mut().rev().enumerate() {
            let start = index * 8;
            *limb = u64::from_be_bytes(
                bytes[start..start + 8]
                    .try_into()
                    .expect("eight-byte chunk"),
            );
        }
        Self(limbs)
    }

    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for (index, limb) in self.0.iter().rev().enumerate() {
            let start = index * 8;
            bytes[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        bytes
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

    pub fn checked_sub(self, other: Self) -> Result<Self, ArithmeticError> {
        if self < other {
            return Err(ArithmeticError::Underflow);
        }
        let mut output = [0_u64; 4];
        let mut borrow = false;
        for (index, output_limb) in output.iter_mut().enumerate() {
            let (difference, first_borrow) = self.0[index].overflowing_sub(other.0[index]);
            let (difference, second_borrow) = difference.overflowing_sub(u64::from(borrow));
            *output_limb = difference;
            borrow = first_borrow || second_borrow;
        }
        debug_assert!(!borrow);
        Ok(Self(output))
    }

    pub fn checked_mul_u64(self, multiplier: u64) -> Result<Self, ArithmeticError> {
        let mut output = [0_u64; 4];
        let mut carry = 0_u128;
        for (index, output_limb) in output.iter_mut().enumerate() {
            let product = u128::from(self.0[index]) * u128::from(multiplier) + carry;
            *output_limb = product as u64;
            carry = product >> 64;
        }
        if carry == 0 {
            Ok(Self(output))
        } else {
            Err(ArithmeticError::Overflow)
        }
    }

    pub fn checked_div_u64(self, divisor: u64) -> Result<Self, ArithmeticError> {
        if divisor == 0 {
            return Err(ArithmeticError::Underflow);
        }
        let mut output = [0_u64; 4];
        let mut remainder = 0_u128;
        for index in (0..4).rev() {
            let dividend = (remainder << 64) | u128::from(self.0[index]);
            output[index] = (dividend / u128::from(divisor)) as u64;
            remainder = dividend % u128::from(divisor);
        }
        Ok(Self(output))
    }
}

impl Ord for Chainwork {
    fn cmp(&self, other: &Self) -> Ordering {
        for index in (0..4).rev() {
            match self.0[index].cmp(&other.0[index]) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Chainwork {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
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
    fn outpoint_null_and_fixed_transaction_encoding_are_exact() {
        assert_eq!(Outpoint::default(), Outpoint::NULL);
        assert!(Outpoint::NULL.is_null());
        let outpoint = Outpoint {
            transaction_hash: TransactionHash::new([0x42; 32]),
            index: 0x1020_3040,
        };
        assert!(!outpoint.is_null());
        assert_eq!(&outpoint.encode()[..32], &[0x42; 32]);
        assert_eq!(&outpoint.encode()[32..], &[0x40, 0x30, 0x20, 0x10]);
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
    fn chainwork_numeric_order_and_checked_operations_are_256_bit() {
        let lower = Chainwork::from_limbs_le([u64::MAX, 0, 0, 0]);
        let higher = Chainwork::from_limbs_le([0, 1, 0, 0]);
        assert!(higher > lower);
        assert_eq!(
            higher.checked_sub(lower).expect("fits").limbs_le(),
            [1, 0, 0, 0]
        );
        assert_eq!(
            Chainwork::from_limbs_le([u64::MAX, 0, 0, 0])
                .checked_mul_u64(2)
                .expect("fits")
                .limbs_le(),
            [u64::MAX - 1, 1, 0, 0]
        );
        assert_eq!(
            Chainwork::from_limbs_le([0, 1, 0, 0])
                .checked_div_u64(2)
                .expect("fits")
                .limbs_le(),
            [1_u64 << 63, 0, 0, 0]
        );
        let bytes = [0x5a; 32];
        assert_eq!(Chainwork::from_be_bytes(bytes).to_be_bytes(), bytes);
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
