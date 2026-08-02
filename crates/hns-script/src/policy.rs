//! Runtime-independent HSD transaction fee-policy arithmetic.
//!
//! The formulas and constants in this module follow
//! `handshake-org/hsd@698e252ebc7b5c1dd0a9587e342fdd153d020ae4`:
//! `lib/primitives/tx.js#getSigopsSize` and
//! `lib/protocol/policy.js#getMinFee`. Policy virtual size is measured in
//! virtual bytes after sigop adjustment. [`FeeRate`] is measured in
//! dollarydoos per 1,000 policy virtual bytes.

use hns_primitives::Dollarydoos;
use hns_transaction::{Coin, Transaction, TransactionError};
use thiserror::Error;

use crate::{ScriptError, transaction_sigops};

/// HSD witness weight units per policy virtual byte.
pub const POLICY_WITNESS_SCALE_FACTOR: u32 = 4;

/// HSD weight units charged per signature operation for policy sizing.
pub const POLICY_BYTES_PER_SIGOP: u32 = 20;

/// Number of policy virtual bytes in HSD's fee-rate unit.
pub const POLICY_FEE_RATE_SCALE: u32 = 1_000;

/// HSD's default minimum relay rate in dollarydoos per 1,000 policy virtual
/// bytes.
pub const MIN_RELAY_FEE_RATE: FeeRate = FeeRate::new(1_000);

/// Maximum standard transaction weight admitted by the pinned HSD policy.
///
/// This bound is deliberately not enforced by [`sigop_adjusted_virtual_size`]:
/// HSD calculates size and applies standardness checks as separate operations.
pub const MAX_POLICY_TRANSACTION_WEIGHT: TransactionWeight =
    TransactionWeight::new(400_000);

/// Maximum standard transaction sigop cost admitted by the pinned HSD policy.
///
/// This bound is deliberately not enforced by [`sigop_adjusted_virtual_size`]
/// so callers can calculate evidence before reporting a policy rejection.
pub const MAX_POLICY_TRANSACTION_SIGOPS: SigopCost = SigopCost::new(16_000);

/// Serialized transaction weight, in HSD witness weight units.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransactionWeight(u32);

impl TransactionWeight {
    pub const fn new(weight_units: u32) -> Self {
        Self(weight_units)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for TransactionWeight {
    fn from(weight_units: u32) -> Self {
        Self::new(weight_units)
    }
}

/// HSD signature-operation cost used by transaction policy sizing.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SigopCost(u32);

impl SigopCost {
    pub const fn new(sigops: u32) -> Self {
        Self(sigops)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for SigopCost {
    fn from(sigops: u32) -> Self {
        Self::new(sigops)
    }
}

/// Sigop-adjusted transaction size in HSD policy virtual bytes.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PolicyVirtualSize(u32);

impl PolicyVirtualSize {
    pub const fn new(virtual_bytes: u32) -> Self {
        Self(virtual_bytes)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for PolicyVirtualSize {
    fn from(virtual_bytes: u32) -> Self {
        Self::new(virtual_bytes)
    }
}

/// Fee rate in dollarydoos per 1,000 HSD policy virtual bytes.
///
/// HSD runtime configuration restricts relay and wallet fee rates to unsigned
/// 32-bit values. Keeping that bound in the type makes the multiplication in
/// [`minimum_policy_fee`] exact in `u64`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FeeRate(u32);

impl FeeRate {
    pub const fn new(dollarydoos_per_thousand_virtual_bytes: u32) -> Self {
        Self(dollarydoos_per_thousand_virtual_bytes)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for FeeRate {
    fn from(dollarydoos_per_thousand_virtual_bytes: u32) -> Self {
        Self::new(dollarydoos_per_thousand_virtual_bytes)
    }
}

/// Calculate HSD's sigop-adjusted policy virtual size.
///
/// HSD takes the greater of serialized transaction weight and `sigops * 20`,
/// then divides by four with ceiling. This function does not decide whether
/// the weight or sigop cost is standard; the pinned implementation performs
/// those admission checks separately.
pub fn sigop_adjusted_virtual_size(
    transaction_weight: TransactionWeight,
    sigops: SigopCost,
) -> Result<PolicyVirtualSize, FeePolicyError> {
    let sigop_weight = u64::from(sigops.get())
        .checked_mul(u64::from(POLICY_BYTES_PER_SIGOP))
        .ok_or(FeePolicyError::ArithmeticOverflow)?;
    let adjusted_weight = u64::from(transaction_weight.get()).max(sigop_weight);
    let virtual_bytes = adjusted_weight
        .checked_add(u64::from(POLICY_WITNESS_SCALE_FACTOR - 1))
        .ok_or(FeePolicyError::ArithmeticOverflow)?
        / u64::from(POLICY_WITNESS_SCALE_FACTOR);
    let virtual_bytes = u32::try_from(virtual_bytes)
        .map_err(|_| FeePolicyError::VirtualSizeOutOfRange { virtual_bytes })?;
    Ok(PolicyVirtualSize::new(virtual_bytes))
}

/// Calculate the exact HSD policy virtual size for a transaction and its
/// resolved input coins.
///
/// Input coins are outpoint-bound by [`transaction_sigops`]. Coinbase
/// transactions have zero sigops, matching HSD. Transaction encoding bounds
/// are enforced by [`Transaction::weight`].
pub fn transaction_policy_virtual_size(
    transaction: &Transaction,
    input_coins: &[Coin],
) -> Result<PolicyVirtualSize, FeePolicyError> {
    let weight = transaction.weight()?;
    let weight =
        u32::try_from(weight).map_err(|_| FeePolicyError::TransactionWeightOutOfRange)?;
    let sigops = transaction_sigops(transaction, input_coins)?;
    sigop_adjusted_virtual_size(TransactionWeight::new(weight), SigopCost::new(sigops))
}

/// Calculate HSD's minimum policy fee for a virtual size and fee rate.
///
/// The multiplication is divided by 1,000 with floor rounding. HSD's unusual
/// low-value rule is preserved exactly: for nonzero size and rate, a zero
/// quotient returns the entire rate rather than one dollarydoo. Zero size or a
/// zero rate returns zero.
pub fn minimum_policy_fee(
    virtual_size: PolicyVirtualSize,
    rate: FeeRate,
) -> Result<Dollarydoos, FeePolicyError> {
    if virtual_size.get() == 0 {
        return Ok(Dollarydoos::new(0));
    }

    let fee = u64::from(rate.get())
        .checked_mul(u64::from(virtual_size.get()))
        .ok_or(FeePolicyError::ArithmeticOverflow)?
        / u64::from(POLICY_FEE_RATE_SCALE);
    if fee == 0 && rate.get() > 0 {
        return Ok(Dollarydoos::new(u64::from(rate.get())));
    }
    Ok(Dollarydoos::new(fee))
}

#[derive(Debug, Error)]
pub enum FeePolicyError {
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Script(#[from] ScriptError),
    #[error("transaction weight exceeds the public 32-bit weight unit")]
    TransactionWeightOutOfRange,
    #[error("sigop-adjusted virtual size {virtual_bytes} exceeds the public 32-bit unit")]
    VirtualSizeOutOfRange { virtual_bytes: u64 },
    #[error("fee-policy arithmetic overflow")]
    ArithmeticOverflow,
}

#[cfg(test)]
mod tests {
    use hns_covenants::Covenant;
    use hns_primitives::{Height, Outpoint, TransactionHash};
    use hns_transaction::{Address, Input, Output, Witness};
    use sha2::{Digest, Sha256};

    use super::*;

    const HSD_FEE_POLICY_VECTORS: &str =
        include_str!("../../../fixtures/hsd/fee-policy-v1.txt");
    const HSD_FEE_POLICY_VECTORS_SHA256: &str =
        include_str!("../../../fixtures/hsd/fee-policy-v1.txt.sha256");
    const PINNED_HSD_FEE_POLICY_VECTORS_SHA256: &str =
        "ec01d6f43456aa28c3b40549349e9c430473d3c074da4e3d7280ac3db817c0c5";

    #[test]
    fn exact_pinned_hsd_fee_policy_vectors() {
        let sidecar_hash = HSD_FEE_POLICY_VECTORS_SHA256
            .split_ascii_whitespace()
            .next()
            .expect("fixture digest");
        assert_eq!(sidecar_hash, PINNED_HSD_FEE_POLICY_VECTORS_SHA256);
        assert_eq!(
            hex::encode(Sha256::digest(HSD_FEE_POLICY_VECTORS)),
            sidecar_hash
        );

        for line in HSD_FEE_POLICY_VECTORS.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields = line
                .split('|')
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>()
                .expect("numeric HSD fee-policy vector");
            assert_eq!(fields.len(), 5, "five fields in vector: {line}");
            let weight = u32::try_from(fields[0]).expect("weight unit");
            let sigops = u32::try_from(fields[1]).expect("sigop unit");
            let expected_size = u32::try_from(fields[2]).expect("virtual-size unit");
            let rate = u32::try_from(fields[3]).expect("fee-rate unit");
            let expected_fee = fields[4];

            let virtual_size = sigop_adjusted_virtual_size(
                TransactionWeight::new(weight),
                SigopCost::new(sigops),
            )
            .expect("bounded HSD vector");
            assert_eq!(
                virtual_size,
                PolicyVirtualSize::new(expected_size),
                "{line}"
            );
            assert_eq!(
                minimum_policy_fee(virtual_size, FeeRate::new(rate))
                    .expect("bounded HSD fee")
                    .get(),
                expected_fee,
                "{line}",
            );
        }
    }

    #[test]
    fn policy_size_binds_resolved_coin_outpoints() {
        let outpoint = Outpoint {
            transaction_hash: TransactionHash::new([7; 32]),
            index: 3,
        };
        let address = Address::new(0, vec![9; 20]).expect("address");
        let transaction = Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: outpoint,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: Dollarydoos::new(1),
                address: address.clone(),
                covenant: Covenant::default(),
            }],
            locktime: 0,
        };
        let coin = Coin {
            outpoint,
            value: Dollarydoos::new(2),
            height: Height::new(1),
            coinbase: false,
            address,
            covenant: Covenant::default(),
        };

        let weight = u32::try_from(transaction.weight().expect("transaction weight"))
            .expect("bounded weight");
        assert_eq!(
            transaction_policy_virtual_size(&transaction, &[coin.clone()])
                .expect("bound policy size"),
            sigop_adjusted_virtual_size(TransactionWeight::new(weight), SigopCost::new(1))
                .expect("direct policy size"),
        );

        let mut wrong_coin = coin;
        wrong_coin.outpoint.index = 4;
        assert!(matches!(
            transaction_policy_virtual_size(&transaction, &[wrong_coin]),
            Err(FeePolicyError::Script(ScriptError::InputCoinMismatch))
        ));
    }

    #[test]
    fn out_of_range_sigop_size_fails_closed() {
        assert!(matches!(
            sigop_adjusted_virtual_size(
                TransactionWeight::new(0),
                SigopCost::new(u32::MAX),
            ),
            Err(FeePolicyError::VirtualSizeOutOfRange { .. })
        ));
    }

    #[test]
    fn pinned_policy_constants_retain_their_units() {
        assert_eq!(POLICY_WITNESS_SCALE_FACTOR, 4);
        assert_eq!(POLICY_BYTES_PER_SIGOP, 20);
        assert_eq!(POLICY_FEE_RATE_SCALE, 1_000);
        assert_eq!(MIN_RELAY_FEE_RATE.get(), 1_000);
        assert_eq!(MAX_POLICY_TRANSACTION_WEIGHT.get(), 400_000);
        assert_eq!(MAX_POLICY_TRANSACTION_SIGOPS.get(), 16_000);
    }
}
