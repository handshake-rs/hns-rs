use hns_covenants::{Covenant, CovenantKind, blind_bid};
use thiserror::Error;

use crate::{Address, Coin, Outpoint, Output, Transaction};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CovenantLinkSummary {
    pub inputs_checked: usize,
    pub linked_outputs: usize,
    pub name_inputs: usize,
}

pub fn verify_covenant_links(
    transaction: &Transaction,
    input_coins: &[Coin],
) -> Result<CovenantLinkSummary, CovenantLinkError> {
    if transaction.is_coinbase() {
        return Err(CovenantLinkError::CoinbaseRequiresIssuanceVerifier);
    }
    if transaction.inputs.len() != input_coins.len() {
        return Err(CovenantLinkError::InputCountMismatch {
            transaction: transaction.inputs.len(),
            coins: input_coins.len(),
        });
    }
    let mut summary = CovenantLinkSummary {
        inputs_checked: input_coins.len(),
        ..CovenantLinkSummary::default()
    };
    for (input_index, (input, coin)) in transaction.inputs.iter().zip(input_coins).enumerate() {
        if input.previous_output != coin.outpoint {
            return Err(CovenantLinkError::CoinOutpointMismatch {
                input_index,
                expected: input.previous_output,
                actual: coin.outpoint,
            });
        }
        let output = transaction.outputs.get(input_index);
        let spent = &coin.covenant;
        let spent_kind = spent.kind;
        if spent_kind.is_name() {
            summary.name_inputs += 1;
        }
        match spent_kind {
            CovenantKind::None | CovenantKind::Open | CovenantKind::Redeem => {
                let Some(output) = output else {
                    continue;
                };
                if !matches!(
                    output.covenant.kind,
                    CovenantKind::None | CovenantKind::Open | CovenantKind::Bid
                ) {
                    return Err(CovenantLinkError::InvalidTransition {
                        input_index,
                        from: spent_kind,
                        to: output.covenant.kind,
                    });
                }
            }
            CovenantKind::Bid => {
                let output = require_linked_output(input_index, spent_kind, output)?;
                require_transition(input_index, spent_kind, output, CovenantKind::Reveal)?;
                require_name_and_start_match(input_index, spent, &output.covenant)?;
                let nonce = required_hash(input_index, &output.covenant, 2, "reveal nonce")?;
                let commitment = required_hash(input_index, spent, 3, "bid commitment")?;
                if blind_bid(output.value.get(), &nonce) != commitment {
                    return Err(CovenantLinkError::BlindCommitmentMismatch { input_index });
                }
                if coin.value < output.value {
                    return Err(CovenantLinkError::BidValueInflation { input_index });
                }
                summary.linked_outputs += 1;
            }
            CovenantKind::Claim | CovenantKind::Reveal => {
                let output = require_linked_output(input_index, spent_kind, output)?;
                match output.covenant.kind {
                    CovenantKind::Register => {
                        require_name_and_start_match(input_index, spent, &output.covenant)?;
                        require_address_match(input_index, &coin.address, output)?;
                    }
                    CovenantKind::Redeem => {
                        require_name_and_start_match(input_index, spent, &output.covenant)?;
                        if spent_kind == CovenantKind::Claim {
                            return Err(CovenantLinkError::ClaimCannotRedeem { input_index });
                        }
                    }
                    to => {
                        return Err(CovenantLinkError::InvalidTransition {
                            input_index,
                            from: spent_kind,
                            to,
                        });
                    }
                }
                summary.linked_outputs += 1;
            }
            CovenantKind::Register
            | CovenantKind::Update
            | CovenantKind::Renew
            | CovenantKind::Finalize => {
                let output = require_linked_output(input_index, spent_kind, output)?;
                require_locked_value(input_index, coin, output)?;
                require_address_match(input_index, &coin.address, output)?;
                if !matches!(
                    output.covenant.kind,
                    CovenantKind::Update
                        | CovenantKind::Renew
                        | CovenantKind::Transfer
                        | CovenantKind::Revoke
                ) {
                    return Err(CovenantLinkError::InvalidTransition {
                        input_index,
                        from: spent_kind,
                        to: output.covenant.kind,
                    });
                }
                require_name_and_start_match(input_index, spent, &output.covenant)?;
                summary.linked_outputs += 1;
            }
            CovenantKind::Transfer => {
                let output = require_linked_output(input_index, spent_kind, output)?;
                require_locked_value(input_index, coin, output)?;
                match output.covenant.kind {
                    CovenantKind::Update | CovenantKind::Renew | CovenantKind::Revoke => {
                        require_name_and_start_match(input_index, spent, &output.covenant)?;
                        require_address_match(input_index, &coin.address, output)?;
                    }
                    CovenantKind::Finalize => {
                        require_name_and_start_match(input_index, spent, &output.covenant)?;
                        let version = required_u8(input_index, spent, 2, "transfer version")?;
                        let hash = required_item(input_index, spent, 3, "transfer hash")?;
                        if output.address.version != version
                            || output.address.hash.as_slice() != hash
                        {
                            return Err(CovenantLinkError::TransferDestinationMismatch {
                                input_index,
                            });
                        }
                    }
                    to => {
                        return Err(CovenantLinkError::InvalidTransition {
                            input_index,
                            from: spent_kind,
                            to,
                        });
                    }
                }
                summary.linked_outputs += 1;
            }
            CovenantKind::Revoke => {
                return Err(CovenantLinkError::RevokedCoinSpent { input_index });
            }
            CovenantKind::Unknown(_) => {
                if let Some(output) = output
                    && output.covenant.kind.is_name()
                {
                    return Err(CovenantLinkError::UnknownCovenantCreatesName {
                        input_index,
                        to: output.covenant.kind,
                    });
                }
            }
        }
    }
    Ok(summary)
}

fn require_linked_output(
    input_index: usize,
    from: CovenantKind,
    output: Option<&Output>,
) -> Result<&Output, CovenantLinkError> {
    output.ok_or(CovenantLinkError::MissingLinkedOutput { input_index, from })
}

fn require_transition(
    input_index: usize,
    from: CovenantKind,
    output: &Output,
    expected: CovenantKind,
) -> Result<(), CovenantLinkError> {
    if output.covenant.kind != expected {
        return Err(CovenantLinkError::InvalidTransition {
            input_index,
            from,
            to: output.covenant.kind,
        });
    }
    Ok(())
}

fn require_name_and_start_match(
    input_index: usize,
    spent: &Covenant,
    created: &Covenant,
) -> Result<(), CovenantLinkError> {
    if required_hash(input_index, spent, 0, "spent name")?
        != required_hash(input_index, created, 0, "created name")?
    {
        return Err(CovenantLinkError::NameHashMismatch { input_index });
    }
    if required_u32(input_index, spent, 1, "spent start")?
        != required_u32(input_index, created, 1, "created start")?
    {
        return Err(CovenantLinkError::StartHeightMismatch { input_index });
    }
    Ok(())
}

fn require_locked_value(
    input_index: usize,
    coin: &Coin,
    output: &Output,
) -> Result<(), CovenantLinkError> {
    if output.value != coin.value {
        return Err(CovenantLinkError::LockedValueMismatch { input_index });
    }
    Ok(())
}

fn require_address_match(
    input_index: usize,
    expected: &Address,
    output: &Output,
) -> Result<(), CovenantLinkError> {
    if &output.address != expected {
        return Err(CovenantLinkError::AddressMismatch { input_index });
    }
    Ok(())
}

fn required_item<'a>(
    input_index: usize,
    covenant: &'a Covenant,
    item_index: usize,
    field: &'static str,
) -> Result<&'a [u8], CovenantLinkError> {
    covenant
        .item(item_index)
        .ok_or(CovenantLinkError::MalformedCovenant { input_index, field })
}

fn required_u8(
    input_index: usize,
    covenant: &Covenant,
    item_index: usize,
    field: &'static str,
) -> Result<u8, CovenantLinkError> {
    covenant
        .item_u8(item_index)
        .ok_or(CovenantLinkError::MalformedCovenant { input_index, field })
}

fn required_u32(
    input_index: usize,
    covenant: &Covenant,
    item_index: usize,
    field: &'static str,
) -> Result<u32, CovenantLinkError> {
    covenant
        .item_u32(item_index)
        .ok_or(CovenantLinkError::MalformedCovenant { input_index, field })
}

fn required_hash(
    input_index: usize,
    covenant: &Covenant,
    item_index: usize,
    field: &'static str,
) -> Result<[u8; 32], CovenantLinkError> {
    required_item(input_index, covenant, item_index, field)?
        .try_into()
        .map_err(|_| CovenantLinkError::MalformedCovenant { input_index, field })
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CovenantLinkError {
    #[error("coinbase covenant issuance requires its dedicated verifier")]
    CoinbaseRequiresIssuanceVerifier,
    #[error("transaction input count does not match resolved coins")]
    InputCountMismatch { transaction: usize, coins: usize },
    #[error("input {input_index} outpoint does not match resolved coin")]
    CoinOutpointMismatch {
        input_index: usize,
        expected: Outpoint,
        actual: Outpoint,
    },
    #[error("input {input_index} covenant {from:?} requires a linked output")]
    MissingLinkedOutput {
        input_index: usize,
        from: CovenantKind,
    },
    #[error("input {input_index} covenant transition {from:?} -> {to:?} is invalid")]
    InvalidTransition {
        input_index: usize,
        from: CovenantKind,
        to: CovenantKind,
    },
    #[error("input {input_index} mis-encodes {field}")]
    MalformedCovenant {
        input_index: usize,
        field: &'static str,
    },
    #[error("input {input_index} name hash differs from linked output")]
    NameHashMismatch { input_index: usize },
    #[error("input {input_index} start height differs from linked output")]
    StartHeightMismatch { input_index: usize },
    #[error("input {input_index} reveal does not match blind commitment")]
    BlindCommitmentMismatch { input_index: usize },
    #[error("input {input_index} reveal value exceeds locked bid value")]
    BidValueInflation { input_index: usize },
    #[error("input {input_index} claim cannot redeem")]
    ClaimCannotRedeem { input_index: usize },
    #[error("input {input_index} output address differs from locked address")]
    AddressMismatch { input_index: usize },
    #[error("input {input_index} output value differs from locked value")]
    LockedValueMismatch { input_index: usize },
    #[error("input {input_index} finalize destination differs from transfer")]
    TransferDestinationMismatch { input_index: usize },
    #[error("input {input_index} attempts to spend a revoked name")]
    RevokedCoinSpent { input_index: usize },
    #[error("input {input_index} unknown covenant creates name covenant {to:?}")]
    UnknownCovenantCreatesName {
        input_index: usize,
        to: CovenantKind,
    },
}

#[cfg(test)]
mod tests {
    use hns_primitives::{Dollarydoos, Height, TransactionHash};

    use super::*;
    use crate::{Input, Witness};

    #[test]
    fn bid_reveal_commitment_and_revoke_rules_match_hsd() {
        let outpoint = Outpoint {
            transaction_hash: TransactionHash::new([1; 32]),
            index: 0,
        };
        let nonce = [3; 32];
        let spent = Covenant {
            kind: CovenantKind::Bid,
            items: vec![
                vec![2; 32],
                9_u32.to_le_bytes().to_vec(),
                b"name".to_vec(),
                blind_bid(100, &nonce).to_vec(),
            ],
        };
        let revealed = Covenant {
            kind: CovenantKind::Reveal,
            items: vec![vec![2; 32], 9_u32.to_le_bytes().to_vec(), nonce.to_vec()],
        };
        let address = Address::new(0, vec![4; 20]).expect("address");
        let coin = Coin {
            outpoint,
            value: Dollarydoos::new(100),
            height: Height::new(1),
            coinbase: false,
            address: address.clone(),
            covenant: spent,
        };
        let transaction = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: outpoint,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: Dollarydoos::new(100),
                address,
                covenant: revealed,
            }],
            locktime: 0,
        };
        assert_eq!(
            verify_covenant_links(&transaction, &[coin])
                .expect("valid")
                .linked_outputs,
            1
        );
    }
}
