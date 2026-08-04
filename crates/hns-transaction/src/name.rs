use hns_covenants::{
    Covenant, CovenantError, CovenantKind, FinalizeCovenant, MAX_RESOURCE_SIZE, NameState,
    TransferCovenant,
};
use hns_primitives::{BlockHash, Height, NameHash};
use thiserror::Error;

use crate::{Address, Coin, Input, Output, Transaction, TransactionError, Witness};

const NAME_TRANSACTION_VERSION: u32 = 0;
const NAME_TRANSACTION_LOCKTIME: u32 = 0;
const NAME_INPUT_SEQUENCE: u32 = u32::MAX;

/// Build the exact linked `TRANSFER` output for a currently owned name coin.
///
/// The locked value and current owner address are copied from `owner`; the
/// recipient is committed only inside the four-item covenant, as required by
/// HSD. The source must be an exact REGISTER, UPDATE, RENEW, or FINALIZE
/// covenant.
pub fn build_transfer_output(
    owner: &Coin,
    recipient: &Address,
) -> Result<Output, NameTransactionError> {
    validate_name_coin_source(owner, "TRANSFER")?;
    owner.address.validate()?;
    recipient.validate()?;
    let (name_hash, start_height) = transferable_owner_anchor(&owner.covenant)?;
    let transfer = TransferCovenant::new(
        name_hash,
        start_height,
        recipient.version,
        recipient.hash.clone(),
    )?;
    let output = Output {
        value: owner.value,
        address: owner.address.clone(),
        covenant: transfer.to_covenant()?,
    };
    output.encode()?;
    Ok(output)
}

/// Verify an exact linked `TRANSFER` output against its owner coin and
/// independently selected recipient.
pub fn verify_transfer_output(
    output: &Output,
    owner: &Coin,
    recipient: &Address,
) -> Result<(), NameTransactionError> {
    if output != &build_transfer_output(owner, recipient)? {
        return Err(NameTransactionError::InvalidTransfer(
            "linked output differs from the canonical owner-preserving TRANSFER",
        ));
    }
    TransferCovenant::try_from(&output.covenant)?;
    Ok(())
}

/// Build an unsigned HSD-style name `TRANSFER` transaction with this
/// transition at input/output index zero and caller-supplied suffixes.
///
/// The returned name witness is empty for the wallet signing layer.
/// `additional_inputs` and `additional_outputs` are appended without
/// covenant-link validation; they may contain funding or independent batched
/// name transitions. The caller remains responsible for validating and
/// signing the complete batch. The complete transaction is checked against
/// transaction allocation and weight bounds before return.
pub fn build_transfer_transaction(
    owner: &Coin,
    recipient: &Address,
    mut additional_inputs: Vec<Input>,
    additional_outputs: Vec<Output>,
) -> Result<Transaction, NameTransactionError> {
    reject_repeated_name_input(owner, &additional_inputs)?;
    let mut inputs = vec![Input {
        previous_output: owner.outpoint,
        sequence: NAME_INPUT_SEQUENCE,
        witness: Witness::default(),
    }];
    inputs.append(&mut additional_inputs);
    let mut outputs = vec![build_transfer_output(owner, recipient)?];
    outputs.extend(additional_outputs);
    let transaction = Transaction {
        version: NAME_TRANSACTION_VERSION,
        inputs,
        outputs,
        locktime: NAME_TRANSACTION_LOCKTIME,
    };
    transaction.size()?;
    Ok(transaction)
}

/// Verify the canonical header and `TRANSFER` transition at input/output index
/// zero.
///
/// Additional inputs are checked only to prevent reuse of `owner`; additional
/// outputs are not covenant-validated. Independent batched transitions,
/// resolved coins, signatures, balance, and fee policy must be verified by
/// their respective authorities.
pub fn verify_transfer_at_index_zero(
    transaction: &Transaction,
    owner: &Coin,
    recipient: &Address,
) -> Result<(), NameTransactionError> {
    verify_name_transaction_header(transaction, owner, "TRANSFER")?;
    let output = transaction
        .outputs
        .first()
        .ok_or(NameTransactionError::InvalidTransfer(
            "linked output at index zero is missing",
        ))?;
    verify_transfer_output(output, owner, recipient)?;
    Ok(())
}

/// Build the exact linked `FINALIZE` output for a confirmed TRANSFER coin and
/// authenticated current name state.
///
/// The output preserves the locked value, moves the owner address to the
/// recipient committed by TRANSFER, and carries the exact name, claim,
/// renewal, and renewal-block fields required by HSD. The caller must supply
/// chain-verified current state and an eligible renewal block after checking
/// the network's transfer lockup at the intended inclusion height.
pub fn build_finalize_output(
    transfer_coin: &Coin,
    state: &NameState,
    renewal_block: BlockHash,
) -> Result<Output, NameTransactionError> {
    validate_name_coin_source(transfer_coin, "FINALIZE")?;
    transfer_coin.address.validate()?;
    let transfer = TransferCovenant::try_from(&transfer_coin.covenant)?;
    validate_transfer_state(transfer_coin, state, &transfer)?;
    let recipient = Address::new(transfer.recipient_version, transfer.recipient_hash.clone())?;
    let finalize = FinalizeCovenant::from_name_state(state, renewal_block)?;
    let output = Output {
        value: transfer_coin.value,
        address: recipient,
        covenant: finalize.to_covenant()?,
    };
    output.encode()?;
    Ok(output)
}

/// Verify an exact linked `FINALIZE` output against its TRANSFER coin,
/// authenticated current state, and independently supplied renewal block.
/// This structural verifier does not replace chain-height maturity or renewal
/// block ancestry checks.
pub fn verify_finalize_output(
    output: &Output,
    transfer_coin: &Coin,
    state: &NameState,
    renewal_block: BlockHash,
) -> Result<(), NameTransactionError> {
    if output != &build_finalize_output(transfer_coin, state, renewal_block)? {
        return Err(NameTransactionError::InvalidFinalize(
            "linked output differs from the canonical value-preserving FINALIZE",
        ));
    }
    FinalizeCovenant::try_from(&output.covenant)?;
    Ok(())
}

/// Build an unsigned HSD-style name `FINALIZE` transaction with this
/// transition at input/output index zero and caller-supplied suffixes.
///
/// `additional_inputs` and `additional_outputs` are appended without
/// covenant-link validation; they may contain funding or independent batched
/// name transitions. The caller remains responsible for validating and
/// signing the complete batch. The complete transaction is checked against
/// transaction allocation and weight bounds before return.
pub fn build_finalize_transaction(
    transfer_coin: &Coin,
    state: &NameState,
    renewal_block: BlockHash,
    mut additional_inputs: Vec<Input>,
    additional_outputs: Vec<Output>,
) -> Result<Transaction, NameTransactionError> {
    reject_repeated_name_input(transfer_coin, &additional_inputs)?;
    let mut inputs = vec![Input {
        previous_output: transfer_coin.outpoint,
        sequence: NAME_INPUT_SEQUENCE,
        witness: Witness::default(),
    }];
    inputs.append(&mut additional_inputs);
    let mut outputs = vec![build_finalize_output(transfer_coin, state, renewal_block)?];
    outputs.extend(additional_outputs);
    let transaction = Transaction {
        version: NAME_TRANSACTION_VERSION,
        inputs,
        outputs,
        locktime: NAME_TRANSACTION_LOCKTIME,
    };
    transaction.size()?;
    Ok(transaction)
}

/// Verify the canonical header and `FINALIZE` transition at input/output index
/// zero.
///
/// Additional inputs are checked only to prevent reuse of `transfer_coin`;
/// additional outputs are not covenant-validated. Independent batched
/// transitions, resolved coins, signatures, balance, and fee policy must be
/// verified by their respective authorities.
pub fn verify_finalize_at_index_zero(
    transaction: &Transaction,
    transfer_coin: &Coin,
    state: &NameState,
    renewal_block: BlockHash,
) -> Result<(), NameTransactionError> {
    verify_name_transaction_header(transaction, transfer_coin, "FINALIZE")?;
    let output = transaction
        .outputs
        .first()
        .ok_or(NameTransactionError::InvalidFinalize(
            "linked output at index zero is missing",
        ))?;
    verify_finalize_output(output, transfer_coin, state, renewal_block)?;
    Ok(())
}

fn transferable_owner_anchor(
    covenant: &Covenant,
) -> Result<(NameHash, Height), NameTransactionError> {
    match covenant.kind {
        CovenantKind::Register => {
            require_exact_items(covenant, 4, "REGISTER")?;
            require_bounded_resource(covenant, 2, "REGISTER")?;
            require_hash(covenant, 3, "REGISTER renewal block")?;
        }
        CovenantKind::Update => {
            require_exact_items(covenant, 3, "UPDATE")?;
            require_bounded_resource(covenant, 2, "UPDATE")?;
        }
        CovenantKind::Renew => {
            require_exact_items(covenant, 3, "RENEW")?;
            require_hash(covenant, 2, "RENEW renewal block")?;
        }
        CovenantKind::Finalize => {
            let finalize = FinalizeCovenant::try_from(covenant)?;
            return Ok((finalize.name_hash, finalize.start_height));
        }
        kind => return Err(NameTransactionError::UnsupportedTransferSource { kind }),
    }
    Ok((
        NameHash::new(require_hash(covenant, 0, "name hash")?),
        Height::new(require_u32(covenant, 1, "start height")?),
    ))
}

fn validate_transfer_state(
    transfer_coin: &Coin,
    state: &NameState,
    transfer: &TransferCovenant,
) -> Result<(), NameTransactionError> {
    state.validate_key_binding()?;
    if state.is_null()
        || !state.registered
        || state.expired
        || state.revoked.get() != 0
        || state.transfer.get() == 0
    {
        return Err(NameTransactionError::InvalidFinalize(
            "name state is not an active registered transfer",
        ));
    }
    if state.owner_outpoint() != Some(transfer_coin.outpoint) {
        return Err(NameTransactionError::InvalidFinalize(
            "name-state owner does not identify the TRANSFER coin",
        ));
    }
    if state.value != transfer_coin.value {
        return Err(NameTransactionError::InvalidFinalize(
            "name-state locked value differs from the TRANSFER coin",
        ));
    }
    if state.transfer != transfer_coin.height {
        return Err(NameTransactionError::InvalidFinalize(
            "name-state transfer height differs from the TRANSFER coin height",
        ));
    }
    if state.name_hash != transfer.name_hash || state.height != transfer.start_height {
        return Err(NameTransactionError::InvalidFinalize(
            "name-state identity differs from the TRANSFER covenant",
        ));
    }
    Ok(())
}

fn verify_name_transaction_header(
    transaction: &Transaction,
    name_coin: &Coin,
    operation: &'static str,
) -> Result<(), NameTransactionError> {
    transaction.size()?;
    if transaction.version != NAME_TRANSACTION_VERSION
        || transaction.locktime != NAME_TRANSACTION_LOCKTIME
    {
        return Err(NameTransactionError::InvalidTransaction(
            "name transaction version or locktime differs from HSD construction",
        ));
    }
    let name_input = transaction
        .inputs
        .first()
        .ok_or(NameTransactionError::InvalidTransaction(
            "name input at index zero is missing",
        ))?;
    if name_input.previous_output != name_coin.outpoint
        || name_input.sequence != NAME_INPUT_SEQUENCE
    {
        return Err(NameTransactionError::InvalidTransaction(
            "name input is not the canonical index-zero outpoint",
        ));
    }
    if transaction.inputs[1..]
        .iter()
        .any(|input| input.previous_output == name_coin.outpoint)
    {
        return Err(NameTransactionError::RepeatedNameInput { operation });
    }
    Ok(())
}

fn reject_repeated_name_input(
    name_coin: &Coin,
    additional_inputs: &[Input],
) -> Result<(), NameTransactionError> {
    if additional_inputs
        .iter()
        .any(|input| input.previous_output == name_coin.outpoint)
    {
        return Err(NameTransactionError::RepeatedNameInput {
            operation: "name transition",
        });
    }
    Ok(())
}

fn validate_name_coin_source(
    coin: &Coin,
    operation: &'static str,
) -> Result<(), NameTransactionError> {
    if coin.outpoint.is_null() || coin.coinbase {
        return Err(NameTransactionError::InvalidSourceCoin { operation });
    }
    Ok(())
}

fn require_exact_items(
    covenant: &Covenant,
    expected: usize,
    kind: &'static str,
) -> Result<(), NameTransactionError> {
    if covenant.items.len() != expected {
        return Err(NameTransactionError::MalformedOwnerCovenant { kind });
    }
    Ok(())
}

fn require_bounded_resource(
    covenant: &Covenant,
    index: usize,
    kind: &'static str,
) -> Result<(), NameTransactionError> {
    if covenant
        .item(index)
        .is_none_or(|resource| resource.len() > MAX_RESOURCE_SIZE)
    {
        return Err(NameTransactionError::MalformedOwnerCovenant { kind });
    }
    Ok(())
}

fn require_hash(
    covenant: &Covenant,
    index: usize,
    field: &'static str,
) -> Result<[u8; 32], NameTransactionError> {
    covenant
        .item(index)
        .and_then(|item| item.try_into().ok())
        .ok_or(NameTransactionError::MalformedOwnerField { field })
}

fn require_u32(
    covenant: &Covenant,
    index: usize,
    field: &'static str,
) -> Result<u32, NameTransactionError> {
    covenant
        .item_u32(index)
        .ok_or(NameTransactionError::MalformedOwnerField { field })
}

#[derive(Debug, Error)]
pub enum NameTransactionError {
    #[error(transparent)]
    Covenant(#[from] CovenantError),
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error("{kind:?} cannot be the source of a TRANSFER")]
    UnsupportedTransferSource { kind: CovenantKind },
    #[error("malformed owner {kind} covenant")]
    MalformedOwnerCovenant { kind: &'static str },
    #[error("malformed owner covenant field: {field}")]
    MalformedOwnerField { field: &'static str },
    #[error("invalid canonical TRANSFER: {0}")]
    InvalidTransfer(&'static str),
    #[error("invalid canonical FINALIZE: {0}")]
    InvalidFinalize(&'static str),
    #[error("invalid canonical name transaction: {0}")]
    InvalidTransaction(&'static str),
    #[error("{operation} source is a null-outpoint or coinbase coin")]
    InvalidSourceCoin { operation: &'static str },
    #[error("{operation} repeats the name outpoint in its funding inputs")]
    RepeatedNameInput { operation: &'static str },
}

#[cfg(test)]
mod tests {
    use hns_covenants::hash_name;
    use hns_primitives::{Dollarydoos, Outpoint, TransactionHash};

    use super::*;

    fn owner_coin() -> Coin {
        let name = b"handshake";
        Coin {
            outpoint: Outpoint {
                transaction_hash: TransactionHash::new([1; 32]),
                index: 2,
            },
            value: Dollarydoos::new(3),
            height: Height::new(4),
            coinbase: false,
            address: Address::new(0, vec![5; 20]).expect("address"),
            covenant: FinalizeCovenant::new(
                name.to_vec(),
                Height::new(6),
                false,
                Height::new(0),
                1,
                BlockHash::new([7; 32]),
            )
            .expect("finalize")
            .to_covenant()
            .expect("covenant"),
        }
    }

    #[test]
    fn transfer_preserves_owner_value_and_address() {
        let owner = owner_coin();
        let recipient = Address::new(0, vec![8; 20]).expect("recipient");
        let transaction = build_transfer_transaction(&owner, &recipient, Vec::new(), Vec::new())
            .expect("transfer");
        assert_eq!(transaction.outputs[0].value, owner.value);
        assert_eq!(transaction.outputs[0].address, owner.address);
        verify_transfer_at_index_zero(&transaction, &owner, &recipient).expect("valid");
    }

    #[test]
    fn index_zero_transfer_accepts_an_independent_name_transition_suffix() {
        let owner = owner_coin();
        let recipient = Address::new(0, vec![8; 20]).expect("recipient");
        let mut additional_owner = owner_coin();
        additional_owner.outpoint = Outpoint {
            transaction_hash: TransactionHash::new([12; 32]),
            index: 3,
        };
        additional_owner.covenant = FinalizeCovenant::new(
            b"batched".to_vec(),
            Height::new(7),
            false,
            Height::new(0),
            1,
            BlockHash::new([13; 32]),
        )
        .expect("additional finalize")
        .to_covenant()
        .expect("additional covenant");
        let additional_recipient = Address::new(0, vec![14; 20]).expect("recipient");
        let additional_output = build_transfer_output(&additional_owner, &additional_recipient)
            .expect("additional transfer output");
        let transaction = build_transfer_transaction(
            &owner,
            &recipient,
            vec![Input {
                previous_output: additional_owner.outpoint,
                sequence: NAME_INPUT_SEQUENCE,
                witness: Witness::default(),
            }],
            vec![additional_output],
        )
        .expect("batched transfer");

        verify_transfer_at_index_zero(&transaction, &owner, &recipient)
            .expect("index-zero transfer");
        assert_eq!(
            crate::verify_covenant_links(&transaction, &[owner, additional_owner])
                .expect("valid covenant batch")
                .linked_outputs,
            2
        );
    }

    #[test]
    fn finalize_binds_current_state_and_transfer_recipient() {
        let owner = owner_coin();
        let recipient = Address::new(0, vec![8; 20]).expect("recipient");
        let transfer_output = build_transfer_output(&owner, &recipient).expect("transfer output");
        let transfer_coin = Coin {
            outpoint: Outpoint {
                transaction_hash: TransactionHash::new([9; 32]),
                index: 0,
            },
            value: transfer_output.value,
            height: Height::new(10),
            coinbase: false,
            address: transfer_output.address,
            covenant: transfer_output.covenant,
        };
        let name = b"handshake".to_vec();
        let mut state = NameState::null(hash_name(&name).expect("name hash"));
        state.name = name;
        state.height = Height::new(6);
        state.owner = transfer_coin.outpoint;
        state.value = transfer_coin.value;
        state.transfer = transfer_coin.height;
        state.registered = true;
        let renewal_block = BlockHash::new([11; 32]);
        let transaction = build_finalize_transaction(
            &transfer_coin,
            &state,
            renewal_block,
            Vec::new(),
            Vec::new(),
        )
        .expect("finalize");
        assert_eq!(transaction.outputs[0].value, transfer_coin.value);
        assert_eq!(transaction.outputs[0].address, recipient);
        verify_finalize_at_index_zero(&transaction, &transfer_coin, &state, renewal_block)
            .expect("valid");
    }

    #[test]
    fn name_transition_authority_mutations_fail_closed() {
        let owner = owner_coin();
        let recipient = Address::new(0, vec![8; 20]).expect("recipient");

        let mut null_owner = owner.clone();
        null_owner.outpoint = Outpoint::NULL;
        assert!(matches!(
            build_transfer_output(&null_owner, &recipient),
            Err(NameTransactionError::InvalidSourceCoin {
                operation: "TRANSFER"
            })
        ));
        let mut coinbase_owner = owner.clone();
        coinbase_owner.coinbase = true;
        assert!(build_transfer_output(&coinbase_owner, &recipient).is_err());
        assert!(matches!(
            build_transfer_transaction(
                &owner,
                &recipient,
                vec![Input {
                    previous_output: owner.outpoint,
                    sequence: NAME_INPUT_SEQUENCE,
                    witness: Witness::default(),
                }],
                Vec::new(),
            ),
            Err(NameTransactionError::RepeatedNameInput { .. })
        ));

        let transfer_output = build_transfer_output(&owner, &recipient).expect("transfer output");
        let transfer_coin = Coin {
            outpoint: Outpoint {
                transaction_hash: TransactionHash::new([9; 32]),
                index: 0,
            },
            value: transfer_output.value,
            height: Height::new(10),
            coinbase: false,
            address: transfer_output.address,
            covenant: transfer_output.covenant,
        };
        let name = b"handshake".to_vec();
        let mut state = NameState::null(hash_name(&name).expect("name hash"));
        state.name = name;
        state.height = Height::new(6);
        state.owner = transfer_coin.outpoint;
        state.value = transfer_coin.value;
        state.transfer = transfer_coin.height;
        state.registered = true;
        let renewal_block = BlockHash::new([11; 32]);

        let assert_state_rejected = |mutated: NameState| {
            assert!(build_finalize_output(&transfer_coin, &mutated, renewal_block).is_err());
        };
        let mut wrong_owner = state.clone();
        wrong_owner.owner.index += 1;
        assert_state_rejected(wrong_owner);
        let mut wrong_value = state.clone();
        wrong_value.value = Dollarydoos::new(state.value.get() + 1);
        assert_state_rejected(wrong_value);
        let mut wrong_transfer_height = state.clone();
        wrong_transfer_height.transfer = Height::new(state.transfer.get() + 1);
        assert_state_rejected(wrong_transfer_height);
        let mut unregistered = state.clone();
        unregistered.registered = false;
        assert_state_rejected(unregistered);
        let mut expired = state.clone();
        expired.expired = true;
        assert_state_rejected(expired);
        let mut revoked = state.clone();
        revoked.revoked = Height::new(1);
        assert_state_rejected(revoked);
        let mut wrong_identity = state.clone();
        wrong_identity.height = Height::new(state.height.get() + 1);
        assert_state_rejected(wrong_identity);

        let transaction = build_finalize_transaction(
            &transfer_coin,
            &state,
            renewal_block,
            Vec::new(),
            Vec::new(),
        )
        .expect("finalize");
        let mut wrong_version = transaction.clone();
        wrong_version.version += 1;
        assert!(
            verify_finalize_at_index_zero(&wrong_version, &transfer_coin, &state, renewal_block,)
                .is_err()
        );
        let mut wrong_sequence = transaction.clone();
        wrong_sequence.inputs[0].sequence -= 1;
        assert!(
            verify_finalize_at_index_zero(&wrong_sequence, &transfer_coin, &state, renewal_block,)
                .is_err()
        );
        let mut wrong_outpoint = transaction.clone();
        wrong_outpoint.inputs[0].previous_output.index += 1;
        assert!(
            verify_finalize_at_index_zero(&wrong_outpoint, &transfer_coin, &state, renewal_block,)
                .is_err()
        );
        let mut wrong_output = transaction;
        wrong_output.outputs[0].value = Dollarydoos::new(transfer_coin.value.get() + 1);
        assert!(
            verify_finalize_at_index_zero(&wrong_output, &transfer_coin, &state, renewal_block,)
                .is_err()
        );
    }
}
