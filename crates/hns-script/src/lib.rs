#![doc = "Consensus-visible Handshake script and signature-hash primitives."]

mod interpreter;

pub use interpreter::*;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_encoding::Encoder;
use hns_transaction::{Outpoint, Transaction};

pub const SIGHASH_ALL: u32 = 1;
pub const SIGHASH_NONE: u32 = 2;
pub const SIGHASH_SINGLE: u32 = 3;
pub const SIGHASH_SINGLE_REVERSE: u32 = 4;
pub const SIGHASH_NOINPUT: u32 = 0x40;
pub const SIGHASH_ANYONE_CAN_PAY: u32 = 0x80;
pub const SIGHASH_BASE_MASK: u32 = 0x1f;
pub const HIP1_SELLER_SIGHASH: u32 = SIGHASH_SINGLE_REVERSE | SIGHASH_ANYONE_CAN_PAY;

pub const LOCKTIME_FLAG: u32 = 1 << 31;
pub const LOCKTIME_MASK: u32 = LOCKTIME_FLAG - 1;
pub const LOCKTIME_GRANULARITY: u32 = 9;
pub const LOCKTIME_MULTIPLIER: u32 = 1 << LOCKTIME_GRANULARITY;
pub const SEQUENCE_DISABLE_FLAG: u32 = 1 << 31;
pub const SEQUENCE_TYPE_FLAG: u32 = 1 << 22;
pub const SEQUENCE_GRANULARITY: u32 = 9;
pub const SEQUENCE_MASK: u32 = 0x0000_ffff;

pub const fn is_valid_signature_hash_type(hash_type: u8) -> bool {
    let normalized = (hash_type as u32) & !(SIGHASH_NOINPUT | SIGHASH_ANYONE_CAN_PAY);
    normalized >= SIGHASH_ALL && normalized <= SIGHASH_SINGLE_REVERSE
}

pub fn signature_hash(
    transaction: &Transaction,
    input_index: usize,
    previous_script: &[u8],
    previous_value: u64,
    hash_type: u32,
) -> Result<[u8; 32], ScriptError> {
    let input = transaction
        .inputs
        .get(input_index)
        .ok_or(ScriptError::InputIndex {
            requested: input_index,
            inputs: transaction.inputs.len(),
        })?;
    let base = hash_type & SIGHASH_BASE_MASK;
    if !(SIGHASH_ALL..=SIGHASH_SINGLE_REVERSE).contains(&base) {
        return Err(ScriptError::InvalidSignatureHashType(hash_type));
    }
    let anyone_can_pay = hash_type & SIGHASH_ANYONE_CAN_PAY != 0;
    let no_input = hash_type & SIGHASH_NOINPUT != 0;
    let zero_hash = [0_u8; 32];

    let hash_prevouts = if anyone_can_pay {
        zero_hash
    } else {
        let mut bytes = Vec::with_capacity(transaction.inputs.len().saturating_mul(36));
        for transaction_input in &transaction.inputs {
            bytes.extend_from_slice(&transaction_input.previous_output.encode());
        }
        blake2b_256(&bytes)
    };

    let hash_sequences = if anyone_can_pay
        || matches!(base, SIGHASH_NONE | SIGHASH_SINGLE | SIGHASH_SINGLE_REVERSE)
    {
        zero_hash
    } else {
        let mut encoder = Encoder::with_capacity(transaction.inputs.len().saturating_mul(4));
        for transaction_input in &transaction.inputs {
            encoder.put_u32_le(transaction_input.sequence);
        }
        blake2b_256(&encoder.into_bytes())
    };

    let hash_outputs = match base {
        SIGHASH_NONE => zero_hash,
        SIGHASH_SINGLE => transaction
            .outputs
            .get(input_index)
            .map(|output| output.encode().map(|bytes| blake2b_256(&bytes)))
            .transpose()?
            .unwrap_or(zero_hash),
        SIGHASH_SINGLE_REVERSE => {
            if input_index < transaction.outputs.len() {
                let output_index = transaction.outputs.len() - 1 - input_index;
                blake2b_256(&transaction.outputs[output_index].encode()?)
            } else {
                zero_hash
            }
        }
        SIGHASH_ALL => {
            let mut bytes = Vec::new();
            for output in &transaction.outputs {
                bytes.extend_from_slice(&output.encode()?);
            }
            blake2b_256(&bytes)
        }
        _ => unreachable!("signature hash base was checked"),
    };

    let (current_outpoint, current_sequence) = if no_input {
        (Outpoint::NULL, u32::MAX)
    } else {
        (input.previous_output, input.sequence)
    };

    let mut encoder = Encoder::with_capacity(156_usize.saturating_add(previous_script.len()));
    encoder.put_u32_le(transaction.version);
    encoder.put_bytes(&hash_prevouts);
    encoder.put_bytes(&hash_sequences);
    encoder.put_bytes(&current_outpoint.encode());
    encoder.put_varbytes(previous_script);
    encoder.put_u64_le(previous_value);
    encoder.put_u32_le(current_sequence);
    encoder.put_bytes(&hash_outputs);
    encoder.put_u32_le(transaction.locktime);
    encoder.put_u32_le(hash_type);
    Ok(blake2b_256(&encoder.into_bytes()))
}

pub fn verify_locktime_predicate(
    transaction: &Transaction,
    input_index: usize,
    predicate: u32,
) -> bool {
    let Some(input) = transaction.inputs.get(input_index) else {
        return false;
    };
    (transaction.locktime & LOCKTIME_FLAG) == (predicate & LOCKTIME_FLAG)
        && (predicate & LOCKTIME_MASK) <= (transaction.locktime & LOCKTIME_MASK)
        && input.sequence != u32::MAX
}

pub fn verify_sequence_predicate(
    transaction: &Transaction,
    input_index: usize,
    predicate: u32,
) -> bool {
    let Some(input) = transaction.inputs.get(input_index) else {
        return false;
    };
    if predicate & SEQUENCE_DISABLE_FLAG != 0 {
        return true;
    }
    if input.sequence & SEQUENCE_DISABLE_FLAG != 0 {
        return false;
    }
    (input.sequence & SEQUENCE_TYPE_FLAG) == (predicate & SEQUENCE_TYPE_FLAG)
        && (predicate & SEQUENCE_MASK) <= (input.sequence & SEQUENCE_MASK)
}

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    hasher.update(input);
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "020000000211111111111111111111111111111111111111111111111111111111111111110300000078563412222222222222222222222222222222222222222222222222222222222222222205000000214365870307b20100000000000014aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000e640300000000000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000015160500000000000014cccccccccccccccccccccccccccccccccccccccc0000907856340000";

    #[test]
    fn signature_hashes_match_pinned_hsd_oracle() {
        let transaction =
            Transaction::decode(&hex::decode(RAW).expect("hex")).expect("transaction");
        let script = hex::decode("5253935587").expect("hex");
        let vectors = [
            (
                0,
                1,
                "cb4a35c13f76461bb3643ce11b1fc67b2b714abf0c7f6e1e2e7047068f35b48c",
            ),
            (
                0,
                2,
                "e8b7106ef2f0df452b12364631d378e2d0e8d038788c1b3d26a101303544293e",
            ),
            (
                0,
                3,
                "2badccb2547452294fce40200dde2e0b815f533736b0501d92241ec3877f953a",
            ),
            (
                0,
                4,
                "36635027506339b57147797c1c21896f67885701c6d60852aa5e7d6a11957b9d",
            ),
            (
                0,
                65,
                "3308248a050d86b124892b19b7ebf11a45d0c8f7068859de6e23e42758fa0ab4",
            ),
            (
                0,
                68,
                "f10465c8399650d0be57443cdbf120361abd3ad23ccee6d53fc527d96a457e82",
            ),
            (
                0,
                129,
                "e701f42f9acdbae7701c7e9385920c3703464ef1a0a470614f4d4050363d82dd",
            ),
            (
                0,
                132,
                "ad3258f7941426d7fdb0156d8aa54e9d5be1c5e92835acfac26b8ad64d0be412",
            ),
            (
                0,
                193,
                "ab225099577a95638bce984856b66fd120841ca973e8ac28326c30fefeaecbf7",
            ),
            (
                0,
                196,
                "bdd91d3743dee83ac581820261735071babf6931fb411e1789287053c69bb65b",
            ),
            (
                1,
                1,
                "4a4117ac47acdd10d82f0f05fb6899d015b5aa42cef22d224ce826ed8e33b3a2",
            ),
            (
                1,
                2,
                "08c99aa330db462ac2157149e5f04be29c6d62119ba61249caaa1c4d23554701",
            ),
            (
                1,
                3,
                "664feef71a0d2e5c9c8fe86ca390cd273cfe122e89457461f5832817eac0e912",
            ),
            (
                1,
                4,
                "bf35522c50c16e473574695a6ddc1ecaf85ce382478faacf746e8ae504a75294",
            ),
            (
                1,
                65,
                "3308248a050d86b124892b19b7ebf11a45d0c8f7068859de6e23e42758fa0ab4",
            ),
            (
                1,
                68,
                "2b2b3d03745b2c8d2865585f21ec5952fbaca033366407c45c18467fd6779c7f",
            ),
            (
                1,
                129,
                "8015e96e71335685c73f7ab7f435adc1d52d68fb85bc1ca12fd65c8f7c614799",
            ),
            (
                1,
                132,
                "a515e6e7fcfb29dac6d22da2916c11f0b078414820e63333357419589bbdca3a",
            ),
            (
                1,
                193,
                "ab225099577a95638bce984856b66fd120841ca973e8ac28326c30fefeaecbf7",
            ),
            (
                1,
                196,
                "e26f14476b55a26a0999e4f1b196fc718aa37b56d7db3ea70007617c59f23018",
            ),
        ];
        for (input_index, hash_type, expected) in vectors {
            assert_eq!(
                hex::encode(
                    signature_hash(&transaction, input_index, &script, 987_654_321, hash_type,)
                        .expect("sighash"),
                ),
                expected,
                "input {input_index} type {hash_type:#x}",
            );
        }
    }

    #[test]
    fn hash_type_and_lock_predicates_match_hsd_boundaries() {
        for base in 1_u8..=4 {
            assert!(is_valid_signature_hash_type(base));
            assert!(is_valid_signature_hash_type(base | SIGHASH_NOINPUT as u8));
            assert!(is_valid_signature_hash_type(
                base | SIGHASH_ANYONE_CAN_PAY as u8
            ));
        }
        assert!(!is_valid_signature_hash_type(0));
        assert!(!is_valid_signature_hash_type(5));

        let mut transaction =
            Transaction::decode(&hex::decode(RAW).expect("hex")).expect("transaction");
        transaction.locktime = 10;
        transaction.inputs[0].sequence = 7;
        assert!(verify_locktime_predicate(&transaction, 0, 9));
        assert!(!verify_locktime_predicate(&transaction, 0, 11));
        assert!(verify_sequence_predicate(&transaction, 0, 6));
        assert!(!verify_sequence_predicate(&transaction, 0, 8));
    }
}
