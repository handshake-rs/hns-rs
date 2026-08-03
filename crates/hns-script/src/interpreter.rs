use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_transaction::{Address, Coin, Transaction, Witness};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use sha3::{Keccak256, Sha3_256};
use thiserror::Error;

use crate::{
    is_valid_signature_hash_type, signature_hash, verify_locktime_predicate,
    verify_sequence_predicate,
};

/// Maximum serialized script size accepted by HSD consensus.
pub const MAX_SCRIPT_SIZE: usize = 10_000;
/// Maximum size of an individual pushed stack item.
pub const MAX_SCRIPT_PUSH: usize = 520;
/// Maximum number of non-push operations in a script.
pub const MAX_SCRIPT_OPS: usize = 201;
/// Maximum combined main- and alternate-stack item count.
pub const MAX_SCRIPT_STACK: usize = 1_000;
/// Maximum number of public keys consumed by `OP_CHECKMULTISIG`.
pub const MAX_MULTISIG_PUBKEYS: usize = 20;

pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_PUSHDATA4: u8 = 0x4e;
pub const OP_1NEGATE: u8 = 0x4f;
pub const OP_RESERVED: u8 = 0x50;
pub const OP_1: u8 = 0x51;
pub const OP_2: u8 = 0x52;
pub const OP_3: u8 = 0x53;
pub const OP_4: u8 = 0x54;
pub const OP_5: u8 = 0x55;
pub const OP_6: u8 = 0x56;
pub const OP_7: u8 = 0x57;
pub const OP_8: u8 = 0x58;
pub const OP_9: u8 = 0x59;
pub const OP_10: u8 = 0x5a;
pub const OP_11: u8 = 0x5b;
pub const OP_12: u8 = 0x5c;
pub const OP_13: u8 = 0x5d;
pub const OP_14: u8 = 0x5e;
pub const OP_15: u8 = 0x5f;
pub const OP_16: u8 = 0x60;
pub const OP_NOP: u8 = 0x61;
pub const OP_VER: u8 = 0x62;
pub const OP_IF: u8 = 0x63;
pub const OP_NOTIF: u8 = 0x64;
pub const OP_VERIF: u8 = 0x65;
pub const OP_VERNOTIF: u8 = 0x66;
pub const OP_ELSE: u8 = 0x67;
pub const OP_ENDIF: u8 = 0x68;
pub const OP_VERIFY: u8 = 0x69;
pub const OP_RETURN: u8 = 0x6a;
pub const OP_TOALTSTACK: u8 = 0x6b;
pub const OP_FROMALTSTACK: u8 = 0x6c;
pub const OP_2DROP: u8 = 0x6d;
pub const OP_2DUP: u8 = 0x6e;
pub const OP_3DUP: u8 = 0x6f;
pub const OP_2OVER: u8 = 0x70;
pub const OP_2ROT: u8 = 0x71;
pub const OP_2SWAP: u8 = 0x72;
pub const OP_IFDUP: u8 = 0x73;
pub const OP_DEPTH: u8 = 0x74;
pub const OP_DROP: u8 = 0x75;
pub const OP_DUP: u8 = 0x76;
pub const OP_NIP: u8 = 0x77;
pub const OP_OVER: u8 = 0x78;
pub const OP_PICK: u8 = 0x79;
pub const OP_ROLL: u8 = 0x7a;
pub const OP_ROT: u8 = 0x7b;
pub const OP_SWAP: u8 = 0x7c;
pub const OP_TUCK: u8 = 0x7d;
pub const OP_CAT: u8 = 0x7e;
pub const OP_SUBSTR: u8 = 0x7f;
pub const OP_LEFT: u8 = 0x80;
pub const OP_RIGHT: u8 = 0x81;
pub const OP_SIZE: u8 = 0x82;
pub const OP_INVERT: u8 = 0x83;
pub const OP_AND: u8 = 0x84;
pub const OP_OR: u8 = 0x85;
pub const OP_XOR: u8 = 0x86;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_RESERVED1: u8 = 0x89;
pub const OP_RESERVED2: u8 = 0x8a;
pub const OP_1ADD: u8 = 0x8b;
pub const OP_1SUB: u8 = 0x8c;
pub const OP_2MUL: u8 = 0x8d;
pub const OP_2DIV: u8 = 0x8e;
pub const OP_NEGATE: u8 = 0x8f;
pub const OP_ABS: u8 = 0x90;
pub const OP_NOT: u8 = 0x91;
pub const OP_0NOTEQUAL: u8 = 0x92;
pub const OP_ADD: u8 = 0x93;
pub const OP_SUB: u8 = 0x94;
pub const OP_MUL: u8 = 0x95;
pub const OP_DIV: u8 = 0x96;
pub const OP_MOD: u8 = 0x97;
pub const OP_LSHIFT: u8 = 0x98;
pub const OP_RSHIFT: u8 = 0x99;
pub const OP_BOOLAND: u8 = 0x9a;
pub const OP_BOOLOR: u8 = 0x9b;
pub const OP_NUMEQUAL: u8 = 0x9c;
pub const OP_NUMEQUALVERIFY: u8 = 0x9d;
pub const OP_NUMNOTEQUAL: u8 = 0x9e;
pub const OP_LESSTHAN: u8 = 0x9f;
pub const OP_GREATERTHAN: u8 = 0xa0;
pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
pub const OP_MIN: u8 = 0xa3;
pub const OP_MAX: u8 = 0xa4;
pub const OP_WITHIN: u8 = 0xa5;
pub const OP_RIPEMD160: u8 = 0xa6;
pub const OP_SHA1: u8 = 0xa7;
pub const OP_SHA256: u8 = 0xa8;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_HASH256: u8 = 0xaa;
pub const OP_CODESEPARATOR: u8 = 0xab;
pub const OP_CHECKSIG: u8 = 0xac;
pub const OP_CHECKSIGVERIFY: u8 = 0xad;
pub const OP_CHECKMULTISIG: u8 = 0xae;
pub const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
pub const OP_NOP1: u8 = 0xb0;
pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
pub const OP_NOP4: u8 = 0xb3;
pub const OP_NOP5: u8 = 0xb4;
pub const OP_NOP6: u8 = 0xb5;
pub const OP_NOP7: u8 = 0xb6;
pub const OP_NOP8: u8 = 0xb7;
pub const OP_NOP9: u8 = 0xb8;
pub const OP_NOP10: u8 = 0xb9;
pub const OP_BLAKE160: u8 = 0xc0;
pub const OP_BLAKE256: u8 = 0xc1;
pub const OP_SHA3: u8 = 0xc2;
pub const OP_KECCAK: u8 = 0xc3;
pub const OP_TYPE: u8 = 0xd0;
pub const OP_INVALIDOPCODE: u8 = 0xff;

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ScriptFlags(u32);

impl ScriptFlags {
    pub const NONE: Self = Self(0);
    pub const VERIFY_MINIMAL_DATA: Self = Self(1 << 1);
    pub const VERIFY_DISCOURAGE_UPGRADABLE_NOPS: Self = Self(1 << 2);
    pub const VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: Self = Self(1 << 3);
    pub const VERIFY_MINIMAL_IF: Self = Self(1 << 4);
    pub const VERIFY_NULLFAIL: Self = Self(1 << 5);
    pub const MANDATORY: Self =
        Self(Self::VERIFY_MINIMAL_DATA.0 | Self::VERIFY_MINIMAL_IF.0 | Self::VERIFY_NULLFAIL.0);
    pub const STANDARD: Self = Self(
        Self::MANDATORY.0
            | Self::VERIFY_DISCOURAGE_UPGRADABLE_NOPS.0
            | Self::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.0,
    );

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// One bounded, decoded script instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Instruction {
    pub opcode: u8,
    pub data: Option<Vec<u8>>,
    pub start: usize,
    pub end: usize,
}

/// Parse a serialized script using HSD's pushdata encoding and consensus size
/// bound. Push-size policy is enforced by execution so callers can inspect a
/// syntactically valid script containing an oversized push.
pub fn parse_script(script: &[u8]) -> Result<Vec<Instruction>, ScriptError> {
    if script.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }

    let mut instructions = Vec::new();
    let mut offset = 0usize;
    while offset < script.len() {
        let start = offset;
        let opcode = script[offset];
        offset += 1;
        let data_len = match opcode {
            0x01..=0x4b => Some(usize::from(opcode)),
            OP_PUSHDATA1 => Some(usize::from(read_u8(script, &mut offset)?)),
            OP_PUSHDATA2 => Some(usize::from(read_u16(script, &mut offset)?)),
            OP_PUSHDATA4 => Some(
                usize::try_from(read_u32(script, &mut offset)?)
                    .map_err(|_| ScriptError::BadOpcode(opcode))?,
            ),
            _ => None,
        };
        let data = if let Some(data_len) = data_len {
            let end = offset
                .checked_add(data_len)
                .filter(|end| *end <= script.len())
                .ok_or(ScriptError::BadOpcode(opcode))?;
            let data = script[offset..end].to_vec();
            offset = end;
            Some(data)
        } else {
            None
        };
        instructions.push(Instruction {
            opcode,
            data,
            start,
            end: offset,
        });
    }
    Ok(instructions)
}

/// Count HSD witness sigops without executing the script. A malformed trailing
/// push terminates scanning after the valid prefix, matching HSD.
pub fn count_script_sigops(script: &[u8]) -> u32 {
    let mut total = 0u32;
    let mut offset = 0usize;
    let mut last_opcode = None;

    while offset < script.len() {
        let opcode = script[offset];
        offset += 1;
        let data_length = match opcode {
            0x01..=0x4b => Some(usize::from(opcode)),
            OP_PUSHDATA1 => {
                let Some(length) = script.get(offset).copied() else {
                    break;
                };
                offset += 1;
                Some(usize::from(length))
            }
            OP_PUSHDATA2 => {
                let Some(bytes) = script.get(offset..offset.saturating_add(2)) else {
                    break;
                };
                let Ok(bytes) = <[u8; 2]>::try_from(bytes) else {
                    break;
                };
                offset += 2;
                Some(usize::from(u16::from_le_bytes(bytes)))
            }
            OP_PUSHDATA4 => {
                let Some(bytes) = script.get(offset..offset.saturating_add(4)) else {
                    break;
                };
                let Ok(bytes) = <[u8; 4]>::try_from(bytes) else {
                    break;
                };
                offset += 4;
                let Ok(length) = usize::try_from(u32::from_le_bytes(bytes)) else {
                    break;
                };
                Some(length)
            }
            _ => None,
        };
        if let Some(data_length) = data_length {
            let Some(end) = offset.checked_add(data_length) else {
                break;
            };
            if end > script.len() {
                break;
            }
            offset = end;
        }

        match opcode {
            OP_CHECKSIG | OP_CHECKSIGVERIFY => total = total.saturating_add(1),
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                let sigops = match last_opcode {
                    Some(opcode @ OP_1..=OP_16) => u32::from(opcode - 0x50),
                    _ => MAX_MULTISIG_PUBKEYS as u32,
                };
                total = total.saturating_add(sigops);
            }
            _ => {}
        }
        last_opcode = Some(opcode);
    }
    total
}

pub fn witness_program_sigops(address: &Address, witness: &Witness) -> u32 {
    if address.version != 0 {
        return 0;
    }
    match address.hash.len() {
        20 => 1,
        32 => witness
            .items
            .last()
            .map_or(0, |script| count_script_sigops(script)),
        _ => 0,
    }
}

pub fn transaction_sigops(
    transaction: &Transaction,
    input_coins: &[Coin],
) -> Result<u32, ScriptError> {
    if transaction.is_coinbase() {
        return Ok(0);
    }
    if transaction.inputs.len() != input_coins.len() {
        return Err(ScriptError::InputCoinCount {
            inputs: transaction.inputs.len(),
            coins: input_coins.len(),
        });
    }

    transaction
        .inputs
        .iter()
        .zip(input_coins)
        .try_fold(0u32, |total, (input, coin)| {
            if input.previous_output != coin.outpoint {
                return Err(ScriptError::InputCoinMismatch);
            }
            Ok(total.saturating_add(witness_program_sigops(&coin.address, &input.witness)))
        })
}

/// Pluggable compact-secp256k1 verifier used by the runtime-independent
/// interpreter. Implementations must enforce HSD's low-S encoding rule.
pub trait SignatureVerifier: Send + Sync {
    fn validate_compact_signature(&self, signature: &[u8; 64]) -> Result<(), ScriptError>;

    fn verify(
        &self,
        message: &[u8; 32],
        signature: &[u8; 64],
        public_key: &[u8; 33],
    ) -> Result<bool, ScriptError>;

    fn is_consensus_complete(&self) -> bool {
        false
    }
}

/// Fail-closed verifier for builds which intentionally supply no secp256k1
/// backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableSignatureVerifier;

impl SignatureVerifier for UnavailableSignatureVerifier {
    fn validate_compact_signature(&self, _signature: &[u8; 64]) -> Result<(), ScriptError> {
        Err(ScriptError::SignatureBackendUnavailable)
    }

    fn verify(
        &self,
        _message: &[u8; 32],
        _signature: &[u8; 64],
        _public_key: &[u8; 33],
    ) -> Result<bool, ScriptError> {
        Err(ScriptError::SignatureBackendUnavailable)
    }
}

/// Pure Rust secp256k1 verifier backed by `k256`.
#[derive(Clone, Copy, Debug, Default)]
pub struct K256SignatureVerifier;

impl SignatureVerifier for K256SignatureVerifier {
    fn validate_compact_signature(&self, signature: &[u8; 64]) -> Result<(), ScriptError> {
        let signature =
            Signature::from_slice(signature).map_err(|_| ScriptError::SignatureEncoding)?;
        if signature.normalize_s().is_some() {
            return Err(ScriptError::SignatureEncoding);
        }
        Ok(())
    }

    fn verify(
        &self,
        message: &[u8; 32],
        signature: &[u8; 64],
        public_key: &[u8; 33],
    ) -> Result<bool, ScriptError> {
        let signature =
            Signature::from_slice(signature).map_err(|_| ScriptError::SignatureEncoding)?;
        let public_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|_| ScriptError::PublicKeyEncoding)?;
        Ok(public_key.verify_prehash(message, &signature).is_ok())
    }

    fn is_consensus_complete(&self) -> bool {
        true
    }
}

pub fn verify_witness_program(
    transaction: &Transaction,
    input_index: usize,
    coin: &Coin,
    flags: ScriptFlags,
    signatures: &dyn SignatureVerifier,
) -> Result<(), ScriptError> {
    let input = transaction
        .inputs
        .get(input_index)
        .ok_or(ScriptError::InputIndex {
            requested: input_index,
            inputs: transaction.inputs.len(),
        })?;
    if input.previous_output != coin.outpoint {
        return Err(ScriptError::InputCoinMismatch);
    }
    let address = &coin.address;

    if address.version == 31 {
        return Err(ScriptError::OpReturn);
    }
    if input.witness.items.len() > MAX_SCRIPT_STACK {
        return Err(ScriptError::StackSize);
    }

    let mut stack = input.witness.items.clone();
    let redeem = if address.version == 0 {
        match address.hash.len() {
            32 => {
                let witness_script = stack.pop().ok_or(ScriptError::WitnessProgramWitnessEmpty)?;
                if witness_script.len() > MAX_SCRIPT_SIZE {
                    return Err(ScriptError::ScriptSize);
                }
                if sha3_256(&witness_script).as_slice() != address.hash.as_slice() {
                    return Err(ScriptError::WitnessProgramMismatch);
                }
                witness_script
            }
            20 => {
                if stack.len() != 2 {
                    return Err(ScriptError::WitnessProgramMismatch);
                }
                pubkey_hash_script(&address.hash)
            }
            _ => return Err(ScriptError::WitnessProgramWrongLength),
        }
    } else {
        if flags.contains(ScriptFlags::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
            return Err(ScriptError::DiscourageUpgradableWitnessProgram);
        }
        return Ok(());
    };

    execute_script(
        &redeem,
        &mut stack,
        transaction,
        input_index,
        coin.value.get(),
        flags,
        signatures,
    )?;

    if stack.len() != 1 || !cast_to_bool(&stack[0]) {
        return Err(ScriptError::EvalFalse);
    }
    Ok(())
}

fn pubkey_hash_script(hash: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[OP_DUP, OP_BLAKE160, 20]);
    script.extend_from_slice(hash);
    script.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
    script
}

/// Execute one script against an existing stack. The caller retains the final
/// stack, making this useful below witness-program policy while remaining
/// bounded and independent of any async runtime or storage.
#[allow(clippy::too_many_lines)]
pub fn execute_script(
    script: &[u8],
    stack: &mut Vec<Vec<u8>>,
    transaction: &Transaction,
    input_index: usize,
    previous_value: u64,
    flags: ScriptFlags,
    signatures: &dyn SignatureVerifier,
) -> Result<(), ScriptError> {
    if transaction.inputs.get(input_index).is_none() {
        return Err(ScriptError::InputIndex {
            requested: input_index,
            inputs: transaction.inputs.len(),
        });
    }
    if stack.len() > MAX_SCRIPT_STACK {
        return Err(ScriptError::StackSize);
    }
    if stack.iter().any(|item| item.len() > MAX_SCRIPT_PUSH) {
        return Err(ScriptError::PushSize);
    }

    let instructions = parse_script(script)?;
    let mut alt_stack = Vec::<Vec<u8>>::new();
    let mut conditions = Vec::<bool>::new();
    let mut operation_count = 0usize;
    let mut last_separator = 0usize;

    for instruction in instructions {
        if instruction
            .data
            .as_ref()
            .is_some_and(|data| data.len() > MAX_SCRIPT_PUSH)
        {
            return Err(ScriptError::PushSize);
        }
        if instruction.opcode > OP_16 {
            operation_count = operation_count
                .checked_add(1)
                .ok_or(ScriptError::OperationCount)?;
            if operation_count > MAX_SCRIPT_OPS {
                return Err(ScriptError::OperationCount);
            }
        }
        if is_disabled_opcode(instruction.opcode) {
            return Err(ScriptError::DisabledOpcode(instruction.opcode));
        }

        let executing = conditions.iter().all(|condition| *condition);
        let is_branch = (OP_IF..=OP_ENDIF).contains(&instruction.opcode);
        if !executing && !is_branch {
            enforce_stack_limit(stack, &alt_stack)?;
            continue;
        }

        if let Some(data) = instruction.data {
            if flags.contains(ScriptFlags::VERIFY_MINIMAL_DATA)
                && !is_minimal_push(instruction.opcode, &data)
            {
                return Err(ScriptError::MinimalData);
            }
            stack.push(data);
            enforce_stack_limit(stack, &alt_stack)?;
            continue;
        }

        match instruction.opcode {
            OP_0 => stack.push(Vec::new()),
            OP_1NEGATE => stack.push(encode_script_number(-1)),
            OP_1..=OP_16 => {
                stack.push(encode_script_number(i64::from(
                    instruction.opcode - OP_1 + 1,
                )));
            }
            OP_NOP => {}
            OP_TYPE => {
                let covenant_type = transaction
                    .outputs
                    .get(input_index)
                    .map(|output| i64::from(output.covenant.kind.as_u8()))
                    .unwrap_or(0);
                stack.push(encode_script_number(covenant_type));
            }
            OP_CHECKLOCKTIMEVERIFY => {
                let value = decode_top_number(stack, flags, 5)?;
                if value < 0 {
                    return Err(ScriptError::NegativeLocktime);
                }
                let predicate =
                    u32::try_from(value).map_err(|_| ScriptError::UnsatisfiedLocktime)?;
                if !verify_locktime_predicate(transaction, input_index, predicate) {
                    return Err(ScriptError::UnsatisfiedLocktime);
                }
            }
            OP_CHECKSEQUENCEVERIFY => {
                let value = decode_top_number(stack, flags, 5)?;
                if value < 0 {
                    return Err(ScriptError::NegativeLocktime);
                }
                let predicate =
                    u32::try_from(value).map_err(|_| ScriptError::UnsatisfiedLocktime)?;
                if !verify_sequence_predicate(transaction, input_index, predicate) {
                    return Err(ScriptError::UnsatisfiedLocktime);
                }
            }
            opcode if opcode == OP_NOP1 || (OP_NOP4..=OP_NOP10).contains(&opcode) => {
                if flags.contains(ScriptFlags::VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                    return Err(ScriptError::DiscourageUpgradableNops);
                }
            }
            OP_IF | OP_NOTIF => {
                let parent_executing = conditions.iter().all(|condition| *condition);
                let mut value = false;
                if parent_executing {
                    let item = stack.pop().ok_or(ScriptError::UnbalancedConditional)?;
                    if flags.contains(ScriptFlags::VERIFY_MINIMAL_IF)
                        && !(item.is_empty() || item.as_slice() == [1u8])
                    {
                        return Err(ScriptError::MinimalIf);
                    }
                    value = cast_to_bool(&item);
                    if instruction.opcode == OP_NOTIF {
                        value = !value;
                    }
                }
                conditions.push(value);
            }
            OP_ELSE => {
                let Some(condition) = conditions.last_mut() else {
                    return Err(ScriptError::UnbalancedConditional);
                };
                *condition = !*condition;
            }
            OP_ENDIF => {
                conditions.pop().ok_or(ScriptError::UnbalancedConditional)?;
            }
            OP_VERIFY => {
                if !cast_to_bool(&pop(stack)?) {
                    return Err(ScriptError::Verify);
                }
            }
            OP_RETURN => return Err(ScriptError::OpReturn),
            OP_TOALTSTACK => alt_stack.push(pop(stack)?),
            OP_FROMALTSTACK => {
                let item = alt_stack
                    .pop()
                    .ok_or(ScriptError::InvalidAltStackOperation)?;
                stack.push(item);
            }
            OP_2DROP => {
                require_stack(stack, 2)?;
                stack.truncate(stack.len() - 2);
            }
            OP_2DUP => duplicate_tail(stack, 2)?,
            OP_3DUP => duplicate_tail(stack, 3)?,
            OP_2OVER => {
                require_stack(stack, 4)?;
                let len = stack.len();
                let values = stack[len - 4..len - 2].to_vec();
                stack.extend(values);
            }
            OP_2ROT => {
                require_stack(stack, 6)?;
                let len = stack.len();
                let first = stack.remove(len - 6);
                let second = stack.remove(len - 6);
                stack.push(first);
                stack.push(second);
            }
            OP_2SWAP => {
                require_stack(stack, 4)?;
                let len = stack.len();
                stack.swap(len - 4, len - 2);
                stack.swap(len - 3, len - 1);
            }
            OP_IFDUP => {
                let value = stack.last().ok_or(ScriptError::InvalidStackOperation)?;
                if cast_to_bool(value) {
                    stack.push(value.clone());
                }
            }
            OP_DEPTH => stack.push(encode_script_number(stack.len() as i64)),
            OP_DROP => {
                pop(stack)?;
            }
            OP_DUP => duplicate_tail(stack, 1)?,
            OP_NIP => {
                require_stack(stack, 2)?;
                let len = stack.len();
                stack.remove(len - 2);
            }
            OP_OVER => {
                require_stack(stack, 2)?;
                let len = stack.len();
                stack.push(stack[len - 2].clone());
            }
            OP_PICK | OP_ROLL => {
                let depth = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let depth =
                    usize::try_from(depth).map_err(|_| ScriptError::InvalidStackOperation)?;
                if depth >= stack.len() {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let index = stack.len() - 1 - depth;
                let item = if instruction.opcode == OP_ROLL {
                    stack.remove(index)
                } else {
                    stack[index].clone()
                };
                stack.push(item);
            }
            OP_ROT => {
                require_stack(stack, 3)?;
                let len = stack.len();
                let item = stack.remove(len - 3);
                stack.push(item);
            }
            OP_SWAP => {
                require_stack(stack, 2)?;
                let len = stack.len();
                stack.swap(len - 2, len - 1);
            }
            OP_TUCK => {
                require_stack(stack, 2)?;
                let len = stack.len();
                let item = stack[len - 1].clone();
                stack.insert(len - 2, item);
            }
            OP_SIZE => {
                let size = stack
                    .last()
                    .ok_or(ScriptError::InvalidStackOperation)?
                    .len();
                stack.push(encode_script_number(size as i64));
            }
            OP_EQUAL | OP_EQUALVERIFY => {
                require_stack(stack, 2)?;
                let right = pop(stack)?;
                let left = pop(stack)?;
                let equal = left == right;
                if instruction.opcode == OP_EQUALVERIFY {
                    if !equal {
                        return Err(ScriptError::EqualVerify);
                    }
                } else {
                    push_bool(stack, equal);
                }
            }
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                let value = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let result = match instruction.opcode {
                    OP_1ADD => value.checked_add(1),
                    OP_1SUB => value.checked_sub(1),
                    OP_NEGATE => value.checked_neg(),
                    OP_ABS => value.checked_abs(),
                    OP_NOT => Some(i64::from(value == 0)),
                    OP_0NOTEQUAL => Some(i64::from(value != 0)),
                    _ => None,
                }
                .ok_or(ScriptError::NumericOverflow)?;
                stack.push(encode_script_number(result));
            }
            OP_ADD
            | OP_SUB
            | OP_BOOLAND
            | OP_BOOLOR
            | OP_NUMEQUAL
            | OP_NUMEQUALVERIFY
            | OP_NUMNOTEQUAL
            | OP_LESSTHAN
            | OP_GREATERTHAN
            | OP_LESSTHANOREQUAL
            | OP_GREATERTHANOREQUAL
            | OP_MIN
            | OP_MAX => {
                require_stack(stack, 2)?;
                let right = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let left = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let result = match instruction.opcode {
                    OP_ADD => left
                        .checked_add(right)
                        .ok_or(ScriptError::NumericOverflow)?,
                    OP_SUB => left
                        .checked_sub(right)
                        .ok_or(ScriptError::NumericOverflow)?,
                    OP_BOOLAND => i64::from(left != 0 && right != 0),
                    OP_BOOLOR => i64::from(left != 0 || right != 0),
                    OP_NUMEQUAL | OP_NUMEQUALVERIFY => i64::from(left == right),
                    OP_NUMNOTEQUAL => i64::from(left != right),
                    OP_LESSTHAN => i64::from(left < right),
                    OP_GREATERTHAN => i64::from(left > right),
                    OP_LESSTHANOREQUAL => i64::from(left <= right),
                    OP_GREATERTHANOREQUAL => i64::from(left >= right),
                    OP_MIN => left.min(right),
                    OP_MAX => left.max(right),
                    _ => unreachable!(),
                };
                if instruction.opcode == OP_NUMEQUALVERIFY {
                    if result == 0 {
                        return Err(ScriptError::NumEqualVerify);
                    }
                } else {
                    stack.push(encode_script_number(result));
                }
            }
            OP_WITHIN => {
                require_stack(stack, 3)?;
                let maximum = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let minimum = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let value = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                push_bool(stack, minimum <= value && value < maximum);
            }
            OP_BLAKE160 | OP_BLAKE256 | OP_SHA3 | OP_KECCAK => {
                let item = pop(stack)?;
                let digest = match instruction.opcode {
                    OP_BLAKE160 => blake2b_160(&item).to_vec(),
                    OP_BLAKE256 => blake2b_256(&item).to_vec(),
                    OP_SHA3 => sha3_256(&item).to_vec(),
                    OP_KECCAK => Keccak256::digest(&item).to_vec(),
                    _ => unreachable!(),
                };
                stack.push(digest);
            }
            OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => {
                let item = pop(stack)?;
                let digest = match instruction.opcode {
                    OP_RIPEMD160 => Ripemd160::digest(&item).to_vec(),
                    OP_SHA1 => Sha1::digest(&item).to_vec(),
                    OP_SHA256 => Sha256::digest(&item).to_vec(),
                    OP_HASH160 => Ripemd160::digest(Sha256::digest(&item)).to_vec(),
                    OP_HASH256 => Sha256::digest(Sha256::digest(&item)).to_vec(),
                    _ => unreachable!(),
                };
                stack.push(digest);
            }
            OP_CODESEPARATOR => last_separator = instruction.end,
            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                require_stack(stack, 2)?;
                let public_key = pop(stack)?;
                let signature = pop(stack)?;
                let valid = check_signature(
                    transaction,
                    input_index,
                    previous_value,
                    &script[last_separator..],
                    &signature,
                    &public_key,
                    signatures,
                )?;
                if !valid && flags.contains(ScriptFlags::VERIFY_NULLFAIL) && !signature.is_empty() {
                    return Err(ScriptError::NullFail);
                }
                if instruction.opcode == OP_CHECKSIGVERIFY {
                    if !valid {
                        return Err(ScriptError::CheckSigVerify);
                    }
                } else {
                    push_bool(stack, valid);
                }
            }
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                let valid = check_multisig(
                    stack,
                    transaction,
                    input_index,
                    previous_value,
                    &script[last_separator..],
                    flags,
                    signatures,
                    &mut operation_count,
                )?;
                if instruction.opcode == OP_CHECKMULTISIGVERIFY {
                    if !valid {
                        return Err(ScriptError::CheckMultiSigVerify);
                    }
                } else {
                    push_bool(stack, valid);
                }
            }
            OP_RESERVED | OP_VER | OP_VERIF | OP_VERNOTIF | OP_RESERVED1 | OP_RESERVED2
            | OP_INVALIDOPCODE => return Err(ScriptError::BadOpcode(instruction.opcode)),
            opcode => return Err(ScriptError::BadOpcode(opcode)),
        }

        enforce_stack_limit(stack, &alt_stack)?;
    }

    if !conditions.is_empty() {
        return Err(ScriptError::UnbalancedConditional);
    }
    Ok(())
}

fn check_signature(
    transaction: &Transaction,
    input_index: usize,
    previous_value: u64,
    subscript: &[u8],
    signature: &[u8],
    public_key: &[u8],
    signatures: &dyn SignatureVerifier,
) -> Result<bool, ScriptError> {
    let compact = if signature.is_empty() {
        None
    } else {
        if signature.len() != 65 || !is_valid_signature_hash_type(signature[64]) {
            return Err(ScriptError::SignatureEncoding);
        }
        let compact: &[u8; 64] = signature[..64]
            .try_into()
            .map_err(|_| ScriptError::SignatureEncoding)?;
        signatures.validate_compact_signature(compact)?;
        Some(compact)
    };
    let public_key: &[u8; 33] = public_key
        .try_into()
        .map_err(|_| ScriptError::PublicKeyEncoding)?;
    if !matches!(public_key[0], 0x02 | 0x03) {
        return Err(ScriptError::PublicKeyEncoding);
    }
    let Some(compact) = compact else {
        return Ok(false);
    };
    let message = signature_hash(
        transaction,
        input_index,
        subscript,
        previous_value,
        u32::from(signature[64]),
    )?;
    signatures.verify(&message, compact, public_key)
}

#[allow(clippy::too_many_arguments)]
fn check_multisig(
    stack: &mut Vec<Vec<u8>>,
    transaction: &Transaction,
    input_index: usize,
    previous_value: u64,
    subscript: &[u8],
    flags: ScriptFlags,
    signatures: &dyn SignatureVerifier,
    operation_count: &mut usize,
) -> Result<bool, ScriptError> {
    let key_count = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
    let key_count = usize::try_from(key_count).map_err(|_| ScriptError::PublicKeyCount)?;
    if key_count > MAX_MULTISIG_PUBKEYS {
        return Err(ScriptError::PublicKeyCount);
    }
    *operation_count = (*operation_count)
        .checked_add(key_count)
        .ok_or(ScriptError::OperationCount)?;
    if *operation_count > MAX_SCRIPT_OPS {
        return Err(ScriptError::OperationCount);
    }
    require_stack(stack, key_count.saturating_add(1))?;
    let keys_start = stack.len() - key_count;
    let keys = stack.split_off(keys_start);
    let signature_count = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
    let signature_count =
        usize::try_from(signature_count).map_err(|_| ScriptError::SignatureCount)?;
    if signature_count > key_count {
        return Err(ScriptError::SignatureCount);
    }
    require_stack(stack, signature_count.saturating_add(1))?;
    let signatures_start = stack.len() - signature_count;
    let candidate_signatures = stack.split_off(signatures_start);
    let dummy = pop(stack)?;

    let mut remaining_signatures = candidate_signatures.len();
    let mut remaining_keys = keys.len();
    let mut valid = true;
    while remaining_signatures > 0 {
        if remaining_signatures > remaining_keys {
            valid = false;
            break;
        }
        let signature = &candidate_signatures[remaining_signatures - 1];
        let key = &keys[remaining_keys - 1];
        if check_signature(
            transaction,
            input_index,
            previous_value,
            subscript,
            signature,
            key,
            signatures,
        )? {
            remaining_signatures -= 1;
        }
        remaining_keys -= 1;
    }
    valid &= remaining_signatures == 0;

    if !valid
        && flags.contains(ScriptFlags::VERIFY_NULLFAIL)
        && candidate_signatures
            .iter()
            .any(|signature| !signature.is_empty())
    {
        return Err(ScriptError::NullFail);
    }
    if !dummy.is_empty() {
        return Err(ScriptError::SignatureNullDummy);
    }
    Ok(valid)
}

fn read_u8(script: &[u8], offset: &mut usize) -> Result<u8, ScriptError> {
    let value = *script
        .get(*offset)
        .ok_or(ScriptError::BadOpcode(OP_PUSHDATA1))?;
    *offset += 1;
    Ok(value)
}

fn read_u16(script: &[u8], offset: &mut usize) -> Result<u16, ScriptError> {
    let end = offset
        .checked_add(2)
        .filter(|end| *end <= script.len())
        .ok_or(ScriptError::BadOpcode(OP_PUSHDATA2))?;
    let bytes: [u8; 2] = script[*offset..end]
        .try_into()
        .map_err(|_| ScriptError::BadOpcode(OP_PUSHDATA2))?;
    *offset = end;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(script: &[u8], offset: &mut usize) -> Result<u32, ScriptError> {
    let end = offset
        .checked_add(4)
        .filter(|end| *end <= script.len())
        .ok_or(ScriptError::BadOpcode(OP_PUSHDATA4))?;
    let bytes: [u8; 4] = script[*offset..end]
        .try_into()
        .map_err(|_| ScriptError::BadOpcode(OP_PUSHDATA4))?;
    *offset = end;
    Ok(u32::from_le_bytes(bytes))
}

fn is_minimal_push(opcode: u8, data: &[u8]) -> bool {
    if data.is_empty() {
        return opcode == OP_0;
    }
    if data.len() == 1 && (1..=16).contains(&data[0]) {
        return opcode == OP_1 + data[0] - 1;
    }
    if data == [0x81] {
        return opcode == OP_1NEGATE;
    }
    match data.len() {
        1..=75 => opcode == data.len() as u8,
        76..=255 => opcode == OP_PUSHDATA1,
        256..=65_535 => opcode == OP_PUSHDATA2,
        _ => opcode == OP_PUSHDATA4,
    }
}

fn is_disabled_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        OP_CAT
            | OP_SUBSTR
            | OP_LEFT
            | OP_RIGHT
            | OP_INVERT
            | OP_AND
            | OP_OR
            | OP_XOR
            | OP_2MUL
            | OP_2DIV
            | OP_MUL
            | OP_DIV
            | OP_MOD
            | OP_LSHIFT
            | OP_RSHIFT
    )
}

fn minimal_numbers(flags: ScriptFlags) -> bool {
    flags.contains(ScriptFlags::VERIFY_MINIMAL_DATA)
}

fn decode_top_number(
    stack: &[Vec<u8>],
    flags: ScriptFlags,
    maximum_size: usize,
) -> Result<i64, ScriptError> {
    let item = stack.last().ok_or(ScriptError::InvalidStackOperation)?;
    decode_script_number(item, minimal_numbers(flags), maximum_size)
}

fn decode_script_number(
    bytes: &[u8],
    require_minimal: bool,
    maximum_size: usize,
) -> Result<i64, ScriptError> {
    if bytes.len() > maximum_size {
        return Err(ScriptError::NumericOverflow);
    }
    if require_minimal && !is_minimal_script_number(bytes) {
        return Err(ScriptError::NonMinimalNumber);
    }
    if bytes.is_empty() {
        return Ok(0);
    }

    let mut magnitude = 0u64;
    for (index, byte) in bytes.iter().copied().enumerate() {
        magnitude |= u64::from(byte) << (8 * index);
    }
    let sign_bit = 1u64 << (bytes.len() * 8 - 1);
    let negative = magnitude & sign_bit != 0;
    magnitude &= !sign_bit;
    let magnitude = i64::try_from(magnitude).map_err(|_| ScriptError::NumericOverflow)?;
    Ok(if negative { -magnitude } else { magnitude })
}

fn encode_script_number(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }

    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut bytes = Vec::new();
    while magnitude != 0 {
        bytes.push(magnitude as u8);
        magnitude >>= 8;
    }
    if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.push(if negative { 0x80 } else { 0x00 });
    } else if negative && let Some(last) = bytes.last_mut() {
        *last |= 0x80;
    }
    bytes
}

fn is_minimal_script_number(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    if bytes.last().is_some_and(|byte| byte & 0x7f == 0) {
        if bytes.len() == 1 {
            return false;
        }
        if bytes[bytes.len() - 2] & 0x80 == 0 {
            return false;
        }
    }
    true
}

fn cast_to_bool(bytes: &[u8]) -> bool {
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == 0 {
            continue;
        }
        if index == bytes.len() - 1 && byte == 0x80 {
            return false;
        }
        return true;
    }
    false
}

fn push_bool(stack: &mut Vec<Vec<u8>>, value: bool) {
    stack.push(if value { vec![1] } else { Vec::new() });
}

fn pop(stack: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, ScriptError> {
    stack.pop().ok_or(ScriptError::InvalidStackOperation)
}

fn require_stack(stack: &[Vec<u8>], count: usize) -> Result<(), ScriptError> {
    if stack.len() < count {
        Err(ScriptError::InvalidStackOperation)
    } else {
        Ok(())
    }
}

fn duplicate_tail(stack: &mut Vec<Vec<u8>>, count: usize) -> Result<(), ScriptError> {
    require_stack(stack, count)?;
    let start = stack.len() - count;
    let values = stack[start..].to_vec();
    stack.extend(values);
    Ok(())
}

fn enforce_stack_limit(stack: &[Vec<u8>], alt_stack: &[Vec<u8>]) -> Result<(), ScriptError> {
    if stack.len().saturating_add(alt_stack.len()) > MAX_SCRIPT_STACK {
        Err(ScriptError::StackSize)
    } else {
        Ok(())
    }
}

fn blake2b_160(input: &[u8]) -> [u8; 20] {
    let mut hasher = Blake2bVar::new(20).expect("valid BLAKE2b output length");
    hasher.update(input);
    let mut output = [0u8; 20];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    hasher.update(input);
    let mut output = [0u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

fn sha3_256(input: &[u8]) -> [u8; 32] {
    Sha3_256::digest(input).into()
}

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error("signature input {requested} is outside {inputs} inputs")]
    InputIndex { requested: usize, inputs: usize },
    #[error("invalid signature hash type 0x{0:08x}")]
    InvalidSignatureHashType(u32),
    #[error(transparent)]
    Transaction(#[from] hns_transaction::TransactionError),
    #[error("resolved input count {coins} does not match transaction input count {inputs}")]
    InputCoinCount { inputs: usize, coins: usize },
    #[error("resolved input coin does not match the transaction outpoint")]
    InputCoinMismatch,
    #[error("OP_RETURN")]
    OpReturn,
    #[error("script exceeds the consensus size limit")]
    ScriptSize,
    #[error("script stack exceeds the consensus item limit")]
    StackSize,
    #[error("script push exceeds the consensus item-size limit")]
    PushSize,
    #[error("witness program has an empty witness")]
    WitnessProgramWitnessEmpty,
    #[error("witness program does not match the committed hash or shape")]
    WitnessProgramMismatch,
    #[error("version-zero witness program has the wrong length")]
    WitnessProgramWrongLength,
    #[error("upgradable witness program is discouraged by policy")]
    DiscourageUpgradableWitnessProgram,
    #[error("upgradable NOP is discouraged by policy")]
    DiscourageUpgradableNops,
    #[error("script evaluated to false")]
    EvalFalse,
    #[error("script contains malformed or invalid opcode 0x{0:02x}")]
    BadOpcode(u8),
    #[error("script contains disabled opcode 0x{0:02x}")]
    DisabledOpcode(u8),
    #[error("script operation count exceeds the consensus limit")]
    OperationCount,
    #[error("script push is not minimally encoded")]
    MinimalData,
    #[error("script number is not minimally encoded")]
    NonMinimalNumber,
    #[error("conditional argument is not minimally encoded")]
    MinimalIf,
    #[error("script conditional is unbalanced")]
    UnbalancedConditional,
    #[error("invalid main-stack operation")]
    InvalidStackOperation,
    #[error("invalid alt-stack operation")]
    InvalidAltStackOperation,
    #[error("VERIFY failed")]
    Verify,
    #[error("EQUALVERIFY failed")]
    EqualVerify,
    #[error("NUMEQUALVERIFY failed")]
    NumEqualVerify,
    #[error("negative locktime")]
    NegativeLocktime,
    #[error("locktime predicate is not satisfied")]
    UnsatisfiedLocktime,
    #[error("script number overflow")]
    NumericOverflow,
    #[error("public key count is invalid")]
    PublicKeyCount,
    #[error("signature count is invalid")]
    SignatureCount,
    #[error("public key encoding is invalid")]
    PublicKeyEncoding,
    #[error("signature encoding is invalid")]
    SignatureEncoding,
    #[error("multisig dummy argument is not empty")]
    SignatureNullDummy,
    #[error("NULLFAIL")]
    NullFail,
    #[error("CHECKSIGVERIFY failed")]
    CheckSigVerify,
    #[error("CHECKMULTISIGVERIFY failed")]
    CheckMultiSigVerify,
    #[error("secp256k1 signature backend is unavailable")]
    SignatureBackendUnavailable,
}

impl ScriptError {
    /// Return HSD's rejection code for the same failure class.
    pub const fn hsd_code(&self) -> &'static str {
        match self {
            Self::InputIndex { .. }
            | Self::InvalidSignatureHashType(_)
            | Self::Transaction(_)
            | Self::InputCoinCount { .. }
            | Self::InputCoinMismatch
            | Self::NumericOverflow
            | Self::NonMinimalNumber
            | Self::SignatureBackendUnavailable => "UNKNOWN_ERROR",
            Self::OpReturn => "OP_RETURN",
            Self::ScriptSize => "SCRIPT_SIZE",
            Self::StackSize => "STACK_SIZE",
            Self::PushSize => "PUSH_SIZE",
            Self::WitnessProgramWitnessEmpty => "WITNESS_PROGRAM_WITNESS_EMPTY",
            Self::WitnessProgramMismatch => "WITNESS_PROGRAM_MISMATCH",
            Self::WitnessProgramWrongLength => "WITNESS_PROGRAM_WRONG_LENGTH",
            Self::DiscourageUpgradableWitnessProgram => "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            Self::DiscourageUpgradableNops => "DISCOURAGE_UPGRADABLE_NOPS",
            Self::EvalFalse => "EVAL_FALSE",
            Self::BadOpcode(_) => "BAD_OPCODE",
            Self::DisabledOpcode(_) => "DISABLED_OPCODE",
            Self::OperationCount => "OP_COUNT",
            Self::MinimalData => "MINIMALDATA",
            Self::MinimalIf => "MINIMALIF",
            Self::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            Self::InvalidStackOperation => "INVALID_STACK_OPERATION",
            Self::InvalidAltStackOperation => "INVALID_ALTSTACK_OPERATION",
            Self::Verify => "VERIFY",
            Self::EqualVerify => "EQUALVERIFY",
            Self::NumEqualVerify => "NUMEQUALVERIFY",
            Self::NegativeLocktime => "NEGATIVE_LOCKTIME",
            Self::UnsatisfiedLocktime => "UNSATISFIED_LOCKTIME",
            Self::PublicKeyCount => "PUBKEY_COUNT",
            Self::SignatureCount => "SIG_COUNT",
            Self::PublicKeyEncoding => "PUBKEY_ENCODING",
            Self::SignatureEncoding => "SIG_ENCODING",
            Self::SignatureNullDummy => "SIG_NULLDUMMY",
            Self::NullFail => "NULLFAIL",
            Self::CheckSigVerify => "CHECKSIGVERIFY",
            Self::CheckMultiSigVerify => "CHECKMULTISIGVERIFY",
        }
    }
}

#[cfg(test)]
mod tests {
    use hns_covenants::CovenantKind;
    use hns_transaction::{Input, Outpoint, Output};

    use super::*;

    const HSD_SCRIPT_VECTORS: &str = include_str!("../fixtures/hsd/script-tests-v1.txt");

    #[derive(Debug)]
    struct HsdScriptVector {
        index: usize,
        expected: String,
        flags: ScriptFlags,
        value: u64,
        locktime: u32,
        sequence: u32,
        script: Vec<u8>,
        witness: Vec<Vec<u8>>,
    }

    fn parse_vector(line: &str) -> HsdScriptVector {
        let mut fields = line.split('|');
        let index = fields
            .next()
            .expect("index")
            .parse()
            .expect("numeric index");
        let expected = fields.next().expect("result").to_owned();
        let flags = ScriptFlags::from_bits(
            fields
                .next()
                .expect("flags")
                .parse()
                .expect("numeric flags"),
        );
        let value = fields
            .next()
            .expect("value")
            .parse()
            .expect("numeric value");
        let locktime = fields
            .next()
            .expect("locktime")
            .parse()
            .expect("numeric locktime");
        let sequence = fields
            .next()
            .expect("sequence")
            .parse()
            .expect("numeric sequence");
        let script = hex::decode(fields.next().expect("script")).expect("script hex");
        let witness_count = fields
            .next()
            .expect("witness count")
            .parse::<usize>()
            .expect("numeric witness count");
        let witness_field = fields.next().expect("witness");
        assert!(fields.next().is_none(), "unexpected vector field");
        let witness = if witness_count == 0 {
            assert!(witness_field.is_empty());
            Vec::new()
        } else {
            let items = witness_field
                .split(',')
                .map(|item| hex::decode(item).expect("witness hex"))
                .collect::<Vec<_>>();
            assert_eq!(items.len(), witness_count);
            items
        };
        HsdScriptVector {
            index,
            expected,
            flags,
            value,
            locktime,
            sequence,
            script,
            witness,
        }
    }

    fn spending_fixture(vector: &HsdScriptVector) -> (Transaction, Coin) {
        let script_address =
            Address::new(0, sha3_256(&vector.script).to_vec()).expect("script address");
        let funding = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint::NULL,
                sequence: u32::MAX,
                witness: Witness {
                    items: vec![vec![0], vec![0]],
                },
            }],
            outputs: vec![Output {
                value: vector.value.into(),
                address: script_address.clone(),
                covenant: Default::default(),
            }],
            locktime: 0,
        };
        let outpoint = Outpoint {
            transaction_hash: funding
                .transaction_hash()
                .expect("funding transaction hash"),
            index: 0,
        };
        let mut witness = vector.witness.clone();
        witness.push(vector.script.clone());
        let spending = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: outpoint,
                sequence: vector.sequence,
                witness: Witness { items: witness },
            }],
            outputs: vec![Output {
                value: vector.value.into(),
                address: Address::new(0, vec![0; 20]).expect("null public-key hash"),
                covenant: Default::default(),
            }],
            locktime: vector.locktime,
        };
        let coin = Coin {
            outpoint,
            value: vector.value.into(),
            height: 1_u32.into(),
            coinbase: false,
            address: script_address,
            covenant: Default::default(),
        };
        (spending, coin)
    }

    #[test]
    fn all_pinned_hsd_script_vectors_match_exact_results() {
        assert!(
            HSD_SCRIPT_VECTORS.contains("# hsd_revision=698e252ebc7b5c1dd0a9587e342fdd153d020ae4")
        );
        assert!(HSD_SCRIPT_VECTORS.contains(
            "# source_sha256=71548a587d1c7921cb899de192f59ed1833c85a6cd62d9dac8cd5b86b1225c86"
        ));
        let vectors = HSD_SCRIPT_VECTORS
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(parse_vector)
            .collect::<Vec<_>>();
        assert_eq!(vectors.len(), 876);

        for vector in vectors {
            let (transaction, coin) = spending_fixture(&vector);
            let result = verify_witness_program(
                &transaction,
                0,
                &coin,
                vector.flags,
                &K256SignatureVerifier,
            );
            match (vector.expected.as_str(), result) {
                ("OK", Ok(())) => {}
                ("OK", Err(error)) => {
                    panic!(
                        "HSD script vector {} expected OK but returned {} ({})",
                        vector.index,
                        error.hsd_code(),
                        error
                    );
                }
                (expected, Err(error)) if error.hsd_code() == expected => {}
                (expected, Err(error)) => {
                    panic!(
                        "HSD script vector {} expected {} but returned {} ({})",
                        vector.index,
                        expected,
                        error.hsd_code(),
                        error
                    );
                }
                (expected, Ok(())) => {
                    panic!(
                        "HSD script vector {} expected {} but succeeded",
                        vector.index, expected
                    );
                }
            }
        }
    }

    #[test]
    fn op_type_and_coin_binding_are_consensus_visible() {
        let vector = HsdScriptVector {
            index: 0,
            expected: "OK".to_owned(),
            flags: ScriptFlags::MANDATORY,
            value: 1_000,
            locktime: 0,
            sequence: u32::MAX,
            script: vec![OP_TYPE, OP_7, OP_EQUAL],
            witness: Vec::new(),
        };
        let (mut transaction, coin) = spending_fixture(&vector);
        transaction
            .outputs
            .first_mut()
            .expect("fixture output")
            .covenant
            .kind = CovenantKind::Update;
        verify_witness_program(
            &transaction,
            0,
            &coin,
            ScriptFlags::MANDATORY,
            &K256SignatureVerifier,
        )
        .expect("OP_TYPE matches output covenant");

        let mut wrong_coin = coin.clone();
        wrong_coin.outpoint.index = 1;
        assert!(matches!(
            verify_witness_program(
                &transaction,
                0,
                &wrong_coin,
                ScriptFlags::MANDATORY,
                &K256SignatureVerifier
            ),
            Err(ScriptError::InputCoinMismatch)
        ));
    }
}
