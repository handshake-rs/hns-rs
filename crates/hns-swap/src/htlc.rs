use hns_covenants::{Covenant, CovenantKind};
use hns_encoding::{Decoder, Encoder};
use hns_primitives::Dollarydoos;
use hns_script::{
    K256SignatureVerifier, LOCKTIME_MASK, OP_CHECKLOCKTIMEVERIFY, OP_CHECKSIG, OP_DROP, OP_ELSE,
    OP_ENDIF, OP_EQUALVERIFY, OP_IF, OP_SHA256, SIGHASH_ALL, ScriptFlags,
    signature_hash as hns_signature_hash, verify_witness_program,
};
use hns_transaction::{Address, Coin, Outpoint, Output, Transaction, Witness};
use k256::ecdsa::Signature;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

use crate::{NetworkBinding, SwapError, blake2b_256};

pub const HNS_HTLC_VERSION: u16 = 1;
pub const HNS_HTLC_PREIMAGE_SIZE: usize = 32;
pub const HNS_HTLC_HASHLOCK_SIZE: usize = 32;
pub const MAX_HNS_HTLC_DESCRIPTOR_SIZE: usize = 256;
/// The only signature-hash mode admitted by native HNS HTLC helpers.
pub const HNS_HTLC_SIGHASH: u8 = SIGHASH_ALL as u8;

const HNS_HTLC_DESCRIPTOR_HASH_DOMAIN: &[u8] = b"hns-rs/hns-swap/hns-htlc/v1/descriptor";

/// Runtime-independent descriptor for a native Handshake absolute-timelock
/// HTLC. The lock script has a receiver-signed SHA-256 preimage branch and a
/// refund-owner-signed `OP_CHECKLOCKTIMEVERIFY` branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsHtlc {
    pub network: NetworkBinding,
    pub value: Dollarydoos,
    pub hashlock: [u8; HNS_HTLC_HASHLOCK_SIZE],
    pub receiver_public_key: [u8; 33],
    pub refund_public_key: [u8; 33],
    /// Absolute HSD locktime encoding. Height locktimes have the high bit
    /// clear; median-time locktimes use HSD's high-bit time flag.
    pub refund_locktime: u32,
}

#[derive(Clone, Eq, PartialEq)]
pub struct HnsHtlcPreimage([u8; HNS_HTLC_PREIMAGE_SIZE]);

impl HnsHtlcPreimage {
    fn new(preimage: [u8; HNS_HTLC_PREIMAGE_SIZE]) -> Self {
        Self(preimage)
    }

    /// Explicitly expose the secret for a settlement transaction builder.
    /// Callers should keep the returned borrow out of logs and diagnostics.
    pub const fn expose_for_settlement(&self) -> &[u8; HNS_HTLC_PREIMAGE_SIZE] {
        &self.0
    }
}

impl core::fmt::Debug for HnsHtlcPreimage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("HnsHtlcPreimage([REDACTED])")
    }
}

impl Drop for HnsHtlcPreimage {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HnsHtlcSpend {
    Redeem { preimage: HnsHtlcPreimage },
    Refund,
}

impl HnsHtlcSpend {
    /// Return the redeem preimage only through an explicit settlement accessor.
    pub const fn preimage_for_settlement(&self) -> Option<&[u8; HNS_HTLC_PREIMAGE_SIZE]> {
        match self {
            Self::Redeem { preimage } => Some(preimage.expose_for_settlement()),
            Self::Refund => None,
        }
    }
}

impl HnsHtlc {
    pub fn validate(&self) -> Result<(), SwapError> {
        if self.value.get() == 0 {
            return Err(SwapError::ZeroHtlcValue);
        }
        if self.hashlock == [0; HNS_HTLC_HASHLOCK_SIZE] {
            return Err(SwapError::ZeroHtlcHashlock);
        }
        k256::ecdsa::VerifyingKey::from_sec1_bytes(&self.receiver_public_key)
            .map_err(|_| SwapError::InvalidPublicKey)?;
        k256::ecdsa::VerifyingKey::from_sec1_bytes(&self.refund_public_key)
            .map_err(|_| SwapError::InvalidPublicKey)?;
        if self.receiver_public_key == self.refund_public_key {
            return Err(SwapError::HtlcKeyReuse);
        }
        if self.refund_locktime & LOCKTIME_MASK == 0 {
            return Err(SwapError::ZeroHtlcRefundLocktime);
        }
        Ok(())
    }

    pub fn verify_for_network(&self, expected_network: NetworkBinding) -> Result<(), SwapError> {
        if self.network != expected_network {
            return Err(SwapError::NetworkMismatch);
        }
        self.validate()
    }

    pub fn encode(&self) -> Result<Vec<u8>, SwapError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(148);
        encoder.put_u16_le(HNS_HTLC_VERSION);
        encoder.put_u32_le(self.network.magic);
        encoder.put_bytes(self.network.genesis.as_bytes());
        encoder.put_u64_le(self.value.get());
        encoder.put_bytes(&self.hashlock);
        encoder.put_bytes(&self.receiver_public_key);
        encoder.put_bytes(&self.refund_public_key);
        encoder.put_u32_le(self.refund_locktime);
        let encoded = encoder.into_bytes();
        if encoded.len() > MAX_HNS_HTLC_DESCRIPTOR_SIZE {
            return Err(SwapError::HtlcTooLarge(encoded.len()));
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, SwapError> {
        if input.len() > MAX_HNS_HTLC_DESCRIPTOR_SIZE {
            return Err(SwapError::HtlcTooLarge(input.len()));
        }
        let mut decoder = Decoder::new(input);
        let version = decoder.read_u16_le()?;
        if version != HNS_HTLC_VERSION {
            return Err(SwapError::UnsupportedHtlcVersion(version));
        }
        let htlc = Self {
            network: NetworkBinding {
                magic: decoder.read_u32_le()?,
                genesis: decoder.read_array::<32>()?.into(),
            },
            value: Dollarydoos::new(decoder.read_u64_le()?),
            hashlock: decoder.read_array()?,
            receiver_public_key: decoder.read_array()?,
            refund_public_key: decoder.read_array()?,
            refund_locktime: decoder.read_u32_le()?,
        };
        decoder.finish()?;
        htlc.validate()?;
        Ok(htlc)
    }

    pub fn descriptor_hash(&self) -> Result<[u8; 32], SwapError> {
        let encoded = self.encode()?;
        let mut bytes = Vec::with_capacity(
            HNS_HTLC_DESCRIPTOR_HASH_DOMAIN
                .len()
                .saturating_add(encoded.len()),
        );
        bytes.extend_from_slice(HNS_HTLC_DESCRIPTOR_HASH_DOMAIN);
        bytes.extend_from_slice(&encoded);
        Ok(blake2b_256(&bytes))
    }

    pub fn hash_preimage(preimage: &[u8; HNS_HTLC_PREIMAGE_SIZE]) -> [u8; 32] {
        Sha256::digest(preimage).into()
    }

    /// Construct the exact witness script committed by [`Self::address`].
    pub fn script(&self) -> Result<Vec<u8>, SwapError> {
        self.validate()?;
        let encoded_locktime = encode_script_number(u64::from(self.refund_locktime));
        let mut script = Vec::with_capacity(109_usize.saturating_add(encoded_locktime.len()));
        script.extend_from_slice(&[OP_IF, OP_SHA256, 32]);
        script.extend_from_slice(&self.hashlock);
        script.extend_from_slice(&[OP_EQUALVERIFY, 33]);
        script.extend_from_slice(&self.receiver_public_key);
        script.push(OP_ELSE);
        push_minimal_data(&mut script, &encoded_locktime);
        script.extend_from_slice(&[OP_CHECKLOCKTIMEVERIFY, OP_DROP, 33]);
        script.extend_from_slice(&self.refund_public_key);
        script.extend_from_slice(&[OP_ENDIF, OP_CHECKSIG]);
        Ok(script)
    }

    pub fn script_hash(&self) -> Result<[u8; 32], SwapError> {
        Ok(Sha3_256::digest(self.script()?).into())
    }

    pub fn address(&self) -> Result<Address, SwapError> {
        Ok(Address::new(0, self.script_hash()?.to_vec())?)
    }

    pub fn funding_output(&self) -> Result<Output, SwapError> {
        Ok(Output {
            value: self.value,
            address: self.address()?,
            covenant: Covenant::default(),
        })
    }

    pub fn verify_funding_output(&self, output: &Output) -> Result<(), SwapError> {
        self.validate()?;
        if output.value != self.value {
            return Err(SwapError::HtlcValueMismatch);
        }
        if output.address != self.address()? {
            return Err(SwapError::HtlcAddressMismatch);
        }
        if output.covenant.kind != CovenantKind::None || !output.covenant.items.is_empty() {
            return Err(SwapError::HtlcCovenantMismatch);
        }
        Ok(())
    }

    pub fn verify_funding_transaction(
        &self,
        transaction: &Transaction,
        output_index: usize,
    ) -> Result<Outpoint, SwapError> {
        let output =
            transaction
                .outputs
                .get(output_index)
                .ok_or(SwapError::HtlcFundingOutputIndex {
                    requested: output_index,
                    outputs: transaction.outputs.len(),
                })?;
        self.verify_funding_output(output)?;
        Ok(Outpoint {
            transaction_hash: transaction.transaction_hash()?,
            index: u32::try_from(output_index).map_err(|_| SwapError::ArithmeticOverflow)?,
        })
    }

    pub fn verify_funding_coin(&self, coin: &Coin) -> Result<(), SwapError> {
        self.verify_funding_output(&Output {
            value: coin.value,
            address: coin.address.clone(),
            covenant: coin.covenant.clone(),
        })
    }

    /// Produce the consensus `SIGHASH_ALL` digest for either HTLC spend branch.
    /// No caller-selected signature-hash mode is accepted by this API.
    pub fn signature_hash(
        &self,
        transaction: &Transaction,
        input_index: usize,
        funding_coin: &Coin,
    ) -> Result<[u8; 32], SwapError> {
        self.verify_funding_coin(funding_coin)?;
        let input = transaction
            .inputs
            .get(input_index)
            .ok_or(SwapError::HtlcSpendInputIndex {
                requested: input_index,
                inputs: transaction.inputs.len(),
            })?;
        if input.previous_output != funding_coin.outpoint {
            return Err(SwapError::HtlcOutpointMismatch);
        }
        Ok(hns_signature_hash(
            transaction,
            input_index,
            &self.script()?,
            funding_coin.value.get(),
            u32::from(HNS_HTLC_SIGHASH),
        )?)
    }

    /// Assemble the canonical redeem witness after checking signature encoding
    /// and the preimage. Use [`Self::verify_spend`] to authenticate the
    /// signature against a transaction and the receiver key.
    pub fn redeem_witness(
        &self,
        signature: &[u8; 65],
        preimage: &[u8; HNS_HTLC_PREIMAGE_SIZE],
    ) -> Result<Witness, SwapError> {
        self.validate()?;
        validate_htlc_signature(signature)?;
        if Self::hash_preimage(preimage) != self.hashlock {
            return Err(SwapError::HtlcPreimageMismatch);
        }
        Ok(Witness {
            items: vec![
                signature.to_vec(),
                preimage.to_vec(),
                vec![1],
                self.script()?,
            ],
        })
    }

    /// Assemble the canonical refund witness after checking signature
    /// encoding. Use [`Self::verify_spend`] to authenticate it against a
    /// transaction, the refund key, and the absolute locktime.
    pub fn refund_witness(&self, signature: &[u8; 65]) -> Result<Witness, SwapError> {
        self.validate()?;
        validate_htlc_signature(signature)?;
        Ok(Witness {
            items: vec![signature.to_vec(), Vec::new(), self.script()?],
        })
    }

    /// Extract a preimage only from the exact canonical redeem layout and only
    /// after checking it against this descriptor's hashlock. Call
    /// [`Self::verify_spend`] when transaction/signature validity is required.
    pub fn extract_preimage(
        &self,
        witness: &Witness,
    ) -> Result<[u8; HNS_HTLC_PREIMAGE_SIZE], SwapError> {
        let [signature, preimage, selector, script] = witness.items.as_slice() else {
            return Err(SwapError::InvalidHtlcWitness);
        };
        let signature: &[u8; 65] = signature
            .as_slice()
            .try_into()
            .map_err(|_| SwapError::InvalidHtlcWitness)?;
        validate_htlc_signature(signature)?;
        if selector.as_slice() != [1] || script != &self.script()? {
            return Err(SwapError::InvalidHtlcWitness);
        }
        let preimage: [u8; HNS_HTLC_PREIMAGE_SIZE] = preimage
            .as_slice()
            .try_into()
            .map_err(|_| SwapError::InvalidHtlcWitness)?;
        if Self::hash_preimage(&preimage) != self.hashlock {
            return Err(SwapError::HtlcPreimageMismatch);
        }
        Ok(preimage)
    }

    /// Verify funding terms and execute the HNS witness program with the
    /// consensus-complete k256 backend before classifying the spend.
    pub fn verify_spend(
        &self,
        transaction: &Transaction,
        input_index: usize,
        funding_coin: &Coin,
    ) -> Result<HnsHtlcSpend, SwapError> {
        let input = transaction
            .inputs
            .get(input_index)
            .ok_or(SwapError::HtlcSpendInputIndex {
                requested: input_index,
                inputs: transaction.inputs.len(),
            })?;
        self.verify_funding_coin(funding_coin)?;
        verify_witness_program(
            transaction,
            input_index,
            funding_coin,
            ScriptFlags::STANDARD,
            &K256SignatureVerifier,
        )?;
        let witness = &input.witness;
        match witness.items.as_slice() {
            [signature, selector, script]
                if selector.is_empty() && script.as_slice() == self.script()?.as_slice() =>
            {
                let signature: &[u8; 65] = signature
                    .as_slice()
                    .try_into()
                    .map_err(|_| SwapError::InvalidHtlcWitness)?;
                validate_htlc_signature(signature)?;
                Ok(HnsHtlcSpend::Refund)
            }
            [_, _, _, _] => Ok(HnsHtlcSpend::Redeem {
                preimage: HnsHtlcPreimage::new(self.extract_preimage(witness)?),
            }),
            _ => Err(SwapError::InvalidHtlcWitness),
        }
    }
}

fn validate_htlc_signature(signature: &[u8; 65]) -> Result<(), SwapError> {
    if signature[64] != HNS_HTLC_SIGHASH {
        return Err(SwapError::InvalidHtlcSignatureHashType(signature[64]));
    }
    let signature =
        Signature::from_slice(&signature[..64]).map_err(|_| SwapError::InvalidHtlcSignature)?;
    if signature.normalize_s().is_some() {
        return Err(SwapError::HighHtlcSignature);
    }
    Ok(())
}

fn encode_script_number(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let mut value = value;
    let mut bytes = Vec::new();
    while value != 0 {
        bytes.push(value as u8);
        value >>= 8;
    }
    if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.push(0);
    }
    bytes
}

fn push_minimal_data(script: &mut Vec<u8>, data: &[u8]) {
    debug_assert!(!data.is_empty() && data.len() <= 75);
    if data.len() == 1 && (1..=16).contains(&data[0]) {
        script.push(hns_script::OP_1 + data[0] - 1);
        return;
    }
    script.push(data.len() as u8);
    script.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use hns_primitives::{BlockHash, Height, TransactionHash};
    use hns_script::{SIGHASH_ANYONE_CAN_PAY, SIGHASH_NONE, SIGHASH_SINGLE};
    use hns_transaction::{Input, Output};
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    use super::*;

    const PROTOCOL_V1_FIXTURES: &str =
        include_str!("../fixtures/protocol-v1/hns-swap-v1.txt");

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let value = PROTOCOL_V1_FIXTURES
            .lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value))
            .unwrap_or_else(|| panic!("missing fixture {name}"));
        hex::decode(value).expect("fixture hex")
    }

    fn htlc_fixture() -> (HnsHtlc, [u8; 32], SigningKey, SigningKey) {
        let receiver_key = SigningKey::from_slice(&[0x41; 32]).expect("receiver key");
        let refund_key = SigningKey::from_slice(&[0x42; 32]).expect("refund key");
        let receiver_public_key = receiver_key.verifying_key().to_encoded_point(true);
        let refund_public_key = refund_key.verifying_key().to_encoded_point(true);
        let preimage = [0x55; HNS_HTLC_PREIMAGE_SIZE];
        (
            HnsHtlc {
                network: NetworkBinding {
                    magic: 0x5b6e_c393,
                    genesis: BlockHash::new([0x11; 32]),
                },
                value: Dollarydoos::new(5_000_000),
                hashlock: HnsHtlc::hash_preimage(&preimage),
                receiver_public_key: receiver_public_key
                    .as_bytes()
                    .try_into()
                    .expect("compressed receiver key"),
                refund_public_key: refund_public_key
                    .as_bytes()
                    .try_into()
                    .expect("compressed refund key"),
                refund_locktime: 500_000,
            },
            preimage,
            receiver_key,
            refund_key,
        )
    }

    fn funding_fixture(htlc: &HnsHtlc) -> (Transaction, Coin) {
        let funding = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    transaction_hash: TransactionHash::new([0x22; 32]),
                    index: 3,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![htlc.funding_output().expect("funding output")],
            locktime: 0,
        };
        let outpoint = htlc
            .verify_funding_transaction(&funding, 0)
            .expect("funding transaction");
        let coin = Coin {
            outpoint,
            value: htlc.value,
            height: Height::new(100),
            coinbase: false,
            address: htlc.address().expect("HTLC address"),
            covenant: Covenant::default(),
        };
        (funding, coin)
    }

    fn unsigned_spend(coin: &Coin, locktime: u32) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: coin.outpoint,
                sequence: u32::MAX - 1,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: Dollarydoos::new(coin.value.get() - 1_000),
                address: Address::new(0, vec![0x77; 20]).expect("destination address"),
                covenant: Covenant::default(),
            }],
            locktime,
        }
    }

    fn compact_signature(
        htlc: &HnsHtlc,
        transaction: &Transaction,
        coin: &Coin,
        key: &SigningKey,
    ) -> [u8; 65] {
        let digest = htlc
            .signature_hash(transaction, 0, coin)
            .expect("HTLC signature hash");
        let signature: Signature = key.sign_prehash(&digest).expect("HTLC signature");
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut compact = [0_u8; 65];
        compact[..64].copy_from_slice(&signature.to_bytes());
        compact[64] = HNS_HTLC_SIGHASH;
        compact
    }

    #[test]
    fn hns_htlc_descriptor_and_script_vectors_are_stable() {
        let (htlc, _, _, _) = htlc_fixture();
        let encoded = htlc.encode().expect("descriptor encoding");
        assert_eq!(encoded.len(), 148);
        assert_eq!(
            HnsHtlc::decode(&encoded).expect("descriptor decoding"),
            htlc
        );
        assert_eq!(
            hex::encode(htlc.script().expect("HTLC script")),
            "63a82084126d0dd850199be29021aadbaee68cb9199047b1cb7ec9894ddb1e3562783c882102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619670320a107b175210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c68ac"
        );
        assert_eq!(
            hex::encode(htlc.script_hash().expect("HTLC script hash")),
            "23c2a34d907f099fe7dec5bf92281578b519ab9a802b3b629eeb4c976d1c1a1c"
        );
        assert_eq!(
            hex::encode(htlc.descriptor_hash().expect("descriptor hash")),
            "93d2e4d84d43df867c0e99e6864feac6317992a57b96e17cf851278ba869cdfc"
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            HnsHtlc::decode(&trailing),
            Err(SwapError::Decode(_))
        ));
        assert!(matches!(
            HnsHtlc::decode(&vec![0; MAX_HNS_HTLC_DESCRIPTOR_SIZE + 1]),
            Err(SwapError::HtlcTooLarge(_))
        ));

        let mut zero_value = htlc;
        zero_value.value = Dollarydoos::new(0);
        assert!(matches!(
            zero_value.validate(),
            Err(SwapError::ZeroHtlcValue)
        ));
        let mut zero_hashlock = htlc;
        zero_hashlock.hashlock = [0; HNS_HTLC_HASHLOCK_SIZE];
        assert!(matches!(
            zero_hashlock.validate(),
            Err(SwapError::ZeroHtlcHashlock)
        ));
        let mut reused_key = htlc;
        reused_key.refund_public_key = reused_key.receiver_public_key;
        assert!(matches!(
            reused_key.validate(),
            Err(SwapError::HtlcKeyReuse)
        ));
        let mut zero_time = htlc;
        zero_time.refund_locktime = hns_script::LOCKTIME_FLAG;
        assert!(matches!(
            zero_time.validate(),
            Err(SwapError::ZeroHtlcRefundLocktime)
        ));

        let mut time_locked = htlc;
        time_locked.refund_locktime = hns_script::LOCKTIME_FLAG | 123;
        let script = time_locked.script().expect("time-based lock script");
        assert!(script.windows(6).any(|part| part == [5, 123, 0, 0, 128, 0]));

        let mut small_height = htlc;
        small_height.refund_locktime = 1;
        assert!(
            small_height
                .script()
                .expect("small-height script")
                .windows(3)
                .any(|part| {
                    part == [
                        hns_script::OP_ELSE,
                        hns_script::OP_1,
                        hns_script::OP_CHECKLOCKTIMEVERIFY,
                    ]
                })
        );
    }

    #[test]
    fn exact_v1_htlc_descriptor_and_transaction_vectors_are_consumed() {
        let (htlc, preimage, receiver_key, refund_key) = htlc_fixture();
        assert_eq!(
            htlc.encode().expect("descriptor encoding"),
            fixture_bytes("htlc_descriptor")
        );
        assert_eq!(
            htlc.descriptor_hash().expect("descriptor hash").as_slice(),
            fixture_bytes("htlc_descriptor_hash").as_slice()
        );
        assert_eq!(
            htlc.script().expect("HTLC script"),
            fixture_bytes("htlc_script")
        );
        assert_eq!(
            htlc.script_hash().expect("HTLC script hash").as_slice(),
            fixture_bytes("htlc_script_hash").as_slice()
        );
        let encoded_address = fixture_bytes("htlc_address");
        let htlc_address = htlc.address().expect("HTLC address");
        assert_eq!(htlc_address.version, encoded_address[0]);
        assert_eq!(htlc_address.hash.as_slice(), &encoded_address[2..]);
        assert_eq!(usize::from(encoded_address[1]), htlc_address.hash.len());

        let (funding, coin) = funding_fixture(&htlc);
        assert_eq!(
            funding.encode().expect("funding encoding"),
            fixture_bytes("htlc_funding_transaction")
        );
        assert_eq!(
            funding
                .transaction_hash()
                .expect("funding txid")
                .as_bytes()
                .as_slice(),
            fixture_bytes("htlc_funding_txid").as_slice()
        );

        let mut redeem = unsigned_spend(&coin, 0);
        assert_eq!(
            htlc
                .signature_hash(&redeem, 0, &coin)
                .expect("redeem sighash")
                .as_slice(),
            fixture_bytes("htlc_redeem_sighash").as_slice()
        );
        let signature = compact_signature(&htlc, &redeem, &coin, &receiver_key);
        redeem.inputs[0].witness = htlc
            .redeem_witness(&signature, &preimage)
            .expect("redeem witness");
        assert_eq!(
            redeem.encode().expect("redeem encoding"),
            fixture_bytes("htlc_redeem_transaction")
        );
        assert_eq!(
            redeem
                .transaction_hash()
                .expect("redeem txid")
                .as_bytes()
                .as_slice(),
            fixture_bytes("htlc_redeem_txid").as_slice()
        );

        let mut refund = unsigned_spend(&coin, htlc.refund_locktime);
        assert_eq!(
            htlc
                .signature_hash(&refund, 0, &coin)
                .expect("refund sighash")
                .as_slice(),
            fixture_bytes("htlc_refund_sighash").as_slice()
        );
        let signature = compact_signature(&htlc, &refund, &coin, &refund_key);
        refund.inputs[0].witness = htlc.refund_witness(&signature).expect("refund witness");
        assert_eq!(
            refund.encode().expect("refund encoding"),
            fixture_bytes("htlc_refund_transaction")
        );
        assert_eq!(
            refund
                .transaction_hash()
                .expect("refund txid")
                .as_bytes()
                .as_slice(),
            fixture_bytes("htlc_refund_txid").as_slice()
        );
    }

    #[test]
    fn funding_verifier_requires_exact_amount_script_and_plain_covenant() {
        let (htlc, _, _, _) = htlc_fixture();
        let (funding, coin) = funding_fixture(&htlc);
        htlc.verify_funding_coin(&coin).expect("funding coin");
        assert_eq!(
            htlc.verify_funding_transaction(&funding, 0)
                .expect("funding outpoint"),
            coin.outpoint
        );

        let mut wrong_value = funding.outputs[0].clone();
        wrong_value.value = Dollarydoos::new(htlc.value.get() + 1);
        assert!(matches!(
            htlc.verify_funding_output(&wrong_value),
            Err(SwapError::HtlcValueMismatch)
        ));
        let mut wrong_script = funding.outputs[0].clone();
        wrong_script.address.hash[0] ^= 1;
        assert!(matches!(
            htlc.verify_funding_output(&wrong_script),
            Err(SwapError::HtlcAddressMismatch)
        ));
        let mut wrong_covenant = funding.outputs[0].clone();
        wrong_covenant.covenant.kind = CovenantKind::Open;
        assert!(matches!(
            htlc.verify_funding_output(&wrong_covenant),
            Err(SwapError::HtlcCovenantMismatch)
        ));
        assert!(matches!(
            htlc.verify_funding_transaction(&funding, 1),
            Err(SwapError::HtlcFundingOutputIndex { .. })
        ));
    }

    #[test]
    fn redeem_witness_verifies_signature_and_extracts_only_the_bound_preimage() {
        let (htlc, preimage, receiver_key, refund_key) = htlc_fixture();
        let (_, coin) = funding_fixture(&htlc);
        let mut redeem = unsigned_spend(&coin, 0);
        let receiver_signature = compact_signature(&htlc, &redeem, &coin, &receiver_key);
        redeem.inputs[0].witness = htlc
            .redeem_witness(&receiver_signature, &preimage)
            .expect("redeem witness");
        let spend = htlc
            .verify_spend(&redeem, 0, &coin)
            .expect("verified redeem");
        assert!(matches!(&spend, HnsHtlcSpend::Redeem { .. }));
        assert_eq!(spend.preimage_for_settlement(), Some(&preimage));
        let diagnostic = format!("{spend:?}");
        assert!(diagnostic.contains("REDACTED"));
        assert!(!diagnostic.contains(&hex::encode(preimage)));
        assert!(!diagnostic.contains("85, 85, 85"));
        assert_eq!(
            htlc.extract_preimage(&redeem.inputs[0].witness)
                .expect("preimage"),
            preimage
        );

        let mut wrong_signer = unsigned_spend(&coin, 0);
        let wrong_key_signature = compact_signature(&htlc, &wrong_signer, &coin, &refund_key);
        wrong_signer.inputs[0].witness = htlc
            .redeem_witness(&wrong_key_signature, &preimage)
            .expect("structurally valid witness");
        assert!(matches!(
            htlc.verify_spend(&wrong_signer, 0, &coin),
            Err(SwapError::Script(_))
        ));

        let wrong_preimage = [0x56; HNS_HTLC_PREIMAGE_SIZE];
        assert!(matches!(
            htlc.redeem_witness(&receiver_signature, &wrong_preimage),
            Err(SwapError::HtlcPreimageMismatch)
        ));
        let mut malformed = redeem.inputs[0].witness.clone();
        malformed.items[2] = vec![2];
        assert!(matches!(
            htlc.extract_preimage(&malformed),
            Err(SwapError::InvalidHtlcWitness)
        ));

        let parsed = Signature::from_slice(&receiver_signature[..64]).expect("compact signature");
        let high = Signature::from_scalars(parsed.r().to_bytes(), (-parsed.s()).to_bytes())
            .expect("high-S signature");
        let mut high_signature = receiver_signature;
        high_signature[..64].copy_from_slice(&high.to_bytes());
        assert!(matches!(
            htlc.redeem_witness(&high_signature, &preimage),
            Err(SwapError::HighHtlcSignature)
        ));

        for rejected_hash_type in [
            SIGHASH_NONE as u8,
            SIGHASH_SINGLE as u8,
            (hns_script::SIGHASH_ALL | SIGHASH_ANYONE_CAN_PAY) as u8,
        ] {
            let mut non_all = receiver_signature;
            non_all[64] = rejected_hash_type;
            assert!(matches!(
                htlc.redeem_witness(&non_all, &preimage),
                Err(SwapError::InvalidHtlcSignatureHashType(value))
                    if value == rejected_hash_type
            ));
        }
    }

    #[test]
    fn refund_witness_is_invalid_before_locktime_and_valid_at_locktime() {
        let (htlc, _, _, refund_key) = htlc_fixture();
        let (_, coin) = funding_fixture(&htlc);

        let mut premature = unsigned_spend(&coin, htlc.refund_locktime - 1);
        let signature = compact_signature(&htlc, &premature, &coin, &refund_key);
        premature.inputs[0].witness = htlc.refund_witness(&signature).expect("refund witness");
        assert!(matches!(
            htlc.verify_spend(&premature, 0, &coin),
            Err(SwapError::Script(_))
        ));

        let mut refund = unsigned_spend(&coin, htlc.refund_locktime);
        let signature = compact_signature(&htlc, &refund, &coin, &refund_key);
        refund.inputs[0].witness = htlc.refund_witness(&signature).expect("refund witness");
        assert_eq!(
            htlc.verify_spend(&refund, 0, &coin)
                .expect("verified refund"),
            HnsHtlcSpend::Refund
        );
        assert!(matches!(
            htlc.extract_preimage(&refund.inputs[0].witness),
            Err(SwapError::InvalidHtlcWitness)
        ));

        let mut wrong_coin = coin;
        wrong_coin.outpoint.index += 1;
        assert!(matches!(
            htlc.signature_hash(&refund, 0, &wrong_coin),
            Err(SwapError::HtlcOutpointMismatch)
        ));

        for rejected_hash_type in [
            SIGHASH_NONE as u8,
            SIGHASH_SINGLE as u8,
            (hns_script::SIGHASH_ALL | SIGHASH_ANYONE_CAN_PAY) as u8,
        ] {
            let mut non_all = signature;
            non_all[64] = rejected_hash_type;
            assert!(matches!(
                htlc.refund_witness(&non_all),
                Err(SwapError::InvalidHtlcSignatureHashType(value))
                    if value == rejected_hash_type
            ));
        }
    }

    #[test]
    fn time_based_refund_branch_executes_only_at_encoded_time() {
        let (mut htlc, _, _, refund_key) = htlc_fixture();
        htlc.refund_locktime = hns_script::LOCKTIME_FLAG | 123;
        let (_, coin) = funding_fixture(&htlc);

        let mut premature = unsigned_spend(&coin, hns_script::LOCKTIME_FLAG | 122);
        let signature = compact_signature(&htlc, &premature, &coin, &refund_key);
        premature.inputs[0].witness = htlc.refund_witness(&signature).unwrap();
        assert!(matches!(
            htlc.verify_spend(&premature, 0, &coin),
            Err(SwapError::Script(_))
        ));

        let mut mature = unsigned_spend(&coin, hns_script::LOCKTIME_FLAG | 123);
        let signature = compact_signature(&htlc, &mature, &coin, &refund_key);
        mature.inputs[0].witness = htlc.refund_witness(&signature).unwrap();
        assert_eq!(
            htlc.verify_spend(&mature, 0, &coin).unwrap(),
            HnsHtlcSpend::Refund
        );
    }
}
