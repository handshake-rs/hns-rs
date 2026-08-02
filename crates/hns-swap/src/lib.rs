#![doc = "HIP-0001 name swaps, signed marketplace listings, and HNS HTLC primitives."]

mod htlc;
mod listing;

pub use htlc::{
    HNS_HTLC_HASHLOCK_SIZE, HNS_HTLC_PREIMAGE_SIZE, HNS_HTLC_SIGHASH, HNS_HTLC_VERSION, HnsHtlc,
    HnsHtlcPreimage, HnsHtlcSpend, MAX_HNS_HTLC_DESCRIPTOR_SIZE,
};
pub use listing::{
    FIXED_PRICE_LISTING_VERSION, FixedPriceListing, LISTING_CANCELLATION_VERSION,
    ListingCancellation, MARKETPLACE_SIGNATURE_SIZE, MAX_FIXED_PRICE_LISTING_SIZE,
    MAX_LISTING_CANCELLATION_SIZE,
};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_covenants::{Covenant, CovenantKind, hash_name, validate_name};
use hns_encoding::{Decoder, Encoder};
use hns_primitives::{BlockHash, Dollarydoos, OfferId, TransactionHash};
use hns_script::{
    HIP1_SELLER_SIGHASH, LOCKTIME_FLAG, LOCKTIME_MASK, OP_9, OP_10, OP_CHECKSIG, OP_ELSE, OP_ENDIF,
    OP_EQUAL, OP_IF, OP_TYPE, signature_hash,
};
use hns_transaction::{Address, Coin, Input, Outpoint, Output, Transaction, Witness};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};
use thiserror::Error;

pub const SHAKEDEX_PROTOCOL_VERSION: u16 = 2;
pub const MAX_SWAP_PROOF_SIZE: usize = 4 * 1024;
pub const MAX_AUCTION_STEPS: usize = 512;
pub const MAX_AUCTION_BUNDLE_SIZE: usize = 1024 * 1024;
pub const HSD_LOCKTIME_MULTIPLIER: u64 = 512;
pub const MAX_HSD_TIME_LOCK: u64 = 1_u64 << 40;
pub const SWAP_LOCK_SCRIPT_SIZE: usize = 44;
pub const COMPACT_SIGNATURE_SIZE: usize = 65;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkBinding {
    pub magic: u32,
    pub genesis: BlockHash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwapProof {
    pub network: NetworkBinding,
    pub locking_outpoint: Outpoint,
    pub name: Vec<u8>,
    pub seller_public_key: [u8; 33],
    pub payment_address: Address,
    pub price: Dollarydoos,
    /// Shakedex v2 stores wall-clock seconds and lets HSD encode its
    /// 512-second absolute-locktime granularity when reconstructing the TX.
    pub lock_time_seconds: u64,
    pub signature: Option<[u8; COMPACT_SIGNATURE_SIZE]>,
    pub fee_address: Option<Address>,
    pub fee: Dollarydoos,
}

impl SwapProof {
    pub fn validate(&self) -> Result<(), SwapError> {
        if !validate_name(&self.name) {
            return Err(SwapError::InvalidName);
        }
        VerifyingKey::from_sec1_bytes(&self.seller_public_key)
            .map_err(|_| SwapError::InvalidPublicKey)?;
        self.payment_address.validate()?;
        if self.price.get() == 0 {
            return Err(SwapError::ZeroPrice);
        }
        encode_time_lock(self.lock_time_seconds)?;
        match (&self.fee_address, self.fee.get()) {
            (None, 0) => {}
            (Some(address), fee) if fee > 0 => address.validate()?,
            _ => return Err(SwapError::InvalidFee),
        }
        if let Some(signature) = self.signature
            && signature[64] != HIP1_SELLER_SIGHASH as u8
        {
            return Err(SwapError::WrongSellerHashType(signature[64]));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, SwapError> {
        self.validate()?;
        let mut encoder = Encoder::new();
        encoder.put_u16_le(SHAKEDEX_PROTOCOL_VERSION);
        encoder.put_u32_le(self.network.magic);
        encoder.put_bytes(self.network.genesis.as_bytes());
        encoder.put_bytes(&self.locking_outpoint.encode());
        encoder.put_varbytes(&self.name);
        encoder.put_bytes(&self.seller_public_key);
        encode_address(&self.payment_address, &mut encoder);
        encoder.put_u64_le(self.price.get());
        encoder.put_u64_le(self.lock_time_seconds);
        match self.signature {
            Some(signature) => {
                encoder.put_u8(1);
                encoder.put_bytes(&signature);
            }
            None => encoder.put_u8(0),
        }
        encoder.put_u64_le(self.fee.get());
        match &self.fee_address {
            Some(address) => {
                encoder.put_u8(1);
                encode_address(address, &mut encoder);
            }
            None => encoder.put_u8(0),
        }
        let encoded = encoder.into_bytes();
        if encoded.len() > MAX_SWAP_PROOF_SIZE {
            return Err(SwapError::ProofTooLarge(encoded.len()));
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, SwapError> {
        if input.len() > MAX_SWAP_PROOF_SIZE {
            return Err(SwapError::ProofTooLarge(input.len()));
        }
        let mut decoder = Decoder::new(input);
        let version = decoder.read_u16_le()?;
        if version != SHAKEDEX_PROTOCOL_VERSION {
            return Err(SwapError::UnsupportedVersion(version));
        }
        let network = NetworkBinding {
            magic: decoder.read_u32_le()?,
            genesis: BlockHash::new(decoder.read_array()?),
        };
        let locking_outpoint = Outpoint {
            transaction_hash: TransactionHash::new(decoder.read_array()?),
            index: decoder.read_u32_le()?,
        };
        let name = decoder.read_varbytes(63, "swap name")?;
        let seller_public_key = decoder.read_array()?;
        let payment_address = decode_address(&mut decoder)?;
        let price = Dollarydoos::new(decoder.read_u64_le()?);
        let lock_time_seconds = decoder.read_u64_le()?;
        let signature = match decoder.read_u8()? {
            0 => None,
            1 => Some(decoder.read_array()?),
            _ => return Err(SwapError::InvalidPresenceFlag("signature")),
        };
        let fee = Dollarydoos::new(decoder.read_u64_le()?);
        let fee_address = match decoder.read_u8()? {
            0 => None,
            1 => Some(decode_address(&mut decoder)?),
            _ => return Err(SwapError::InvalidPresenceFlag("fee address")),
        };
        decoder.finish()?;
        let proof = Self {
            network,
            locking_outpoint,
            name,
            seller_public_key,
            payment_address,
            price,
            lock_time_seconds,
            signature,
            fee_address,
            fee,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn offer_id(&self) -> Result<OfferId, SwapError> {
        let signature = self.signature.ok_or(SwapError::UnsignedProof)?;
        let mut encoded = self.encode()?;
        debug_assert!(
            encoded
                .windows(signature.len())
                .any(|part| part == signature)
        );
        encoded.extend_from_slice(b"HIP-0001/Shakedex-v2/offer");
        Ok(OfferId::new(blake2b_256(&encoded)))
    }

    pub fn sign(&mut self, locking_coin: &Coin, signing_key: &SigningKey) -> Result<(), SwapError> {
        let public_key = signing_key.verifying_key().to_encoded_point(true);
        if public_key.as_bytes() != self.seller_public_key {
            return Err(SwapError::SigningKeyMismatch);
        }
        self.signature = None;
        let transaction = self.presigned_transaction(locking_coin)?;
        let script = create_lock_script(&self.seller_public_key);
        let digest = signature_hash(
            &transaction,
            0,
            &script,
            locking_coin.value.get(),
            HIP1_SELLER_SIGHASH,
        )?;
        let signature: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| SwapError::SignatureFailure)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut encoded = [0_u8; COMPACT_SIGNATURE_SIZE];
        encoded[..64].copy_from_slice(&signature.to_bytes());
        encoded[64] = HIP1_SELLER_SIGHASH as u8;
        self.signature = Some(encoded);
        self.verify(locking_coin)
    }

    pub fn verify(&self, locking_coin: &Coin) -> Result<(), SwapError> {
        self.validate()?;
        verify_locking_coin(self, locking_coin)?;
        let encoded_signature = self.signature.ok_or(SwapError::UnsignedProof)?;
        let signature = Signature::from_slice(&encoded_signature[..64])
            .map_err(|_| SwapError::InvalidSignature)?;
        if signature.normalize_s().is_some() {
            return Err(SwapError::HighSignature);
        }
        let transaction = self.presigned_transaction(locking_coin)?;
        let script = create_lock_script(&self.seller_public_key);
        let digest = signature_hash(
            &transaction,
            0,
            &script,
            locking_coin.value.get(),
            HIP1_SELLER_SIGHASH,
        )?;
        let public_key = VerifyingKey::from_sec1_bytes(&self.seller_public_key)
            .map_err(|_| SwapError::InvalidPublicKey)?;
        public_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| SwapError::InvalidSignature)
    }

    pub fn verify_for_network(
        &self,
        expected_network: NetworkBinding,
        locking_coin: &Coin,
    ) -> Result<(), SwapError> {
        if self.network != expected_network {
            return Err(SwapError::NetworkMismatch);
        }
        self.verify(locking_coin)
    }

    pub fn presigned_transaction(&self, locking_coin: &Coin) -> Result<Transaction, SwapError> {
        self.validate()?;
        verify_locking_coin(self, locking_coin)?;
        let script = create_lock_script(&self.seller_public_key);
        let witness = self
            .signature
            .map_or_else(Witness::default, |signature| Witness {
                items: vec![signature.to_vec(), script.to_vec()],
            });
        let mut outputs = vec![Output {
            value: Dollarydoos::new(0),
            address: Address::new(0, vec![0; 20])?,
            covenant: Covenant {
                kind: CovenantKind::Transfer,
                items: Vec::new(),
            },
        }];
        if self.fee.get() > 0 {
            outputs.push(Output {
                value: self.fee,
                address: self.fee_address.clone().ok_or(SwapError::InvalidFee)?,
                covenant: Covenant::default(),
            });
        }
        outputs.push(Output {
            value: self.price,
            address: self.payment_address.clone(),
            covenant: Covenant::default(),
        });
        Ok(Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: self.locking_outpoint,
                sequence: u32::MAX - 1,
                witness,
            }],
            outputs,
            locktime: encode_time_lock(self.lock_time_seconds)?,
        })
    }

    pub fn is_executable(&self, parent_median_time: u64) -> Result<bool, SwapError> {
        let encoded = encode_time_lock(self.lock_time_seconds)?;
        let threshold = u64::from(encoded & LOCKTIME_MASK)
            .checked_mul(HSD_LOCKTIME_MULTIPLIER)
            .ok_or(SwapError::ArithmeticOverflow)?;
        Ok(threshold < parent_median_time)
    }
}

pub fn create_lock_script(public_key: &[u8; 33]) -> [u8; SWAP_LOCK_SCRIPT_SIZE] {
    let mut script = [0_u8; SWAP_LOCK_SCRIPT_SIZE];
    script[0] = OP_TYPE;
    script[1] = OP_9;
    script[2] = OP_EQUAL;
    script[3] = OP_IF;
    script[4] = 33;
    script[5..38].copy_from_slice(public_key);
    script[38] = OP_CHECKSIG;
    script[39] = OP_ELSE;
    script[40] = OP_TYPE;
    script[41] = OP_10;
    script[42] = OP_EQUAL;
    script[43] = OP_ENDIF;
    script
}

pub fn lock_script_hash(public_key: &[u8; 33]) -> [u8; 32] {
    let script = create_lock_script(public_key);
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, script);
    hasher.finalize().into()
}

pub fn encode_time_lock(seconds: u64) -> Result<u32, SwapError> {
    if seconds >= MAX_HSD_TIME_LOCK {
        return Err(SwapError::LockTimeOutOfRange(seconds));
    }
    let units = u32::try_from(seconds / HSD_LOCKTIME_MULTIPLIER)
        .map_err(|_| SwapError::LockTimeOutOfRange(seconds))?;
    Ok(LOCKTIME_FLAG | units)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DutchStep {
    pub price: Dollarydoos,
    pub lock_time_seconds: u64,
}

pub fn canonical_reverse_dutch_schedule(
    start_price: Dollarydoos,
    end_price: Dollarydoos,
    start_time_seconds: u64,
    end_time_seconds: u64,
    steps: usize,
) -> Result<Vec<DutchStep>, SwapError> {
    if !(2..=MAX_AUCTION_STEPS).contains(&steps) {
        return Err(SwapError::InvalidStepCount(steps));
    }
    if start_price < end_price || end_price.get() == 0 {
        return Err(SwapError::InvalidPriceSchedule);
    }
    if start_time_seconds >= end_time_seconds
        || start_time_seconds % HSD_LOCKTIME_MULTIPLIER != 0
        || end_time_seconds % HSD_LOCKTIME_MULTIPLIER != 0
    {
        return Err(SwapError::InvalidLockSchedule);
    }
    let intervals = u64::try_from(steps - 1).map_err(|_| SwapError::ArithmeticOverflow)?;
    let duration = end_time_seconds - start_time_seconds;
    if duration / HSD_LOCKTIME_MULTIPLIER < intervals {
        return Err(SwapError::InvalidLockSchedule);
    }
    let price_delta = start_price.get() - end_price.get();
    let mut schedule = Vec::with_capacity(steps);
    for index in 0..steps {
        let index = u64::try_from(index).map_err(|_| SwapError::ArithmeticOverflow)?;
        let lock_units = (start_time_seconds / HSD_LOCKTIME_MULTIPLIER)
            + (duration / HSD_LOCKTIME_MULTIPLIER)
                .checked_mul(index)
                .ok_or(SwapError::ArithmeticOverflow)?
                / intervals;
        let price_reduction =
            u64::try_from(u128::from(price_delta) * u128::from(index) / u128::from(intervals))
                .map_err(|_| SwapError::ArithmeticOverflow)?;
        schedule.push(DutchStep {
            price: Dollarydoos::new(start_price.get() - price_reduction),
            lock_time_seconds: lock_units
                .checked_mul(HSD_LOCKTIME_MULTIPLIER)
                .ok_or(SwapError::ArithmeticOverflow)?,
        });
    }
    if schedule.first().map(|step| step.price) != Some(start_price)
        || schedule.last().map(|step| step.price) != Some(end_price)
        || schedule.first().map(|step| step.lock_time_seconds) != Some(start_time_seconds)
        || schedule.last().map(|step| step.lock_time_seconds) != Some(end_time_seconds)
    {
        return Err(SwapError::NonCanonicalSchedule);
    }
    for pair in schedule.windows(2) {
        if pair[0].price < pair[1].price
            || encode_time_lock(pair[0].lock_time_seconds)?
                >= encode_time_lock(pair[1].lock_time_seconds)?
        {
            return Err(SwapError::NonCanonicalSchedule);
        }
    }
    Ok(schedule)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DutchAuction {
    proofs: Vec<SwapProof>,
}

impl DutchAuction {
    pub fn new(proofs: Vec<SwapProof>) -> Result<Self, SwapError> {
        if proofs.is_empty() || proofs.len() > MAX_AUCTION_STEPS {
            return Err(SwapError::InvalidStepCount(proofs.len()));
        }
        let first = &proofs[0];
        first.validate()?;
        let mut bundle_size = 0_usize;
        for proof in &proofs {
            proof.validate()?;
            if proof.signature.is_none() {
                return Err(SwapError::UnsignedProof);
            }
            if proof.network != first.network
                || proof.locking_outpoint != first.locking_outpoint
                || proof.name != first.name
                || proof.seller_public_key != first.seller_public_key
                || proof.payment_address != first.payment_address
                || proof.fee_address != first.fee_address
            {
                return Err(SwapError::InconsistentAuction);
            }
            bundle_size = bundle_size
                .checked_add(proof.encode()?.len())
                .ok_or(SwapError::ArithmeticOverflow)?;
            if bundle_size > MAX_AUCTION_BUNDLE_SIZE {
                return Err(SwapError::BundleTooLarge(bundle_size));
            }
        }
        for pair in proofs.windows(2) {
            if pair[0].price < pair[1].price
                || encode_time_lock(pair[0].lock_time_seconds)?
                    >= encode_time_lock(pair[1].lock_time_seconds)?
            {
                return Err(SwapError::NonCanonicalSchedule);
            }
        }
        Ok(Self { proofs })
    }

    pub fn new_verified(
        proofs: Vec<SwapProof>,
        expected_network: NetworkBinding,
        locking_coin: &Coin,
    ) -> Result<Self, SwapError> {
        let auction = Self::new(proofs)?;
        auction.verify_all_for_network(expected_network, locking_coin)?;
        Ok(auction)
    }

    pub fn proofs(&self) -> &[SwapProof] {
        &self.proofs
    }

    pub fn best_executable(
        &self,
        parent_median_time: u64,
    ) -> Result<Option<&SwapProof>, SwapError> {
        for proof in self.proofs.iter().rev() {
            if proof.is_executable(parent_median_time)? {
                return Ok(Some(proof));
            }
        }
        Ok(None)
    }

    pub fn verify_all_for_network(
        &self,
        expected_network: NetworkBinding,
        locking_coin: &Coin,
    ) -> Result<(), SwapError> {
        for proof in &self.proofs {
            proof.verify_for_network(expected_network, locking_coin)?;
        }
        Ok(())
    }
}

fn verify_locking_coin(proof: &SwapProof, coin: &Coin) -> Result<(), SwapError> {
    if coin.outpoint != proof.locking_outpoint {
        return Err(SwapError::OutpointMismatch);
    }
    if coin.covenant.kind != CovenantKind::Finalize {
        return Err(SwapError::LockingCoinNotFinalize);
    }
    if coin.covenant.item(2) != Some(proof.name.as_slice()) {
        return Err(SwapError::NameMismatch);
    }
    let expected_name_hash = hash_name(&proof.name)?;
    if coin.covenant.item_name_hash(0) != Some(expected_name_hash) {
        return Err(SwapError::NameHashMismatch);
    }
    if coin.address.version != 0
        || coin.address.hash.as_slice() != lock_script_hash(&proof.seller_public_key)
    {
        return Err(SwapError::LockScriptMismatch);
    }
    Ok(())
}

fn encode_address(address: &Address, encoder: &mut Encoder) {
    encoder.put_u8(address.version);
    encoder.put_u8(address.hash.len() as u8);
    encoder.put_bytes(&address.hash);
}

fn decode_address(decoder: &mut Decoder<'_>) -> Result<Address, SwapError> {
    let version = decoder.read_u8()?;
    let length = usize::from(decoder.read_u8()?);
    let hash = decoder.read_bounded_vec(length, 40)?;
    Ok(Address::new(version, hash)?)
}

pub(crate) fn blake2b_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    hasher.update(input);
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

#[derive(Debug, Error)]
pub enum SwapError {
    #[error(transparent)]
    Decode(#[from] hns_encoding::DecodeError),
    #[error(transparent)]
    Covenant(#[from] hns_covenants::CovenantError),
    #[error(transparent)]
    Script(#[from] hns_script::ScriptError),
    #[error(transparent)]
    Transaction(#[from] hns_transaction::TransactionError),
    #[error("unsupported swap proof version {0}")]
    UnsupportedVersion(u16),
    #[error("swap proof is {0} bytes, exceeding the configured bound")]
    ProofTooLarge(usize),
    #[error("auction bundle is {0} bytes, exceeding the configured bound")]
    BundleTooLarge(usize),
    #[error("invalid presence flag for {0}")]
    InvalidPresenceFlag(&'static str),
    #[error("invalid Handshake name")]
    InvalidName,
    #[error("invalid compressed secp256k1 public key")]
    InvalidPublicKey,
    #[error("price must be nonzero")]
    ZeroPrice,
    #[error("fee and fee address are inconsistent")]
    InvalidFee,
    #[error("lock time {0} seconds is outside HSD's 40-bit time range")]
    LockTimeOutOfRange(u64),
    #[error("seller signature uses hash type 0x{0:02x}, expected 0x84")]
    WrongSellerHashType(u8),
    #[error("swap proof is unsigned")]
    UnsignedProof,
    #[error("swap proof is bound to a different Handshake network")]
    NetworkMismatch,
    #[error("signing key does not match the advertised seller public key")]
    SigningKeyMismatch,
    #[error("signature operation failed")]
    SignatureFailure,
    #[error("invalid seller signature")]
    InvalidSignature,
    #[error("high-S seller signature is noncanonical")]
    HighSignature,
    #[error("locking coin outpoint differs from the proof")]
    OutpointMismatch,
    #[error("locking coin is not a FINALIZE covenant")]
    LockingCoinNotFinalize,
    #[error("locking coin name differs from the proof")]
    NameMismatch,
    #[error("locking coin name hash differs from the proof")]
    NameHashMismatch,
    #[error("locking coin is not committed to the canonical swap script")]
    LockScriptMismatch,
    #[error("auction step count {0} is outside its bound")]
    InvalidStepCount(usize),
    #[error("reverse-Dutch prices are invalid")]
    InvalidPriceSchedule,
    #[error("reverse-Dutch lock times are invalid")]
    InvalidLockSchedule,
    #[error("reverse-Dutch schedule is not canonical")]
    NonCanonicalSchedule,
    #[error("auction steps do not describe the same listing")]
    InconsistentAuction,
    #[error("fixed-price listing sequence must be nonzero")]
    ZeroListingSequence,
    #[error("fixed-price listing version {0} is unsupported")]
    UnsupportedListingVersion(u16),
    #[error("fixed-price listing expiration must be later than its creation time")]
    InvalidListingLifetime,
    #[error("fixed-price listing is {0} bytes, exceeding the configured bound")]
    ListingTooLarge(usize),
    #[error("fixed-price listing must contain a signed Shakedex presign")]
    UnsignedListingProof,
    #[error("fixed-price listing is unsigned")]
    UnsignedListing,
    #[error("fixed-price listing hash does not match its canonical contents")]
    ListingHashMismatch,
    #[error("fixed-price listing has not reached its creation time")]
    ListingNotYetActive,
    #[error("fixed-price listing has expired")]
    ListingExpired,
    #[error("listing cancellation sequence must be nonzero")]
    ZeroCancellationSequence,
    #[error("listing cancellation version {0} is unsupported")]
    UnsupportedCancellationVersion(u16),
    #[error("listing cancellation expiration must be later than its creation time")]
    InvalidCancellationLifetime,
    #[error("listing cancellation is {0} bytes, exceeding the configured bound")]
    CancellationTooLarge(usize),
    #[error("listing cancellation is unsigned")]
    UnsignedCancellation,
    #[error("listing cancellation hash does not match its canonical contents")]
    CancellationHashMismatch,
    #[error("listing cancellation does not identify the supplied listing")]
    CancellationListingMismatch,
    #[error("listing cancellation sequence is not newer than the listing sequence")]
    CancellationSequenceNotNewer,
    #[error("listing cancellation expires before the listing")]
    CancellationExpiresTooEarly,
    #[error("listing cancellation has not reached its creation time")]
    CancellationNotYetActive,
    #[error("listing cancellation has expired")]
    CancellationExpired,
    #[error("marketplace signature has noncanonical high-S form")]
    HighMarketplaceSignature,
    #[error("HTLC descriptor version {0} is unsupported")]
    UnsupportedHtlcVersion(u16),
    #[error("HNS HTLC descriptor is {0} bytes, exceeding the configured bound")]
    HtlcTooLarge(usize),
    #[error("HNS HTLC value must be nonzero")]
    ZeroHtlcValue,
    #[error("HNS HTLC hashlock must be nonzero")]
    ZeroHtlcHashlock,
    #[error("HNS HTLC receiver and refund public keys must be distinct")]
    HtlcKeyReuse,
    #[error("HNS HTLC refund locktime must be nonzero")]
    ZeroHtlcRefundLocktime,
    #[error("HNS HTLC funding output has the wrong value")]
    HtlcValueMismatch,
    #[error("HNS HTLC funding output has the wrong script address")]
    HtlcAddressMismatch,
    #[error("HNS HTLC funding output must use the NONE covenant")]
    HtlcCovenantMismatch,
    #[error("HNS HTLC funding output index {requested} is outside {outputs} outputs")]
    HtlcFundingOutputIndex { requested: usize, outputs: usize },
    #[error("HNS HTLC spend input index {requested} is outside {inputs} inputs")]
    HtlcSpendInputIndex { requested: usize, inputs: usize },
    #[error("HNS HTLC spend input does not reference the supplied funding coin")]
    HtlcOutpointMismatch,
    #[error("HNS HTLC witness signature uses invalid hash type 0x{0:02x}")]
    InvalidHtlcSignatureHashType(u8),
    #[error("HNS HTLC witness signature is malformed")]
    InvalidHtlcSignature,
    #[error("HNS HTLC witness signature has noncanonical high-S form")]
    HighHtlcSignature,
    #[error("HNS HTLC preimage does not match the descriptor hashlock")]
    HtlcPreimageMismatch,
    #[error("HNS HTLC witness does not have a canonical redeem or refund layout")]
    InvalidHtlcWitness,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
}

#[cfg(test)]
mod tests {
    use hns_primitives::Height;

    use super::*;

    fn unsigned_proof(signing_key: &SigningKey) -> SwapProof {
        let public_key = signing_key.verifying_key().to_encoded_point(true);
        SwapProof {
            network: NetworkBinding {
                magic: 0x5b6e_c393,
                genesis: BlockHash::new([0x11; 32]),
            },
            locking_outpoint: Outpoint {
                transaction_hash: TransactionHash::new([0x22; 32]),
                index: 3,
            },
            name: b"handshake".to_vec(),
            seller_public_key: public_key.as_bytes().try_into().expect("33 bytes"),
            payment_address: Address::new(0, vec![0x33; 20]).expect("address"),
            price: Dollarydoos::new(1_000_000),
            lock_time_seconds: 512,
            signature: None,
            fee_address: None,
            fee: Dollarydoos::new(0),
        }
    }

    fn locking_coin(proof: &SwapProof) -> Coin {
        Coin {
            outpoint: proof.locking_outpoint,
            value: Dollarydoos::new(42),
            height: Height::new(10),
            coinbase: false,
            address: Address::new(0, lock_script_hash(&proof.seller_public_key).to_vec())
                .expect("address"),
            covenant: Covenant {
                kind: CovenantKind::Finalize,
                items: vec![
                    hash_name(&proof.name).expect("name").into_bytes().to_vec(),
                    1_u32.to_le_bytes().to_vec(),
                    proof.name.clone(),
                ],
            },
        }
    }

    #[test]
    fn shakedex_v2_script_layout_and_seller_signature_verify() {
        let signing_key = SigningKey::from_slice(&[7; 32]).expect("key");
        let mut proof = unsigned_proof(&signing_key);
        let expected = format!(
            "d059876321{}ac67d05a8768",
            hex::encode(proof.seller_public_key)
        );
        assert_eq!(
            hex::encode(create_lock_script(&proof.seller_public_key)),
            expected
        );
        let coin = locking_coin(&proof);
        proof.sign(&coin, &signing_key).expect("signed proof");
        proof.verify(&coin).expect("valid proof");
        let encoded = proof.encode().expect("encoded");
        assert_eq!(SwapProof::decode(&encoded).expect("decoded"), proof);
        assert_ne!(proof.offer_id().expect("offer"), OfferId::default());

        let mut tampered = proof.clone();
        tampered.price = Dollarydoos::new(proof.price.get() + 1);
        assert!(tampered.verify(&coin).is_err());
    }

    #[test]
    fn lower_dutch_price_cannot_execute_before_its_locktime() {
        let schedule = canonical_reverse_dutch_schedule(
            Dollarydoos::new(100),
            Dollarydoos::new(10),
            10 * 512,
            20 * 512,
            3,
        )
        .expect("schedule");
        assert_eq!(schedule[0].price.get(), 100);
        assert_eq!(schedule[2].price.get(), 10);
        let signing_key = SigningKey::from_slice(&[8; 32]).expect("key");
        let mut proofs = Vec::new();
        for step in schedule {
            let mut proof = unsigned_proof(&signing_key);
            proof.price = step.price;
            proof.lock_time_seconds = step.lock_time_seconds;
            let coin = locking_coin(&proof);
            proof.sign(&coin, &signing_key).expect("signed proof");
            proofs.push(proof);
        }
        let coin = locking_coin(&proofs[0]);
        let auction =
            DutchAuction::new_verified(proofs, unsigned_proof(&signing_key).network, &coin)
                .expect("auction");
        assert!(auction.best_executable(10 * 512).expect("query").is_none());
        assert_eq!(
            auction
                .best_executable(10 * 512 + 1)
                .expect("query")
                .expect("first")
                .price
                .get(),
            100
        );
        assert_eq!(
            auction
                .best_executable(20 * 512)
                .expect("query")
                .expect("middle")
                .price
                .get(),
            55
        );
        assert_eq!(
            auction
                .best_executable(20 * 512 + 1)
                .expect("query")
                .expect("last")
                .price
                .get(),
            10
        );
    }

    #[test]
    fn proof_parser_rejects_trailing_bytes_wrong_network_coin_and_high_s() {
        let signing_key = SigningKey::from_slice(&[9; 32]).expect("key");
        let mut proof = unsigned_proof(&signing_key);
        let coin = locking_coin(&proof);
        proof.sign(&coin, &signing_key).expect("signed proof");
        let mut encoded = proof.encode().expect("encoded");
        encoded.push(0);
        assert!(SwapProof::decode(&encoded).is_err());

        let mut wrong_coin = coin.clone();
        wrong_coin.outpoint.index += 1;
        assert!(proof.verify(&wrong_coin).is_err());

        let mut wrong_network = proof.clone();
        wrong_network.network.magic ^= 1;
        assert!(
            wrong_network
                .verify_for_network(proof.network, &coin)
                .is_err()
        );
        assert_ne!(
            proof.offer_id().expect("id"),
            wrong_network.offer_id().expect("id")
        );
    }
}
