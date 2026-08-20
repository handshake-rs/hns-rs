use hns_encoding::Decoder;
use hns_primitives::Dollarydoos;
use hns_swap::{
    HnsHtlc, HsdTimeLock, NetworkBinding as HnsNetworkBinding, encode_time_lock_not_before,
};

use crate::crypto;
use crate::types::encode_fixed_versioned;
use crate::{
    AssetAmount, AssetId, ChainId, FillGrant, MarketIntent, MarketplaceError, NetworkBinding,
    PriceRound, PriceRoundVerifier, Result, SignedObjectHeader,
};

pub const MAX_SWAP_MESSAGE_SIZE: usize = 8 * 1024;
pub const MAX_SETTLEMENT_UNIX_TIME: u64 = 0x7fff_ffff;

const SESSION_HELLO_MAKER_SIGNATURE_DOMAIN: &[u8] = b"HNS-MARKET-SWAP-SESSION-HELLO-MAKER-V1\0";
const SESSION_HELLO_TAKER_SIGNATURE_DOMAIN: &[u8] = b"HNS-MARKET-SWAP-SESSION-HELLO-TAKER-V1\0";
const FUNDING_STATUS_SIGNATURE_DOMAIN: &[u8] = b"HNS-MARKET-SWAP-FUNDING-STATUS-V1\0";
const REDEEM_STATUS_SIGNATURE_DOMAIN: &[u8] = b"HNS-MARKET-SWAP-REDEEM-STATUS-V1\0";
const REFUND_STATUS_SIGNATURE_DOMAIN: &[u8] = b"HNS-MARKET-SWAP-REFUND-STATUS-V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DeadlineKind {
    BlockHeight = 1,
    UnixTime = 2,
}

impl TryFrom<u8> for DeadlineKind {
    type Error = MarketplaceError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::BlockHeight),
            2 => Ok(Self::UnixTime),
            _ => Err(MarketplaceError::Invalid(
                "unknown settlement deadline kind",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettlementDeadline {
    pub kind: DeadlineKind,
    pub value: u64,
}

impl SettlementDeadline {
    pub fn validate(self) -> Result<()> {
        if self.value == 0
            || (self.kind == DeadlineKind::BlockHeight && self.value > u64::from(u32::MAX))
            || (self.kind == DeadlineKind::UnixTime && self.value > MAX_SETTLEMENT_UNIX_TIME)
        {
            Err(MarketplaceError::Invalid("invalid settlement deadline"))
        } else {
            Ok(())
        }
    }

    pub fn encode(self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut encoder = hns_encoding::Encoder::with_capacity(9);
        self.encode_to(&mut encoder);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(input);
        let deadline = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        Ok(deadline)
    }

    fn encode_to(self, encoder: &mut hns_encoding::Encoder) {
        encoder.put_u8(self.kind as u8);
        encoder.put_u64_le(self.value);
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        let deadline = Self {
            kind: DeadlineKind::try_from(decoder.read_u8()?)?,
            value: decoder.read_u64_le()?,
        };
        deadline.validate()?;
        Ok(deadline)
    }
}

/// Selects the maker-offered or maker-received side of a swap agreement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwapAssetSide {
    Offered,
    Received,
}

/// Exact native-HNS descriptor and timing identity bound into one session
/// hello side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsHtlcSessionBinding {
    pub descriptor: HnsHtlc,
    pub descriptor_hash: [u8; 32],
    pub promised_refund_unix_time: u64,
    pub effective_refund_unix_time: u64,
}

/// Convert a marketplace Unix safety deadline to HSD's encoded median-time
/// lock without allowing 512-second granularity to shorten the promise.
pub fn hns_refund_time_lock(deadline: SettlementDeadline) -> Result<HsdTimeLock> {
    deadline.validate()?;
    if deadline.kind != DeadlineKind::UnixTime {
        return Err(MarketplaceError::Invalid(
            "native HNS HTLC refunds require a Unix deadline",
        ));
    }
    Ok(encode_time_lock_not_before(deadline.value)?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwapSessionHello {
    pub header: SignedObjectHeader,
    pub fill_grant_hash: [u8; 32],
    pub swap_session_id: [u8; 32],
    /// Independent per-session settlement authority delegated by the maker's
    /// signed fill grant.
    pub maker_settlement_public_key: [u8; 33],
    /// Ephemeral settlement authority supplied by the match requester (taker).
    pub taker_settlement_public_key: [u8; 33],
    pub offered_asset: AssetId,
    pub offered_amount: AssetAmount,
    pub received_asset: AssetId,
    pub received_amount: AssetAmount,
    pub price_round_hash: [u8; 32],
    pub hashlock: [u8; 32],
    pub first_funding_chain: ChainId,
    pub offered_lock_commitment: [u8; 32],
    pub offered_refund_deadline: SettlementDeadline,
    pub offered_minimum_confirmations: u32,
    pub received_lock_commitment: [u8; 32],
    pub received_refund_deadline: SettlementDeadline,
    pub received_minimum_confirmations: u32,
    pub maker_signature: [u8; 64],
    pub taker_signature: [u8; 64],
}

impl SwapSessionHello {
    /// Sign the complete proposed terms as the maker. The taker authority is
    /// already part of the signed terms and cannot be substituted afterward.
    pub fn sign_maker(&mut self, private_key: &[u8; 32]) -> Result<()> {
        let public_key = crypto::public_key(private_key)?;
        if self.maker_settlement_public_key != [0; 33]
            && self.maker_settlement_public_key != public_key
        {
            return Err(MarketplaceError::SigningKeyMismatch);
        }
        self.maker_settlement_public_key = public_key;
        self.validate_fields()?;
        self.maker_signature = crypto::sign(
            SESSION_HELLO_MAKER_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.maker_settlement_public_key,
            private_key,
        )?;
        Ok(())
    }

    /// Sign these complete terms as the maker and convert them into the
    /// canonical wire object that the designated taker can independently
    /// verify before countersigning.
    pub fn into_maker_proposal(mut self, private_key: &[u8; 32]) -> Result<SwapSessionProposal> {
        self.taker_signature = [0; 64];
        self.sign_maker(private_key)?;
        SwapSessionProposal::from_maker_signed(self)
    }

    /// Accept the maker-signed terms as the designated taker. This refuses to
    /// sign an unauthenticated maker proposal.
    pub fn accept_taker(&mut self, private_key: &[u8; 32]) -> Result<()> {
        let public_key = crypto::public_key(private_key)?;
        if self.taker_settlement_public_key != public_key {
            return Err(MarketplaceError::SigningKeyMismatch);
        }
        self.validate_fields()?;
        self.verify_maker_signature()?;
        self.taker_signature = crypto::sign(
            SESSION_HELLO_TAKER_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.taker_settlement_public_key,
            private_key,
        )?;
        Ok(())
    }

    pub fn verify_at(&self, expected_network: NetworkBinding, now: u64) -> Result<()> {
        self.verify_agreement(expected_network)?;
        if now >= self.received_refund_deadline.value {
            return Err(MarketplaceError::Expired {
                expires_at: self.received_refund_deadline.value,
                now,
            });
        }
        self.header.validate_at(expected_network, now)?;
        Ok(())
    }

    fn verify_maker_proposal_at(&self, expected_network: NetworkBinding, now: u64) -> Result<()> {
        self.validate_fields()?;
        if self.header.network != expected_network {
            return Err(MarketplaceError::NetworkMismatch);
        }
        if now >= self.received_refund_deadline.value {
            return Err(MarketplaceError::Expired {
                expires_at: self.received_refund_deadline.value,
                now,
            });
        }
        self.header.validate_at(expected_network, now)?;
        self.verify_maker_signature()
    }

    /// Action gate for admitting a new funding broadcast. Historical funding
    /// and reorg status validation deliberately uses [`Self::verify_agreement`]
    /// instead, because receiving a status cannot create new funding.
    pub fn verify_new_funding_at(&self, expected_network: NetworkBinding, now: u64) -> Result<()> {
        self.verify_at(expected_network, now)
    }

    /// Verify both parties' acceptance without requiring that the funding
    /// window is still open. Recovery/status consumers use this after a
    /// deadline; new funding must use [`Self::verify_at`].
    pub fn verify_agreement(&self, expected_network: NetworkBinding) -> Result<()> {
        self.validate_fields()?;
        if self.header.network != expected_network {
            return Err(MarketplaceError::NetworkMismatch);
        }
        self.verify_signatures()
    }

    pub fn verify_for_grant(
        &self,
        intent: &MarketIntent,
        grant: &FillGrant,
        round: &PriceRound,
        verifier: PriceRoundVerifier<'_>,
        previous_round: Option<&PriceRound>,
        now: u64,
    ) -> Result<()> {
        let expected_network =
            self.verify_terms_for_grant(intent, grant, round, verifier, previous_round, now)?;
        self.verify_at(expected_network, now)
    }

    fn verify_terms_for_grant(
        &self,
        intent: &MarketIntent,
        grant: &FillGrant,
        round: &PriceRound,
        verifier: PriceRoundVerifier<'_>,
        previous_round: Option<&PriceRound>,
        now: u64,
    ) -> Result<NetworkBinding> {
        let expected_network = verifier.expected_network();
        grant.verify_for_price_round(intent, round, verifier, previous_round, now)?;
        let received_asset = intent.header.pair.other(intent.offered_asset)?;
        if self.fill_grant_hash != grant.grant_hash
            || self.swap_session_id != grant.swap_session_id
            || self.price_round_hash != grant.price_round_hash
            || self.header.network != grant.header.network
            || self.header.pair != grant.header.pair
            || self.header.signer_public_key != grant.header.signer_public_key
            || self.maker_settlement_public_key != grant.maker_settlement_key
            || self.taker_settlement_public_key != grant.counterparty_settlement_key
            || self.offered_asset != intent.offered_asset
            || self.received_asset != received_asset
            || self.offered_amount != grant.offered_amount
            || self.received_amount != grant.received_amount
            || self.header.sequence <= grant.header.sequence
            || self.header.created_at < grant.header.created_at
            || self.header.expires_at > grant.header.expires_at
        {
            return Err(MarketplaceError::Invalid(
                "swap session hello does not bind its fill grant",
            ));
        }
        Ok(expected_network)
    }

    /// Construct and commit the exact native-HNS HTLC for one side of this
    /// proposed agreement. The other chain's lock commitment remains the
    /// responsibility of its canonical adapter.
    pub fn build_and_bind_hns_htlc(
        &mut self,
        side: SwapAssetSide,
        receiver_public_key: [u8; 33],
        refund_public_key: [u8; 33],
    ) -> Result<HnsHtlcSessionBinding> {
        let binding = self.build_hns_htlc(side, receiver_public_key, refund_public_key)?;
        match side {
            SwapAssetSide::Offered => self.offered_lock_commitment = binding.descriptor_hash,
            SwapAssetSide::Received => self.received_lock_commitment = binding.descriptor_hash,
        }
        Ok(binding)
    }

    /// Construct the exact native-HNS descriptor implied by one session side
    /// without mutating the hello.
    pub fn build_hns_htlc(
        &self,
        side: SwapAssetSide,
        receiver_public_key: [u8; 33],
        refund_public_key: [u8; 33],
    ) -> Result<HnsHtlcSessionBinding> {
        self.header.validate()?;
        if self.hashlock == [0; 32] {
            return Err(MarketplaceError::Invalid("zero SHA-256 hashlock"));
        }
        let (asset, amount, deadline) = self.hns_side_terms(side);
        if asset != AssetId::HNS {
            return Err(MarketplaceError::Invalid(
                "selected swap side is not native HNS",
            ));
        }
        let amount = u64::try_from(amount.get()).map_err(|_| {
            MarketplaceError::Invalid("native HNS amount exceeds the exact u64 range")
        })?;
        if amount == 0 {
            return Err(MarketplaceError::Invalid("native HNS amount is zero"));
        }
        let time_lock = hns_refund_time_lock(deadline)?;
        let descriptor = HnsHtlc {
            network: HnsNetworkBinding {
                magic: self.header.network.hns_magic,
                genesis: self.header.network.hns_genesis,
            },
            value: Dollarydoos::new(amount),
            hashlock: self.hashlock,
            receiver_public_key,
            refund_public_key,
            refund_locktime: time_lock.encoded,
        };
        descriptor.validate()?;
        Ok(HnsHtlcSessionBinding {
            descriptor,
            descriptor_hash: descriptor.descriptor_hash()?,
            promised_refund_unix_time: deadline.value,
            effective_refund_unix_time: time_lock.effective_time_seconds,
        })
    }

    /// Verify that an externally supplied descriptor is exactly the native-HNS
    /// lock frozen into one side of this signed agreement.
    pub fn verify_hns_htlc(
        &self,
        side: SwapAssetSide,
        descriptor: &HnsHtlc,
    ) -> Result<HnsHtlcSessionBinding> {
        self.verify_signatures()?;
        let expected = self.build_hns_htlc(
            side,
            descriptor.receiver_public_key,
            descriptor.refund_public_key,
        )?;
        let committed = match side {
            SwapAssetSide::Offered => self.offered_lock_commitment,
            SwapAssetSide::Received => self.received_lock_commitment,
        };
        if descriptor != &expected.descriptor || committed != expected.descriptor_hash {
            return Err(MarketplaceError::Invalid(
                "native HNS HTLC differs from the swap session",
            ));
        }
        Ok(expected)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.verify_signatures()?;
        encode_fixed_versioned(MAX_SWAP_MESSAGE_SIZE, |encoder| {
            encoder.put_bytes(&self.encode_unsigned()?);
            encoder.put_bytes(&self.maker_signature);
            encoder.put_bytes(&self.taker_signature);
            Ok(())
        })
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        check_input(input)?;
        let mut decoder = Decoder::new(input);
        let mut message = Self::decode_unsigned_from(&mut decoder)?;
        message.maker_signature = decoder.read_array()?;
        message.taker_signature = decoder.read_array()?;
        decoder.finish()?;
        message.validate_fields()?;
        message.verify_signatures()?;
        Ok(message)
    }

    fn decode_unsigned_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        let message = Self {
            header: SignedObjectHeader::decode_from(decoder)?,
            fill_grant_hash: decoder.read_array()?,
            swap_session_id: decoder.read_array()?,
            maker_settlement_public_key: decoder.read_array()?,
            taker_settlement_public_key: decoder.read_array()?,
            offered_asset: AssetId::decode_from(decoder)?,
            offered_amount: AssetAmount::decode_from(decoder)?,
            received_asset: AssetId::decode_from(decoder)?,
            received_amount: AssetAmount::decode_from(decoder)?,
            price_round_hash: decoder.read_array()?,
            hashlock: decoder.read_array()?,
            first_funding_chain: ChainId::decode_from(decoder)?,
            offered_lock_commitment: decoder.read_array()?,
            offered_refund_deadline: SettlementDeadline::decode_from(decoder)?,
            offered_minimum_confirmations: decoder.read_u32_le()?,
            received_lock_commitment: decoder.read_array()?,
            received_refund_deadline: SettlementDeadline::decode_from(decoder)?,
            received_minimum_confirmations: decoder.read_u32_le()?,
            maker_signature: [0; 64],
            taker_signature: [0; 64],
        };
        message.validate_fields()?;
        Ok(message)
    }

    fn validate_fields(&self) -> Result<()> {
        self.header.validate()?;
        crypto::validate_public_key(&self.maker_settlement_public_key)?;
        crypto::validate_public_key(&self.taker_settlement_public_key)?;
        self.offered_refund_deadline.validate()?;
        self.received_refund_deadline.validate()?;
        if self.header.signer_public_key == self.maker_settlement_public_key
            || self.header.signer_public_key == self.taker_settlement_public_key
            || self.maker_settlement_public_key == self.taker_settlement_public_key
            || self.fill_grant_hash == [0; 32]
            || self.swap_session_id == [0; 32]
            || self.price_round_hash == [0; 32]
            || self.hashlock == [0; 32]
            || self.offered_lock_commitment == [0; 32]
            || self.received_lock_commitment == [0; 32]
            || self.offered_minimum_confirmations == 0
            || self.received_minimum_confirmations == 0
            || self.offered_amount == AssetAmount::ZERO
            || self.received_amount == AssetAmount::ZERO
            || self.offered_asset == self.received_asset
            || !self.header.pair.contains(self.offered_asset)
            || !self.header.pair.contains(self.received_asset)
            || self.first_funding_chain != self.offered_asset.chain()
            || self.offered_refund_deadline.kind != DeadlineKind::UnixTime
            || self.received_refund_deadline.kind != DeadlineKind::UnixTime
            || self.offered_refund_deadline.value <= self.received_refund_deadline.value
            || self.header.expires_at > self.received_refund_deadline.value
        {
            return Err(MarketplaceError::Invalid("invalid swap session hello"));
        }
        Ok(())
    }

    fn hns_side_terms(&self, side: SwapAssetSide) -> (AssetId, AssetAmount, SettlementDeadline) {
        match side {
            SwapAssetSide::Offered => (
                self.offered_asset,
                self.offered_amount,
                self.offered_refund_deadline,
            ),
            SwapAssetSide::Received => (
                self.received_asset,
                self.received_amount,
                self.received_refund_deadline,
            ),
        }
    }

    fn verify_maker_signature(&self) -> Result<()> {
        crypto::verify(
            SESSION_HELLO_MAKER_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.maker_signature,
            &self.maker_settlement_public_key,
        )
    }

    fn verify_signatures(&self) -> Result<()> {
        self.verify_maker_signature()?;
        crypto::verify(
            SESSION_HELLO_TAKER_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.taker_signature,
            &self.taker_settlement_public_key,
        )
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.validate_fields()?;
        encode_fixed_versioned(MAX_SWAP_MESSAGE_SIZE - 128, |encoder| {
            self.header.encode_to(encoder);
            encoder.put_bytes(&self.fill_grant_hash);
            encoder.put_bytes(&self.swap_session_id);
            encoder.put_bytes(&self.maker_settlement_public_key);
            encoder.put_bytes(&self.taker_settlement_public_key);
            self.offered_asset.encode_to(encoder);
            self.offered_amount.encode_to(encoder);
            self.received_asset.encode_to(encoder);
            self.received_amount.encode_to(encoder);
            encoder.put_bytes(&self.price_round_hash);
            encoder.put_bytes(&self.hashlock);
            self.first_funding_chain.encode_to(encoder);
            encoder.put_bytes(&self.offered_lock_commitment);
            self.offered_refund_deadline.encode_to(encoder);
            encoder.put_u32_le(self.offered_minimum_confirmations);
            encoder.put_bytes(&self.received_lock_commitment);
            self.received_refund_deadline.encode_to(encoder);
            encoder.put_u32_le(self.received_minimum_confirmations);
            Ok(())
        })
    }

    fn funding_authority(&self, chain: ChainId) -> Result<[u8; 33]> {
        if chain == self.offered_asset.chain() {
            Ok(self.maker_settlement_public_key)
        } else if chain == self.received_asset.chain() {
            Ok(self.taker_settlement_public_key)
        } else {
            Err(MarketplaceError::Invalid(
                "settlement chain is outside the swap session",
            ))
        }
    }

    fn redeem_authority(&self, chain: ChainId) -> Result<[u8; 33]> {
        if chain == self.received_asset.chain() {
            Ok(self.maker_settlement_public_key)
        } else if chain == self.offered_asset.chain() {
            Ok(self.taker_settlement_public_key)
        } else {
            Err(MarketplaceError::Invalid(
                "settlement chain is outside the swap session",
            ))
        }
    }
}

/// Canonical maker-signed session terms sent to the grant-designated taker
/// before a fully accepted [`SwapSessionHello`] exists.
///
/// This distinct wire type closes the two-party signing round trip without
/// weakening the funding boundary: a proposal cannot be used where a fully
/// countersigned hello is required, and accepting it verifies the maker's
/// signature before adding the taker signature over the identical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwapSessionProposal {
    hello: SwapSessionHello,
}

impl SwapSessionProposal {
    pub fn from_maker_signed(hello: SwapSessionHello) -> Result<Self> {
        if hello.taker_signature != [0; 64] {
            return Err(MarketplaceError::Invalid(
                "swap session proposal already has a taker signature",
            ));
        }
        hello.validate_fields()?;
        hello.verify_maker_signature()?;
        Ok(Self { hello })
    }

    pub const fn terms(&self) -> &SwapSessionHello {
        &self.hello
    }

    pub fn verify_at(&self, expected_network: NetworkBinding, now: u64) -> Result<()> {
        self.hello.verify_maker_proposal_at(expected_network, now)
    }

    pub fn verify_for_grant(
        &self,
        intent: &MarketIntent,
        grant: &FillGrant,
        round: &PriceRound,
        verifier: PriceRoundVerifier<'_>,
        previous_round: Option<&PriceRound>,
        now: u64,
    ) -> Result<()> {
        let expected_network = self.hello.verify_terms_for_grant(
            intent,
            grant,
            round,
            verifier,
            previous_round,
            now,
        )?;
        self.verify_at(expected_network, now)
    }

    pub fn accept_taker(
        mut self,
        expected_network: NetworkBinding,
        now: u64,
        private_key: &[u8; 32],
    ) -> Result<SwapSessionHello> {
        self.verify_at(expected_network, now)?;
        self.hello.accept_taker(private_key)?;
        self.hello.verify_signatures()?;
        Ok(self.hello)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.hello.validate_fields()?;
        if self.hello.taker_signature != [0; 64] {
            return Err(MarketplaceError::Invalid(
                "swap session proposal already has a taker signature",
            ));
        }
        self.hello.verify_maker_signature()?;
        encode_fixed_versioned(MAX_SWAP_MESSAGE_SIZE, |encoder| {
            encoder.put_bytes(&self.hello.encode_unsigned()?);
            encoder.put_bytes(&self.hello.maker_signature);
            Ok(())
        })
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        check_input(input)?;
        let mut decoder = Decoder::new(input);
        let mut hello = SwapSessionHello::decode_unsigned_from(&mut decoder)?;
        hello.maker_signature = decoder.read_array()?;
        decoder.finish()?;
        Self::from_maker_signed(hello)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FundingState {
    Broadcast = 1,
    Seen = 2,
    Confirmed = 3,
    Reorged = 4,
}

impl TryFrom<u8> for FundingState {
    type Error = MarketplaceError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Broadcast),
            2 => Ok(Self::Seen),
            3 => Ok(Self::Confirmed),
            4 => Ok(Self::Reorged),
            _ => Err(MarketplaceError::Invalid("unknown funding state")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwapFundingStatus {
    pub header: SignedObjectHeader,
    pub swap_session_id: [u8; 32],
    pub chain: ChainId,
    pub lock_commitment: [u8; 32],
    pub transaction_id: [u8; 32],
    pub output_index: u32,
    pub amount: AssetAmount,
    pub confirmations: u32,
    pub state: FundingState,
    pub signature: [u8; 64],
}

impl SwapFundingStatus {
    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<()> {
        bind_signer(&mut self.header, private_key)?;
        self.signature = crypto::sign(
            FUNDING_STATUS_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.header.signer_public_key,
            private_key,
        )?;
        Ok(())
    }

    pub fn verify_at(&self, expected_network: NetworkBinding, now: u64) -> Result<()> {
        self.header.validate_at(expected_network, now)?;
        self.verify_signature()
    }

    pub fn verify_for_session(
        &self,
        hello: &SwapSessionHello,
        expected_network: NetworkBinding,
        now: u64,
    ) -> Result<()> {
        let expected_authority = hello.funding_authority(self.chain)?;
        verify_status_session(
            &self.header,
            self.swap_session_id,
            hello,
            expected_network,
            expected_authority,
        )?;
        let expected_amount = if self.chain == hello.offered_asset.chain() {
            hello.offered_amount
        } else if self.chain == hello.received_asset.chain() {
            hello.received_amount
        } else {
            return Err(MarketplaceError::Invalid(
                "funding status chain is outside the swap session",
            ));
        };
        if self.amount != expected_amount {
            return Err(MarketplaceError::Invalid(
                "funding status amount differs from the swap session",
            ));
        }
        let expected_commitment = if self.chain == hello.offered_asset.chain() {
            hello.offered_lock_commitment
        } else {
            hello.received_lock_commitment
        };
        if self.lock_commitment != expected_commitment {
            return Err(MarketplaceError::Invalid(
                "funding status lock differs from the swap session",
            ));
        }
        let minimum_confirmations = if self.chain == hello.offered_asset.chain() {
            hello.offered_minimum_confirmations
        } else {
            hello.received_minimum_confirmations
        };
        if self.state == FundingState::Confirmed && self.confirmations < minimum_confirmations {
            return Err(MarketplaceError::Invalid(
                "confirmed funding status is below the frozen confirmation minimum",
            ));
        }
        self.verify_at(expected_network, now)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_signed(&self.encode_unsigned()?, &self.signature, || {
            self.verify_signature()
        })
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        check_input(input)?;
        let mut decoder = Decoder::new(input);
        let message = Self {
            header: SignedObjectHeader::decode_from(&mut decoder)?,
            swap_session_id: decoder.read_array()?,
            chain: ChainId::decode_from(&mut decoder)?,
            lock_commitment: decoder.read_array()?,
            transaction_id: decoder.read_array()?,
            output_index: decoder.read_u32_le()?,
            amount: AssetAmount::decode_from(&mut decoder)?,
            confirmations: decoder.read_u32_le()?,
            state: FundingState::try_from(decoder.read_u8()?)?,
            signature: decoder.read_array()?,
        };
        decoder.finish()?;
        message.validate_fields()?;
        message.verify_signature()?;
        Ok(message)
    }

    fn validate_fields(&self) -> Result<()> {
        self.header.validate()?;
        let confirmed = self.state == FundingState::Confirmed;
        if self.swap_session_id == [0; 32]
            || self.transaction_id == [0; 32]
            || self.lock_commitment == [0; 32]
            || self.amount == AssetAmount::ZERO
            || !pair_contains_chain(&self.header, self.chain)
            || (self.chain == ChainId::ETHEREUM && self.output_index != 0)
            || confirmed != (self.confirmations > 0)
        {
            return Err(MarketplaceError::Invalid("invalid swap funding status"));
        }
        Ok(())
    }

    fn verify_signature(&self) -> Result<()> {
        verify_status(
            &self.header,
            FUNDING_STATUS_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.signature,
        )
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.validate_fields()?;
        encode_fixed_versioned(MAX_SWAP_MESSAGE_SIZE - 64, |encoder| {
            self.header.encode_to(encoder);
            encoder.put_bytes(&self.swap_session_id);
            self.chain.encode_to(encoder);
            encoder.put_bytes(&self.lock_commitment);
            encoder.put_bytes(&self.transaction_id);
            encoder.put_u32_le(self.output_index);
            self.amount.encode_to(encoder);
            encoder.put_u32_le(self.confirmations);
            encoder.put_u8(self.state as u8);
            Ok(())
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RedeemState {
    Broadcast = 1,
    Seen = 2,
    Confirmed = 3,
    Reorged = 4,
}

impl TryFrom<u8> for RedeemState {
    type Error = MarketplaceError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Broadcast),
            2 => Ok(Self::Seen),
            3 => Ok(Self::Confirmed),
            4 => Ok(Self::Reorged),
            _ => Err(MarketplaceError::Invalid("unknown redeem state")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwapRedeemStatus {
    pub header: SignedObjectHeader,
    pub swap_session_id: [u8; 32],
    pub chain: ChainId,
    pub transaction_id: [u8; 32],
    pub preimage_hash: [u8; 32],
    pub confirmations: u32,
    pub state: RedeemState,
    pub signature: [u8; 64],
}

impl SwapRedeemStatus {
    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<()> {
        bind_signer(&mut self.header, private_key)?;
        self.signature = crypto::sign(
            REDEEM_STATUS_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.header.signer_public_key,
            private_key,
        )?;
        Ok(())
    }

    pub fn verify_at(&self, expected_network: NetworkBinding, now: u64) -> Result<()> {
        self.header.validate_at(expected_network, now)?;
        self.verify_signature()
    }

    pub fn verify_for_session(
        &self,
        hello: &SwapSessionHello,
        expected_network: NetworkBinding,
        now: u64,
    ) -> Result<()> {
        let expected_authority = hello.redeem_authority(self.chain)?;
        verify_status_session(
            &self.header,
            self.swap_session_id,
            hello,
            expected_network,
            expected_authority,
        )?;
        if self.preimage_hash != hello.hashlock {
            return Err(MarketplaceError::Invalid(
                "redeem status hashlock differs from the swap session",
            ));
        }
        self.verify_at(expected_network, now)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_signed(&self.encode_unsigned()?, &self.signature, || {
            self.verify_signature()
        })
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        check_input(input)?;
        let mut decoder = Decoder::new(input);
        let message = Self {
            header: SignedObjectHeader::decode_from(&mut decoder)?,
            swap_session_id: decoder.read_array()?,
            chain: ChainId::decode_from(&mut decoder)?,
            transaction_id: decoder.read_array()?,
            preimage_hash: decoder.read_array()?,
            confirmations: decoder.read_u32_le()?,
            state: RedeemState::try_from(decoder.read_u8()?)?,
            signature: decoder.read_array()?,
        };
        decoder.finish()?;
        message.validate_fields()?;
        message.verify_signature()?;
        Ok(message)
    }

    fn validate_fields(&self) -> Result<()> {
        self.header.validate()?;
        let confirmed = self.state == RedeemState::Confirmed;
        if self.swap_session_id == [0; 32]
            || self.transaction_id == [0; 32]
            || self.preimage_hash == [0; 32]
            || !pair_contains_chain(&self.header, self.chain)
            || confirmed != (self.confirmations > 0)
        {
            return Err(MarketplaceError::Invalid("invalid swap redeem status"));
        }
        Ok(())
    }

    fn verify_signature(&self) -> Result<()> {
        verify_status(
            &self.header,
            REDEEM_STATUS_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.signature,
        )
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.validate_fields()?;
        encode_fixed_versioned(MAX_SWAP_MESSAGE_SIZE - 64, |encoder| {
            self.header.encode_to(encoder);
            encoder.put_bytes(&self.swap_session_id);
            self.chain.encode_to(encoder);
            encoder.put_bytes(&self.transaction_id);
            encoder.put_bytes(&self.preimage_hash);
            encoder.put_u32_le(self.confirmations);
            encoder.put_u8(self.state as u8);
            Ok(())
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RefundState {
    Broadcast = 1,
    Seen = 2,
    Confirmed = 3,
    Reorged = 4,
}

impl TryFrom<u8> for RefundState {
    type Error = MarketplaceError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Broadcast),
            2 => Ok(Self::Seen),
            3 => Ok(Self::Confirmed),
            4 => Ok(Self::Reorged),
            _ => Err(MarketplaceError::Invalid("unknown refund state")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwapRefundStatus {
    pub header: SignedObjectHeader,
    pub swap_session_id: [u8; 32],
    pub chain: ChainId,
    pub transaction_id: [u8; 32],
    pub confirmations: u32,
    pub state: RefundState,
    pub signature: [u8; 64],
}

impl SwapRefundStatus {
    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<()> {
        bind_signer(&mut self.header, private_key)?;
        self.signature = crypto::sign(
            REFUND_STATUS_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.header.signer_public_key,
            private_key,
        )?;
        Ok(())
    }

    pub fn verify_at(&self, expected_network: NetworkBinding, now: u64) -> Result<()> {
        self.header.validate_at(expected_network, now)?;
        self.verify_signature()
    }

    pub fn verify_for_session(
        &self,
        hello: &SwapSessionHello,
        expected_network: NetworkBinding,
        now: u64,
    ) -> Result<()> {
        let expected_authority = hello.funding_authority(self.chain)?;
        verify_status_session(
            &self.header,
            self.swap_session_id,
            hello,
            expected_network,
            expected_authority,
        )?;
        self.verify_at(expected_network, now)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_signed(&self.encode_unsigned()?, &self.signature, || {
            self.verify_signature()
        })
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        check_input(input)?;
        let mut decoder = Decoder::new(input);
        let message = Self {
            header: SignedObjectHeader::decode_from(&mut decoder)?,
            swap_session_id: decoder.read_array()?,
            chain: ChainId::decode_from(&mut decoder)?,
            transaction_id: decoder.read_array()?,
            confirmations: decoder.read_u32_le()?,
            state: RefundState::try_from(decoder.read_u8()?)?,
            signature: decoder.read_array()?,
        };
        decoder.finish()?;
        message.validate_fields()?;
        message.verify_signature()?;
        Ok(message)
    }

    fn validate_fields(&self) -> Result<()> {
        self.header.validate()?;
        let confirmed = self.state == RefundState::Confirmed;
        if self.swap_session_id == [0; 32]
            || self.transaction_id == [0; 32]
            || !pair_contains_chain(&self.header, self.chain)
            || confirmed != (self.confirmations > 0)
        {
            return Err(MarketplaceError::Invalid("invalid swap refund status"));
        }
        Ok(())
    }

    fn verify_signature(&self) -> Result<()> {
        verify_status(
            &self.header,
            REFUND_STATUS_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.signature,
        )
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.validate_fields()?;
        encode_fixed_versioned(MAX_SWAP_MESSAGE_SIZE - 64, |encoder| {
            self.header.encode_to(encoder);
            encoder.put_bytes(&self.swap_session_id);
            self.chain.encode_to(encoder);
            encoder.put_bytes(&self.transaction_id);
            encoder.put_u32_le(self.confirmations);
            encoder.put_u8(self.state as u8);
            Ok(())
        })
    }
}

fn bind_signer(header: &mut SignedObjectHeader, private_key: &[u8; 32]) -> Result<()> {
    let public_key = crypto::public_key(private_key)?;
    if header.signer_public_key != [0; 33] && header.signer_public_key != public_key {
        return Err(MarketplaceError::SigningKeyMismatch);
    }
    header.signer_public_key = public_key;
    header.validate()
}

fn verify_status(
    header: &SignedObjectHeader,
    domain: &[u8],
    unsigned: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    crypto::verify(domain, unsigned, signature, &header.signer_public_key)
}

fn verify_status_session(
    header: &SignedObjectHeader,
    swap_session_id: [u8; 32],
    hello: &SwapSessionHello,
    expected_network: NetworkBinding,
    expected_authority: [u8; 33],
) -> Result<()> {
    hello.verify_agreement(expected_network)?;
    if swap_session_id != hello.swap_session_id
        || header.network != hello.header.network
        || header.pair != hello.header.pair
        || header.signer_public_key != expected_authority
        || header.sequence <= hello.header.sequence
        || header.created_at < hello.header.created_at
    {
        return Err(MarketplaceError::Invalid(
            "swap status does not bind its session hello",
        ));
    }
    Ok(())
}

fn encode_signed<F>(unsigned: &[u8], signature: &[u8; 64], verify: F) -> Result<Vec<u8>>
where
    F: FnOnce() -> Result<()>,
{
    verify()?;
    encode_fixed_versioned(MAX_SWAP_MESSAGE_SIZE, |encoder| {
        encoder.put_bytes(unsigned);
        encoder.put_bytes(signature);
        Ok(())
    })
}

fn pair_contains_chain(header: &SignedObjectHeader, chain: ChainId) -> bool {
    header.pair.base.chain() == chain || header.pair.quote.chain() == chain
}

fn check_input(input: &[u8]) -> Result<()> {
    if input.len() > MAX_SWAP_MESSAGE_SIZE {
        Err(MarketplaceError::TooLarge {
            actual: input.len(),
            maximum: MAX_SWAP_MESSAGE_SIZE,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hns_primitives::BlockHash;

    use super::*;
    use crate::{CrossChainMessage, MARKETPLACE_PROTOCOL_VERSION, MarketPair};

    fn network() -> NetworkBinding {
        NetworkBinding {
            hns_magic: 0x5b6e_c393,
            hns_genesis: BlockHash::new([1; 32]),
            counterchain: ChainId::BITCOIN,
            counterchain_network: 1,
            counterchain_genesis: [2; 32],
        }
    }

    fn header(sequence: u64) -> SignedObjectHeader {
        SignedObjectHeader {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: network(),
            pair: MarketPair::HNS_BTC,
            signer_public_key: [0; 33],
            sequence,
            created_at: 100,
            expires_at: 200,
        }
    }

    fn unsigned_hello() -> SwapSessionHello {
        let mut hello_header = header(1);
        hello_header.signer_public_key = crypto::public_key(&[7; 32]).unwrap();
        let mut hello = SwapSessionHello {
            header: hello_header,
            fill_grant_hash: [3; 32],
            swap_session_id: [4; 32],
            maker_settlement_public_key: [0; 33],
            taker_settlement_public_key: crypto::public_key(&[8; 32]).unwrap(),
            offered_asset: AssetId::HNS,
            offered_amount: AssetAmount::new(1_000_000),
            received_asset: AssetId::BTC,
            received_amount: AssetAmount::new(10_000),
            price_round_hash: [5; 32],
            hashlock: HnsHtlc::hash_preimage(&[6; 32]),
            first_funding_chain: ChainId::HANDSHAKE,
            offered_lock_commitment: [10; 32],
            offered_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 800,
            },
            offered_minimum_confirmations: 5,
            received_lock_commitment: [11; 32],
            received_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 500,
            },
            received_minimum_confirmations: 6,
            maker_signature: [0; 64],
            taker_signature: [0; 64],
        };
        hello
            .build_and_bind_hns_htlc(
                SwapAssetSide::Offered,
                crypto::public_key(&[0x41; 32]).unwrap(),
                crypto::public_key(&[0x42; 32]).unwrap(),
            )
            .unwrap();
        hello
    }

    fn accepted_hello() -> SwapSessionHello {
        let mut hello = unsigned_hello();
        hello.sign_maker(&[9; 32]).unwrap();
        hello.accept_taker(&[8; 32]).unwrap();
        hello
    }

    #[test]
    fn session_hello_is_signed_bounded_and_canonical() {
        let proposal = unsigned_hello().into_maker_proposal(&[9; 32]).unwrap();
        proposal.verify_at(network(), 150).unwrap();
        assert!(proposal.terms().verify_at(network(), 150).is_err());
        let encoded_proposal = proposal.encode().unwrap();
        let decoded_proposal = SwapSessionProposal::decode(&encoded_proposal).unwrap();
        assert_eq!(decoded_proposal, proposal);
        let proposal_envelope = CrossChainMessage::SwapSessionProposal(proposal.clone())
            .encode_envelope(77)
            .unwrap();
        assert_eq!(
            CrossChainMessage::decode_envelope(&proposal_envelope).unwrap(),
            (77, CrossChainMessage::SwapSessionProposal(proposal.clone()))
        );
        assert!(matches!(
            proposal.clone().accept_taker(network(), 150, &[9; 32]),
            Err(MarketplaceError::SigningKeyMismatch)
        ));
        assert!(matches!(
            proposal.clone().accept_taker(network(), 500, &[8; 32]),
            Err(MarketplaceError::Expired { .. })
        ));
        let hello = decoded_proposal
            .accept_taker(network(), 150, &[8; 32])
            .unwrap();
        hello.verify_at(network(), 150).unwrap();
        assert!(SwapSessionProposal::from_maker_signed(hello.clone()).is_err());
        assert!(matches!(
            hello.verify_at(network(), 200),
            Err(MarketplaceError::Expired { .. })
        ));
        assert!(matches!(
            hello.verify_at(network(), 500),
            Err(MarketplaceError::Expired { .. })
        ));
        let encoded = hello.encode().unwrap();
        assert_eq!(SwapSessionHello::decode(&encoded).unwrap(), hello);
        let mut unsafe_timeouts = hello.clone();
        unsafe_timeouts.offered_refund_deadline.value = 400;
        unsafe_timeouts.maker_signature = [0; 64];
        unsafe_timeouts.taker_signature = [0; 64];
        assert!(unsafe_timeouts.sign_maker(&[9; 32]).is_err());
        let mut header_overrun = hello.clone();
        header_overrun.header.expires_at = 501;
        header_overrun.maker_signature = [0; 64];
        header_overrun.taker_signature = [0; 64];
        assert!(header_overrun.sign_maker(&[9; 32]).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(SwapSessionHello::decode(&trailing).is_err());
        let mut trailing_proposal = encoded_proposal;
        trailing_proposal.push(0);
        assert!(SwapSessionProposal::decode(&trailing_proposal).is_err());
    }

    #[test]
    fn status_replay_fields_and_signatures_are_enforced() {
        let hello = accepted_hello();

        let mut funding = SwapFundingStatus {
            header: header(2),
            swap_session_id: [4; 32],
            chain: ChainId::HANDSHAKE,
            lock_commitment: hello.offered_lock_commitment,
            transaction_id: [7; 32],
            output_index: 0,
            amount: AssetAmount::new(1_000_000),
            confirmations: 5,
            state: FundingState::Confirmed,
            signature: [0; 64],
        };
        funding.sign(&[9; 32]).unwrap();
        funding.verify_for_session(&hello, network(), 150).unwrap();
        let mut below_minimum = funding.clone();
        below_minimum.confirmations = hello.offered_minimum_confirmations - 1;
        below_minimum.signature = [0; 64];
        below_minimum.sign(&[9; 32]).unwrap();
        assert!(
            below_minimum
                .verify_for_session(&hello, network(), 150)
                .is_err()
        );
        let mut maker_only = hello.clone();
        maker_only.taker_signature = [0; 64];
        assert!(
            funding
                .verify_for_session(&maker_only, network(), 150)
                .is_err()
        );
        let mut taker_funding = funding.clone();
        taker_funding.header.signer_public_key = [0; 33];
        taker_funding.chain = ChainId::BITCOIN;
        taker_funding.lock_commitment = hello.received_lock_commitment;
        taker_funding.amount = hello.received_amount;
        taker_funding.confirmations = hello.received_minimum_confirmations;
        taker_funding.signature = [0; 64];
        taker_funding.sign(&[8; 32]).unwrap();
        taker_funding
            .verify_for_session(&hello, network(), 150)
            .unwrap();
        let mut third_party_funding = funding.clone();
        third_party_funding.header.signer_public_key = [0; 33];
        third_party_funding.signature = [0; 64];
        third_party_funding.sign(&[10; 32]).unwrap();
        assert!(
            third_party_funding
                .verify_for_session(&hello, network(), 150)
                .is_err()
        );
        let mut wrong_lock = funding.clone();
        wrong_lock.lock_commitment = [12; 32];
        assert!(
            wrong_lock
                .verify_for_session(&hello, network(), 150)
                .is_err()
        );
        assert_eq!(
            SwapFundingStatus::decode(&funding.encode().unwrap()).unwrap(),
            funding
        );
        let mut replay = funding.clone();
        replay.header.sequence += 1;
        assert!(replay.encode().is_err());

        let mut redeem = SwapRedeemStatus {
            header: header(3),
            swap_session_id: [4; 32],
            chain: ChainId::BITCOIN,
            transaction_id: [8; 32],
            preimage_hash: hello.hashlock,
            confirmations: 0,
            state: RedeemState::Seen,
            signature: [0; 64],
        };
        redeem.sign(&[9; 32]).unwrap();
        redeem.verify_for_session(&hello, network(), 150).unwrap();
        assert_eq!(
            SwapRedeemStatus::decode(&redeem.encode().unwrap()).unwrap(),
            redeem
        );
        let mut taker_redeem = redeem.clone();
        taker_redeem.header.signer_public_key = [0; 33];
        taker_redeem.chain = ChainId::HANDSHAKE;
        taker_redeem.signature = [0; 64];
        taker_redeem.sign(&[8; 32]).unwrap();
        taker_redeem
            .verify_for_session(&hello, network(), 150)
            .unwrap();
        let mut third_party_redeem = redeem.clone();
        third_party_redeem.header.signer_public_key = [0; 33];
        third_party_redeem.signature = [0; 64];
        third_party_redeem.sign(&[10; 32]).unwrap();
        assert!(
            third_party_redeem
                .verify_for_session(&hello, network(), 150)
                .is_err()
        );

        let mut refund = SwapRefundStatus {
            header: header(4),
            swap_session_id: [4; 32],
            chain: ChainId::HANDSHAKE,
            transaction_id: [9; 32],
            confirmations: 0,
            state: RefundState::Broadcast,
            signature: [0; 64],
        };
        refund.sign(&[9; 32]).unwrap();
        refund.verify_for_session(&hello, network(), 150).unwrap();
        assert_eq!(
            SwapRefundStatus::decode(&refund.encode().unwrap()).unwrap(),
            refund
        );
        let mut taker_refund = refund.clone();
        taker_refund.header.signer_public_key = [0; 33];
        taker_refund.chain = ChainId::BITCOIN;
        taker_refund.signature = [0; 64];
        taker_refund.sign(&[8; 32]).unwrap();
        taker_refund
            .verify_for_session(&hello, network(), 150)
            .unwrap();
        let mut third_party_refund = refund;
        third_party_refund.header.signer_public_key = [0; 33];
        third_party_refund.signature = [0; 64];
        third_party_refund.sign(&[10; 32]).unwrap();
        assert!(
            third_party_refund
                .verify_for_session(&hello, network(), 150)
                .is_err()
        );

        let mut historical = funding;
        historical.header.expires_at = 900;
        historical.header.signer_public_key = [0; 33];
        historical.state = FundingState::Reorged;
        historical.confirmations = 0;
        historical.signature = [0; 64];
        historical.sign(&[9; 32]).unwrap();
        historical
            .verify_for_session(&hello, network(), 550)
            .expect("historical reorg status remains verifiable after funding closes");
        assert!(hello.verify_new_funding_at(network(), 550).is_err());
    }

    #[test]
    fn native_hns_binding_is_exact_and_rounds_safety_deadline_up() {
        let hello = accepted_hello();
        let descriptor = hello
            .build_hns_htlc(
                SwapAssetSide::Offered,
                crypto::public_key(&[0x41; 32]).unwrap(),
                crypto::public_key(&[0x42; 32]).unwrap(),
            )
            .unwrap();
        assert_eq!(descriptor.promised_refund_unix_time, 800);
        assert_eq!(descriptor.effective_refund_unix_time, 1_024);
        assert_eq!(descriptor.descriptor.refund_locktime, 0x8000_0002);
        assert_eq!(descriptor.descriptor_hash, hello.offered_lock_commitment);
        hello
            .verify_hns_htlc(SwapAssetSide::Offered, &descriptor.descriptor)
            .unwrap();

        let mut wrong_amount = descriptor.descriptor;
        wrong_amount.value = Dollarydoos::new(wrong_amount.value.get() + 1);
        assert!(
            hello
                .verify_hns_htlc(SwapAssetSide::Offered, &wrong_amount)
                .is_err()
        );
        assert!(
            hello
                .build_hns_htlc(
                    SwapAssetSide::Received,
                    crypto::public_key(&[0x41; 32]).unwrap(),
                    crypto::public_key(&[0x42; 32]).unwrap(),
                )
                .is_err()
        );
    }
}
