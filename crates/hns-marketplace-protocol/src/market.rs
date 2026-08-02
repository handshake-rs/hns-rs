use hns_encoding::Decoder;

use crate::crypto;
use crate::types::encode_fixed_versioned;
use crate::{
    AssetAmount, AssetId, MarketplaceError, NetworkBinding, PriceRound, PriceRoundVerifier,
    RationalPrice, Result, Rounding, SignedObjectHeader,
};

pub const MAX_MARKET_OBJECT_SIZE: usize = 8 * 1024;

const INTENT_ID_DOMAIN: &[u8] = b"HNS-MARKET-INTENT-ID-V1\0";
const INTENT_SIGNATURE_DOMAIN: &[u8] = b"HNS-MARKET-INTENT-SIGNATURE-V1\0";
const INTENT_CANCEL_SIGNATURE_DOMAIN: &[u8] = b"HNS-MARKET-INTENT-CANCEL-V1\0";
const INTENT_CANCEL_HASH_DOMAIN: &[u8] = b"HNS-MARKET-INTENT-CANCEL-ID-V1\0";
const MATCH_REQUEST_SIGNATURE_DOMAIN: &[u8] = b"HNS-MARKET-MATCH-REQUEST-V1\0";
const MATCH_REJECT_SIGNATURE_DOMAIN: &[u8] = b"HNS-MARKET-MATCH-REJECT-V1\0";
const FILL_GRANT_ID_DOMAIN: &[u8] = b"HNS-MARKET-FILL-GRANT-ID-V1\0";
const FILL_GRANT_SIGNATURE_DOMAIN: &[u8] = b"HNS-MARKET-FILL-GRANT-SIGNATURE-V1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarketIntent {
    pub header: SignedObjectHeader,
    pub intent_id: [u8; 32],
    pub offered_asset: AssetId,
    pub maximum_amount: AssetAmount,
    pub minimum_fill: AssetAmount,
    pub partial_fills: bool,
    pub signature: [u8; 64],
}

impl MarketIntent {
    pub fn refresh_id(&mut self) -> Result<()> {
        self.intent_id = crypto::hash(INTENT_ID_DOMAIN, &self.encode_unsigned()?);
        Ok(())
    }

    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<()> {
        bind_signer(&mut self.header, private_key)?;
        self.refresh_id()?;
        self.signature = crypto::sign(
            INTENT_SIGNATURE_DOMAIN,
            &self.signature_bytes()?,
            &self.header.signer_public_key,
            private_key,
        )?;
        Ok(())
    }

    pub fn verify_at(&self, expected_network: NetworkBinding, now: u64) -> Result<()> {
        self.header.validate_at(expected_network, now)?;
        self.verify_id()?;
        crypto::verify(
            INTENT_SIGNATURE_DOMAIN,
            &self.signature_bytes()?,
            &self.signature,
            &self.header.signer_public_key,
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.verify_id()?;
        crypto::verify(
            INTENT_SIGNATURE_DOMAIN,
            &self.signature_bytes()?,
            &self.signature,
            &self.header.signer_public_key,
        )?;
        encode_fixed_versioned(MAX_MARKET_OBJECT_SIZE, |encoder| {
            encoder.put_bytes(&self.encode_unsigned()?);
            encoder.put_bytes(&self.intent_id);
            encoder.put_bytes(&self.signature);
            Ok(())
        })
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        check_input(input)?;
        let mut decoder = Decoder::new(input);
        let intent = Self {
            header: SignedObjectHeader::decode_from(&mut decoder)?,
            offered_asset: AssetId::decode_from(&mut decoder)?,
            maximum_amount: AssetAmount::decode_from(&mut decoder)?,
            minimum_fill: AssetAmount::decode_from(&mut decoder)?,
            partial_fills: decode_bool(&mut decoder)?,
            intent_id: decoder.read_array()?,
            signature: decoder.read_array()?,
        };
        decoder.finish()?;
        intent.validate_fields()?;
        intent.verify_id()?;
        crypto::verify(
            INTENT_SIGNATURE_DOMAIN,
            &intent.signature_bytes()?,
            &intent.signature,
            &intent.header.signer_public_key,
        )?;
        Ok(intent)
    }

    fn validate_fields(&self) -> Result<()> {
        self.header.validate()?;
        if !self.header.pair.contains(self.offered_asset)
            || self.maximum_amount == AssetAmount::ZERO
            || self.minimum_fill == AssetAmount::ZERO
            || self.minimum_fill > self.maximum_amount
            || (!self.partial_fills && self.minimum_fill != self.maximum_amount)
        {
            return Err(MarketplaceError::Invalid("invalid market-intent amounts"));
        }
        Ok(())
    }

    fn verify_id(&self) -> Result<()> {
        let expected = crypto::hash(INTENT_ID_DOMAIN, &self.encode_unsigned()?);
        if self.intent_id == expected {
            Ok(())
        } else {
            Err(MarketplaceError::HashMismatch)
        }
    }

    fn signature_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(32 + 256);
        bytes.extend_from_slice(&self.intent_id);
        bytes.extend_from_slice(&self.encode_unsigned()?);
        Ok(bytes)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.validate_fields()?;
        encode_fixed_versioned(MAX_MARKET_OBJECT_SIZE - 96, |encoder| {
            self.header.encode_to(encoder);
            self.offered_asset.encode_to(encoder);
            self.maximum_amount.encode_to(encoder);
            self.minimum_fill.encode_to(encoder);
            encoder.put_u8(u8::from(self.partial_fills));
            Ok(())
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarketIntentCancellation {
    pub header: SignedObjectHeader,
    pub intent_id: [u8; 32],
    pub intent_sequence: u64,
    pub signature: [u8; 64],
}

impl MarketIntentCancellation {
    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<()> {
        bind_signer(&mut self.header, private_key)?;
        self.signature = crypto::sign(
            INTENT_CANCEL_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.header.signer_public_key,
            private_key,
        )?;
        Ok(())
    }

    pub fn verify_for_intent(
        &self,
        intent: &MarketIntent,
        expected_network: NetworkBinding,
        now: u64,
    ) -> Result<()> {
        self.header.validate_at(expected_network, now)?;
        intent.encode()?;
        if self.intent_id != intent.intent_id
            || self.intent_sequence != intent.header.sequence
            || self.header.network != intent.header.network
            || self.header.pair != intent.header.pair
            || self.header.signer_public_key != intent.header.signer_public_key
            || self.header.sequence <= intent.header.sequence
            || self.header.created_at < intent.header.created_at
            || self.header.expires_at < intent.header.expires_at
        {
            return Err(MarketplaceError::Invalid(
                "intent cancellation does not bind its intent",
            ));
        }
        self.verify_signature()
    }

    pub fn cancellation_hash(&self) -> Result<[u8; 32]> {
        Ok(crypto::hash(INTENT_CANCEL_HASH_DOMAIN, &self.encode()?))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.verify_signature()?;
        encode_signed(&self.encode_unsigned()?, &self.signature)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        check_input(input)?;
        let mut decoder = Decoder::new(input);
        let cancellation = Self {
            header: SignedObjectHeader::decode_from(&mut decoder)?,
            intent_id: decoder.read_array()?,
            intent_sequence: decoder.read_u64_le()?,
            signature: decoder.read_array()?,
        };
        decoder.finish()?;
        cancellation.validate_fields()?;
        cancellation.verify_signature()?;
        Ok(cancellation)
    }

    fn validate_fields(&self) -> Result<()> {
        self.header.validate()?;
        if self.intent_id == [0; 32] || self.intent_sequence == 0 {
            return Err(MarketplaceError::Invalid("invalid intent cancellation"));
        }
        Ok(())
    }

    fn verify_signature(&self) -> Result<()> {
        crypto::verify(
            INTENT_CANCEL_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.signature,
            &self.header.signer_public_key,
        )
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.validate_fields()?;
        encode_fixed_versioned(MAX_MARKET_OBJECT_SIZE - 64, |encoder| {
            self.header.encode_to(encoder);
            encoder.put_bytes(&self.intent_id);
            encoder.put_u64_le(self.intent_sequence);
            Ok(())
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchRequest {
    pub header: SignedObjectHeader,
    pub intent_id: [u8; 32],
    pub intent_sequence: u64,
    pub swap_session_id: [u8; 32],
    pub settlement_public_key: [u8; 33],
    pub requested_amount: AssetAmount,
    pub signature: [u8; 64],
}

impl MatchRequest {
    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<()> {
        bind_signer(&mut self.header, private_key)?;
        self.signature = crypto::sign(
            MATCH_REQUEST_SIGNATURE_DOMAIN,
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

    pub fn verify_for_intent(&self, intent: &MarketIntent) -> Result<()> {
        self.encode()?;
        intent.encode()?;
        if self.intent_id != intent.intent_id
            || self.intent_sequence != intent.header.sequence
            || self.header.network != intent.header.network
            || self.header.pair != intent.header.pair
            || self.header.created_at < intent.header.created_at
            || self.header.expires_at > intent.header.expires_at
            || self.requested_amount > intent.maximum_amount
            || self.requested_amount < intent.minimum_fill
            || (!intent.partial_fills && self.requested_amount != intent.maximum_amount)
        {
            return Err(MarketplaceError::Invalid(
                "match request does not bind its intent",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.verify_signature()?;
        encode_signed(&self.encode_unsigned()?, &self.signature)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        check_input(input)?;
        let mut decoder = Decoder::new(input);
        let request = Self {
            header: SignedObjectHeader::decode_from(&mut decoder)?,
            intent_id: decoder.read_array()?,
            intent_sequence: decoder.read_u64_le()?,
            swap_session_id: decoder.read_array()?,
            settlement_public_key: decoder.read_array()?,
            requested_amount: AssetAmount::decode_from(&mut decoder)?,
            signature: decoder.read_array()?,
        };
        decoder.finish()?;
        request.validate_fields()?;
        request.verify_signature()?;
        Ok(request)
    }

    fn validate_fields(&self) -> Result<()> {
        self.header.validate()?;
        crypto::validate_public_key(&self.settlement_public_key)?;
        if self.intent_id == [0; 32]
            || self.intent_sequence == 0
            || self.swap_session_id == [0; 32]
            || self.requested_amount == AssetAmount::ZERO
        {
            return Err(MarketplaceError::Invalid("invalid match request"));
        }
        Ok(())
    }

    fn verify_signature(&self) -> Result<()> {
        crypto::verify(
            MATCH_REQUEST_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.signature,
            &self.header.signer_public_key,
        )
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.validate_fields()?;
        encode_fixed_versioned(MAX_MARKET_OBJECT_SIZE - 64, |encoder| {
            self.header.encode_to(encoder);
            encoder.put_bytes(&self.intent_id);
            encoder.put_u64_le(self.intent_sequence);
            encoder.put_bytes(&self.swap_session_id);
            encoder.put_bytes(&self.settlement_public_key);
            self.requested_amount.encode_to(encoder);
            Ok(())
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum MatchRejectReason {
    Unavailable = 1,
    Expired = 2,
    InsufficientBalance = 3,
    ReservationConflict = 4,
    UnsupportedTerms = 5,
    RateLimited = 6,
}

impl TryFrom<u16> for MatchRejectReason {
    type Error = MarketplaceError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::Unavailable),
            2 => Ok(Self::Expired),
            3 => Ok(Self::InsufficientBalance),
            4 => Ok(Self::ReservationConflict),
            5 => Ok(Self::UnsupportedTerms),
            6 => Ok(Self::RateLimited),
            _ => Err(MarketplaceError::Invalid("unknown match rejection reason")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchReject {
    pub header: SignedObjectHeader,
    pub intent_id: [u8; 32],
    pub swap_session_id: [u8; 32],
    pub reason: MatchRejectReason,
    pub signature: [u8; 64],
}

impl MatchReject {
    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<()> {
        bind_signer(&mut self.header, private_key)?;
        self.signature = crypto::sign(
            MATCH_REJECT_SIGNATURE_DOMAIN,
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

    pub fn verify_for_request(&self, intent: &MarketIntent, request: &MatchRequest) -> Result<()> {
        self.encode()?;
        intent.encode()?;
        request.verify_for_intent(intent)?;
        if self.intent_id != intent.intent_id
            || self.swap_session_id != request.swap_session_id
            || self.header.network != intent.header.network
            || self.header.pair != intent.header.pair
            || self.header.signer_public_key != intent.header.signer_public_key
            || self.header.sequence <= intent.header.sequence
            || self.header.created_at < request.header.created_at
            || self.header.expires_at > request.header.expires_at
        {
            return Err(MarketplaceError::Invalid(
                "match rejection does not bind its request",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.verify_signature()?;
        encode_signed(&self.encode_unsigned()?, &self.signature)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        check_input(input)?;
        let mut decoder = Decoder::new(input);
        let rejection = Self {
            header: SignedObjectHeader::decode_from(&mut decoder)?,
            intent_id: decoder.read_array()?,
            swap_session_id: decoder.read_array()?,
            reason: MatchRejectReason::try_from(decoder.read_u16_le()?)?,
            signature: decoder.read_array()?,
        };
        decoder.finish()?;
        rejection.validate_fields()?;
        rejection.verify_signature()?;
        Ok(rejection)
    }

    fn validate_fields(&self) -> Result<()> {
        self.header.validate()?;
        if self.intent_id == [0; 32] || self.swap_session_id == [0; 32] {
            return Err(MarketplaceError::Invalid("invalid match rejection"));
        }
        Ok(())
    }

    fn verify_signature(&self) -> Result<()> {
        crypto::verify(
            MATCH_REJECT_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.signature,
            &self.header.signer_public_key,
        )
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.validate_fields()?;
        encode_fixed_versioned(MAX_MARKET_OBJECT_SIZE - 64, |encoder| {
            self.header.encode_to(encoder);
            encoder.put_bytes(&self.intent_id);
            encoder.put_bytes(&self.swap_session_id);
            encoder.put_u16_le(self.reason as u16);
            Ok(())
        })
    }
}

fn canonical_received_amount(
    offered_asset: AssetId,
    base_asset: AssetId,
    quote_asset: AssetId,
    offered_amount: AssetAmount,
    price: RationalPrice,
) -> Result<AssetAmount> {
    if offered_asset == base_asset {
        price.quote(offered_amount, Rounding::Down)
    } else if offered_asset == quote_asset {
        RationalPrice::new(price.denominator(), price.numerator())?
            .quote(offered_amount, Rounding::Down)
    } else {
        Err(MarketplaceError::Invalid(
            "fill grant offered asset is outside the price pair",
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FillGrant {
    pub header: SignedObjectHeader,
    pub grant_hash: [u8; 32],
    pub intent_id: [u8; 32],
    pub intent_sequence: u64,
    pub swap_session_id: [u8; 32],
    pub counterparty_settlement_key: [u8; 33],
    pub offered_amount: AssetAmount,
    pub received_amount: AssetAmount,
    pub price_round_hash: [u8; 32],
    pub reservation_sequence: u64,
    pub signature: [u8; 64],
}

impl FillGrant {
    pub fn refresh_hash(&mut self) -> Result<()> {
        self.grant_hash = crypto::hash(FILL_GRANT_ID_DOMAIN, &self.encode_unsigned()?);
        Ok(())
    }

    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<()> {
        bind_signer(&mut self.header, private_key)?;
        self.refresh_hash()?;
        self.signature = crypto::sign(
            FILL_GRANT_SIGNATURE_DOMAIN,
            &self.signature_bytes()?,
            &self.header.signer_public_key,
            private_key,
        )?;
        Ok(())
    }

    pub fn verify_at(&self, expected_network: NetworkBinding, now: u64) -> Result<()> {
        self.header.validate_at(expected_network, now)?;
        self.verify_hash()?;
        crypto::verify(
            FILL_GRANT_SIGNATURE_DOMAIN,
            &self.signature_bytes()?,
            &self.signature,
            &self.header.signer_public_key,
        )
    }

    pub fn verify_for_intent(&self, intent: &MarketIntent) -> Result<()> {
        self.encode()?;
        intent.encode()?;
        if self.intent_id != intent.intent_id
            || self.intent_sequence != intent.header.sequence
            || self.header.network != intent.header.network
            || self.header.pair != intent.header.pair
            || self.header.signer_public_key != intent.header.signer_public_key
            || self.offered_amount > intent.maximum_amount
            || self.offered_amount < intent.minimum_fill
            || self.header.sequence <= intent.header.sequence
            || self.header.created_at < intent.header.created_at
            || self.header.expires_at > intent.header.expires_at
        {
            return Err(MarketplaceError::Invalid(
                "fill grant does not bind its intent",
            ));
        }
        Ok(())
    }

    pub fn verify_for_request(&self, intent: &MarketIntent, request: &MatchRequest) -> Result<()> {
        request.verify_for_intent(intent)?;
        self.verify_for_intent(intent)?;
        if self.swap_session_id != request.swap_session_id
            || self.counterparty_settlement_key != request.settlement_public_key
            || self.offered_amount != request.requested_amount
            || self.header.created_at < request.header.created_at
            || self.header.expires_at > request.header.expires_at
        {
            return Err(MarketplaceError::Invalid(
                "fill grant does not bind its match request",
            ));
        }
        Ok(())
    }

    /// Verify the grant against a caller-trusted price round and require the
    /// exact canonical receive amount.
    ///
    /// Version 1 prices are quote units per base unit. In either offer
    /// direction the received side is rounded down, so a grant can never
    /// promise more than the exact rational conversion. Overflow fails closed.
    pub fn verify_for_price_round(
        &self,
        intent: &MarketIntent,
        round: &PriceRound,
        verifier: PriceRoundVerifier<'_>,
        previous_round: Option<&PriceRound>,
        now: u64,
    ) -> Result<()> {
        let expected_network = verifier.expected_network();
        intent.verify_at(expected_network, now)?;
        self.verify_at(expected_network, now)?;
        self.verify_for_intent(intent)?;
        round.verify(verifier, previous_round, now)?;
        if self.price_round_hash != round.round_hash
            || self.header.network != round.network
            || self.header.pair != round.pair
            || self.header.created_at < round.interval_end
            || self.header.expires_at > round.valid_until
        {
            return Err(MarketplaceError::Invalid(
                "fill grant does not bind its verified price round",
            ));
        }
        let expected_received = canonical_received_amount(
            intent.offered_asset,
            round.pair.base,
            round.pair.quote,
            self.offered_amount,
            round.canonical_price,
        )?;
        if self.received_amount != expected_received {
            return Err(MarketplaceError::PriceMismatch);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.verify_hash()?;
        crypto::verify(
            FILL_GRANT_SIGNATURE_DOMAIN,
            &self.signature_bytes()?,
            &self.signature,
            &self.header.signer_public_key,
        )?;
        encode_fixed_versioned(MAX_MARKET_OBJECT_SIZE, |encoder| {
            encoder.put_bytes(&self.encode_unsigned()?);
            encoder.put_bytes(&self.grant_hash);
            encoder.put_bytes(&self.signature);
            Ok(())
        })
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        check_input(input)?;
        let mut decoder = Decoder::new(input);
        let grant = Self {
            header: SignedObjectHeader::decode_from(&mut decoder)?,
            intent_id: decoder.read_array()?,
            intent_sequence: decoder.read_u64_le()?,
            swap_session_id: decoder.read_array()?,
            counterparty_settlement_key: decoder.read_array()?,
            offered_amount: AssetAmount::decode_from(&mut decoder)?,
            received_amount: AssetAmount::decode_from(&mut decoder)?,
            price_round_hash: decoder.read_array()?,
            reservation_sequence: decoder.read_u64_le()?,
            grant_hash: decoder.read_array()?,
            signature: decoder.read_array()?,
        };
        decoder.finish()?;
        grant.validate_fields()?;
        grant.verify_hash()?;
        crypto::verify(
            FILL_GRANT_SIGNATURE_DOMAIN,
            &grant.signature_bytes()?,
            &grant.signature,
            &grant.header.signer_public_key,
        )?;
        Ok(grant)
    }

    fn validate_fields(&self) -> Result<()> {
        self.header.validate()?;
        crypto::validate_public_key(&self.counterparty_settlement_key)?;
        if self.intent_id == [0; 32]
            || self.intent_sequence == 0
            || self.swap_session_id == [0; 32]
            || self.offered_amount == AssetAmount::ZERO
            || self.received_amount == AssetAmount::ZERO
            || self.price_round_hash == [0; 32]
            || self.reservation_sequence == 0
        {
            return Err(MarketplaceError::Invalid("invalid fill grant"));
        }
        Ok(())
    }

    fn verify_hash(&self) -> Result<()> {
        let expected = crypto::hash(FILL_GRANT_ID_DOMAIN, &self.encode_unsigned()?);
        if self.grant_hash == expected {
            Ok(())
        } else {
            Err(MarketplaceError::HashMismatch)
        }
    }

    fn signature_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(MAX_MARKET_OBJECT_SIZE);
        bytes.extend_from_slice(&self.grant_hash);
        bytes.extend_from_slice(&self.encode_unsigned()?);
        Ok(bytes)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.validate_fields()?;
        encode_fixed_versioned(MAX_MARKET_OBJECT_SIZE - 96, |encoder| {
            self.header.encode_to(encoder);
            encoder.put_bytes(&self.intent_id);
            encoder.put_u64_le(self.intent_sequence);
            encoder.put_bytes(&self.swap_session_id);
            encoder.put_bytes(&self.counterparty_settlement_key);
            self.offered_amount.encode_to(encoder);
            self.received_amount.encode_to(encoder);
            encoder.put_bytes(&self.price_round_hash);
            encoder.put_u64_le(self.reservation_sequence);
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

fn encode_signed(unsigned: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>> {
    encode_fixed_versioned(MAX_MARKET_OBJECT_SIZE, |encoder| {
        encoder.put_bytes(unsigned);
        encoder.put_bytes(signature);
        Ok(())
    })
}

fn decode_bool(decoder: &mut Decoder<'_>) -> Result<bool> {
    match decoder.read_u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(MarketplaceError::Invalid("invalid Boolean encoding")),
    }
}

fn check_input(input: &[u8]) -> Result<()> {
    if input.len() > MAX_MARKET_OBJECT_SIZE {
        Err(MarketplaceError::TooLarge {
            actual: input.len(),
            maximum: MAX_MARKET_OBJECT_SIZE,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use hns_primitives::BlockHash;

    use super::*;
    use crate::{
        ChainAnchor, ChainId, DeadlineKind, MARKETPLACE_PROTOCOL_VERSION, MarketPair,
        PriceObservation, PriceRoundPolicy, SettlementDeadline, SwapSessionHello,
    };

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
            version: 1,
            network: network(),
            pair: MarketPair::HNS_BTC,
            signer_public_key: [0; 33],
            sequence,
            created_at: 100,
            expires_at: 200,
        }
    }

    fn intent() -> MarketIntent {
        let mut intent = MarketIntent {
            header: header(1),
            intent_id: [0; 32],
            offered_asset: AssetId::HNS,
            maximum_amount: AssetAmount::new(20_000_000),
            minimum_fill: AssetAmount::new(1_000_000),
            partial_fills: true,
            signature: [0; 64],
        };
        intent.sign(&[7; 32]).unwrap();
        intent
    }

    fn priced_intent(offered_asset: AssetId) -> MarketIntent {
        let mut intent = MarketIntent {
            header: header(1),
            intent_id: [0; 32],
            offered_asset,
            maximum_amount: AssetAmount::new(100),
            minimum_fill: AssetAmount::new(1),
            partial_fills: true,
            signature: [0; 64],
        };
        intent.sign(&[7; 32]).unwrap();
        intent
    }

    fn price_round() -> PriceRound {
        let hns_anchor = ChainAnchor {
            chain: ChainId::HANDSHAKE,
            height: 100,
            block_hash: [3; 32],
        };
        let counterchain_anchor = ChainAnchor {
            chain: ChainId::BITCOIN,
            height: 200,
            block_hash: [4; 32],
        };
        let observations = (1_u8..=3)
            .map(|index| {
                let mut observation = PriceObservation {
                    version: MARKETPLACE_PROTOCOL_VERSION,
                    network: network(),
                    pair: MarketPair::HNS_BTC,
                    price: RationalPrice::new(3, 2).unwrap(),
                    source_id: [index; 32],
                    reporter_public_key: [0; 33],
                    observed_at: 110,
                    valid_until: 160,
                    hns_anchor,
                    counterchain_anchor,
                    sequence: u64::from(index),
                    signature: [0; 64],
                };
                observation.sign(&[index; 32]).unwrap();
                observation
            })
            .collect();
        let mut round = PriceRound {
            version: MARKETPLACE_PROTOCOL_VERSION,
            network: network(),
            pair: MarketPair::HNS_BTC,
            round_id: [9; 32],
            interval_start: 100,
            interval_end: 120,
            canonical_price: RationalPrice::new(1, 1).unwrap(),
            observations,
            reporter_set: Vec::new(),
            source_set: Vec::new(),
            policy: PriceRoundPolicy {
                minimum_reporters: 3,
                minimum_sources: 3,
                maximum_observation_age: 30,
                trim_each_side: 0,
                maximum_movement_basis_points: 1_000,
            },
            hns_anchor,
            counterchain_anchor,
            valid_until: 150,
            previous_round_hash: [0; 32],
            round_hash: [0; 32],
        };
        round.refresh_derived().unwrap();
        round
    }

    fn priced_grant(
        intent: &MarketIntent,
        round: &PriceRound,
        offered_amount: u128,
        received_amount: u128,
    ) -> FillGrant {
        let mut grant_header = header(3);
        grant_header.created_at = 125;
        grant_header.expires_at = 145;
        let mut grant = FillGrant {
            header: grant_header,
            grant_hash: [0; 32],
            intent_id: intent.intent_id,
            intent_sequence: intent.header.sequence,
            swap_session_id: [8; 32],
            counterparty_settlement_key: crypto::public_key(&[8; 32]).unwrap(),
            offered_amount: AssetAmount::new(offered_amount),
            received_amount: AssetAmount::new(received_amount),
            price_round_hash: round.round_hash,
            reservation_sequence: 1,
            signature: [0; 64],
        };
        grant.sign(&[7; 32]).unwrap();
        grant
    }

    #[test]
    fn signed_intent_round_trip_and_mutation_rejection() {
        let intent = intent();
        intent.verify_at(network(), 150).unwrap();
        assert!(matches!(
            intent.verify_at(network(), 99),
            Err(MarketplaceError::NotYetValid { .. })
        ));
        assert!(matches!(
            intent.verify_at(network(), 200),
            Err(MarketplaceError::Expired { .. })
        ));
        let encoded = intent.encode().unwrap();
        assert_eq!(MarketIntent::decode(&encoded).unwrap(), intent);
        let mut mutated = intent.clone();
        mutated.maximum_amount = AssetAmount::new(20_000_001);
        assert!(mutated.encode().is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(MarketIntent::decode(&trailing).is_err());

        let mut indivisible = intent;
        indivisible.partial_fills = false;
        indivisible.signature = [0; 64];
        assert!(indivisible.sign(&[7; 32]).is_err());
    }

    #[test]
    fn cancellation_and_fill_grant_bind_intent_and_reservation() {
        let intent = intent();
        let mut cancellation = MarketIntentCancellation {
            header: header(2),
            intent_id: intent.intent_id,
            intent_sequence: intent.header.sequence,
            signature: [0; 64],
        };
        cancellation.sign(&[7; 32]).unwrap();
        cancellation
            .verify_for_intent(&intent, network(), 150)
            .unwrap();
        assert_eq!(
            MarketIntentCancellation::decode(&cancellation.encode().unwrap()).unwrap(),
            cancellation
        );

        let mut request = MatchRequest {
            header: header(1),
            intent_id: intent.intent_id,
            intent_sequence: intent.header.sequence,
            swap_session_id: [8; 32],
            settlement_public_key: crypto::public_key(&[8; 32]).unwrap(),
            requested_amount: AssetAmount::new(2_000_000),
            signature: [0; 64],
        };
        request.sign(&[8; 32]).unwrap();
        request.verify_for_intent(&intent).unwrap();

        let mut grant = FillGrant {
            header: header(3),
            grant_hash: [0; 32],
            intent_id: intent.intent_id,
            intent_sequence: intent.header.sequence,
            swap_session_id: [8; 32],
            counterparty_settlement_key: [0; 33],
            offered_amount: AssetAmount::new(2_000_000),
            received_amount: AssetAmount::new(200),
            price_round_hash: [9; 32],
            reservation_sequence: 1,
            signature: [0; 64],
        };
        grant.counterparty_settlement_key = crypto::public_key(&[8; 32]).unwrap();
        grant.sign(&[7; 32]).unwrap();
        grant.verify_for_intent(&intent).unwrap();
        grant.verify_for_request(&intent, &request).unwrap();
        assert_eq!(FillGrant::decode(&grant.encode().unwrap()).unwrap(), grant);

        let mut rejection = MatchReject {
            header: header(3),
            intent_id: intent.intent_id,
            swap_session_id: request.swap_session_id,
            reason: MatchRejectReason::ReservationConflict,
            signature: [0; 64],
        };
        rejection.sign(&[7; 32]).unwrap();
        rejection.verify_for_request(&intent, &request).unwrap();

        let mut replay = grant.clone();
        replay.reservation_sequence = 2;
        assert!(replay.encode().is_err());
    }

    #[test]
    fn fill_grant_binds_exact_round_hash_direction_and_floor_rounding() {
        let round = price_round();
        let verifier = PriceRoundVerifier::new(
            network(),
            round.policy,
            &round.reporter_set,
            &round.source_set,
        )
        .unwrap();

        let base_offer = priced_intent(AssetId::HNS);
        let grant = priced_grant(&base_offer, &round, 3, 4);
        grant
            .verify_for_price_round(&base_offer, &round, verifier, None, 130)
            .unwrap();

        let wrong_amount = priced_grant(&base_offer, &round, 3, 6);
        assert!(matches!(
            wrong_amount.verify_for_price_round(&base_offer, &round, verifier, None, 130),
            Err(MarketplaceError::PriceMismatch)
        ));
        let rounded_up = priced_grant(&base_offer, &round, 3, 5);
        assert!(matches!(
            rounded_up.verify_for_price_round(&base_offer, &round, verifier, None, 130),
            Err(MarketplaceError::PriceMismatch)
        ));

        let mut wrong_hash = priced_grant(&base_offer, &round, 3, 4);
        wrong_hash.price_round_hash = [7; 32];
        wrong_hash.signature = [0; 64];
        wrong_hash.sign(&[7; 32]).unwrap();
        assert!(
            wrong_hash
                .verify_for_price_round(&base_offer, &round, verifier, None, 130)
                .is_err()
        );

        let quote_offer = priced_intent(AssetId::BTC);
        let reverse_grant = priced_grant(&quote_offer, &round, 10, 6);
        reverse_grant
            .verify_for_price_round(&quote_offer, &round, verifier, None, 130)
            .unwrap();
        let wrong_direction = priced_grant(&quote_offer, &round, 10, 15);
        assert!(matches!(
            wrong_direction.verify_for_price_round(&quote_offer, &round, verifier, None, 130),
            Err(MarketplaceError::PriceMismatch)
        ));
    }

    #[test]
    fn session_requires_verified_price_grant_and_bilateral_acceptance() {
        let round = price_round();
        let verifier = PriceRoundVerifier::new(
            network(),
            round.policy,
            &round.reporter_set,
            &round.source_set,
        )
        .unwrap();
        let intent = priced_intent(AssetId::HNS);
        let grant = priced_grant(&intent, &round, 3, 4);
        let mut session_header = header(4);
        session_header.created_at = 126;
        session_header.expires_at = 140;
        let mut hello = SwapSessionHello {
            header: session_header,
            fill_grant_hash: grant.grant_hash,
            swap_session_id: grant.swap_session_id,
            maker_settlement_public_key: [0; 33],
            taker_settlement_public_key: grant.counterparty_settlement_key,
            offered_asset: AssetId::HNS,
            offered_amount: grant.offered_amount,
            received_asset: AssetId::BTC,
            received_amount: grant.received_amount,
            price_round_hash: round.round_hash,
            hashlock: [6; 32],
            first_funding_chain: ChainId::HANDSHAKE,
            offered_lock_commitment: [10; 32],
            offered_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 180,
            },
            offered_minimum_confirmations: 5,
            received_lock_commitment: [11; 32],
            received_refund_deadline: SettlementDeadline {
                kind: DeadlineKind::UnixTime,
                value: 160,
            },
            received_minimum_confirmations: 6,
            maker_signature: [0; 64],
            taker_signature: [0; 64],
        };
        hello.sign_maker(&[7; 32]).unwrap();
        assert!(
            hello
                .verify_for_grant(&intent, &grant, &round, verifier, None, 130)
                .is_err()
        );
        hello.accept_taker(&[8; 32]).unwrap();
        hello
            .verify_for_grant(&intent, &grant, &round, verifier, None, 130)
            .unwrap();

        let mut wrong_amount = hello;
        wrong_amount.received_amount = AssetAmount::new(5);
        wrong_amount.maker_signature = [0; 64];
        wrong_amount.taker_signature = [0; 64];
        wrong_amount.sign_maker(&[7; 32]).unwrap();
        wrong_amount.accept_taker(&[8; 32]).unwrap();
        assert!(
            wrong_amount
                .verify_for_grant(&intent, &grant, &round, verifier, None, 130)
                .is_err()
        );
    }
}
