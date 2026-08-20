use hns_encoding::{Decoder, Encoder};
use hns_p2p_experimental::{
    ATOMIC_MARKET_PROTOCOL_ID, ATOMIC_MARKET_PROTOCOL_VERSION, CANCEL_MARKET_INTENT_MESSAGE_TYPE,
    CROSS_CHAIN_MARKET_MAX_PAYLOAD, CROSS_CHAIN_MARKET_PROTOCOL_ID,
    CROSS_CHAIN_MARKET_PROTOCOL_VERSION as DENUO_CROSS_CHAIN_MARKET_PROTOCOL_VERSION,
    DENUO_V1_REGISTRY_VERSION, DENUO_V2_REGISTRY_VERSION, DenuoExtensionEnvelope,
    FILL_GRANT_MESSAGE_TYPE, GET_MARKET_INTENT_MESSAGE_TYPE, GET_PRICE_OBSERVATION_MESSAGE_TYPE,
    MARKET_INTENT_INV_MESSAGE_TYPE, MARKET_INTENT_MESSAGE_TYPE, MATCH_REJECT_MESSAGE_TYPE,
    MATCH_REQUEST_MESSAGE_TYPE, PRICE_OBSERVATION_INV_MESSAGE_TYPE, PRICE_OBSERVATION_MESSAGE_TYPE,
    PRICE_ROUND_MESSAGE_TYPE, SWAP_FUNDING_STATUS_MESSAGE_TYPE, SWAP_REDEEM_STATUS_MESSAGE_TYPE,
    SWAP_REFUND_STATUS_MESSAGE_TYPE, SWAP_SESSION_HELLO_MESSAGE_TYPE,
    SWAP_SESSION_PROPOSAL_MESSAGE_TYPE,
};
use hns_primitives::BlockHash;
use hns_swap::{FixedPriceListing, ListingCancellation};

use crate::{
    FillGrant, MarketIntent, MarketIntentCancellation, MarketplaceError, MatchReject, MatchRequest,
    PriceObservation, PriceRound, Result, SwapFundingStatus, SwapRedeemStatus, SwapRefundStatus,
    SwapSessionHello, SwapSessionProposal, ensure_size,
};

pub const NAME_MARKET_PROTOCOL_VERSION: u16 = ATOMIC_MARKET_PROTOCOL_VERSION;
pub const CROSS_CHAIN_MARKET_PROTOCOL_VERSION: u16 = DENUO_CROSS_CHAIN_MARKET_PROTOCOL_VERSION;
pub const MAX_DENUO_MARKET_PAYLOAD: usize = CROSS_CHAIN_MARKET_MAX_PAYLOAD;
pub const MAX_INVENTORY_ENTRIES: usize = 4096;
pub const MAX_NAME_OFFERS_PER_MESSAGE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum DenuoRegistryVersion {
    V1 = DENUO_V1_REGISTRY_VERSION,
    V2 = DENUO_V2_REGISTRY_VERSION,
}

impl TryFrom<u16> for DenuoRegistryVersion {
    type Error = MarketplaceError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            DENUO_V1_REGISTRY_VERSION => Ok(Self::V1),
            DENUO_V2_REGISTRY_VERSION => Ok(Self::V2),
            _ => Err(MarketplaceError::Invalid(
                "unsupported Denuo registry version",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NameMarketHello {
    pub hns_magic: u32,
    pub hns_genesis: BlockHash,
    pub maximum_payload: u32,
    pub feature_flags: u64,
}

impl NameMarketHello {
    fn validate(self) -> Result<()> {
        if self.hns_magic == 0
            || self.hns_genesis.as_bytes() == &[0; 32]
            || self.maximum_payload == 0
            || usize::try_from(self.maximum_payload).unwrap_or(usize::MAX)
                > MAX_DENUO_MARKET_PAYLOAD
        {
            return Err(MarketplaceError::Invalid(
                "invalid name-market network binding or receive limit",
            ));
        }
        Ok(())
    }

    fn encode(self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(48);
        encoder.put_u32_le(self.hns_magic);
        encoder.put_bytes(self.hns_genesis.as_bytes());
        encoder.put_u32_le(self.maximum_payload);
        encoder.put_u64_le(self.feature_flags);
        Ok(encoder.into_bytes())
    }

    fn decode(input: &[u8]) -> Result<Self> {
        let mut decoder = Decoder::new(input);
        let hello = Self {
            hns_magic: decoder.read_u32_le()?,
            hns_genesis: BlockHash::new(decoder.read_array()?),
            maximum_payload: decoder.read_u32_le()?,
            feature_flags: decoder.read_u64_le()?,
        };
        decoder.finish()?;
        hello.validate()?;
        Ok(hello)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NameMarketMessage {
    Hello(NameMarketHello),
    GetOfferInventory,
    OfferInventory(Vec<[u8; 32]>),
    GetOffers(Vec<[u8; 32]>),
    Offers(Vec<FixedPriceListing>),
    GetOffer([u8; 32]),
    Offer(FixedPriceListing),
    Cancel(ListingCancellation),
}

impl NameMarketMessage {
    pub fn encode_envelope(
        &self,
        registry: DenuoRegistryVersion,
        request_id: u64,
    ) -> Result<Vec<u8>> {
        let (message_type, payload) = self.encode_payload()?;
        let envelope = DenuoExtensionEnvelope {
            registry_version: registry as u16,
            protocol_id: ATOMIC_MARKET_PROTOCOL_ID,
            protocol_version: NAME_MARKET_PROTOCOL_VERSION,
            message_type,
            flags: 0,
            request_id,
            payload,
        };
        Ok(envelope.encode(MAX_DENUO_MARKET_PAYLOAD)?)
    }

    pub fn decode_envelope(input: &[u8]) -> Result<(DenuoRegistryVersion, u64, Self)> {
        let envelope = DenuoExtensionEnvelope::decode(input, MAX_DENUO_MARKET_PAYLOAD)?;
        let registry = DenuoRegistryVersion::try_from(envelope.registry_version)?;
        if envelope.protocol_id != ATOMIC_MARKET_PROTOCOL_ID
            || envelope.protocol_version != NAME_MARKET_PROTOCOL_VERSION
            || envelope.flags != 0
            || envelope.payload.len() > MAX_DENUO_MARKET_PAYLOAD
        {
            return Err(MarketplaceError::Invalid("invalid name-market envelope"));
        }
        let message = Self::decode_payload(envelope.message_type, &envelope.payload)?;
        Ok((registry, envelope.request_id, message))
    }

    fn encode_payload(&self) -> Result<(u16, Vec<u8>)> {
        let encoded = match self {
            Self::Hello(hello) => (1, hello.encode()?),
            Self::GetOfferInventory => (2, Vec::new()),
            Self::OfferInventory(listing_hashes) => (3, encode_hashes(listing_hashes, true)?),
            Self::GetOffers(listing_hashes) => (4, encode_hashes(listing_hashes, false)?),
            Self::Offers(listings) => (5, encode_listings(listings)?),
            Self::GetOffer(listing_hash) => (6, encode_nonzero_hash(*listing_hash)?),
            Self::Offer(listing) => (7, listing.encode()?),
            Self::Cancel(cancellation) => (8, cancellation.encode()?),
        };
        Ok((encoded.0, ensure_size(encoded.1, MAX_DENUO_MARKET_PAYLOAD)?))
    }

    fn decode_payload(message_type: u16, payload: &[u8]) -> Result<Self> {
        if payload.len() > MAX_DENUO_MARKET_PAYLOAD {
            return Err(MarketplaceError::TooLarge {
                actual: payload.len(),
                maximum: MAX_DENUO_MARKET_PAYLOAD,
            });
        }
        match message_type {
            1 => Ok(Self::Hello(NameMarketHello::decode(payload)?)),
            2 => {
                require_empty(payload)?;
                Ok(Self::GetOfferInventory)
            }
            3 => Ok(Self::OfferInventory(decode_hashes(payload, true)?)),
            4 => Ok(Self::GetOffers(decode_hashes(payload, false)?)),
            5 => Ok(Self::Offers(decode_listings(payload)?)),
            6 => Ok(Self::GetOffer(decode_nonzero_hash(payload)?)),
            7 => Ok(Self::Offer(FixedPriceListing::decode(payload)?)),
            8 => Ok(Self::Cancel(ListingCancellation::decode(payload)?)),
            _ => Err(MarketplaceError::UnknownMessage {
                protocol_id: ATOMIC_MARKET_PROTOCOL_ID,
                message_type,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CrossChainMessage {
    MarketIntentInventory(Vec<[u8; 32]>),
    GetMarketIntent([u8; 32]),
    MarketIntent(MarketIntent),
    CancelMarketIntent(MarketIntentCancellation),
    PriceObservationInventory(Vec<[u8; 32]>),
    GetPriceObservation([u8; 32]),
    PriceObservation(PriceObservation),
    PriceRound(PriceRound),
    MatchRequest(MatchRequest),
    FillGrant(FillGrant),
    MatchReject(MatchReject),
    SwapSessionHello(SwapSessionHello),
    SwapFundingStatus(SwapFundingStatus),
    SwapRedeemStatus(SwapRedeemStatus),
    SwapRefundStatus(SwapRefundStatus),
    SwapSessionProposal(SwapSessionProposal),
}

impl CrossChainMessage {
    pub fn encode_envelope(&self, request_id: u64) -> Result<Vec<u8>> {
        let (message_type, payload) = self.encode_payload()?;
        let envelope = DenuoExtensionEnvelope {
            registry_version: DENUO_V2_REGISTRY_VERSION,
            protocol_id: CROSS_CHAIN_MARKET_PROTOCOL_ID,
            protocol_version: CROSS_CHAIN_MARKET_PROTOCOL_VERSION,
            message_type,
            flags: 0,
            request_id,
            payload,
        };
        Ok(envelope.encode(MAX_DENUO_MARKET_PAYLOAD)?)
    }

    pub fn decode_envelope(input: &[u8]) -> Result<(u64, Self)> {
        let envelope = DenuoExtensionEnvelope::decode(input, MAX_DENUO_MARKET_PAYLOAD)?;
        if envelope.registry_version != DENUO_V2_REGISTRY_VERSION
            || envelope.protocol_id != CROSS_CHAIN_MARKET_PROTOCOL_ID
            || envelope.protocol_version != CROSS_CHAIN_MARKET_PROTOCOL_VERSION
            || envelope.flags != 0
            || envelope.payload.len() > MAX_DENUO_MARKET_PAYLOAD
        {
            return Err(MarketplaceError::Invalid(
                "invalid cross-chain marketplace envelope",
            ));
        }
        let message = Self::decode_payload(envelope.message_type, &envelope.payload)?;
        Ok((envelope.request_id, message))
    }

    fn encode_payload(&self) -> Result<(u16, Vec<u8>)> {
        let encoded = match self {
            Self::MarketIntentInventory(hashes) => (
                MARKET_INTENT_INV_MESSAGE_TYPE,
                encode_hashes(hashes, false)?,
            ),
            Self::GetMarketIntent(hash) => {
                (GET_MARKET_INTENT_MESSAGE_TYPE, encode_nonzero_hash(*hash)?)
            }
            Self::MarketIntent(intent) => (MARKET_INTENT_MESSAGE_TYPE, intent.encode()?),
            Self::CancelMarketIntent(cancellation) => {
                (CANCEL_MARKET_INTENT_MESSAGE_TYPE, cancellation.encode()?)
            }
            Self::PriceObservationInventory(hashes) => (
                PRICE_OBSERVATION_INV_MESSAGE_TYPE,
                encode_hashes(hashes, false)?,
            ),
            Self::GetPriceObservation(hash) => (
                GET_PRICE_OBSERVATION_MESSAGE_TYPE,
                encode_nonzero_hash(*hash)?,
            ),
            Self::PriceObservation(observation) => {
                (PRICE_OBSERVATION_MESSAGE_TYPE, observation.encode()?)
            }
            Self::PriceRound(round) => (PRICE_ROUND_MESSAGE_TYPE, round.encode()?),
            Self::MatchRequest(request) => (MATCH_REQUEST_MESSAGE_TYPE, request.encode()?),
            Self::FillGrant(grant) => (FILL_GRANT_MESSAGE_TYPE, grant.encode()?),
            Self::MatchReject(rejection) => (MATCH_REJECT_MESSAGE_TYPE, rejection.encode()?),
            Self::SwapSessionHello(hello) => (SWAP_SESSION_HELLO_MESSAGE_TYPE, hello.encode()?),
            Self::SwapFundingStatus(status) => (SWAP_FUNDING_STATUS_MESSAGE_TYPE, status.encode()?),
            Self::SwapRedeemStatus(status) => (SWAP_REDEEM_STATUS_MESSAGE_TYPE, status.encode()?),
            Self::SwapRefundStatus(status) => (SWAP_REFUND_STATUS_MESSAGE_TYPE, status.encode()?),
            Self::SwapSessionProposal(proposal) => {
                (SWAP_SESSION_PROPOSAL_MESSAGE_TYPE, proposal.encode()?)
            }
        };
        Ok((encoded.0, ensure_size(encoded.1, MAX_DENUO_MARKET_PAYLOAD)?))
    }

    fn decode_payload(message_type: u16, payload: &[u8]) -> Result<Self> {
        if payload.len() > MAX_DENUO_MARKET_PAYLOAD {
            return Err(MarketplaceError::TooLarge {
                actual: payload.len(),
                maximum: MAX_DENUO_MARKET_PAYLOAD,
            });
        }
        match message_type {
            MARKET_INTENT_INV_MESSAGE_TYPE => {
                Ok(Self::MarketIntentInventory(decode_hashes(payload, false)?))
            }
            GET_MARKET_INTENT_MESSAGE_TYPE => {
                Ok(Self::GetMarketIntent(decode_nonzero_hash(payload)?))
            }
            MARKET_INTENT_MESSAGE_TYPE => Ok(Self::MarketIntent(MarketIntent::decode(payload)?)),
            CANCEL_MARKET_INTENT_MESSAGE_TYPE => Ok(Self::CancelMarketIntent(
                MarketIntentCancellation::decode(payload)?,
            )),
            PRICE_OBSERVATION_INV_MESSAGE_TYPE => Ok(Self::PriceObservationInventory(
                decode_hashes(payload, false)?,
            )),
            GET_PRICE_OBSERVATION_MESSAGE_TYPE => {
                Ok(Self::GetPriceObservation(decode_nonzero_hash(payload)?))
            }
            PRICE_OBSERVATION_MESSAGE_TYPE => {
                Ok(Self::PriceObservation(PriceObservation::decode(payload)?))
            }
            PRICE_ROUND_MESSAGE_TYPE => Ok(Self::PriceRound(PriceRound::decode(payload)?)),
            MATCH_REQUEST_MESSAGE_TYPE => Ok(Self::MatchRequest(MatchRequest::decode(payload)?)),
            FILL_GRANT_MESSAGE_TYPE => Ok(Self::FillGrant(FillGrant::decode(payload)?)),
            MATCH_REJECT_MESSAGE_TYPE => Ok(Self::MatchReject(MatchReject::decode(payload)?)),
            SWAP_SESSION_HELLO_MESSAGE_TYPE => {
                Ok(Self::SwapSessionHello(SwapSessionHello::decode(payload)?))
            }
            SWAP_FUNDING_STATUS_MESSAGE_TYPE => {
                Ok(Self::SwapFundingStatus(SwapFundingStatus::decode(payload)?))
            }
            SWAP_REDEEM_STATUS_MESSAGE_TYPE => {
                Ok(Self::SwapRedeemStatus(SwapRedeemStatus::decode(payload)?))
            }
            SWAP_REFUND_STATUS_MESSAGE_TYPE => {
                Ok(Self::SwapRefundStatus(SwapRefundStatus::decode(payload)?))
            }
            SWAP_SESSION_PROPOSAL_MESSAGE_TYPE => Ok(Self::SwapSessionProposal(
                SwapSessionProposal::decode(payload)?,
            )),
            _ => Err(MarketplaceError::UnknownMessage {
                protocol_id: CROSS_CHAIN_MARKET_PROTOCOL_ID,
                message_type,
            }),
        }
    }
}

fn encode_hashes(hashes: &[[u8; 32]], permit_empty: bool) -> Result<Vec<u8>> {
    if (!permit_empty && hashes.is_empty()) || hashes.len() > MAX_INVENTORY_ENTRIES {
        return Err(MarketplaceError::Invalid("invalid inventory length"));
    }
    if hashes.contains(&[0; 32]) || hashes.windows(2).any(|window| window[0] >= window[1]) {
        return Err(MarketplaceError::Invalid(
            "inventory identifiers must be nonzero, sorted, and unique",
        ));
    }
    let mut encoder = Encoder::with_capacity(9 + hashes.len() * 32);
    encoder.put_compact_size(hashes.len() as u64);
    for hash in hashes {
        encoder.put_bytes(hash);
    }
    ensure_size(encoder.into_bytes(), MAX_DENUO_MARKET_PAYLOAD)
}

fn decode_hashes(input: &[u8], permit_empty: bool) -> Result<Vec<[u8; 32]>> {
    let mut decoder = Decoder::new(input);
    let count = decoder.read_compact_usize(MAX_INVENTORY_ENTRIES, "market inventory")?;
    if count == 0 && !permit_empty {
        return Err(MarketplaceError::Invalid("empty inventory"));
    }
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        hashes.push(decoder.read_array()?);
    }
    decoder.finish()?;
    encode_hashes(&hashes, permit_empty)?;
    Ok(hashes)
}

fn encode_listings(listings: &[FixedPriceListing]) -> Result<Vec<u8>> {
    if listings.is_empty() || listings.len() > MAX_NAME_OFFERS_PER_MESSAGE {
        return Err(MarketplaceError::Invalid("invalid listing batch length"));
    }
    let mut keyed = Vec::with_capacity(listings.len());
    for listing in listings {
        keyed.push((listing.listing_hash()?, listing.encode()?));
    }
    if keyed.windows(2).any(|window| window[0].0 >= window[1].0) {
        return Err(MarketplaceError::Invalid(
            "listing batch must be sorted by unique offer identifier",
        ));
    }
    let mut encoder = Encoder::new();
    encoder.put_compact_size(keyed.len() as u64);
    for (_, listing) in keyed {
        encoder.put_varbytes(&listing);
    }
    ensure_size(encoder.into_bytes(), MAX_DENUO_MARKET_PAYLOAD)
}

fn decode_listings(input: &[u8]) -> Result<Vec<FixedPriceListing>> {
    let mut decoder = Decoder::new(input);
    let count = decoder.read_compact_usize(MAX_NAME_OFFERS_PER_MESSAGE, "name offers")?;
    if count == 0 {
        return Err(MarketplaceError::Invalid("empty listing batch"));
    }
    let mut listings = Vec::with_capacity(count);
    for _ in 0..count {
        let bytes = decoder.read_varbytes(
            hns_swap::MAX_FIXED_PRICE_LISTING_SIZE,
            "fixed-price listing",
        )?;
        listings.push(FixedPriceListing::decode(&bytes)?);
    }
    decoder.finish()?;
    encode_listings(&listings)?;
    Ok(listings)
}

fn encode_nonzero_hash(hash: [u8; 32]) -> Result<Vec<u8>> {
    if hash == [0; 32] {
        Err(MarketplaceError::Invalid("zero object identifier"))
    } else {
        Ok(hash.to_vec())
    }
}

fn decode_nonzero_hash(input: &[u8]) -> Result<[u8; 32]> {
    let hash = decode_exact_hash(input)?;
    encode_nonzero_hash(hash)?;
    Ok(hash)
}

fn decode_exact_hash(input: &[u8]) -> Result<[u8; 32]> {
    let mut decoder = Decoder::new(input);
    let hash = decoder.read_array()?;
    decoder.finish()?;
    Ok(hash)
}

fn require_empty(input: &[u8]) -> Result<()> {
    if input.is_empty() {
        Ok(())
    } else {
        Err(MarketplaceError::Invalid("expected empty Denuo payload"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_market_hello_requires_nonzero_network_binding() {
        let hello = NameMarketHello {
            hns_magic: 0x5b6e_c393,
            hns_genesis: BlockHash::new([1; 32]),
            maximum_payload: MAX_DENUO_MARKET_PAYLOAD as u32,
            feature_flags: 0,
        };
        NameMarketMessage::Hello(hello)
            .encode_envelope(DenuoRegistryVersion::V2, 1)
            .unwrap();

        let mut zero_magic = hello;
        zero_magic.hns_magic = 0;
        assert!(
            NameMarketMessage::Hello(zero_magic)
                .encode_envelope(DenuoRegistryVersion::V2, 1)
                .is_err()
        );

        let mut zero_genesis = hello;
        zero_genesis.hns_genesis = BlockHash::new([0; 32]);
        assert!(
            NameMarketMessage::Hello(zero_genesis)
                .encode_envelope(DenuoRegistryVersion::V2, 1)
                .is_err()
        );
    }

    #[test]
    fn name_market_empty_request_has_stable_v1_vector() {
        let encoded = NameMarketMessage::GetOfferInventory
            .encode_envelope(DenuoRegistryVersion::V1, 7)
            .unwrap();
        assert_eq!(
            hex::encode(&encoded),
            "444e553101000100010002000000070000000000000000000000"
        );
        assert_eq!(
            NameMarketMessage::decode_envelope(&encoded).unwrap(),
            (
                DenuoRegistryVersion::V1,
                7,
                NameMarketMessage::GetOfferInventory
            )
        );
    }

    #[test]
    fn inventories_are_sorted_unique_bounded_and_v2_only_for_cross_chain() {
        let message = CrossChainMessage::MarketIntentInventory(vec![[1; 32], [2; 32]]);
        let encoded = message.encode_envelope(7).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            concat!(
                "444e55310200020001000100000007000000000000004100000002",
                "0101010101010101010101010101010101010101010101010101010101010101",
                "0202020202020202020202020202020202020202020202020202020202020202"
            )
        );
        assert_eq!(
            CrossChainMessage::decode_envelope(&encoded).unwrap(),
            (7, message)
        );

        let duplicate = CrossChainMessage::MarketIntentInventory(vec![[1; 32], [1; 32]]);
        assert!(duplicate.encode_envelope(7).is_err());

        let mut wrong_registry = DenuoExtensionEnvelope::decode_canonical(&encoded).unwrap();
        wrong_registry.registry_version = DENUO_V1_REGISTRY_VERSION;
        assert!(wrong_registry.encode_canonical().is_err());
    }

    #[test]
    fn empty_offer_inventory_is_canonical_but_empty_requests_and_batches_are_not() {
        let inventory = NameMarketMessage::OfferInventory(Vec::new());
        let encoded = inventory
            .encode_envelope(DenuoRegistryVersion::V2, 8)
            .expect("empty inventory response");
        assert_eq!(
            NameMarketMessage::decode_envelope(&encoded).expect("empty inventory decoding"),
            (DenuoRegistryVersion::V2, 8, inventory)
        );
        assert!(
            NameMarketMessage::GetOffers(Vec::new())
                .encode_envelope(DenuoRegistryVersion::V2, 9)
                .is_err()
        );
        assert!(
            NameMarketMessage::Offers(Vec::new())
                .encode_envelope(DenuoRegistryVersion::V2, 10)
                .is_err()
        );
    }

    #[test]
    fn typed_decoders_reject_trailing_and_wrong_protocol_payloads() {
        let encoded = NameMarketMessage::GetOffer([3; 32])
            .encode_envelope(DenuoRegistryVersion::V2, 9)
            .unwrap();
        let mut envelope = DenuoExtensionEnvelope::decode_canonical(&encoded).unwrap();
        envelope.payload.push(0);
        let malformed = envelope.encode_canonical().unwrap();
        assert!(NameMarketMessage::decode_envelope(&malformed).is_err());
    }
}
