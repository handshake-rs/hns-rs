#![doc = "Canonical Handshake marketplace and bilateral cross-chain wire protocols."]

mod crypto;
mod denuo;
mod market;
mod price;
mod swap;
mod types;

pub use denuo::*;
pub use market::*;
pub use price::*;
pub use swap::*;
pub use types::*;

use thiserror::Error;

pub const MARKETPLACE_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Error)]
pub enum MarketplaceError {
    #[error(transparent)]
    Decode(#[from] hns_encoding::DecodeError),
    #[error(transparent)]
    Envelope(#[from] hns_p2p_experimental::EnvelopeError),
    #[error(transparent)]
    Swap(#[from] hns_swap::SwapError),
    #[error("unsupported marketplace protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("invalid marketplace field: {0}")]
    Invalid(&'static str),
    #[error("marketplace object is {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("marketplace arithmetic overflow")]
    ArithmeticOverflow,
    #[error("invalid or noncanonical marketplace signature")]
    InvalidSignature,
    #[error("signing key does not match the advertised public key")]
    SigningKeyMismatch,
    #[error("marketplace object is bound to another network")]
    NetworkMismatch,
    #[error("marketplace object is not valid until {created_at}; current time is {now}")]
    NotYetValid { created_at: u64, now: u64 },
    #[error("marketplace object expired at {expires_at}; current time is {now}")]
    Expired { expires_at: u64, now: u64 },
    #[error("marketplace object hash differs from its canonical fields")]
    HashMismatch,
    #[error("price round has insufficient reporter or source quorum")]
    WeakQuorum,
    #[error("caller-supplied price reporter/source admission is invalid")]
    InvalidPriceAdmission,
    #[error("price round embeds a policy different from caller policy")]
    PricePolicyMismatch,
    #[error("price round contains a reporter not admitted by caller policy")]
    UnadmittedReporter,
    #[error("price round contains a source not admitted by caller policy")]
    UnadmittedSource,
    #[error("price round repeats a reporter")]
    DuplicateReporter,
    #[error("price round repeats a source")]
    DuplicateSource,
    #[error("price round canonical price differs from its deterministic median")]
    PriceMismatch,
    #[error("price round movement exceeds its circuit-breaker policy")]
    CircuitBreaker,
    #[error("price round does not link to the supplied previous round")]
    PreviousRoundMismatch,
    #[error("Denuo message type {message_type} is unknown for protocol {protocol_id}")]
    UnknownMessage { protocol_id: u16, message_type: u16 },
}

pub type Result<T> = core::result::Result<T, MarketplaceError>;

pub(crate) fn ensure_size(bytes: Vec<u8>, maximum: usize) -> Result<Vec<u8>> {
    if bytes.len() > maximum {
        Err(MarketplaceError::TooLarge {
            actual: bytes.len(),
            maximum,
        })
    } else {
        Ok(bytes)
    }
}

#[cfg(test)]
mod protocol_v1_vectors {
    use super::*;

    const FIXTURES: &str =
        include_str!("../fixtures/protocol-v1/hns-marketplace-v1.txt");

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let value = FIXTURES
            .lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value))
            .unwrap_or_else(|| panic!("missing fixture {name}"));
        hex::decode(value).expect("fixture hex")
    }

    fn fixture_hash(name: &str) -> [u8; 32] {
        fixture_bytes(name)
            .try_into()
            .unwrap_or_else(|_| panic!("fixture {name} is not 32 bytes"))
    }

    fn assert_envelope(name: &str, request_id: u64) {
        let exact = fixture_bytes(name);
        let (decoded_request_id, message) =
            CrossChainMessage::decode_envelope(&exact).expect("exact Denuo envelope");
        assert_eq!(decoded_request_id, request_id);
        assert_eq!(
            message.encode_envelope(request_id).expect("Denuo encoding"),
            exact
        );
    }

    #[test]
    fn exact_marketplace_v1_objects_and_envelopes_are_consumed() {
        let exact = fixture_bytes("market_intent");
        let intent = MarketIntent::decode(&exact).expect("market intent");
        assert_eq!(intent.encode().expect("market intent encoding"), exact);
        assert_eq!(intent.intent_id, fixture_hash("market_intent_id"));

        let exact = fixture_bytes("market_intent_cancellation");
        let cancellation =
            MarketIntentCancellation::decode(&exact).expect("market intent cancellation");
        assert_eq!(
            cancellation.encode().expect("cancellation encoding"),
            exact
        );
        assert_eq!(
            cancellation.cancellation_hash().expect("cancellation hash"),
            fixture_hash("market_intent_cancellation_hash")
        );

        let exact = fixture_bytes("price_observation");
        let observation = PriceObservation::decode(&exact).expect("price observation");
        assert_eq!(
            observation.encode().expect("observation encoding"),
            exact
        );
        assert_eq!(
            observation.observation_hash().expect("observation hash"),
            fixture_hash("price_observation_hash")
        );

        let exact = fixture_bytes("price_round");
        let round = PriceRound::decode(&exact).expect("price round");
        assert_eq!(round.encode().expect("price round encoding"), exact);
        assert_eq!(round.round_hash, fixture_hash("price_round_hash"));

        let exact = fixture_bytes("match_request");
        let request = MatchRequest::decode(&exact).expect("match request");
        assert_eq!(request.encode().expect("match request encoding"), exact);

        let exact = fixture_bytes("fill_grant");
        let grant = FillGrant::decode(&exact).expect("fill grant");
        assert_eq!(grant.encode().expect("fill grant encoding"), exact);
        assert_eq!(grant.grant_hash, fixture_hash("fill_grant_hash"));
        assert_ne!(
            grant.header.signer_public_key,
            grant.maker_settlement_key,
            "long-term maker identity must be independent from settlement authority"
        );

        let exact = fixture_bytes("match_reject");
        let rejection = MatchReject::decode(&exact).expect("match rejection");
        assert_eq!(rejection.encode().expect("match rejection encoding"), exact);

        let exact = fixture_bytes("swap_session_hello");
        let hello = SwapSessionHello::decode(&exact).expect("swap session hello");
        assert_eq!(hello.encode().expect("session hello encoding"), exact);
        let descriptor = hns_swap::HnsHtlc::decode(&fixture_bytes("hns_session_descriptor"))
            .expect("native HNS session descriptor");
        assert_eq!(
            descriptor.descriptor_hash().expect("descriptor hash"),
            fixture_hash("hns_session_descriptor_hash")
        );
        let binding = hello
            .verify_hns_htlc(SwapAssetSide::Offered, &descriptor)
            .expect("hello HNS descriptor binding");
        assert_eq!(binding.promised_refund_unix_time, 900);
        assert_eq!(binding.effective_refund_unix_time, 1_024);

        let exact = fixture_bytes("swap_funding_status");
        let funding = SwapFundingStatus::decode(&exact).expect("funding status");
        assert_eq!(funding.encode().expect("funding status encoding"), exact);

        let exact = fixture_bytes("swap_redeem_status");
        let redeem = SwapRedeemStatus::decode(&exact).expect("redeem status");
        assert_eq!(redeem.encode().expect("redeem status encoding"), exact);

        let exact = fixture_bytes("swap_refund_status");
        let refund = SwapRefundStatus::decode(&exact).expect("refund status");
        assert_eq!(refund.encode().expect("refund status encoding"), exact);

        for (name, request_id) in [
            ("denuo_market_intent_envelope", 101),
            ("denuo_market_intent_cancellation_envelope", 0),
            ("denuo_price_observation_envelope", 102),
            ("denuo_price_round_envelope", 0),
            ("denuo_match_request_envelope", 103),
            ("denuo_fill_grant_envelope", 104),
            ("denuo_match_reject_envelope", 105),
            ("denuo_swap_session_hello_envelope", 106),
            ("denuo_swap_funding_status_envelope", 0),
            ("denuo_swap_redeem_status_envelope", 0),
            ("denuo_swap_refund_status_envelope", 0),
        ] {
            assert_envelope(name, request_id);
        }
    }
}
