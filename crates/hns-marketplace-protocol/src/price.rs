use std::collections::BTreeSet;

use hns_encoding::{Decoder, Encoder};

use crate::crypto;
use crate::types::{decode_nested, encode_fixed_versioned, encode_nested};
use crate::{
    ChainAnchor, ChainId, MARKETPLACE_PROTOCOL_VERSION, MarketPair, MarketplaceError,
    NetworkBinding, RationalPrice, Result,
};

pub const MAX_PRICE_OBSERVATION_SIZE: usize = 4 * 1024;
pub const MAX_PRICE_ROUND_SIZE: usize = 256 * 1024;
pub const MAX_ROUND_OBSERVATIONS: usize = 64;

const OBSERVATION_SIGNATURE_DOMAIN: &[u8] = b"HNS-MARKET-PRICE-OBSERVATION-V1\0";
const OBSERVATION_HASH_DOMAIN: &[u8] = b"HNS-MARKET-PRICE-OBSERVATION-ID-V1\0";
const ROUND_HASH_DOMAIN: &[u8] = b"HNS-MARKET-PRICE-ROUND-V1\0";

type DerivedRound = (Vec<[u8; 33]>, Vec<[u8; 32]>, RationalPrice);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriceObservation {
    pub version: u16,
    pub network: NetworkBinding,
    pub pair: MarketPair,
    pub price: RationalPrice,
    pub source_id: [u8; 32],
    pub reporter_public_key: [u8; 33],
    pub observed_at: u64,
    pub valid_until: u64,
    pub hns_anchor: ChainAnchor,
    pub counterchain_anchor: ChainAnchor,
    pub sequence: u64,
    pub signature: [u8; 64],
}

impl PriceObservation {
    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<()> {
        let public_key = crypto::public_key(private_key)?;
        if self.reporter_public_key != [0; 33] && self.reporter_public_key != public_key {
            return Err(MarketplaceError::SigningKeyMismatch);
        }
        self.reporter_public_key = public_key;
        self.validate_structure()?;
        self.signature = crypto::sign(
            OBSERVATION_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.reporter_public_key,
            private_key,
        )?;
        Ok(())
    }

    pub fn verify_at(&self, expected_network: NetworkBinding, now: u64) -> Result<()> {
        self.validate_structure()?;
        if self.network != expected_network {
            return Err(MarketplaceError::NetworkMismatch);
        }
        if now < self.observed_at {
            return Err(MarketplaceError::Invalid("observation is from the future"));
        }
        if now >= self.valid_until {
            return Err(MarketplaceError::Expired {
                expires_at: self.valid_until,
                now,
            });
        }
        self.verify_signature()
    }

    pub fn observation_hash(&self) -> Result<[u8; 32]> {
        Ok(crypto::hash(OBSERVATION_HASH_DOMAIN, &self.encode()?))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        self.verify_signature()?;
        encode_fixed_versioned(MAX_PRICE_OBSERVATION_SIZE, |encoder| {
            encoder.put_bytes(&self.encode_unsigned()?);
            encoder.put_bytes(&self.signature);
            Ok(())
        })
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_PRICE_OBSERVATION_SIZE {
            return Err(MarketplaceError::TooLarge {
                actual: input.len(),
                maximum: MAX_PRICE_OBSERVATION_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        let observation = Self::decode_from(&mut decoder)?;
        decoder.finish()?;
        observation.verify_signature()?;
        Ok(observation)
    }

    fn validate_structure(&self) -> Result<()> {
        if self.version != MARKETPLACE_PROTOCOL_VERSION {
            return Err(MarketplaceError::UnsupportedVersion(self.version));
        }
        self.network.validate_for_pair(self.pair)?;
        self.hns_anchor.validate()?;
        self.counterchain_anchor.validate()?;
        crypto::validate_public_key(&self.reporter_public_key)?;
        if self.source_id == [0; 32]
            || self.sequence == 0
            || self.observed_at >= self.valid_until
            || self.hns_anchor.chain != ChainId::HANDSHAKE
            || self.counterchain_anchor.chain != self.network.counterchain
        {
            return Err(MarketplaceError::Invalid(
                "invalid observation identity, interval, or anchors",
            ));
        }
        Ok(())
    }

    fn verify_signature(&self) -> Result<()> {
        crypto::verify(
            OBSERVATION_SIGNATURE_DOMAIN,
            &self.encode_unsigned()?,
            &self.signature,
            &self.reporter_public_key,
        )
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        encode_fixed_versioned(MAX_PRICE_OBSERVATION_SIZE - 64, |encoder| {
            encoder.put_u16_le(self.version);
            self.network.encode_to(encoder);
            self.pair.encode_to(encoder);
            self.price.encode_to(encoder);
            encoder.put_bytes(&self.source_id);
            encoder.put_bytes(&self.reporter_public_key);
            encoder.put_u64_le(self.observed_at);
            encoder.put_u64_le(self.valid_until);
            self.hns_anchor.encode_to(encoder);
            self.counterchain_anchor.encode_to(encoder);
            encoder.put_u64_le(self.sequence);
            Ok(())
        })
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        let observation = Self {
            version: decoder.read_u16_le()?,
            network: NetworkBinding::decode_from(decoder)?,
            pair: MarketPair::decode_from(decoder)?,
            price: RationalPrice::decode_from(decoder)?,
            source_id: decoder.read_array()?,
            reporter_public_key: decoder.read_array()?,
            observed_at: decoder.read_u64_le()?,
            valid_until: decoder.read_u64_le()?,
            hns_anchor: ChainAnchor::decode_from(decoder)?,
            counterchain_anchor: ChainAnchor::decode_from(decoder)?,
            sequence: decoder.read_u64_le()?,
            signature: decoder.read_array()?,
        };
        observation.validate_structure()?;
        Ok(observation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PriceRoundPolicy {
    pub minimum_reporters: u16,
    pub minimum_sources: u16,
    pub maximum_observation_age: u64,
    /// Remove this many lowest and highest observations before selecting the
    /// lower median of the retained set.
    pub trim_each_side: u16,
    pub maximum_movement_basis_points: u32,
}

/// Caller-owned trust inputs for price-round verification.
///
/// These values are deliberately not learned from a received round. A wallet
/// or other policy authority must construct this verifier from its configured
/// policy and admitted reporter/source identities. Admission lists are
/// canonical sorted sets and are bounded by [`MAX_ROUND_OBSERVATIONS`].
#[derive(Clone, Copy, Debug)]
pub struct PriceRoundVerifier<'a> {
    expected_network: NetworkBinding,
    expected_policy: PriceRoundPolicy,
    admitted_reporters: &'a [[u8; 33]],
    admitted_sources: &'a [[u8; 32]],
}

impl<'a> PriceRoundVerifier<'a> {
    pub fn new(
        expected_network: NetworkBinding,
        expected_policy: PriceRoundPolicy,
        admitted_reporters: &'a [[u8; 33]],
        admitted_sources: &'a [[u8; 32]],
    ) -> Result<Self> {
        let verifier = Self {
            expected_network,
            expected_policy,
            admitted_reporters,
            admitted_sources,
        };
        verifier.validate()?;
        Ok(verifier)
    }

    pub const fn expected_network(self) -> NetworkBinding {
        self.expected_network
    }

    pub const fn expected_policy(self) -> PriceRoundPolicy {
        self.expected_policy
    }

    fn validate(self) -> Result<()> {
        self.expected_network.validate()?;
        self.expected_policy.validate()?;
        if self.admitted_reporters.is_empty()
            || self.admitted_sources.is_empty()
            || self.admitted_reporters.len() > MAX_ROUND_OBSERVATIONS
            || self.admitted_sources.len() > MAX_ROUND_OBSERVATIONS
            || self.admitted_reporters.len() < usize::from(self.expected_policy.minimum_reporters)
            || self.admitted_sources.len() < usize::from(self.expected_policy.minimum_sources)
            || !strictly_sorted(self.admitted_reporters)
            || !strictly_sorted(self.admitted_sources)
        {
            return Err(MarketplaceError::InvalidPriceAdmission);
        }
        for reporter in self.admitted_reporters {
            crypto::validate_public_key(reporter)
                .map_err(|_| MarketplaceError::InvalidPriceAdmission)?;
        }
        if self.admitted_sources.contains(&[0; 32]) {
            return Err(MarketplaceError::InvalidPriceAdmission);
        }
        Ok(())
    }
}

impl PriceRoundPolicy {
    pub fn validate(self) -> Result<()> {
        if self.minimum_reporters == 0
            || self.minimum_sources == 0
            || usize::from(self.minimum_reporters) > MAX_ROUND_OBSERVATIONS
            || usize::from(self.minimum_sources) > MAX_ROUND_OBSERVATIONS
            || self.maximum_observation_age == 0
            || self.maximum_movement_basis_points == 0
            || self.maximum_movement_basis_points > 1_000_000
        {
            return Err(MarketplaceError::Invalid("invalid price-round policy"));
        }
        Ok(())
    }

    fn encode_to(self, encoder: &mut Encoder) {
        encoder.put_u16_le(self.minimum_reporters);
        encoder.put_u16_le(self.minimum_sources);
        encoder.put_u64_le(self.maximum_observation_age);
        encoder.put_u16_le(self.trim_each_side);
        encoder.put_u32_le(self.maximum_movement_basis_points);
    }

    fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self> {
        let policy = Self {
            minimum_reporters: decoder.read_u16_le()?,
            minimum_sources: decoder.read_u16_le()?,
            maximum_observation_age: decoder.read_u64_le()?,
            trim_each_side: decoder.read_u16_le()?,
            maximum_movement_basis_points: decoder.read_u32_le()?,
        };
        policy.validate()?;
        Ok(policy)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriceRound {
    pub version: u16,
    pub network: NetworkBinding,
    pub pair: MarketPair,
    pub round_id: [u8; 32],
    pub interval_start: u64,
    pub interval_end: u64,
    pub canonical_price: RationalPrice,
    pub observations: Vec<PriceObservation>,
    pub reporter_set: Vec<[u8; 33]>,
    pub source_set: Vec<[u8; 32]>,
    pub policy: PriceRoundPolicy,
    pub hns_anchor: ChainAnchor,
    pub counterchain_anchor: ChainAnchor,
    pub valid_until: u64,
    pub previous_round_hash: [u8; 32],
    pub round_hash: [u8; 32],
}

impl PriceRound {
    /// Derive the canonical reporter/source sets, trimmed lower median, and
    /// round hash after callers populate the remaining public fields.
    pub fn refresh_derived(&mut self) -> Result<()> {
        self.sort_observations()?;
        let (reporters, sources, price) = self.derive_sets_and_price()?;
        self.reporter_set = reporters;
        self.source_set = sources;
        self.canonical_price = price;
        self.round_hash = crypto::hash(ROUND_HASH_DOMAIN, &self.encode_unsigned()?);
        Ok(())
    }

    pub fn verify(
        &self,
        verifier: PriceRoundVerifier<'_>,
        previous: Option<&PriceRound>,
        now: u64,
    ) -> Result<()> {
        verifier.validate()?;
        self.verify_intrinsic()?;
        self.verify_trusted_context(verifier)?;
        if now < self.interval_end {
            return Err(MarketplaceError::NotYetValid {
                created_at: self.interval_end,
                now,
            });
        }
        let freshness_deadline = self
            .interval_end
            .checked_add(verifier.expected_policy.maximum_observation_age)
            .ok_or(MarketplaceError::ArithmeticOverflow)?;
        if now > freshness_deadline {
            return Err(MarketplaceError::Expired {
                expires_at: freshness_deadline,
                now,
            });
        }
        if self.network != verifier.expected_network {
            return Err(MarketplaceError::NetworkMismatch);
        }
        if now >= self.valid_until {
            return Err(MarketplaceError::Expired {
                expires_at: self.valid_until,
                now,
            });
        }
        match previous {
            None if self.previous_round_hash != [0; 32] => {
                return Err(MarketplaceError::PreviousRoundMismatch);
            }
            Some(previous) => {
                previous
                    .verify_intrinsic()
                    .and_then(|()| previous.verify_trusted_context(verifier))
                    .map_err(|_| MarketplaceError::PreviousRoundMismatch)?;
                if previous.round_hash != self.previous_round_hash
                    || previous.network != self.network
                    || previous.pair != self.pair
                    || previous.interval_end >= self.interval_start
                {
                    return Err(MarketplaceError::PreviousRoundMismatch);
                }
                if movement_exceeds(
                    previous.canonical_price,
                    self.canonical_price,
                    self.policy.maximum_movement_basis_points,
                )? {
                    return Err(MarketplaceError::CircuitBreaker);
                }
            }
            None => {}
        }
        Ok(())
    }

    fn verify_trusted_context(&self, verifier: PriceRoundVerifier<'_>) -> Result<()> {
        if self.network != verifier.expected_network {
            return Err(MarketplaceError::NetworkMismatch);
        }
        if self.policy != verifier.expected_policy {
            return Err(MarketplaceError::PricePolicyMismatch);
        }
        if self
            .reporter_set
            .iter()
            .any(|reporter| verifier.admitted_reporters.binary_search(reporter).is_err())
        {
            return Err(MarketplaceError::UnadmittedReporter);
        }
        if self
            .source_set
            .iter()
            .any(|source| verifier.admitted_sources.binary_search(source).is_err())
        {
            return Err(MarketplaceError::UnadmittedSource);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.verify_intrinsic()?;
        encode_fixed_versioned(MAX_PRICE_ROUND_SIZE, |encoder| {
            encoder.put_bytes(&self.encode_unsigned()?);
            encoder.put_bytes(&self.round_hash);
            Ok(())
        })
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_PRICE_ROUND_SIZE {
            return Err(MarketplaceError::TooLarge {
                actual: input.len(),
                maximum: MAX_PRICE_ROUND_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        let version = decoder.read_u16_le()?;
        let network = NetworkBinding::decode_from(&mut decoder)?;
        let pair = MarketPair::decode_from(&mut decoder)?;
        let round_id = decoder.read_array()?;
        let interval_start = decoder.read_u64_le()?;
        let interval_end = decoder.read_u64_le()?;
        let canonical_price = RationalPrice::decode_from(&mut decoder)?;
        let observation_count =
            decoder.read_compact_usize(MAX_ROUND_OBSERVATIONS, "price-round observations")?;
        let mut observations = Vec::with_capacity(observation_count);
        for _ in 0..observation_count {
            let bytes = decode_nested(
                &mut decoder,
                MAX_PRICE_OBSERVATION_SIZE,
                "price observation",
            )?;
            observations.push(PriceObservation::decode(&bytes)?);
        }
        let reporter_count =
            decoder.read_compact_usize(MAX_ROUND_OBSERVATIONS, "price-round reporters")?;
        let mut reporter_set = Vec::with_capacity(reporter_count);
        for _ in 0..reporter_count {
            reporter_set.push(decoder.read_array()?);
        }
        let source_count =
            decoder.read_compact_usize(MAX_ROUND_OBSERVATIONS, "price-round sources")?;
        let mut source_set = Vec::with_capacity(source_count);
        for _ in 0..source_count {
            source_set.push(decoder.read_array()?);
        }
        let round = Self {
            version,
            network,
            pair,
            round_id,
            interval_start,
            interval_end,
            canonical_price,
            observations,
            reporter_set,
            source_set,
            policy: PriceRoundPolicy::decode_from(&mut decoder)?,
            hns_anchor: ChainAnchor::decode_from(&mut decoder)?,
            counterchain_anchor: ChainAnchor::decode_from(&mut decoder)?,
            valid_until: decoder.read_u64_le()?,
            previous_round_hash: decoder.read_array()?,
            round_hash: decoder.read_array()?,
        };
        decoder.finish()?;
        round.verify_intrinsic()?;
        Ok(round)
    }

    pub fn verify_hash(&self) -> Result<()> {
        let expected = crypto::hash(ROUND_HASH_DOMAIN, &self.encode_unsigned()?);
        if expected == self.round_hash {
            Ok(())
        } else {
            Err(MarketplaceError::HashMismatch)
        }
    }

    fn verify_intrinsic(&self) -> Result<()> {
        self.validate_structure()?;
        self.verify_hash()?;
        let (reporters, sources, expected_price) = self.derive_sets_and_price()?;
        if reporters != self.reporter_set || sources != self.source_set {
            return Err(MarketplaceError::Invalid(
                "price-round reporter or source set is noncanonical",
            ));
        }
        if expected_price != self.canonical_price {
            return Err(MarketplaceError::PriceMismatch);
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<()> {
        if self.version != MARKETPLACE_PROTOCOL_VERSION {
            return Err(MarketplaceError::UnsupportedVersion(self.version));
        }
        self.network.validate_for_pair(self.pair)?;
        self.policy.validate()?;
        self.hns_anchor.validate()?;
        self.counterchain_anchor.validate()?;
        if self.round_id == [0; 32]
            || self.interval_start >= self.interval_end
            || self.interval_end >= self.valid_until
            || self.observations.is_empty()
            || self.observations.len() > MAX_ROUND_OBSERVATIONS
            || self.reporter_set.len() > MAX_ROUND_OBSERVATIONS
            || self.source_set.len() > MAX_ROUND_OBSERVATIONS
            || self.hns_anchor.chain != ChainId::HANDSHAKE
            || self.counterchain_anchor.chain != self.network.counterchain
        {
            return Err(MarketplaceError::Invalid("invalid price-round fields"));
        }
        let maximum_valid_until = self
            .interval_end
            .checked_add(self.policy.maximum_observation_age)
            .ok_or(MarketplaceError::ArithmeticOverflow)?;
        if self.valid_until > maximum_valid_until {
            return Err(MarketplaceError::Invalid(
                "price round outlives its maximum freshness age",
            ));
        }
        let trim = usize::from(self.policy.trim_each_side);
        if trim
            .checked_mul(2)
            .and_then(|removed| self.observations.len().checked_sub(removed))
            .is_none_or(|remaining| remaining == 0)
        {
            return Err(MarketplaceError::Invalid(
                "price-round trimming removes quorum",
            ));
        }
        if !strictly_sorted(&self.reporter_set) || !strictly_sorted(&self.source_set) {
            return Err(MarketplaceError::Invalid(
                "price-round sets must be sorted and unique",
            ));
        }
        let mut previous_hash = None;
        for observation in &self.observations {
            let hash = observation.observation_hash()?;
            if previous_hash.is_some_and(|previous| previous >= hash) {
                return Err(MarketplaceError::Invalid(
                    "price-round observations must be sorted by unique content hash",
                ));
            }
            previous_hash = Some(hash);
        }
        Ok(())
    }

    fn sort_observations(&mut self) -> Result<()> {
        let mut keyed = self
            .observations
            .iter()
            .cloned()
            .map(|observation| Ok((observation.observation_hash()?, observation)))
            .collect::<Result<Vec<_>>>()?;
        keyed.sort_unstable_by_key(|(hash, _)| *hash);
        if keyed.windows(2).any(|window| window[0].0 == window[1].0) {
            return Err(MarketplaceError::Invalid(
                "duplicate price-round observation",
            ));
        }
        self.observations = keyed
            .into_iter()
            .map(|(_, observation)| observation)
            .collect();
        Ok(())
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        encode_fixed_versioned(MAX_PRICE_ROUND_SIZE - 32, |encoder| {
            encoder.put_u16_le(self.version);
            self.network.encode_to(encoder);
            self.pair.encode_to(encoder);
            encoder.put_bytes(&self.round_id);
            encoder.put_u64_le(self.interval_start);
            encoder.put_u64_le(self.interval_end);
            self.canonical_price.encode_to(encoder);
            encoder.put_compact_size(self.observations.len() as u64);
            for observation in &self.observations {
                encode_nested(&observation.encode()?, encoder, MAX_PRICE_OBSERVATION_SIZE)?;
            }
            encoder.put_compact_size(self.reporter_set.len() as u64);
            for reporter in &self.reporter_set {
                encoder.put_bytes(reporter);
            }
            encoder.put_compact_size(self.source_set.len() as u64);
            for source in &self.source_set {
                encoder.put_bytes(source);
            }
            self.policy.encode_to(encoder);
            self.hns_anchor.encode_to(encoder);
            self.counterchain_anchor.encode_to(encoder);
            encoder.put_u64_le(self.valid_until);
            encoder.put_bytes(&self.previous_round_hash);
            Ok(())
        })
    }

    fn derive_sets_and_price(&self) -> Result<DerivedRound> {
        self.policy.validate()?;
        if self.observations.is_empty() || self.observations.len() > MAX_ROUND_OBSERVATIONS {
            return Err(MarketplaceError::WeakQuorum);
        }
        let mut reporters = BTreeSet::new();
        let mut sources = BTreeSet::new();
        let mut prices = Vec::with_capacity(self.observations.len());
        for observation in &self.observations {
            observation.verify_at(self.network, self.interval_end)?;
            if observation.pair != self.pair
                || observation.observed_at < self.interval_start
                || self.interval_end.saturating_sub(observation.observed_at)
                    > self.policy.maximum_observation_age
                || observation.hns_anchor != self.hns_anchor
                || observation.counterchain_anchor != self.counterchain_anchor
                || self.valid_until > observation.valid_until
            {
                return Err(MarketplaceError::Invalid(
                    "observation is outside the price round",
                ));
            }
            if !reporters.insert(observation.reporter_public_key) {
                return Err(MarketplaceError::DuplicateReporter);
            }
            if !sources.insert(observation.source_id) {
                return Err(MarketplaceError::DuplicateSource);
            }
            prices.push(observation.price);
        }
        if reporters.len() < usize::from(self.policy.minimum_reporters)
            || sources.len() < usize::from(self.policy.minimum_sources)
        {
            return Err(MarketplaceError::WeakQuorum);
        }
        prices.sort_unstable();
        let trim = usize::from(self.policy.trim_each_side);
        let retained = prices
            .get(trim..prices.len().saturating_sub(trim))
            .ok_or(MarketplaceError::WeakQuorum)?;
        if retained.is_empty() {
            return Err(MarketplaceError::WeakQuorum);
        }
        let lower_median = retained[(retained.len() - 1) / 2];
        Ok((
            reporters.into_iter().collect(),
            sources.into_iter().collect(),
            lower_median,
        ))
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn movement_exceeds(
    previous: RationalPrice,
    current: RationalPrice,
    maximum_basis_points: u32,
) -> Result<bool> {
    let current_scaled = current
        .numerator()
        .checked_mul(previous.denominator())
        .ok_or(MarketplaceError::ArithmeticOverflow)?;
    let previous_scaled = previous
        .numerator()
        .checked_mul(current.denominator())
        .ok_or(MarketplaceError::ArithmeticOverflow)?;
    let difference = current_scaled.abs_diff(previous_scaled);
    let left = difference
        .checked_mul(10_000)
        .ok_or(MarketplaceError::ArithmeticOverflow)?;
    let right = previous_scaled
        .checked_mul(u128::from(maximum_basis_points))
        .ok_or(MarketplaceError::ArithmeticOverflow)?;
    Ok(left > right)
}

#[cfg(test)]
mod tests {
    use hns_primitives::BlockHash;

    use super::*;

    fn network() -> NetworkBinding {
        NetworkBinding {
            hns_magic: 0x5b6e_c393,
            hns_genesis: BlockHash::new([1; 32]),
            counterchain: ChainId::BITCOIN,
            counterchain_network: 0xdab5_bffa,
            counterchain_genesis: [2; 32],
        }
    }

    fn anchors() -> (ChainAnchor, ChainAnchor) {
        (
            ChainAnchor {
                chain: ChainId::HANDSHAKE,
                height: 100,
                block_hash: [3; 32],
            },
            ChainAnchor {
                chain: ChainId::BITCOIN,
                height: 200,
                block_hash: [4; 32],
            },
        )
    }

    fn observation(index: u8, price: u128) -> PriceObservation {
        let (hns_anchor, counterchain_anchor) = anchors();
        let mut observation = PriceObservation {
            version: 1,
            network: network(),
            pair: MarketPair::HNS_BTC,
            price: RationalPrice::new(price, 10).unwrap(),
            source_id: [index; 32],
            reporter_public_key: [0; 33],
            observed_at: 110,
            valid_until: 200,
            hns_anchor,
            counterchain_anchor,
            sequence: u64::from(index),
            signature: [0; 64],
        };
        observation.sign(&[index; 32]).unwrap();
        observation
    }

    fn resign(observation: &mut PriceObservation) {
        let signer = (1_u8..=64)
            .find(|index| {
                crypto::public_key(&[*index; 32]).unwrap() == observation.reporter_public_key
            })
            .unwrap();
        observation.sign(&[signer; 32]).unwrap();
    }

    fn round(prices: &[u128]) -> PriceRound {
        let (hns_anchor, counterchain_anchor) = anchors();
        let mut round = PriceRound {
            version: 1,
            network: network(),
            pair: MarketPair::HNS_BTC,
            round_id: [9; 32],
            interval_start: 100,
            interval_end: 120,
            canonical_price: RationalPrice::new(1, 1).unwrap(),
            observations: prices
                .iter()
                .enumerate()
                .map(|(index, price)| observation(index as u8 + 1, *price))
                .collect(),
            reporter_set: Vec::new(),
            source_set: Vec::new(),
            policy: PriceRoundPolicy {
                minimum_reporters: 3,
                minimum_sources: 3,
                maximum_observation_age: 30,
                trim_each_side: 1,
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

    fn verifier(round: &PriceRound) -> PriceRoundVerifier<'_> {
        PriceRoundVerifier::new(
            network(),
            round.policy,
            &round.reporter_set,
            &round.source_set,
        )
        .unwrap()
    }

    #[test]
    fn signed_observation_has_exact_round_trip_and_rejects_mutation() {
        let observation = observation(7, 100);
        let encoded = observation.encode().unwrap();
        assert_eq!(PriceObservation::decode(&encoded).unwrap(), observation);
        let mut mutated = observation.clone();
        mutated.price = RationalPrice::new(101, 10).unwrap();
        assert!(mutated.encode().is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(PriceObservation::decode(&trailing).is_err());
    }

    #[test]
    fn round_trims_outliers_and_selects_deterministic_lower_median() {
        let round = round(&[1, 98, 100, 102, 1_000]);
        assert_eq!(round.canonical_price, RationalPrice::new(100, 10).unwrap());
        round.verify(verifier(&round), None, 130).unwrap();
        let encoded = round.encode().unwrap();
        assert_eq!(PriceRound::decode(&encoded).unwrap(), round);
    }

    #[test]
    fn duplicate_reporters_weak_quorum_hash_conflicts_and_circuit_breaker_fail_closed() {
        let mut duplicate = round(&[90, 100, 110]);
        duplicate.observations[1] = duplicate.observations[0].clone();
        duplicate.observations[1].source_id = [8; 32];
        duplicate.observations[1].price = RationalPrice::new(101, 10).unwrap();
        duplicate.observations[1].sequence += 10;
        duplicate.observations[1].signature = [0; 64];
        resign(&mut duplicate.observations[1]);
        assert_eq!(
            duplicate.refresh_derived().unwrap_err().to_string(),
            MarketplaceError::DuplicateReporter.to_string()
        );

        let mut duplicate_source = round(&[90, 100, 110]);
        duplicate_source.observations[1].source_id = duplicate_source.observations[0].source_id;
        duplicate_source.observations[1].signature = [0; 64];
        resign(&mut duplicate_source.observations[1]);
        assert!(matches!(
            duplicate_source.refresh_derived(),
            Err(MarketplaceError::DuplicateSource)
        ));

        let mut weak = round(&[90, 100, 110]);
        weak.policy.minimum_sources = 4;
        assert!(matches!(
            weak.refresh_derived(),
            Err(MarketplaceError::WeakQuorum)
        ));

        let mut stale = round(&[90, 100, 110]);
        stale.observations[0].observed_at = 80;
        stale.observations[0].signature = [0; 64];
        resign(&mut stale.observations[0]);
        assert!(stale.refresh_derived().is_err());

        let previous = round(&[95, 100, 105]);
        let mut next = round(&[190, 200, 210]);
        next.round_id = [10; 32];
        next.interval_start = 121;
        next.interval_end = 140;
        next.valid_until = 170;
        for observation in &mut next.observations {
            observation.observed_at = 130;
            observation.valid_until = 180;
            observation.signature = [0; 64];
        }
        for observation in &mut next.observations {
            resign(observation);
        }
        next.previous_round_hash = previous.round_hash;
        next.refresh_derived().unwrap();
        assert!(matches!(
            next.verify(verifier(&previous), Some(&previous), 150),
            Err(MarketplaceError::CircuitBreaker)
        ));

        let mut hash_conflict = previous.clone();
        hash_conflict.round_hash[0] ^= 1;
        assert!(hash_conflict.encode().is_err());

        let mut reordered = previous;
        reordered.observations.swap(0, 1);
        assert!(reordered.encode().is_err());
    }

    #[test]
    fn round_requires_caller_policy_admission_and_closed_interval() {
        let trusted_round = round(&[90, 100, 110]);
        let admitted_reporters = trusted_round.reporter_set.clone();
        let admitted_sources = trusted_round.source_set.clone();
        let trusted = PriceRoundVerifier::new(
            network(),
            trusted_round.policy,
            &admitted_reporters,
            &admitted_sources,
        )
        .unwrap();

        assert!(matches!(
            trusted_round.verify(trusted, None, trusted_round.interval_end - 1),
            Err(MarketplaceError::NotYetValid { .. })
        ));
        assert!(matches!(
            trusted_round.verify(trusted, None, trusted_round.valid_until),
            Err(MarketplaceError::Expired { .. })
        ));

        let mut downgraded = trusted_round.clone();
        downgraded.policy.minimum_reporters = 2;
        downgraded.policy.minimum_sources = 2;
        downgraded.refresh_derived().unwrap();
        assert!(matches!(
            downgraded.verify(trusted, None, 130),
            Err(MarketplaceError::PricePolicyMismatch)
        ));

        let mut sybil_reporter = trusted_round.clone();
        sybil_reporter.observations[0].reporter_public_key = [0; 33];
        sybil_reporter.observations[0].signature = [0; 64];
        sybil_reporter.observations[0].sign(&[8; 32]).unwrap();
        sybil_reporter.refresh_derived().unwrap();
        assert!(matches!(
            sybil_reporter.verify(trusted, None, 130),
            Err(MarketplaceError::UnadmittedReporter)
        ));

        let mut unadmitted_source = trusted_round.clone();
        unadmitted_source.observations[0].source_id = [8; 32];
        unadmitted_source.observations[0].signature = [0; 64];
        resign(&mut unadmitted_source.observations[0]);
        unadmitted_source.refresh_derived().unwrap();
        assert!(matches!(
            unadmitted_source.verify(trusted, None, 130),
            Err(MarketplaceError::UnadmittedSource)
        ));

        let duplicate_reporters = [admitted_reporters[0], admitted_reporters[0]];
        assert!(matches!(
            PriceRoundVerifier::new(
                network(),
                trusted_round.policy,
                &duplicate_reporters,
                &admitted_sources,
            ),
            Err(MarketplaceError::InvalidPriceAdmission)
        ));
    }

    #[test]
    fn round_and_previous_cannot_escape_admission_or_observation_lifetime() {
        let trusted_previous = round(&[90, 100, 110]);
        let admitted_reporters = trusted_previous.reporter_set.clone();
        let admitted_sources = trusted_previous.source_set.clone();
        let trusted = PriceRoundVerifier::new(
            network(),
            trusted_previous.policy,
            &admitted_reporters,
            &admitted_sources,
        )
        .unwrap();

        let mut outlives_observation = trusted_previous.clone();
        outlives_observation.observations[0].valid_until = outlives_observation.valid_until - 1;
        outlives_observation.observations[0].signature = [0; 64];
        resign(&mut outlives_observation.observations[0]);
        assert!(outlives_observation.refresh_derived().is_err());

        let mut unadmitted_previous = trusted_previous.clone();
        unadmitted_previous.observations[0].reporter_public_key = [0; 33];
        unadmitted_previous.observations[0].signature = [0; 64];
        unadmitted_previous.observations[0].sign(&[8; 32]).unwrap();
        unadmitted_previous.refresh_derived().unwrap();

        let mut next = round(&[91, 101, 109]);
        next.round_id = [10; 32];
        next.interval_start = 121;
        next.interval_end = 140;
        next.valid_until = 170;
        for observation in &mut next.observations {
            observation.observed_at = 130;
            observation.valid_until = 180;
            observation.signature = [0; 64];
            resign(observation);
        }
        next.previous_round_hash = unadmitted_previous.round_hash;
        next.refresh_derived().unwrap();
        assert!(matches!(
            next.verify(trusted, Some(&unadmitted_previous), 150),
            Err(MarketplaceError::PreviousRoundMismatch)
        ));
    }
}
