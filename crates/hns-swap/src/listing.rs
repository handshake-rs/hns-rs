use hns_covenants::hash_name;
use hns_encoding::{Decoder, Encoder};
use hns_primitives::{NameHash, OfferId};
use hns_transaction::Coin;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::{
    MAX_SWAP_PROOF_SIZE, NetworkBinding, SwapError, SwapProof, blake2b_256, lock_script_hash,
};

pub const FIXED_PRICE_LISTING_VERSION: u16 = 1;
pub const LISTING_CANCELLATION_VERSION: u16 = 1;
pub const MARKETPLACE_SIGNATURE_SIZE: usize = 64;
pub const MAX_FIXED_PRICE_LISTING_SIZE: usize = 8 * 1024;
pub const MAX_LISTING_CANCELLATION_SIZE: usize = 512;

const LISTING_SIGNATURE_DOMAIN: &[u8] = b"hns-rs/hns-swap/fixed-price-listing/v1/signature";
const LISTING_HASH_DOMAIN: &[u8] = b"hns-rs/hns-swap/fixed-price-listing/v1/hash";
const CANCELLATION_SIGNATURE_DOMAIN: &[u8] = b"hns-rs/hns-swap/listing-cancellation/v1/signature";
const CANCELLATION_HASH_DOMAIN: &[u8] = b"hns-rs/hns-swap/listing-cancellation/v1/hash";

/// A signed, expiring publication envelope around one fixed-price Shakedex
/// presign. The embedded [`SwapProof`] remains the sole authority for the name,
/// owner outpoint, lock script, seller key, price, network, and genesis hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixedPriceListing {
    pub proof: SwapProof,
    /// Unix time in seconds at which the listing becomes publishable.
    pub created_at: u64,
    /// Unix time in seconds at which the listing is no longer active.
    pub expires_at: u64,
    /// Monotonically increasing seller/name sequence used by board replay
    /// protection. Zero is reserved and rejected.
    pub sequence: u64,
    /// Compact low-S secp256k1 signature over the canonical unsigned envelope.
    pub signature: Option<[u8; MARKETPLACE_SIGNATURE_SIZE]>,
}

impl FixedPriceListing {
    pub fn validate(&self) -> Result<(), SwapError> {
        self.proof.validate()?;
        if self.proof.signature.is_none() {
            return Err(SwapError::UnsignedListingProof);
        }
        if self.sequence == 0 {
            return Err(SwapError::ZeroListingSequence);
        }
        if self.expires_at <= self.created_at {
            return Err(SwapError::InvalidListingLifetime);
        }
        if let Some(signature) = &self.signature {
            validate_marketplace_signature(signature)?;
        }
        Ok(())
    }

    pub const fn network(&self) -> NetworkBinding {
        self.proof.network
    }

    pub fn name_hash(&self) -> Result<NameHash, SwapError> {
        Ok(hash_name(&self.proof.name)?)
    }

    pub fn lock_script_identifier(&self) -> [u8; 32] {
        lock_script_hash(&self.proof.seller_public_key)
    }

    pub fn offer_id(&self) -> Result<OfferId, SwapError> {
        self.proof.offer_id()
    }

    pub const fn seller_public_key(&self) -> &[u8; 33] {
        &self.proof.seller_public_key
    }

    pub fn is_active_at(&self, now: u64) -> Result<bool, SwapError> {
        self.verify()?;
        Ok(self.created_at <= now && now < self.expires_at)
    }

    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), SwapError> {
        let public_key = signing_key.verifying_key().to_encoded_point(true);
        if public_key.as_bytes() != self.proof.seller_public_key {
            return Err(SwapError::SigningKeyMismatch);
        }
        self.signature = None;
        self.validate()?;
        let digest = domain_hash(LISTING_SIGNATURE_DOMAIN, &self.signing_bytes()?);
        let signature: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| SwapError::SignatureFailure)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        self.signature = Some(signature.to_bytes().into());
        self.verify()
    }

    /// Verify the marketplace envelope signature. This does not replace
    /// [`SwapProof::verify`], which additionally requires the current locked
    /// name coin.
    pub fn verify(&self) -> Result<(), SwapError> {
        self.validate()?;
        let encoded_signature = self.signature.ok_or(SwapError::UnsignedListing)?;
        let signature = validate_marketplace_signature(&encoded_signature)?;
        let digest = domain_hash(LISTING_SIGNATURE_DOMAIN, &self.signing_bytes()?);
        let public_key = VerifyingKey::from_sec1_bytes(&self.proof.seller_public_key)
            .map_err(|_| SwapError::InvalidPublicKey)?;
        public_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| SwapError::InvalidSignature)
    }

    /// Verify the envelope, its time window, its network binding, and the
    /// embedded Shakedex presign against the current locked name coin.
    pub fn verify_for_network(
        &self,
        expected_network: NetworkBinding,
        now: u64,
        locking_coin: &Coin,
    ) -> Result<(), SwapError> {
        if self.network() != expected_network {
            return Err(SwapError::NetworkMismatch);
        }
        if now < self.created_at {
            return Err(SwapError::ListingNotYetActive);
        }
        if now >= self.expires_at {
            return Err(SwapError::ListingExpired);
        }
        self.verify()?;
        self.proof
            .verify_for_network(expected_network, locking_coin)
    }

    /// Stable content identifier committed into the wire encoding. It covers
    /// the low-S envelope signature as well as all signed terms.
    pub fn listing_hash(&self) -> Result<[u8; 32], SwapError> {
        self.verify()?;
        Ok(domain_hash(
            LISTING_HASH_DOMAIN,
            &self.encoding_without_hash()?,
        ))
    }

    pub fn encode(&self) -> Result<Vec<u8>, SwapError> {
        self.verify()?;
        let mut encoded = self.encoding_without_hash()?;
        let listing_hash = domain_hash(LISTING_HASH_DOMAIN, &encoded);
        encoded.extend_from_slice(&listing_hash);
        if encoded.len() > MAX_FIXED_PRICE_LISTING_SIZE {
            return Err(SwapError::ListingTooLarge(encoded.len()));
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, SwapError> {
        if input.len() > MAX_FIXED_PRICE_LISTING_SIZE {
            return Err(SwapError::ListingTooLarge(input.len()));
        }
        let mut decoder = Decoder::new(input);
        let version = decoder.read_u16_le()?;
        if version != FIXED_PRICE_LISTING_VERSION {
            return Err(SwapError::UnsupportedListingVersion(version));
        }
        let created_at = decoder.read_u64_le()?;
        let expires_at = decoder.read_u64_le()?;
        let sequence = decoder.read_u64_le()?;
        let proof_bytes = decoder.read_varbytes(MAX_SWAP_PROOF_SIZE, "swap proof")?;
        let proof = SwapProof::decode(&proof_bytes)?;
        let signature = decode_marketplace_signature(&mut decoder, "listing signature")?;
        let claimed_hash: [u8; 32] = decoder.read_array()?;
        decoder.finish()?;

        let listing = Self {
            proof,
            created_at,
            expires_at,
            sequence,
            signature,
        };
        listing.validate()?;
        let actual_hash = domain_hash(LISTING_HASH_DOMAIN, &listing.encoding_without_hash()?);
        if claimed_hash != actual_hash {
            return Err(SwapError::ListingHashMismatch);
        }
        listing.verify()?;
        Ok(listing)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, SwapError> {
        self.validate()?;
        let proof = self.proof.encode()?;
        let mut encoder = Encoder::with_capacity(26_usize.saturating_add(proof.len()));
        encoder.put_u16_le(FIXED_PRICE_LISTING_VERSION);
        encoder.put_u64_le(self.created_at);
        encoder.put_u64_le(self.expires_at);
        encoder.put_u64_le(self.sequence);
        encoder.put_varbytes(&proof);
        Ok(encoder.into_bytes())
    }

    fn encoding_without_hash(&self) -> Result<Vec<u8>, SwapError> {
        let mut encoded = self.signing_bytes()?;
        match self.signature {
            Some(signature) => {
                encoded.push(1);
                encoded.extend_from_slice(&signature);
            }
            None => encoded.push(0),
        }
        Ok(encoded)
    }
}

/// A signed, expiring tombstone for one exact fixed-price listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListingCancellation {
    pub network: NetworkBinding,
    pub listing_hash: [u8; 32],
    pub seller_public_key: [u8; 33],
    pub created_at: u64,
    pub expires_at: u64,
    /// Must be greater than the cancelled listing sequence.
    pub sequence: u64,
    pub signature: Option<[u8; MARKETPLACE_SIGNATURE_SIZE]>,
}

impl ListingCancellation {
    pub fn for_listing(
        listing: &FixedPriceListing,
        created_at: u64,
        expires_at: u64,
        sequence: u64,
    ) -> Result<Self, SwapError> {
        listing.verify()?;
        let cancellation = Self {
            network: listing.network(),
            listing_hash: listing.listing_hash()?,
            seller_public_key: *listing.seller_public_key(),
            created_at,
            expires_at,
            sequence,
            signature: None,
        };
        cancellation.validate()?;
        if cancellation.sequence <= listing.sequence {
            return Err(SwapError::CancellationSequenceNotNewer);
        }
        if cancellation.created_at < listing.created_at {
            return Err(SwapError::CancellationListingMismatch);
        }
        if cancellation.expires_at < listing.expires_at {
            return Err(SwapError::CancellationExpiresTooEarly);
        }
        Ok(cancellation)
    }

    pub fn validate(&self) -> Result<(), SwapError> {
        VerifyingKey::from_sec1_bytes(&self.seller_public_key)
            .map_err(|_| SwapError::InvalidPublicKey)?;
        if self.sequence == 0 {
            return Err(SwapError::ZeroCancellationSequence);
        }
        if self.expires_at <= self.created_at {
            return Err(SwapError::InvalidCancellationLifetime);
        }
        if let Some(signature) = &self.signature {
            validate_marketplace_signature(signature)?;
        }
        Ok(())
    }

    pub fn is_active_at(&self, now: u64) -> Result<bool, SwapError> {
        self.verify()?;
        Ok(self.created_at <= now && now < self.expires_at)
    }

    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), SwapError> {
        let public_key = signing_key.verifying_key().to_encoded_point(true);
        if public_key.as_bytes() != self.seller_public_key {
            return Err(SwapError::SigningKeyMismatch);
        }
        self.signature = None;
        self.validate()?;
        let digest = domain_hash(CANCELLATION_SIGNATURE_DOMAIN, &self.signing_bytes()?);
        let signature: Signature = signing_key
            .sign_prehash(&digest)
            .map_err(|_| SwapError::SignatureFailure)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        self.signature = Some(signature.to_bytes().into());
        self.verify()
    }

    pub fn verify(&self) -> Result<(), SwapError> {
        self.validate()?;
        let encoded_signature = self.signature.ok_or(SwapError::UnsignedCancellation)?;
        let signature = validate_marketplace_signature(&encoded_signature)?;
        let digest = domain_hash(CANCELLATION_SIGNATURE_DOMAIN, &self.signing_bytes()?);
        let public_key = VerifyingKey::from_sec1_bytes(&self.seller_public_key)
            .map_err(|_| SwapError::InvalidPublicKey)?;
        public_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| SwapError::InvalidSignature)
    }

    pub fn verify_for_listing(
        &self,
        listing: &FixedPriceListing,
        expected_network: NetworkBinding,
        now: u64,
    ) -> Result<(), SwapError> {
        if self.network != expected_network || listing.network() != expected_network {
            return Err(SwapError::NetworkMismatch);
        }
        if now < self.created_at {
            return Err(SwapError::CancellationNotYetActive);
        }
        if now >= self.expires_at {
            return Err(SwapError::CancellationExpired);
        }
        self.verify()?;
        listing.verify()?;
        if self.listing_hash != listing.listing_hash()?
            || self.seller_public_key != *listing.seller_public_key()
            || self.created_at < listing.created_at
        {
            return Err(SwapError::CancellationListingMismatch);
        }
        if self.sequence <= listing.sequence {
            return Err(SwapError::CancellationSequenceNotNewer);
        }
        if self.expires_at < listing.expires_at {
            return Err(SwapError::CancellationExpiresTooEarly);
        }
        Ok(())
    }

    pub fn cancellation_hash(&self) -> Result<[u8; 32], SwapError> {
        self.verify()?;
        Ok(domain_hash(
            CANCELLATION_HASH_DOMAIN,
            &self.encoding_without_hash()?,
        ))
    }

    pub fn encode(&self) -> Result<Vec<u8>, SwapError> {
        self.verify()?;
        let mut encoded = self.encoding_without_hash()?;
        let cancellation_hash = domain_hash(CANCELLATION_HASH_DOMAIN, &encoded);
        encoded.extend_from_slice(&cancellation_hash);
        if encoded.len() > MAX_LISTING_CANCELLATION_SIZE {
            return Err(SwapError::CancellationTooLarge(encoded.len()));
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, SwapError> {
        if input.len() > MAX_LISTING_CANCELLATION_SIZE {
            return Err(SwapError::CancellationTooLarge(input.len()));
        }
        let mut decoder = Decoder::new(input);
        let version = decoder.read_u16_le()?;
        if version != LISTING_CANCELLATION_VERSION {
            return Err(SwapError::UnsupportedCancellationVersion(version));
        }
        let network = NetworkBinding {
            magic: decoder.read_u32_le()?,
            genesis: decoder.read_array::<32>()?.into(),
        };
        let listing_hash = decoder.read_array()?;
        let seller_public_key = decoder.read_array()?;
        let created_at = decoder.read_u64_le()?;
        let expires_at = decoder.read_u64_le()?;
        let sequence = decoder.read_u64_le()?;
        let signature = decode_marketplace_signature(&mut decoder, "cancellation signature")?;
        let claimed_hash: [u8; 32] = decoder.read_array()?;
        decoder.finish()?;

        let cancellation = Self {
            network,
            listing_hash,
            seller_public_key,
            created_at,
            expires_at,
            sequence,
            signature,
        };
        cancellation.validate()?;
        let actual_hash = domain_hash(
            CANCELLATION_HASH_DOMAIN,
            &cancellation.encoding_without_hash()?,
        );
        if claimed_hash != actual_hash {
            return Err(SwapError::CancellationHashMismatch);
        }
        cancellation.verify()?;
        Ok(cancellation)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, SwapError> {
        self.validate()?;
        let mut encoder = Encoder::with_capacity(127);
        encoder.put_u16_le(LISTING_CANCELLATION_VERSION);
        encoder.put_u32_le(self.network.magic);
        encoder.put_bytes(self.network.genesis.as_bytes());
        encoder.put_bytes(&self.listing_hash);
        encoder.put_bytes(&self.seller_public_key);
        encoder.put_u64_le(self.created_at);
        encoder.put_u64_le(self.expires_at);
        encoder.put_u64_le(self.sequence);
        Ok(encoder.into_bytes())
    }

    fn encoding_without_hash(&self) -> Result<Vec<u8>, SwapError> {
        let mut encoded = self.signing_bytes()?;
        match self.signature {
            Some(signature) => {
                encoded.push(1);
                encoded.extend_from_slice(&signature);
            }
            None => encoded.push(0),
        }
        Ok(encoded)
    }
}

fn decode_marketplace_signature(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<Option<[u8; MARKETPLACE_SIGNATURE_SIZE]>, SwapError> {
    match decoder.read_u8()? {
        0 => Ok(None),
        1 => Ok(Some(decoder.read_array()?)),
        _ => Err(SwapError::InvalidPresenceFlag(field)),
    }
}

fn validate_marketplace_signature(
    encoded: &[u8; MARKETPLACE_SIGNATURE_SIZE],
) -> Result<Signature, SwapError> {
    let signature = Signature::from_slice(encoded).map_err(|_| SwapError::InvalidSignature)?;
    if signature.normalize_s().is_some() {
        return Err(SwapError::HighMarketplaceSignature);
    }
    Ok(signature)
}

fn domain_hash(domain: &[u8], encoded: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(domain.len().saturating_add(encoded.len()));
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(encoded);
    blake2b_256(&bytes)
}

#[cfg(test)]
mod tests {
    use hns_covenants::FinalizeCovenant;
    use hns_primitives::{BlockHash, Dollarydoos, Height, TransactionHash};
    use hns_transaction::{Address, Coin, Outpoint};

    use super::*;
    use crate::lock_script_hash;

    const PROTOCOL_V1_FIXTURES: &str = include_str!("../fixtures/protocol-v1/hns-swap-v1.txt");

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let value = PROTOCOL_V1_FIXTURES
            .lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value))
            .unwrap_or_else(|| panic!("missing fixture {name}"));
        hex::decode(value).expect("fixture hex")
    }

    fn listing_fixture() -> (FixedPriceListing, Coin, SigningKey) {
        let signing_key = SigningKey::from_slice(&[0x31; 32]).expect("seller key");
        let seller_public_key = signing_key.verifying_key().to_encoded_point(true);
        let seller_public_key = seller_public_key
            .as_bytes()
            .try_into()
            .expect("compressed public key");
        let mut proof = SwapProof {
            network: NetworkBinding {
                magic: 0x5b6e_c393,
                genesis: BlockHash::new([0x11; 32]),
            },
            locking_outpoint: Outpoint {
                transaction_hash: TransactionHash::new([0x22; 32]),
                index: 7,
            },
            name: b"market-name".to_vec(),
            seller_public_key,
            payment_address: Address::new(0, vec![0x33; 20]).expect("payment address"),
            price: Dollarydoos::new(12_345_678),
            lock_time_seconds: 1_800_000_000,
            signature: None,
            fee_address: Some(Address::new(0, vec![0x44; 20]).expect("fee address")),
            fee: Dollarydoos::new(25_000),
        };
        let coin = Coin {
            outpoint: proof.locking_outpoint,
            value: Dollarydoos::new(900_000),
            height: Height::new(123),
            coinbase: false,
            address: Address::new(0, lock_script_hash(&proof.seller_public_key).to_vec())
                .expect("lock address"),
            covenant: FinalizeCovenant::new(
                proof.name.clone(),
                Height::new(1),
                false,
                Height::new(0),
                0,
                BlockHash::new([0x55; 32]),
            )
            .expect("finalize")
            .to_covenant()
            .expect("covenant"),
        };
        proof
            .sign(&coin, &signing_key)
            .expect("signed Shakedex proof");
        let mut listing = FixedPriceListing {
            proof,
            created_at: 1_800_000_100,
            expires_at: 1_800_003_700,
            sequence: 42,
            signature: None,
        };
        listing
            .sign(&signing_key)
            .expect("signed fixed-price listing");
        (listing, coin, signing_key)
    }

    #[test]
    fn fixed_price_listing_vector_round_trips_and_verifies_all_bindings() {
        let (listing, coin, _) = listing_fixture();
        listing.verify().expect("marketplace signature");
        assert!(listing.is_active_at(1_800_000_200).unwrap());
        listing
            .verify_for_network(listing.network(), 1_800_000_200, &coin)
            .expect("listing and presign");
        assert_eq!(
            listing.name_hash().expect("name hash"),
            hash_name(&listing.proof.name).expect("name hash")
        );
        assert_eq!(
            listing.lock_script_identifier(),
            lock_script_hash(listing.seller_public_key())
        );

        let encoded = listing.encode().expect("listing encoding");
        assert_eq!(encoded, fixture_bytes("fixed_price_listing"));
        assert_eq!(
            FixedPriceListing::decode(&encoded).expect("listing decoding"),
            listing
        );
        assert_eq!(encoded.len(), 380);
        assert_eq!(
            hex::encode(listing.signature.expect("signature")),
            "c096028fbaf60633eea9ebe29a13767111930eee36bf7fb74b21d40329730f051dd19f12ab6e30edb0ebfa6f5dcf1272d8790dfb49385bffd87513d1e9d626a0"
        );
        assert_eq!(
            hex::encode(listing.listing_hash().expect("listing hash")),
            "8a49724def7a8a8042b5131901512df001197c5916171c0e2d01edc072f325c0"
        );
        assert_eq!(
            listing.listing_hash().expect("listing hash").as_slice(),
            fixture_bytes("fixed_price_listing_hash").as_slice()
        );
        assert_eq!(
            domain_hash(
                LISTING_SIGNATURE_DOMAIN,
                &listing.signing_bytes().expect("listing signing bytes"),
            )
            .as_slice(),
            fixture_bytes("fixed_price_listing_signature_digest").as_slice()
        );
        assert_eq!(
            encoded[encoded.len() - 32..],
            listing.listing_hash().expect("listing hash")
        );
    }

    #[test]
    fn listing_rejects_tampering_noncanonical_signatures_and_bad_frames() {
        let (listing, coin, _) = listing_fixture();

        let mut tampered = listing.clone();
        tampered.sequence += 1;
        assert!(matches!(
            tampered.verify(),
            Err(SwapError::InvalidSignature)
        ));
        assert!(matches!(
            tampered.is_active_at(1_800_000_200),
            Err(SwapError::InvalidSignature)
        ));

        let mut wrong_network = listing.clone();
        wrong_network.proof.network.magic ^= 1;
        assert!(matches!(
            wrong_network.verify_for_network(listing.network(), 1_800_000_200, &coin),
            Err(SwapError::NetworkMismatch)
        ));
        assert!(matches!(
            listing.verify_for_network(listing.network(), listing.created_at - 1, &coin),
            Err(SwapError::ListingNotYetActive)
        ));
        assert!(matches!(
            listing.verify_for_network(listing.network(), listing.expires_at, &coin),
            Err(SwapError::ListingExpired)
        ));

        let signature = Signature::from_slice(&listing.signature.expect("signature"))
            .expect("compact signature");
        let high_signature =
            Signature::from_scalars(signature.r().to_bytes(), (-signature.s()).to_bytes())
                .expect("high-S signature");
        let mut high_s = listing.clone();
        high_s.signature = Some(high_signature.to_bytes().into());
        assert!(matches!(
            high_s.verify(),
            Err(SwapError::HighMarketplaceSignature)
        ));

        let mut bad_hash = listing.encode().expect("listing encoding");
        let last = bad_hash.last_mut().expect("hash byte");
        *last ^= 1;
        assert!(matches!(
            FixedPriceListing::decode(&bad_hash),
            Err(SwapError::ListingHashMismatch)
        ));
        let mut trailing = listing.encode().expect("listing encoding");
        trailing.push(0);
        assert!(matches!(
            FixedPriceListing::decode(&trailing),
            Err(SwapError::Decode(_))
        ));
        assert!(matches!(
            FixedPriceListing::decode(&vec![0; MAX_FIXED_PRICE_LISTING_SIZE + 1]),
            Err(SwapError::ListingTooLarge(_))
        ));

        let mut oversized_proof = Encoder::new();
        oversized_proof.put_u16_le(FIXED_PRICE_LISTING_VERSION);
        oversized_proof.put_u64_le(listing.created_at);
        oversized_proof.put_u64_le(listing.expires_at);
        oversized_proof.put_u64_le(listing.sequence);
        oversized_proof.put_compact_size((MAX_SWAP_PROOF_SIZE + 1) as u64);
        assert!(matches!(
            FixedPriceListing::decode(&oversized_proof.into_bytes()),
            Err(SwapError::Decode(
                hns_encoding::DecodeError::LengthExceedsBound { .. }
            ))
        ));

        let mut bad_presence = listing.encode().expect("signed listing encoding");
        let presence_index = bad_presence.len() - 97;
        bad_presence[presence_index] = 2;
        assert!(matches!(
            FixedPriceListing::decode(&bad_presence),
            Err(SwapError::InvalidPresenceFlag("listing signature"))
        ));

        let mut unsigned = listing.clone();
        unsigned.signature = None;
        assert!(matches!(unsigned.encode(), Err(SwapError::UnsignedListing)));

        let mut zero_sequence = listing;
        zero_sequence.sequence = 0;
        assert!(matches!(
            zero_sequence.validate(),
            Err(SwapError::ZeroListingSequence)
        ));
    }

    #[test]
    fn cancellation_vector_is_newer_exact_and_expiring() {
        let (listing, _, signing_key) = listing_fixture();
        let mut cancellation = ListingCancellation::for_listing(
            &listing,
            listing.created_at + 20,
            listing.expires_at,
            listing.sequence + 1,
        )
        .expect("unsigned cancellation");
        cancellation
            .sign(&signing_key)
            .expect("signed cancellation");
        cancellation
            .verify_for_listing(&listing, listing.network(), cancellation.created_at + 1)
            .expect("valid tombstone");
        assert!(
            cancellation
                .is_active_at(cancellation.created_at + 1)
                .unwrap()
        );

        let mut forged_active = cancellation.clone();
        forged_active.sequence += 1;
        assert!(matches!(
            forged_active.is_active_at(forged_active.created_at + 1),
            Err(SwapError::InvalidSignature)
        ));

        let encoded = cancellation.encode().expect("cancellation encoding");
        assert_eq!(encoded, fixture_bytes("listing_cancellation"));
        assert_eq!(encoded.len(), 224);
        assert_eq!(
            ListingCancellation::decode(&encoded).expect("cancellation decoding"),
            cancellation
        );
        assert_eq!(
            hex::encode(cancellation.signature.expect("signature")),
            "75ec98bd43e79f4546e802200bfbaa3da89a292e3e4f2e25a2fd696a82c03cde4c1351ab937128cd6ccddfdaa1116f384d5d89d7684cb446dcdd11d54ec5f667"
        );
        assert_eq!(
            hex::encode(cancellation.cancellation_hash().expect("cancellation hash")),
            "7b6b9404e77be37b17fbb5bc756592b81133ffdaee5e969d6db5fbe5463c1ba0"
        );
        assert_eq!(
            cancellation
                .cancellation_hash()
                .expect("cancellation hash")
                .as_slice(),
            fixture_bytes("listing_cancellation_hash").as_slice()
        );
        assert_eq!(
            domain_hash(
                CANCELLATION_SIGNATURE_DOMAIN,
                &cancellation
                    .signing_bytes()
                    .expect("cancellation signing bytes"),
            )
            .as_slice(),
            fixture_bytes("listing_cancellation_signature_digest").as_slice()
        );

        let mut stale = cancellation.clone();
        stale.sequence = listing.sequence;
        stale
            .sign(&signing_key)
            .expect("resigned stale cancellation");
        assert!(matches!(
            stale.verify_for_listing(&listing, listing.network(), stale.created_at),
            Err(SwapError::CancellationSequenceNotNewer)
        ));

        let mut wrong_listing = listing.clone();
        wrong_listing.created_at += 1;
        wrong_listing.signature = None;
        wrong_listing
            .sign(&signing_key)
            .expect("different signed listing");
        assert!(matches!(
            cancellation.verify_for_listing(
                &wrong_listing,
                listing.network(),
                cancellation.created_at
            ),
            Err(SwapError::CancellationListingMismatch)
        ));

        let mut short_lived = cancellation.clone();
        short_lived.expires_at = listing.expires_at - 1;
        short_lived
            .sign(&signing_key)
            .expect("signed short cancellation");
        assert!(matches!(
            short_lived.verify_for_listing(&listing, listing.network(), short_lived.created_at),
            Err(SwapError::CancellationExpiresTooEarly)
        ));

        let mut bad_hash = encoded;
        *bad_hash.last_mut().expect("hash byte") ^= 1;
        assert!(matches!(
            ListingCancellation::decode(&bad_hash),
            Err(SwapError::CancellationHashMismatch)
        ));

        let mut trailing = cancellation.encode().expect("cancellation encoding");
        trailing.push(0);
        assert!(matches!(
            ListingCancellation::decode(&trailing),
            Err(SwapError::Decode(_))
        ));
        assert!(matches!(
            ListingCancellation::decode(&vec![0; MAX_LISTING_CANCELLATION_SIZE + 1]),
            Err(SwapError::CancellationTooLarge(_))
        ));
    }
}
