use hns_primitives::BlockHash;
use hns_swap::NetworkBinding;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{MarketplaceError, Result};

/// Draft HRM/HNSA profile carried by Denuo relay-acceptance receipts.
///
/// No official HNSA application profile number is assigned here. A product
/// must select and validate its own nonzero application profile identifier.
pub const HNSA_NAMED_SERVICE_RESOURCE_PROFILE: &str = "hns.named-service/v1";
/// Maximum canonical size of one endpoint-signed publication receipt.
pub const MAX_DENUO_PUBLICATION_ACCEPTANCE_BYTES: usize = 768;
/// Maximum lifetime admitted by the receipt codec, independent of a stricter
/// caller-selected policy.
pub const MAX_DENUO_PUBLICATION_ACCEPTANCE_LIFETIME_SECONDS: u32 = 7 * 24 * 60 * 60;

const ACCEPTANCE_MAGIC: &[u8; 4] = b"HDRA";
const ACCEPTANCE_VERSION: u16 = 1;
const RELAY_ACCEPTED_OUTCOME: u8 = 1;
const ACCEPTANCE_SIGNATURE_DOMAIN: &[u8] = b"hns-wallet-denuo-name-market-acceptance-v1\0";
const ACCEPTANCE_ID_DOMAIN: &[u8] = b"hns-wallet-denuo-name-market-acceptance-id-v1\0";
const POLICY_FINGERPRINT_DOMAIN: &[u8] = b"hns-wallet-denuo-publication-policy-v1\0";

/// Exact HRM root material that authorized the configured named relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoHrmRootBinding {
    pub subject: [u8; 32],
    pub sequence: u64,
    pub envelope_hash: [u8; 32],
    pub chain_height: u64,
    pub chain_work_be: [u8; 32],
    pub chain_anchor: [u8; 32],
}

/// Exact HNSA service and endpoint delegation material used for relay handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoHnsaEndpointBinding {
    pub canonical_service_name: Vec<u8>,
    pub application_profile_id: u16,
    pub service_resource_id: [u8; 32],
    pub service_delegation_id: [u8; 32],
    pub service_generation: u64,
    pub endpoint_delegation_id: [u8; 32],
    pub endpoint_sequence: u64,
    pub endpoint_public_key: [u8; 33],
    pub effective_not_before_unix: u64,
    pub effective_expires_at_unix: u64,
}

/// Immutable endpoint policy bound into every signed relay acceptance.
///
/// A verified receipt proves only that the configured endpoint accepted the
/// exact handoff. It does not prove peer propagation, board inclusion, offer
/// currentness, chain authority, price authority, or permission to move value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenuoPublicationAcceptancePolicy {
    network_magic: u32,
    network_genesis: [u8; 32],
    hrm: DenuoHrmRootBinding,
    hnsa: DenuoHnsaEndpointBinding,
    maximum_receipt_lifetime_seconds: u32,
    fingerprint: [u8; 32],
}

impl DenuoPublicationAcceptancePolicy {
    pub fn new(
        network: NetworkBinding,
        hrm: DenuoHrmRootBinding,
        hnsa: DenuoHnsaEndpointBinding,
        maximum_receipt_lifetime_seconds: u32,
    ) -> Result<Self> {
        let mut policy = Self {
            network_magic: network.magic,
            network_genesis: *network.genesis.as_bytes(),
            hrm,
            hnsa,
            maximum_receipt_lifetime_seconds,
            fingerprint: [0; 32],
        };
        policy.validate_fields()?;
        policy.fingerprint = policy.compute_fingerprint();
        Ok(policy)
    }

    pub const fn network(&self) -> NetworkBinding {
        NetworkBinding {
            magic: self.network_magic,
            genesis: BlockHash::new(self.network_genesis),
        }
    }

    pub const fn hrm(&self) -> &DenuoHrmRootBinding {
        &self.hrm
    }

    pub const fn hnsa(&self) -> &DenuoHnsaEndpointBinding {
        &self.hnsa
    }

    pub const fn maximum_receipt_lifetime_seconds(&self) -> u32 {
        self.maximum_receipt_lifetime_seconds
    }

    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    fn validate_fields(&self) -> Result<()> {
        if is_zero(&self.network_genesis)
            || is_zero(&self.hrm.subject)
            || is_zero(&self.hrm.envelope_hash)
            || is_zero(&self.hrm.chain_anchor)
            || is_zero(&self.hnsa.service_resource_id)
            || is_zero(&self.hnsa.service_delegation_id)
            || is_zero(&self.hnsa.endpoint_delegation_id)
            || !is_canonical_service_name(&self.hnsa.canonical_service_name)
            || self.hnsa.application_profile_id == 0
            || self.hnsa.service_generation == 0
            || self.hnsa.endpoint_sequence == 0
            || VerifyingKey::from_sec1_bytes(&self.hnsa.endpoint_public_key).is_err()
            || self.hnsa.effective_not_before_unix >= self.hnsa.effective_expires_at_unix
            || !(1..=MAX_DENUO_PUBLICATION_ACCEPTANCE_LIFETIME_SECONDS)
                .contains(&self.maximum_receipt_lifetime_seconds)
        {
            return Err(MarketplaceError::Invalid(
                "invalid Denuo publication acceptance policy",
            ));
        }
        Ok(())
    }

    fn compute_fingerprint(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(320);
        encoded.extend_from_slice(POLICY_FINGERPRINT_DOMAIN);
        encoded.extend_from_slice(HNSA_NAMED_SERVICE_RESOURCE_PROFILE.as_bytes());
        encoded.push(0);
        self.encode_material(&mut encoded);
        Sha256::digest(encoded).into()
    }

    fn encode_material(&self, encoded: &mut Vec<u8>) {
        put_u32(encoded, self.network_magic);
        put_hash(encoded, self.network_genesis);
        put_hash(encoded, self.hrm.subject);
        put_u64(encoded, self.hrm.sequence);
        put_hash(encoded, self.hrm.envelope_hash);
        put_u64(encoded, self.hrm.chain_height);
        encoded.extend_from_slice(&self.hrm.chain_work_be);
        put_hash(encoded, self.hrm.chain_anchor);
        encoded.push(self.hnsa.canonical_service_name.len() as u8);
        encoded.extend_from_slice(&self.hnsa.canonical_service_name);
        put_u16(encoded, self.hnsa.application_profile_id);
        put_hash(encoded, self.hnsa.service_resource_id);
        put_hash(encoded, self.hnsa.service_delegation_id);
        put_u64(encoded, self.hnsa.service_generation);
        put_hash(encoded, self.hnsa.endpoint_delegation_id);
        put_u64(encoded, self.hnsa.endpoint_sequence);
        encoded.extend_from_slice(&self.hnsa.endpoint_public_key);
        put_u64(encoded, self.hnsa.effective_not_before_unix);
        put_u64(encoded, self.hnsa.effective_expires_at_unix);
        put_u32(encoded, self.maximum_receipt_lifetime_seconds);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenuoPublicationMessageKind {
    Offer,
    Cancellation,
}

/// Exact durable wallet handoff fields covered by an endpoint receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenuoPublicationAcceptanceExpectation {
    pub network_magic: u32,
    pub network_genesis: [u8; 32],
    pub attempt_id: [u8; 32],
    pub record_sequence: u64,
    pub prepared_at_unix: u64,
    pub envelope_id: [u8; 32],
    pub envelope_digest: [u8; 32],
    pub content_id: [u8; 32],
    pub message_kind: DenuoPublicationMessageKind,
    pub request_id: u64,
}

/// Canonically decoded and endpoint-signature-verified relay receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDenuoPublicationAcceptance {
    policy: DenuoPublicationAcceptancePolicy,
    expectation: DenuoPublicationAcceptanceExpectation,
    issued_at_unix: u64,
    expires_at_unix: u64,
    receipt_id: [u8; 32],
}

impl VerifiedDenuoPublicationAcceptance {
    pub const fn policy(&self) -> &DenuoPublicationAcceptancePolicy {
        &self.policy
    }

    pub const fn expectation(&self) -> DenuoPublicationAcceptanceExpectation {
        self.expectation
    }

    pub const fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub const fn receipt_id(&self) -> [u8; 32] {
        self.receipt_id
    }
}

#[derive(Clone)]
struct ParsedAcceptance {
    policy: DenuoPublicationAcceptancePolicy,
    expectation: DenuoPublicationAcceptanceExpectation,
    issued_at_unix: u64,
    expires_at_unix: u64,
    signature: Vec<u8>,
}

/// Create a canonical, low-S DER endpoint receipt for one exact handoff.
pub fn sign_denuo_publication_acceptance(
    policy: &DenuoPublicationAcceptancePolicy,
    expectation: DenuoPublicationAcceptanceExpectation,
    issued_at_unix: u64,
    expires_at_unix: u64,
    endpoint_private_key: &[u8; 32],
) -> Result<Vec<u8>> {
    require_policy_expectation(policy, expectation, issued_at_unix)?;
    validate_window(policy, issued_at_unix, expires_at_unix)?;
    let private = Zeroizing::new(*endpoint_private_key);
    let key = SigningKey::from_bytes((&*private).into())
        .map_err(|_| MarketplaceError::InvalidSignature)?;
    if key.verifying_key().to_encoded_point(true).as_bytes() != policy.hnsa.endpoint_public_key {
        return Err(MarketplaceError::SigningKeyMismatch);
    }
    let mut parsed = ParsedAcceptance {
        policy: policy.clone(),
        expectation,
        issued_at_unix,
        expires_at_unix,
        signature: Vec::new(),
    };
    let body = encode_unsigned(&parsed);
    let signature: Signature = key
        .sign_prehash(&acceptance_digest(&body))
        .map_err(|_| MarketplaceError::InvalidSignature)?;
    let signature = signature.normalize_s().unwrap_or(signature).to_der();
    parsed.signature = signature.as_bytes().to_vec();
    let mut receipt = body;
    put_u16(
        &mut receipt,
        parsed
            .signature
            .len()
            .try_into()
            .map_err(|_| MarketplaceError::InvalidSignature)?,
    );
    receipt.extend_from_slice(&parsed.signature);
    if receipt.len() > MAX_DENUO_PUBLICATION_ACCEPTANCE_BYTES {
        return Err(MarketplaceError::TooLarge {
            actual: receipt.len(),
            maximum: MAX_DENUO_PUBLICATION_ACCEPTANCE_BYTES,
        });
    }
    Ok(receipt)
}

/// Decode, canonicalize, and verify one endpoint receipt.
pub fn verify_denuo_publication_acceptance(
    receipt_bytes: &[u8],
) -> Result<VerifiedDenuoPublicationAcceptance> {
    let parsed = parse_and_verify(receipt_bytes)?;
    let mut hasher = Sha256::new();
    hasher.update(ACCEPTANCE_ID_DOMAIN);
    hasher.update(receipt_bytes);
    Ok(VerifiedDenuoPublicationAcceptance {
        policy: parsed.policy,
        expectation: parsed.expectation,
        issued_at_unix: parsed.issued_at_unix,
        expires_at_unix: parsed.expires_at_unix,
        receipt_id: hasher.finalize().into(),
    })
}

/// Verify and bind a receipt to the caller's exact configured policy, durable
/// handoff, and trusted acceptance time.
pub fn verify_expected_denuo_publication_acceptance(
    policy: &DenuoPublicationAcceptancePolicy,
    expectation: DenuoPublicationAcceptanceExpectation,
    receipt_bytes: &[u8],
    accepted_at_unix: u64,
) -> Result<VerifiedDenuoPublicationAcceptance> {
    let verified = verify_denuo_publication_acceptance(receipt_bytes)?;
    if verified.policy != *policy
        || verified.expectation != expectation
        || verified.issued_at_unix != accepted_at_unix
        || accepted_at_unix < expectation.prepared_at_unix
    {
        return Err(MarketplaceError::Invalid(
            "Denuo publication acceptance does not match its handoff",
        ));
    }
    Ok(verified)
}

fn parse_and_verify(receipt_bytes: &[u8]) -> Result<ParsedAcceptance> {
    if receipt_bytes.is_empty() || receipt_bytes.len() > MAX_DENUO_PUBLICATION_ACCEPTANCE_BYTES {
        return Err(MarketplaceError::Invalid(
            "invalid Denuo publication acceptance size",
        ));
    }
    let mut decoder = Decoder::new(receipt_bytes);
    if decoder.take(4)? != ACCEPTANCE_MAGIC
        || decoder.u16()? != ACCEPTANCE_VERSION
        || decoder.u8()? != RELAY_ACCEPTED_OUTCOME
    {
        return Err(invalid_receipt());
    }
    let network_magic = decoder.u32()?;
    let network_genesis = decoder.hash()?;
    let hrm = DenuoHrmRootBinding {
        subject: decoder.hash()?,
        sequence: decoder.u64()?,
        envelope_hash: decoder.hash()?,
        chain_height: decoder.u64()?,
        chain_work_be: decoder.hash()?,
        chain_anchor: decoder.hash()?,
    };
    let name_length = usize::from(decoder.u8()?);
    let canonical_service_name = decoder.take(name_length)?.to_vec();
    let hnsa = DenuoHnsaEndpointBinding {
        canonical_service_name,
        application_profile_id: decoder.u16()?,
        service_resource_id: decoder.hash()?,
        service_delegation_id: decoder.hash()?,
        service_generation: decoder.u64()?,
        endpoint_delegation_id: decoder.hash()?,
        endpoint_sequence: decoder.u64()?,
        endpoint_public_key: decoder.array()?,
        effective_not_before_unix: decoder.u64()?,
        effective_expires_at_unix: decoder.u64()?,
    };
    let maximum_receipt_lifetime_seconds = decoder.u32()?;
    let policy = DenuoPublicationAcceptancePolicy::new(
        NetworkBinding {
            magic: network_magic,
            genesis: BlockHash::new(network_genesis),
        },
        hrm,
        hnsa,
        maximum_receipt_lifetime_seconds,
    )?;
    let policy_fingerprint = decoder.hash()?;
    let expectation = DenuoPublicationAcceptanceExpectation {
        network_magic,
        network_genesis,
        attempt_id: decoder.hash()?,
        record_sequence: decoder.u64()?,
        prepared_at_unix: decoder.u64()?,
        envelope_id: decoder.hash()?,
        envelope_digest: decoder.hash()?,
        content_id: decoder.hash()?,
        message_kind: match decoder.u8()? {
            1 => DenuoPublicationMessageKind::Offer,
            2 => DenuoPublicationMessageKind::Cancellation,
            _ => return Err(invalid_receipt()),
        },
        request_id: decoder.u64()?,
    };
    let issued_at_unix = decoder.u64()?;
    let expires_at_unix = decoder.u64()?;
    let signed_body_length = decoder.position();
    let signature_length = usize::from(decoder.u16()?);
    let signature = decoder.take(signature_length)?.to_vec();
    if !decoder.is_finished() || policy_fingerprint != policy.fingerprint {
        return Err(invalid_receipt());
    }
    require_policy_expectation(&policy, expectation, issued_at_unix)?;
    validate_window(&policy, issued_at_unix, expires_at_unix)?;
    let parsed = ParsedAcceptance {
        policy,
        expectation,
        issued_at_unix,
        expires_at_unix,
        signature,
    };
    let body = encode_unsigned(&parsed);
    let mut canonical = body.clone();
    put_u16(
        &mut canonical,
        parsed
            .signature
            .len()
            .try_into()
            .map_err(|_| invalid_receipt())?,
    );
    canonical.extend_from_slice(&parsed.signature);
    if body.len() != signed_body_length || canonical != receipt_bytes {
        return Err(invalid_receipt());
    }
    let signature =
        Signature::from_der(&parsed.signature).map_err(|_| MarketplaceError::InvalidSignature)?;
    if signature.normalize_s().is_some() || signature.to_der().as_bytes() != parsed.signature {
        return Err(MarketplaceError::InvalidSignature);
    }
    let key = VerifyingKey::from_sec1_bytes(&parsed.policy.hnsa.endpoint_public_key)
        .map_err(|_| MarketplaceError::InvalidSignature)?;
    key.verify_prehash(&acceptance_digest(&body), &signature)
        .map_err(|_| MarketplaceError::InvalidSignature)?;
    Ok(parsed)
}

fn require_policy_expectation(
    policy: &DenuoPublicationAcceptancePolicy,
    expectation: DenuoPublicationAcceptanceExpectation,
    issued_at_unix: u64,
) -> Result<()> {
    if expectation.network_magic != policy.network_magic
        || expectation.network_genesis != policy.network_genesis
        || expectation.request_id == 0
        || expectation.record_sequence == 0
        || is_zero(&expectation.attempt_id)
        || is_zero(&expectation.envelope_id)
        || is_zero(&expectation.envelope_digest)
        || is_zero(&expectation.content_id)
        || issued_at_unix < expectation.prepared_at_unix
    {
        return Err(invalid_receipt());
    }
    Ok(())
}

fn validate_window(
    policy: &DenuoPublicationAcceptancePolicy,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> Result<()> {
    let maximum_expiry = issued_at_unix
        .checked_add(u64::from(policy.maximum_receipt_lifetime_seconds))
        .ok_or_else(invalid_receipt)?;
    if expires_at_unix <= issued_at_unix
        || issued_at_unix < policy.hnsa.effective_not_before_unix
        || expires_at_unix > policy.hnsa.effective_expires_at_unix
        || expires_at_unix > maximum_expiry
    {
        return Err(invalid_receipt());
    }
    Ok(())
}

fn encode_unsigned(parsed: &ParsedAcceptance) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(512);
    encoded.extend_from_slice(ACCEPTANCE_MAGIC);
    put_u16(&mut encoded, ACCEPTANCE_VERSION);
    encoded.push(RELAY_ACCEPTED_OUTCOME);
    parsed.policy.encode_material(&mut encoded);
    put_hash(&mut encoded, parsed.policy.fingerprint);
    put_hash(&mut encoded, parsed.expectation.attempt_id);
    put_u64(&mut encoded, parsed.expectation.record_sequence);
    put_u64(&mut encoded, parsed.expectation.prepared_at_unix);
    put_hash(&mut encoded, parsed.expectation.envelope_id);
    put_hash(&mut encoded, parsed.expectation.envelope_digest);
    put_hash(&mut encoded, parsed.expectation.content_id);
    encoded.push(match parsed.expectation.message_kind {
        DenuoPublicationMessageKind::Offer => 1,
        DenuoPublicationMessageKind::Cancellation => 2,
    });
    put_u64(&mut encoded, parsed.expectation.request_id);
    put_u64(&mut encoded, parsed.issued_at_unix);
    put_u64(&mut encoded, parsed.expires_at_unix);
    encoded
}

fn acceptance_digest(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACCEPTANCE_SIGNATURE_DOMAIN);
    hasher.update(body);
    hasher.finalize().into()
}

fn is_canonical_service_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.first() != Some(&b'-')
        && name.last() != Some(&b'-')
        && name
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn is_zero(hash: &[u8; 32]) -> bool {
    hash == &[0; 32]
}

fn invalid_receipt() -> MarketplaceError {
    MarketplaceError::Invalid("invalid Denuo publication acceptance")
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_hash(output: &mut Vec<u8>, value: [u8; 32]) {
    output.extend_from_slice(&value);
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(invalid_receipt)?;
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| invalid_receipt())
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn hash(&mut self) -> Result<[u8; 32]> {
        self.array()
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        DenuoPublicationAcceptancePolicy,
        DenuoPublicationAcceptanceExpectation,
        [u8; 32],
    ) {
        let private_key = [0x42; 32];
        let signing_key = SigningKey::from_bytes((&private_key).into()).expect("signing key");
        let endpoint_public_key = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed key");
        let network = NetworkBinding {
            magic: 0xae38_95cf,
            genesis: BlockHash::new([0x11; 32]),
        };
        let policy = DenuoPublicationAcceptancePolicy::new(
            network,
            DenuoHrmRootBinding {
                subject: [0x12; 32],
                sequence: 7,
                envelope_hash: [0x13; 32],
                chain_height: 50,
                chain_work_be: [0x14; 32],
                chain_anchor: [0x15; 32],
            },
            DenuoHnsaEndpointBinding {
                canonical_service_name: b"denuo-relay".to_vec(),
                application_profile_id: 7,
                service_resource_id: [0x16; 32],
                service_delegation_id: [0x17; 32],
                service_generation: 3,
                endpoint_delegation_id: [0x18; 32],
                endpoint_sequence: 4,
                endpoint_public_key,
                effective_not_before_unix: 1_700_000_000,
                effective_expires_at_unix: 1_700_100_000,
            },
            300,
        )
        .expect("policy");
        let expectation = DenuoPublicationAcceptanceExpectation {
            network_magic: network.magic,
            network_genesis: *network.genesis.as_bytes(),
            attempt_id: [0x21; 32],
            record_sequence: 1,
            prepared_at_unix: 1_700_000_010,
            envelope_id: [0x22; 32],
            envelope_digest: [0x23; 32],
            content_id: [0x24; 32],
            message_kind: DenuoPublicationMessageKind::Offer,
            request_id: 9,
        };
        (policy, expectation, private_key)
    }

    #[test]
    fn endpoint_receipt_is_canonical_exact_and_handoff_bound() {
        let (policy, expectation, private_key) = fixture();
        let receipt = sign_denuo_publication_acceptance(
            &policy,
            expectation,
            1_700_000_011,
            1_700_000_111,
            &private_key,
        )
        .expect("receipt");
        let verified = verify_expected_denuo_publication_acceptance(
            &policy,
            expectation,
            &receipt,
            1_700_000_011,
        )
        .expect("verified receipt");
        assert_eq!(verified.policy(), &policy);
        assert_eq!(verified.expectation(), expectation);
        assert_eq!(verified.issued_at_unix(), 1_700_000_011);
        assert_eq!(verified.expires_at_unix(), 1_700_000_111);
        assert_ne!(verified.receipt_id(), [0; 32]);

        let mut wrong = expectation;
        wrong.content_id[0] ^= 1;
        assert!(
            verify_expected_denuo_publication_acceptance(&policy, wrong, &receipt, 1_700_000_011,)
                .is_err()
        );
        let mut noncanonical = receipt;
        noncanonical.push(0);
        assert!(verify_denuo_publication_acceptance(&noncanonical).is_err());
    }

    #[test]
    fn endpoint_key_and_receipt_window_fail_closed() {
        let (policy, expectation, _) = fixture();
        assert!(
            sign_denuo_publication_acceptance(
                &policy,
                expectation,
                1_700_000_011,
                1_700_000_111,
                &[0x43; 32],
            )
            .is_err()
        );
        assert!(
            sign_denuo_publication_acceptance(
                &policy,
                expectation,
                1_700_000_011,
                1_700_000_312,
                &[0x42; 32],
            )
            .is_err()
        );
    }
}
