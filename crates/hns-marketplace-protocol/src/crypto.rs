use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::{MarketplaceError, Result};

pub(crate) const COMPACT_SIGNATURE_SIZE: usize = 64;

pub(crate) fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    hasher.update(domain);
    hasher.update(bytes);
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

pub(crate) fn public_key(private_key: &[u8; 32]) -> Result<[u8; 33]> {
    let key = signing_key(private_key)?;
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| MarketplaceError::InvalidSignature)
}

pub(crate) fn validate_public_key(public_key: &[u8; 33]) -> Result<()> {
    VerifyingKey::from_sec1_bytes(public_key)
        .map(|_| ())
        .map_err(|_| MarketplaceError::InvalidSignature)
}

pub(crate) fn sign(
    domain: &[u8],
    bytes: &[u8],
    expected_public_key: &[u8; 33],
    private_key: &[u8; 32],
) -> Result<[u8; COMPACT_SIGNATURE_SIZE]> {
    let key = signing_key(private_key)?;
    let actual = key.verifying_key().to_encoded_point(true);
    if actual.as_bytes() != expected_public_key {
        return Err(MarketplaceError::SigningKeyMismatch);
    }
    let digest = hash(domain, bytes);
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|_| MarketplaceError::InvalidSignature)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    Ok(signature.to_bytes().into())
}

pub(crate) fn verify(
    domain: &[u8],
    bytes: &[u8],
    signature: &[u8; COMPACT_SIGNATURE_SIZE],
    public_key: &[u8; 33],
) -> Result<()> {
    let key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| MarketplaceError::InvalidSignature)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| MarketplaceError::InvalidSignature)?;
    if signature.normalize_s().is_some() {
        return Err(MarketplaceError::InvalidSignature);
    }
    key.verify_prehash(&hash(domain, bytes), &signature)
        .map_err(|_| MarketplaceError::InvalidSignature)
}

fn signing_key(private_key: &[u8; 32]) -> Result<SigningKey> {
    let private = Zeroizing::new(*private_key);
    SigningKey::from_bytes((&*private).into()).map_err(|_| MarketplaceError::InvalidSignature)
}
