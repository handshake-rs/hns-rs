#![doc = "Transport-independent wire types for the draft Handshake Named Service Authority protocol."]

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_encoding::{DecodeError, Decoder, Encoder};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use thiserror::Error;
use zeroize::Zeroizing;

const SERVICE_AUTH_DOMAIN: &[u8] = b"HNS-SERVICE-AUTH-V1\0";
const SERVICE_AUTH_ID_DOMAIN: &[u8] = b"HNS-SERVICE-AUTH-ID-V1\0";
const ENDPOINT_DELEGATION_DOMAIN: &[u8] = b"HNS-ENDPOINT-DELEGATION-V1\0";
const ENDPOINT_DELEGATION_ID_DOMAIN: &[u8] = b"HNS-ENDPOINT-DELEGATION-ID-V1\0";
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const COMPRESSED_KEY_BASE32_LENGTH: usize = 53;

pub const VERSION: u8 = 1;
pub const MIN_ENDPOINT_LIFETIME: u32 = 300;
pub const MAX_ENDPOINT_LIFETIME: u32 = 604_800;
pub const MAX_SERVICE_NAME: usize = 63;
pub const MAX_SIGNATURE_SIZE: usize = 80;
pub const MAX_SERVICE_AUTHORIZATION_SIZE: usize = 256;
pub const MAX_ENDPOINT_DELEGATION_SIZE: usize = 256;
pub const MAX_SERVICE_AUTHORIZATION_CANDIDATES: usize = 16;
pub const MAX_ENDPOINT_DELEGATION_CANDIDATES: usize = 32;

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("invalid named service authority value: {0}")]
    Invalid(&'static str),
    #[error("named service authority cryptographic operation failed")]
    Cryptography,
    #[error("named service authority record is missing")]
    Missing,
    #[error("named service authority records are ambiguous")]
    Ambiguous,
    #[error("conflicting objects have the same replacement sequence")]
    ConflictingSequence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRecord {
    pub root_key: [u8; 33],
    pub epoch: u32,
}

impl AuthorityRecord {
    pub fn parse(text: &str) -> Result<Self, AuthorityError> {
        if !text.is_ascii()
            || text
                .chars()
                .any(|character| !character.is_ascii_graphic() && character != ' ')
        {
            return Err(AuthorityError::Invalid("non-printable hsa1 record"));
        }
        let mut fields = text.split(' ');
        if fields.next() != Some("hsa1") {
            return Err(AuthorityError::Invalid("invalid hsa1 marker"));
        }
        let key = fields
            .next()
            .and_then(|field| field.strip_prefix("k="))
            .ok_or(AuthorityError::Invalid("invalid hsa1 key field"))?;
        let epoch = fields
            .next()
            .and_then(|field| field.strip_prefix("e="))
            .ok_or(AuthorityError::Invalid("invalid hsa1 epoch field"))?;
        if fields.next().is_some() || key.is_empty() || epoch.is_empty() {
            return Err(AuthorityError::Invalid("invalid hsa1 field count"));
        }
        if epoch.len() > 1 && epoch.starts_with('0') {
            return Err(AuthorityError::Invalid("noncanonical hsa1 epoch"));
        }
        let epoch = epoch
            .parse::<u32>()
            .map_err(|_| AuthorityError::Invalid("invalid hsa1 epoch"))?;
        if key.len() != COMPRESSED_KEY_BASE32_LENGTH {
            return Err(AuthorityError::Invalid("invalid hsa1 key length"));
        }
        let decoded_key = decode_base32(key)?;
        if encode_base32(&decoded_key) != key {
            return Err(AuthorityError::Invalid("noncanonical hsa1 key encoding"));
        }
        let root_key: [u8; 33] = decoded_key
            .try_into()
            .map_err(|_| AuthorityError::Invalid("invalid hsa1 key length"))?;
        validate_public_key(&root_key)?;
        Ok(Self { root_key, epoch })
    }

    pub fn encode(&self) -> Result<String, AuthorityError> {
        validate_public_key(&self.root_key)?;
        Ok(format!(
            "hsa1 k={} e={}",
            encode_base32(&self.root_key),
            self.epoch
        ))
    }
}

pub fn select_authority_record<'a>(
    records: impl IntoIterator<Item = &'a str>,
) -> Result<AuthorityRecord, AuthorityError> {
    let mut selected = None;
    for record in records {
        if record != "hsa1" && !record.starts_with("hsa1 ") {
            continue;
        }
        let parsed = AuthorityRecord::parse(record)?;
        if selected.replace(parsed).is_some() {
            return Err(AuthorityError::Ambiguous);
        }
    }
    selected.ok_or(AuthorityError::Missing)
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ServiceIdentity {
    pub network_magic: u32,
    pub name_hash: [u8; 32],
    pub service_name: String,
    pub profile_id: u16,
}

impl ServiceIdentity {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        validate_service_name(&self.service_name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceAuthorizationV1 {
    pub network_magic: u32,
    pub name_hash: [u8; 32],
    pub authority_epoch: u32,
    pub service_name: String,
    pub profile_id: u16,
    pub service_key: [u8; 33],
    pub flags: u16,
    pub serial: u64,
    pub valid_from_height: u32,
    pub valid_until_height: u32,
    pub max_endpoint_lifetime: u32,
    pub root_signature: Vec<u8>,
}

impl ServiceAuthorizationV1 {
    pub fn identity(&self) -> ServiceIdentity {
        ServiceIdentity {
            network_magic: self.network_magic,
            name_hash: self.name_hash,
            service_name: self.service_name.clone(),
            profile_id: self.profile_id,
        }
    }

    pub fn encode_unsigned(&self) -> Result<Vec<u8>, AuthorityError> {
        validate_service_name(&self.service_name)?;
        validate_public_key(&self.service_key)?;
        let service_name = self.service_name.as_bytes();
        let mut encoder = Encoder::with_capacity(96 + service_name.len());
        encoder.put_u8(VERSION);
        encoder.put_u32_le(self.network_magic);
        encoder.put_bytes(&self.name_hash);
        encoder.put_u32_le(self.authority_epoch);
        encoder.put_u8(service_name.len() as u8);
        encoder.put_bytes(service_name);
        encoder.put_u16_le(self.profile_id);
        encoder.put_bytes(&self.service_key);
        encoder.put_u16_le(self.flags);
        encoder.put_u64_le(self.serial);
        encoder.put_u32_le(self.valid_from_height);
        encoder.put_u32_le(self.valid_until_height);
        encoder.put_u32_le(self.max_endpoint_lifetime);
        Ok(encoder.into_bytes())
    }

    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<(), AuthorityError> {
        let unsigned = self.encode_unsigned()?;
        self.root_signature = sign(SERVICE_AUTH_DOMAIN, &unsigned[1..], private_key)?;
        Ok(())
    }

    pub fn verify(
        &self,
        authority: &AuthorityRecord,
        identity: &ServiceIdentity,
        current_height: u32,
        allowed_flags: u16,
    ) -> Result<(), AuthorityError> {
        identity.validate()?;
        if self.identity() != *identity
            || self.profile_id == 0
            || self.authority_epoch != authority.epoch
            || self.flags & !allowed_flags != 0
            || self.serial == 0
            || self.valid_until_height <= self.valid_from_height
            || current_height < self.valid_from_height
            || current_height >= self.valid_until_height
            || !(MIN_ENDPOINT_LIFETIME..=MAX_ENDPOINT_LIFETIME)
                .contains(&self.max_endpoint_lifetime)
        {
            return Err(AuthorityError::Invalid(
                "invalid service authorization context",
            ));
        }
        let unsigned = self.encode_unsigned()?;
        verify(
            SERVICE_AUTH_DOMAIN,
            &unsigned[1..],
            &self.root_signature,
            &authority.root_key,
        )
    }

    pub fn id(&self) -> Result<[u8; 32], AuthorityError> {
        Ok(blake2b_256(&[SERVICE_AUTH_ID_DOMAIN, &self.encode()?]))
    }

    pub fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        let unsigned = self.encode_unsigned()?;
        let mut encoder = Encoder::with_capacity(unsigned.len() + 1 + self.root_signature.len());
        encoder.put_bytes(&unsigned);
        encode_signature(&mut encoder, &self.root_signature)?;
        let encoded = encoder.into_bytes();
        if encoded.len() > MAX_SERVICE_AUTHORIZATION_SIZE {
            return Err(AuthorityError::Invalid(
                "service authorization is too large",
            ));
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, AuthorityError> {
        if input.is_empty() || input.len() > MAX_SERVICE_AUTHORIZATION_SIZE {
            return Err(AuthorityError::Invalid(
                "invalid service authorization size",
            ));
        }
        let mut decoder = Decoder::new(input);
        if decoder.read_u8()? != VERSION {
            return Err(AuthorityError::Invalid(
                "unsupported service authorization version",
            ));
        }
        let network_magic = decoder.read_u32_le()?;
        let name_hash = decoder.read_array()?;
        let authority_epoch = decoder.read_u32_le()?;
        let name_length = decoder.read_u8()? as usize;
        if !(1..=MAX_SERVICE_NAME).contains(&name_length) {
            return Err(AuthorityError::Invalid("invalid service name length"));
        }
        let service_name = std::str::from_utf8(decoder.read_slice(name_length)?)
            .map_err(|_| AuthorityError::Invalid("service name is not ASCII"))?
            .to_owned();
        let authorization = Self {
            network_magic,
            name_hash,
            authority_epoch,
            service_name,
            profile_id: decoder.read_u16_le()?,
            service_key: decoder.read_array()?,
            flags: decoder.read_u16_le()?,
            serial: decoder.read_u64_le()?,
            valid_from_height: decoder.read_u32_le()?,
            valid_until_height: decoder.read_u32_le()?,
            max_endpoint_lifetime: decoder.read_u32_le()?,
            root_signature: decode_signature(&mut decoder)?,
        };
        decoder.finish()?;
        authorization.encode_unsigned()?;
        Ok(authorization)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointDelegationV1 {
    pub network_magic: u32,
    pub authorization_id: [u8; 32],
    pub endpoint_key: [u8; 33],
    pub endpoint_sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub capabilities: u32,
    pub constraints_hash: [u8; 32],
    pub service_signature: Vec<u8>,
}

impl EndpointDelegationV1 {
    pub fn encode_unsigned(&self) -> Result<Vec<u8>, AuthorityError> {
        validate_public_key(&self.endpoint_key)?;
        let mut encoder = Encoder::with_capacity(130);
        encoder.put_u8(VERSION);
        encoder.put_u32_le(self.network_magic);
        encoder.put_bytes(&self.authorization_id);
        encoder.put_bytes(&self.endpoint_key);
        encoder.put_u64_le(self.endpoint_sequence);
        encoder.put_u64_le(self.issued_at);
        encoder.put_u64_le(self.expires_at);
        encoder.put_u32_le(self.capabilities);
        encoder.put_bytes(&self.constraints_hash);
        Ok(encoder.into_bytes())
    }

    pub fn sign(&mut self, private_key: &[u8; 32]) -> Result<(), AuthorityError> {
        let unsigned = self.encode_unsigned()?;
        self.service_signature = sign(ENDPOINT_DELEGATION_DOMAIN, &unsigned[1..], private_key)?;
        Ok(())
    }

    pub fn verify(
        &self,
        authorization: &ServiceAuthorizationV1,
        now: u64,
        allowed_capabilities: u32,
        expected_constraints_hash: [u8; 32],
    ) -> Result<(), AuthorityError> {
        if self.network_magic != authorization.network_magic
            || self.authorization_id != authorization.id()?
            || self.endpoint_sequence == 0
            || self.capabilities & !allowed_capabilities != 0
            || self.constraints_hash != expected_constraints_hash
            || self.expires_at <= self.issued_at
            || self.expires_at.saturating_sub(self.issued_at)
                > u64::from(authorization.max_endpoint_lifetime)
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(AuthorityError::Invalid(
                "invalid endpoint delegation context",
            ));
        }
        let unsigned = self.encode_unsigned()?;
        verify(
            ENDPOINT_DELEGATION_DOMAIN,
            &unsigned[1..],
            &self.service_signature,
            &authorization.service_key,
        )
    }

    pub fn id(&self) -> Result<[u8; 32], AuthorityError> {
        Ok(blake2b_256(&[
            ENDPOINT_DELEGATION_ID_DOMAIN,
            &self.encode()?,
        ]))
    }

    pub fn encode(&self) -> Result<Vec<u8>, AuthorityError> {
        let unsigned = self.encode_unsigned()?;
        let mut encoder = Encoder::with_capacity(unsigned.len() + 1 + self.service_signature.len());
        encoder.put_bytes(&unsigned);
        encode_signature(&mut encoder, &self.service_signature)?;
        let encoded = encoder.into_bytes();
        if encoded.len() > MAX_ENDPOINT_DELEGATION_SIZE {
            return Err(AuthorityError::Invalid("endpoint delegation is too large"));
        }
        Ok(encoded)
    }

    pub fn decode(input: &[u8]) -> Result<Self, AuthorityError> {
        if input.is_empty() || input.len() > MAX_ENDPOINT_DELEGATION_SIZE {
            return Err(AuthorityError::Invalid("invalid endpoint delegation size"));
        }
        let mut decoder = Decoder::new(input);
        if decoder.read_u8()? != VERSION {
            return Err(AuthorityError::Invalid(
                "unsupported endpoint delegation version",
            ));
        }
        let delegation = Self {
            network_magic: decoder.read_u32_le()?,
            authorization_id: decoder.read_array()?,
            endpoint_key: decoder.read_array()?,
            endpoint_sequence: decoder.read_u64_le()?,
            issued_at: decoder.read_u64_le()?,
            expires_at: decoder.read_u64_le()?,
            capabilities: decoder.read_u32_le()?,
            constraints_hash: decoder.read_array()?,
            service_signature: decode_signature(&mut decoder)?,
        };
        decoder.finish()?;
        delegation.encode_unsigned()?;
        Ok(delegation)
    }
}

pub fn select_service_authorization<'a>(
    candidates: impl IntoIterator<Item = &'a ServiceAuthorizationV1>,
) -> Result<&'a ServiceAuthorizationV1, AuthorityError> {
    select_by_sequence(
        candidates,
        MAX_SERVICE_AUTHORIZATION_CANDIDATES,
        |candidate| candidate.serial,
        |candidate| candidate.encode(),
    )
}

pub fn select_endpoint_delegation<'a>(
    candidates: impl IntoIterator<Item = &'a EndpointDelegationV1>,
) -> Result<&'a EndpointDelegationV1, AuthorityError> {
    select_by_sequence(
        candidates,
        MAX_ENDPOINT_DELEGATION_CANDIDATES,
        |candidate| candidate.endpoint_sequence,
        |candidate| candidate.encode(),
    )
}

pub fn public_key(private_key: &[u8; 32]) -> Result<[u8; 33], AuthorityError> {
    let key = signing_key(private_key)?;
    key.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| AuthorityError::Cryptography)
}

fn select_by_sequence<'a, T>(
    candidates: impl IntoIterator<Item = &'a T>,
    maximum: usize,
    sequence: impl Fn(&T) -> u64,
    encode: impl Fn(&T) -> Result<Vec<u8>, AuthorityError>,
) -> Result<&'a T, AuthorityError> {
    let mut selected: Option<&T> = None;
    for (index, candidate) in candidates.into_iter().enumerate() {
        if index >= maximum {
            return Err(AuthorityError::Invalid("too many authorization candidates"));
        }
        match selected {
            None => selected = Some(candidate),
            Some(current) if sequence(candidate) > sequence(current) => selected = Some(candidate),
            Some(current)
                if sequence(candidate) == sequence(current)
                    && encode(candidate)? != encode(current)? =>
            {
                return Err(AuthorityError::ConflictingSequence);
            }
            _ => {}
        }
    }
    selected.ok_or(AuthorityError::Missing)
}

fn validate_service_name(name: &str) -> Result<(), AuthorityError> {
    let bytes = name.as_bytes();
    if !(1..=MAX_SERVICE_NAME).contains(&bytes.len())
        || bytes.first() == Some(&b'-')
        || bytes.last() == Some(&b'-')
        || bytes.first() == Some(&b'.')
        || bytes.last() == Some(&b'.')
        || bytes.windows(2).any(|pair| pair == b"..")
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(*byte, b'-' | b'.')
        })
        || name
            .split('.')
            .any(|label| label.starts_with('-') || label.ends_with('-'))
    {
        return Err(AuthorityError::Invalid("noncanonical service name"));
    }
    Ok(())
}

fn encode_signature(encoder: &mut Encoder, signature: &[u8]) -> Result<(), AuthorityError> {
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_SIZE {
        return Err(AuthorityError::Invalid("invalid signature length"));
    }
    encoder.put_u8(signature.len() as u8);
    encoder.put_bytes(signature);
    Ok(())
}

fn decode_signature(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, AuthorityError> {
    let length = decoder.read_u8()? as usize;
    if !(1..=MAX_SIGNATURE_SIZE).contains(&length) {
        return Err(AuthorityError::Invalid("invalid signature length"));
    }
    Ok(decoder.read_bounded_vec(length, MAX_SIGNATURE_SIZE)?)
}

fn sign(domain: &[u8], message: &[u8], private_key: &[u8; 32]) -> Result<Vec<u8>, AuthorityError> {
    let digest = blake2b_256(&[domain, message]);
    let signature: Signature = signing_key(private_key)?
        .sign_prehash(&digest)
        .map_err(|_| AuthorityError::Cryptography)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    Ok(signature.to_der().as_bytes().to_vec())
}

fn verify(
    domain: &[u8],
    message: &[u8],
    signature: &[u8],
    public_key: &[u8; 33],
) -> Result<(), AuthorityError> {
    validate_public_key(public_key)?;
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_SIZE {
        return Err(AuthorityError::Invalid("invalid signature length"));
    }
    let signature = Signature::from_der(signature).map_err(|_| AuthorityError::Cryptography)?;
    if signature.normalize_s().is_some() {
        return Err(AuthorityError::Cryptography);
    }
    let digest = blake2b_256(&[domain, message]);
    VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| AuthorityError::Cryptography)?
        .verify_prehash(&digest, &signature)
        .map_err(|_| AuthorityError::Cryptography)
}

fn validate_public_key(key: &[u8; 33]) -> Result<(), AuthorityError> {
    VerifyingKey::from_sec1_bytes(key)
        .map(|_| ())
        .map_err(|_| AuthorityError::Invalid("invalid compressed secp256k1 public key"))
}

fn signing_key(private_key: &[u8; 32]) -> Result<SigningKey, AuthorityError> {
    let private = Zeroizing::new(*private_key);
    SigningKey::from_bytes((&*private).into()).map_err(|_| AuthorityError::Cryptography)
}

fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

fn encode_base32(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len().saturating_mul(8).div_ceil(5));
    let mut buffer = 0_u16;
    let mut bits = 0_u8;
    for byte in input {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits != 0 {
        output.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    output
}

fn decode_base32(input: &str) -> Result<Vec<u8>, AuthorityError> {
    let mut output = Vec::with_capacity(input.len().saturating_mul(5) / 8);
    let mut buffer = 0_u16;
    let mut bits = 0_u8;
    for byte in input.bytes() {
        let value = BASE32
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or(AuthorityError::Invalid("invalid lowercase base32"))? as u16;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1_u16 << bits).saturating_sub(1);
        }
    }
    if bits != 0 && buffer != 0 {
        return Err(AuthorityError::Invalid("nonzero base32 padding bits"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAGIC: u32 = 0x6d6f6f6e;

    fn authorization(root_private: &[u8; 32], service_key: [u8; 33]) -> ServiceAuthorizationV1 {
        let mut authorization = ServiceAuthorizationV1 {
            network_magic: MAGIC,
            name_hash: [3; 32],
            authority_epoch: 4,
            service_name: "pool-stats".to_owned(),
            profile_id: 0xff00,
            service_key,
            flags: 0,
            serial: 1,
            valid_from_height: 100,
            valid_until_height: 200,
            max_endpoint_lifetime: 3600,
            root_signature: Vec::new(),
        };
        authorization.sign(root_private).expect("sign");
        authorization
    }

    fn delegation(
        authorization: &ServiceAuthorizationV1,
        service_private: &[u8; 32],
    ) -> EndpointDelegationV1 {
        let mut delegation = EndpointDelegationV1 {
            network_magic: MAGIC,
            authorization_id: authorization.id().expect("id"),
            endpoint_key: public_key(&[3; 32]).expect("key"),
            endpoint_sequence: 1,
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_900,
            capabilities: 1,
            constraints_hash: [0; 32],
            service_signature: Vec::new(),
        };
        delegation.sign(service_private).expect("sign");
        delegation
    }

    #[test]
    fn authority_record_is_exact_and_ambiguous_records_fail() {
        let record = AuthorityRecord {
            root_key: public_key(&[1; 32]).expect("key"),
            epoch: 4,
        };
        let encoded = record.encode().expect("encode");
        assert_eq!(AuthorityRecord::parse(&encoded).expect("parse"), record);
        assert!(AuthorityRecord::parse(&format!("{encoded} ")).is_err());
        assert!(select_authority_record([encoded.as_str(), encoded.as_str()]).is_err());
        assert_eq!(
            select_authority_record(["unrelated", encoded.as_str()]).expect("one"),
            record
        );
        assert!(matches!(
            select_authority_record(["hsa1x unrelated"]),
            Err(AuthorityError::Missing)
        ));
        assert!(AuthorityRecord::parse(&encoded.replacen(" e=", "a e=", 1)).is_err());
        assert!(AuthorityRecord::parse(&encoded.replace(" e=4", "  e=4")).is_err());
        assert!(AuthorityRecord::parse(&encoded.replace("e=4", "e=04")).is_err());
    }

    #[test]
    fn authority_and_endpoint_chain_round_trip_and_bind_context() {
        let root_private = [1; 32];
        let service_private = [2; 32];
        let authority = AuthorityRecord {
            root_key: public_key(&root_private).expect("key"),
            epoch: 4,
        };
        let authorization =
            authorization(&root_private, public_key(&service_private).expect("key"));
        let identity = authorization.identity();
        authorization
            .verify(&authority, &identity, 150, 0)
            .expect("valid");
        let decoded = ServiceAuthorizationV1::decode(&authorization.encode().expect("encode"))
            .expect("decode");
        assert_eq!(decoded, authorization);
        assert!(authorization.verify(&authority, &identity, 200, 0).is_err());

        let delegation = delegation(&authorization, &service_private);
        delegation
            .verify(&authorization, 1_700_000_100, 1, [0; 32])
            .expect("valid");
        let decoded =
            EndpointDelegationV1::decode(&delegation.encode().expect("encode")).expect("decode");
        assert_eq!(decoded, delegation);
        assert!(
            delegation
                .verify(&authorization, 1_700_000_100, 0, [0; 32])
                .is_err()
        );
        assert!(
            delegation
                .verify(&authorization, delegation.expires_at, 1, [0; 32])
                .is_err()
        );
    }

    #[test]
    fn replacement_selection_rejects_equal_sequence_conflicts() {
        let root = [1; 32];
        let service = public_key(&[2; 32]).expect("key");
        let first = authorization(&root, service);
        let mut second = first.clone();
        second.serial = 2;
        second.sign(&root).expect("sign");
        assert_eq!(
            select_service_authorization([&first, &second])
                .expect("latest")
                .serial,
            2
        );
        let mut conflict = second.clone();
        conflict.valid_until_height += 1;
        conflict.sign(&root).expect("sign");
        assert!(matches!(
            select_service_authorization([&second, &conflict]),
            Err(AuthorityError::ConflictingSequence)
        ));
    }

    #[test]
    fn current_authority_context_controls_authorization() {
        let root = [1; 32];
        let service = [2; 32];
        let authority = AuthorityRecord {
            root_key: public_key(&root).expect("key"),
            epoch: 4,
        };
        let authorization = authorization(&root, public_key(&service).expect("key"));
        let identity = authorization.identity();

        let mut wrong_network = identity.clone();
        wrong_network.network_magic ^= 1;
        assert!(
            authorization
                .verify(&authority, &wrong_network, 150, 0)
                .is_err()
        );

        let mut rotated = authority.clone();
        rotated.epoch += 1;
        assert!(authorization.verify(&rotated, &identity, 150, 0).is_err());

        let mut tampered = authorization.clone();
        tampered.serial += 1;
        assert!(tampered.verify(&authority, &identity, 150, 0).is_err());

        let mut zero_serial = authorization.clone();
        zero_serial.serial = 0;
        zero_serial.sign(&root).expect("sign");
        assert!(zero_serial.verify(&authority, &identity, 150, 0).is_err());

        let mut flagged = authorization.clone();
        flagged.flags = 1;
        flagged.sign(&root).expect("sign");
        assert!(flagged.verify(&authority, &identity, 150, 0).is_err());
        flagged
            .verify(&authority, &identity, 150, 1)
            .expect("recognized flag");
    }

    #[test]
    fn endpoint_context_and_signature_are_bounded() {
        let root = [1; 32];
        let service = [2; 32];
        let authorization = authorization(&root, public_key(&service).expect("key"));
        let endpoint = delegation(&authorization, &service);

        let mut tampered = endpoint.clone();
        tampered.endpoint_sequence += 1;
        assert!(
            tampered
                .verify(&authorization, 1_700_000_100, 1, [0; 32])
                .is_err()
        );

        let mut zero_sequence = endpoint.clone();
        zero_sequence.endpoint_sequence = 0;
        zero_sequence.sign(&service).expect("sign");
        assert!(
            zero_sequence
                .verify(&authorization, 1_700_000_100, 1, [0; 32])
                .is_err()
        );

        let mut too_long = endpoint.clone();
        too_long.expires_at = too_long.issued_at + 3601;
        too_long.sign(&service).expect("sign");
        assert!(
            too_long
                .verify(&authorization, 1_700_000_100, 1, [0; 32])
                .is_err()
        );

        assert!(
            endpoint
                .verify(&authorization, 1_700_000_100, 1, [1; 32])
                .is_err()
        );
    }

    #[test]
    fn decoding_requires_complete_bounded_canonical_input() {
        let root = [1; 32];
        let service = [2; 32];
        let authorization = authorization(&root, public_key(&service).expect("key"));
        let endpoint = delegation(&authorization, &service);

        for mut encoded in [
            authorization.encode().expect("authorization"),
            endpoint.encode().expect("endpoint"),
        ] {
            encoded.push(0);
            assert!(
                ServiceAuthorizationV1::decode(&encoded).is_err()
                    && EndpointDelegationV1::decode(&encoded).is_err()
            );
        }
        assert!(ServiceAuthorizationV1::decode(&[]).is_err());
        assert!(EndpointDelegationV1::decode(&[]).is_err());
    }

    #[test]
    fn replacement_candidate_counts_are_bounded() {
        let root = [1; 32];
        let service = [2; 32];
        let authorization = authorization(&root, public_key(&service).expect("key"));
        let endpoint = delegation(&authorization, &service);
        let authorizations = vec![&authorization; MAX_SERVICE_AUTHORIZATION_CANDIDATES + 1];
        let endpoints = vec![&endpoint; MAX_ENDPOINT_DELEGATION_CANDIDATES + 1];

        assert!(select_service_authorization(authorizations).is_err());
        assert!(select_endpoint_delegation(endpoints).is_err());
    }

    #[test]
    fn deterministic_vector_is_stable() {
        let root = [1; 32];
        let service = [2; 32];
        let authority = AuthorityRecord {
            root_key: public_key(&root).expect("key"),
            epoch: 4,
        };
        let authorization = authorization(&root, public_key(&service).expect("key"));
        let endpoint = delegation(&authorization, &service);

        assert_eq!(
            authority.encode().expect("record"),
            "hsa1 k=amnyjrkwpmjgiqezlu7nlkv2avs5ohqygrqeqgp7tql7l2ov3udy6 e=4"
        );
        assert_eq!(
            hex::encode(authorization.encode().expect("authorization")),
            concat!(
                "016e6f6f6d0303030303030303030303030303030303030303030303030303030303030303",
                "040000000a706f6f6c2d737461747300ff024d4b6cd1361032ca9bd2aeb9d900aa4d45d9e",
                "ad80ac9423374c451a7254d07660000010000000000000064000000c8000000100e00004630",
                "4402205498366dd5db5a7739d938483d2bbff7b385d05e1dcef6407606249162fa66a60220",
                "0ea4ff95d74e128ffe00871cbfcb5f57edb558b9f3b105f6f66f436448389f62"
            )
        );
        assert_eq!(
            hex::encode(authorization.id().expect("authorization id")),
            "8be9084286087569965d27b289f1061477fa4984a587b7e1b6bc376fcb8dfb1f"
        );
        assert_eq!(
            hex::encode(endpoint.encode().expect("endpoint")),
            concat!(
                "01",
                "6e6f6f6d",
                "8be9084286087569965d27b289f1061477fa4984a587b7e1b6bc376fcb8dfb1f",
                "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
                "0100000000000000",
                "00f1536500000000",
                "84f4536500000000",
                "01000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "46",
                "3044022016c4ddac408150fc986a8620e7f6b26a9b4956e4fb9e90bb39de865228add05c",
                "022044cf07d46ab3e997807fbb5a17dc3334acd8df0e6989e8f19b5fa09fbd7c05b9"
            )
        );
        assert_eq!(
            hex::encode(endpoint.id().expect("endpoint id")),
            "634c53a729432c2dffd3ef7ea03be6e7d1c869c634b1e742276de869b8808c29"
        );
    }
}
