use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hkdf::Hkdf;
use hns_encoding::{Decoder, Encoder};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use sha2::Sha256;

use crate::{MAX_ODOH_CONFIG_LIFETIME, MAX_ODOH_CONFIG_SIZE, OdohProtocolError};

const TARGET_CONFIG_TAG: &[u8] = b"HNS-P2P-ODOH-CONFIG-V1\0";
const KEY_ID_INFO: &[u8] = b"odoh key id";
const DIRECT_BRONTIDE: u8 = 1;
const HOST_IPV4: u8 = 4;
const HOST_IPV6: u8 = 6;
const SUPPORTED_CONFIG_VERSION: u16 = 1;
const KEM_X25519_SHA256: u16 = 0x0020;
const KDF_HKDF_SHA256: u16 = 0x0001;
const AEAD_AES_128_GCM: u16 = 0x0001;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectTargetLocator {
    pub target_peer_key: [u8; 33],
    pub address: SocketAddr,
}

impl DirectTargetLocator {
    pub fn new(
        target_peer_key: [u8; 33],
        address: SocketAddr,
        allow_private: bool,
    ) -> Result<Self, OdohProtocolError> {
        VerifyingKey::from_sec1_bytes(&target_peer_key)
            .map_err(|_| OdohProtocolError::Invalid("invalid target peer key"))?;
        if address.port() == 0 || address.ip().is_unspecified() {
            return Err(OdohProtocolError::Invalid("invalid target endpoint"));
        }
        if !allow_private && !is_publicly_routable(address.ip()) {
            return Err(OdohProtocolError::Invalid(
                "target endpoint is not publicly routable",
            ));
        }
        Ok(Self {
            target_peer_key,
            address,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::with_capacity(55);
        encoder.put_u8(DIRECT_BRONTIDE);
        encoder.put_bytes(&self.target_peer_key);
        encoder.put_u16_le(19);
        match self.address.ip() {
            IpAddr::V4(address) => {
                encoder.put_u8(HOST_IPV4);
                encoder.put_bytes(&[0; 10]);
                encoder.put_bytes(&[0xff, 0xff]);
                encoder.put_bytes(&address.octets());
            }
            IpAddr::V6(address) => {
                encoder.put_u8(HOST_IPV6);
                encoder.put_bytes(&address.octets());
            }
        }
        encoder.put_u16_le(self.address.port());
        encoder.into_bytes()
    }

    pub fn decode(input: &[u8], allow_private: bool) -> Result<Self, OdohProtocolError> {
        let mut decoder = Decoder::new(input);
        let locator = Self::decode_from(&mut decoder, allow_private)?;
        decoder.finish()?;
        Ok(locator)
    }

    pub(crate) fn decode_from(
        decoder: &mut Decoder<'_>,
        allow_private: bool,
    ) -> Result<Self, OdohProtocolError> {
        if decoder.read_u8()? != DIRECT_BRONTIDE {
            return Err(OdohProtocolError::Invalid(
                "unsupported target locator type",
            ));
        }
        let target_peer_key = decoder.read_array::<33>()?;
        if decoder.read_u16_le()? != 19 {
            return Err(OdohProtocolError::Invalid(
                "unsupported target locator length",
            ));
        }
        let host_type = decoder.read_u8()?;
        let host = decoder.read_array::<16>()?;
        let port = decoder.read_u16_le()?;
        let address = match host_type {
            HOST_IPV4 if host[..10] == [0; 10] && host[10..12] == [0xff, 0xff] => SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(host[12], host[13], host[14], host[15])),
                port,
            ),
            HOST_IPV6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::from(host)), port),
            _ => {
                return Err(OdohProtocolError::Invalid("target host encoding mismatch"));
            }
        };
        Self::new(target_peer_key, address, allow_private)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdohConfig {
    pub public_key: [u8; 32],
}

impl OdohConfig {
    pub fn contents(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(40);
        output.extend(KEM_X25519_SHA256.to_be_bytes());
        output.extend(KDF_HKDF_SHA256.to_be_bytes());
        output.extend(AEAD_AES_128_GCM.to_be_bytes());
        output.extend(32_u16.to_be_bytes());
        output.extend(self.public_key);
        output
    }

    pub fn key_id(&self) -> Result<[u8; 32], OdohProtocolError> {
        let hkdf = Hkdf::<Sha256>::new(Some(&[]), &self.contents());
        let mut key_id = [0_u8; 32];
        hkdf.expand(KEY_ID_INFO, &mut key_id)
            .map_err(|_| OdohProtocolError::Cryptography)?;
        Ok(key_id)
    }
}

pub fn encode_config_list(configurations: &[OdohConfig]) -> Result<Vec<u8>, OdohProtocolError> {
    if configurations.is_empty() {
        return Err(OdohProtocolError::Invalid(
            "ODoH configuration list is empty",
        ));
    }
    let mut list = Vec::new();
    for configuration in configurations {
        list.extend(SUPPORTED_CONFIG_VERSION.to_be_bytes());
        write_tls_vector(&mut list, &configuration.contents(), false)?;
    }
    let mut output = Vec::with_capacity(list.len() + 2);
    write_tls_vector(&mut output, &list, false)?;
    if output.len() > MAX_ODOH_CONFIG_SIZE {
        return Err(OdohProtocolError::TooLarge {
            actual: output.len(),
            maximum: MAX_ODOH_CONFIG_SIZE,
        });
    }
    Ok(output)
}

pub fn decode_config_list(input: &[u8]) -> Result<Vec<OdohConfig>, OdohProtocolError> {
    if input.is_empty() || input.len() > MAX_ODOH_CONFIG_SIZE {
        return Err(OdohProtocolError::TooLarge {
            actual: input.len(),
            maximum: MAX_ODOH_CONFIG_SIZE,
        });
    }
    let mut outer = TlsDecoder::new(input);
    let list = outer.vector(false)?;
    outer.finish()?;
    let mut decoder = TlsDecoder::new(list);
    let mut configurations = Vec::new();
    while decoder.remaining() != 0 {
        let version = decoder.read_u16_be()?;
        let contents = decoder.vector(false)?;
        if version != SUPPORTED_CONFIG_VERSION {
            continue;
        }
        let mut contents_decoder = TlsDecoder::new(contents);
        if contents_decoder.read_u16_be()? != KEM_X25519_SHA256
            || contents_decoder.read_u16_be()? != KDF_HKDF_SHA256
            || contents_decoder.read_u16_be()? != AEAD_AES_128_GCM
        {
            return Err(OdohProtocolError::Invalid("unsupported ODoH cipher suite"));
        }
        let public_key = contents_decoder.vector(false)?;
        if public_key.len() != 32 {
            return Err(OdohProtocolError::Invalid("invalid ODoH public key"));
        }
        contents_decoder.finish()?;
        let mut key = [0_u8; 32];
        key.copy_from_slice(public_key);
        configurations.push(OdohConfig { public_key: key });
    }
    if configurations.is_empty() {
        return Err(OdohProtocolError::Invalid(
            "no supported ODoH configuration",
        ));
    }
    Ok(configurations)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetConfigRecord {
    pub locator: DirectTargetLocator,
    pub network_magic: u32,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub configurations: Vec<OdohConfig>,
    pub record_id: [u8; 32],
    raw: Vec<u8>,
}

impl TargetConfigRecord {
    pub fn decode_and_verify(
        input: &[u8],
        expected_locator: &DirectTargetLocator,
        expected_network_magic: u32,
        now: u64,
        allow_private: bool,
    ) -> Result<Self, OdohProtocolError> {
        if input.is_empty() || input.len() > MAX_ODOH_CONFIG_SIZE {
            return Err(OdohProtocolError::TooLarge {
                actual: input.len(),
                maximum: MAX_ODOH_CONFIG_SIZE,
            });
        }
        let mut decoder = Decoder::new(input);
        if decoder.read_u8()? != 1 {
            return Err(OdohProtocolError::Invalid(
                "unsupported target record version",
            ));
        }
        let network_magic = decoder.read_u32_le()?;
        if network_magic != expected_network_magic {
            return Err(OdohProtocolError::Invalid("wrong target record network"));
        }
        let locator = DirectTargetLocator::decode_from(&mut decoder, allow_private)?;
        if locator != *expected_locator {
            return Err(OdohProtocolError::Invalid("target locator substitution"));
        }
        let sequence = decoder.read_u64_le()?;
        let issued_at = decoder.read_u64_le()?;
        let expires_at = decoder.read_u64_le()?;
        let configurations_length = decoder.read_u16_le()? as usize;
        if configurations_length == 0 || configurations_length > MAX_ODOH_CONFIG_SIZE {
            return Err(OdohProtocolError::TooLarge {
                actual: configurations_length,
                maximum: MAX_ODOH_CONFIG_SIZE,
            });
        }
        let configuration_bytes =
            decoder.read_bounded_vec(configurations_length, MAX_ODOH_CONFIG_SIZE)?;
        let unsigned_length = decoder.position();
        let signature_length = decoder.read_u8()? as usize;
        if !(8..=72).contains(&signature_length) || decoder.remaining() != signature_length {
            return Err(OdohProtocolError::Invalid(
                "invalid target signature length",
            ));
        }
        let signature_bytes = decoder.read_bounded_vec(signature_length, 72)?;
        decoder.finish()?;
        if sequence == 0 {
            return Err(OdohProtocolError::Invalid("target record sequence is zero"));
        }
        if issued_at > now.saturating_add(300)
            || expires_at <= issued_at
            || expires_at <= now
            || expires_at.saturating_sub(issued_at) > MAX_ODOH_CONFIG_LIFETIME
        {
            return Err(OdohProtocolError::Invalid("invalid target record lifetime"));
        }
        let configurations = decode_config_list(&configuration_bytes)?;
        let signature = Signature::from_der(&signature_bytes)
            .map_err(|_| OdohProtocolError::InvalidSignature)?;
        if signature.normalize_s().is_some() {
            return Err(OdohProtocolError::InvalidSignature);
        }
        let digest = blake2b_256(&[TARGET_CONFIG_TAG, &input[..unsigned_length]]);
        let verifying_key = VerifyingKey::from_sec1_bytes(&locator.target_peer_key)
            .map_err(|_| OdohProtocolError::InvalidSignature)?;
        verifying_key
            .verify_prehash(&digest, &signature)
            .map_err(|_| OdohProtocolError::InvalidSignature)?;
        let record_id = blake2b_256(&[input]);
        Ok(Self {
            locator,
            network_magic,
            sequence,
            issued_at,
            expires_at,
            configurations,
            record_id,
            raw: input.to_vec(),
        })
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

pub(crate) fn write_tls_vector(
    output: &mut Vec<u8>,
    value: &[u8],
    allow_empty: bool,
) -> Result<(), OdohProtocolError> {
    if !allow_empty && value.is_empty() {
        return Err(OdohProtocolError::Invalid("empty TLS vector"));
    }
    let length = u16::try_from(value.len()).map_err(|_| OdohProtocolError::TooLarge {
        actual: value.len(),
        maximum: u16::MAX as usize,
    })?;
    output.extend(length.to_be_bytes());
    output.extend(value);
    Ok(())
}

pub(crate) struct TlsDecoder<'input> {
    decoder: Decoder<'input>,
}

impl<'input> TlsDecoder<'input> {
    pub(crate) const fn new(input: &'input [u8]) -> Self {
        Self {
            decoder: Decoder::new(input),
        }
    }

    pub(crate) const fn remaining(&self) -> usize {
        self.decoder.remaining()
    }

    pub(crate) fn read_u16_be(&mut self) -> Result<u16, OdohProtocolError> {
        Ok(u16::from_be_bytes(self.decoder.read_array()?))
    }

    pub(crate) fn vector(&mut self, allow_empty: bool) -> Result<&'input [u8], OdohProtocolError> {
        let length = self.read_u16_be()? as usize;
        if !allow_empty && length == 0 {
            return Err(OdohProtocolError::Invalid("empty TLS vector"));
        }
        Ok(self.decoder.read_slice(length)?)
    }

    pub(crate) fn finish(self) -> Result<(), OdohProtocolError> {
        self.decoder.finish()?;
        Ok(())
    }
}

pub(crate) fn blake2b_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

fn is_publicly_routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_broadcast()
                && !address.is_documentation()
                && !address.is_multicast()
                && !address.is_unspecified()
                && octets[0] != 0
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
                && !(octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
                && octets[0] < 240
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_publicly_routable(IpAddr::V4(mapped));
            }
            !(address.is_loopback()
                || address.is_multicast()
                || address.is_unspecified()
                || segments[0] & 0xfe00 == 0xfc00
                || segments[0] & 0xffc0 == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector_locator() -> DirectTargetLocator {
        DirectTargetLocator::new(
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .expect("hex")
                .try_into()
                .expect("33 bytes"),
            "127.0.0.1:14039".parse().expect("socket"),
            true,
        )
        .expect("valid")
    }

    #[test]
    fn deterministic_configuration_vectors_match_hsd() {
        let locator = vector_locator();
        assert_eq!(
            hex::encode(locator.encode()),
            "010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179813000400000000000000000000ffff7f000001d736"
        );
        let config = OdohConfig {
            public_key: hex::decode(
                "8f40c5adb68f25624ae5b214ea767a6e0ddee42f4a9cfb73d04fc85b3c9b4f5d",
            )
            .expect("hex")
            .try_into()
            .expect("32 bytes"),
        };
        assert_eq!(
            hex::encode(config.contents()),
            "00200001000100208f40c5adb68f25624ae5b214ea767a6e0ddee42f4a9cfb73d04fc85b3c9b4f5d"
        );
        assert_eq!(
            hex::encode(encode_config_list(std::slice::from_ref(&config)).expect("valid")),
            "002c0001002800200001000100208f40c5adb68f25624ae5b214ea767a6e0ddee42f4a9cfb73d04fc85b3c9b4f5d"
        );
        assert_eq!(
            hex::encode(config.key_id().expect("valid")),
            "91eaf90f9a4fa36870e3799a652817f85f888e9652f39a11faaba70470d8f753"
        );
    }

    #[test]
    fn signed_target_record_vector_matches_hsd() {
        let raw = hex::decode(concat!(
            "01cf9538ae010279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "13000400000000000000000000ffff7f000001d736070000000000000000f153650000000080425565",
            "000000002e00002c0001002800200001000100208f40c5adb68f25624ae5b214ea767a6e0ddee42f",
            "4a9cfb73d04fc85b3c9b4f5d473045022100ee73e264dd74d0c05ba717ba46c10634d2f262053286",
            "84596fabae02ee9caca2022055650d588c8c19ddab2540145f1aba212816bd5a0acf4f3802af5992",
            "f04fe2e0"
        ))
        .expect("hex");
        let record = TargetConfigRecord::decode_and_verify(
            &raw,
            &vector_locator(),
            2_922_943_951,
            1_700_000_001,
            true,
        )
        .expect("valid");
        assert_eq!(record.sequence, 7);
        assert_eq!(record.configurations.len(), 1);
        assert_eq!(
            hex::encode(record.record_id),
            "ba9524fe3591e6165d9646a6c08975f6bc38448d1a60bf7f1810534e465e612c"
        );
    }

    #[test]
    fn public_profile_rejects_private_target_addresses() {
        let key = vector_locator().target_peer_key;
        assert!(
            DirectTargetLocator::new(key, "127.0.0.1:14039".parse().expect("socket"), false)
                .is_err()
        );
        assert!(
            DirectTargetLocator::new(key, "8.8.8.8:14039".parse().expect("socket"), false).is_ok()
        );
    }
}
