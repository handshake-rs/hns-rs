use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm as ResponseAes128Gcm, Nonce};
use hkdf::Hkdf;
use hpke::aead::{AeadCtxS, AesGcm128};
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable, setup_receiver, setup_sender,
};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::config::{OdohConfig, TlsDecoder, write_tls_vector};
use crate::{MAX_ODOH_QUERY_SIZE, MAX_ODOH_RESPONSE_SIZE, OdohProtocolError};

const QUERY_INFO: &[u8] = b"odoh query";
const RESPONSE_INFO: &[u8] = b"odoh response";
const RESPONSE_KEY_INFO: &[u8] = b"odoh key";
const RESPONSE_NONCE_INFO: &[u8] = b"odoh nonce";
const X25519_ENCAPSULATED_KEY_SIZE: usize = 32;

type OdohSenderContext = AeadCtxS<AesGcm128, HkdfSha256, X25519HkdfSha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OdohMessageType {
    Query = 1,
    Response = 2,
}

impl TryFrom<u8> for OdohMessageType {
    type Error = OdohProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Query),
            2 => Ok(Self::Response),
            _ => Err(OdohProtocolError::Invalid("unknown RFC 9230 message type")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdohMessage {
    pub message_type: OdohMessageType,
    pub key_id: Vec<u8>,
    pub encrypted_message: Vec<u8>,
}

impl OdohMessage {
    pub fn new(
        message_type: OdohMessageType,
        key_id: Vec<u8>,
        encrypted_message: Vec<u8>,
    ) -> Result<Self, OdohProtocolError> {
        let message = Self {
            message_type,
            key_id,
            encrypted_message,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn encode(&self) -> Result<Vec<u8>, OdohProtocolError> {
        self.validate()?;
        let mut output = Vec::with_capacity(5 + self.key_id.len() + self.encrypted_message.len());
        output.push(self.message_type as u8);
        write_tls_vector(&mut output, &self.key_id, true)?;
        write_tls_vector(&mut output, &self.encrypted_message, false)?;
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, OdohProtocolError> {
        if input.is_empty() {
            return Err(OdohProtocolError::Invalid("truncated ODoH message"));
        }
        let message_type = OdohMessageType::try_from(input[0])?;
        let mut decoder = TlsDecoder::new(&input[1..]);
        let key_id = decoder.vector(true)?.to_vec();
        let encrypted_message = decoder.vector(false)?.to_vec();
        decoder.finish()?;
        Self::new(message_type, key_id, encrypted_message)
    }

    pub fn aad(&self) -> Result<Vec<u8>, OdohProtocolError> {
        let mut output = Vec::with_capacity(3 + self.key_id.len());
        output.push(self.message_type as u8);
        write_tls_vector(&mut output, &self.key_id, true)?;
        Ok(output)
    }

    fn validate(&self) -> Result<(), OdohProtocolError> {
        if self.key_id.len() > u16::MAX as usize {
            return Err(OdohProtocolError::TooLarge {
                actual: self.key_id.len(),
                maximum: u16::MAX as usize,
            });
        }
        if self.encrypted_message.is_empty() || self.encrypted_message.len() > u16::MAX as usize {
            return Err(OdohProtocolError::TooLarge {
                actual: self.encrypted_message.len(),
                maximum: u16::MAX as usize,
            });
        }
        Ok(())
    }
}

pub struct QueryContext {
    context: OdohSenderContext,
    query_plaintext: Vec<u8>,
}

impl QueryContext {
    pub fn open_response(self, response: &OdohMessage) -> Result<Vec<u8>, OdohProtocolError> {
        if response.message_type != OdohMessageType::Response || response.key_id.len() != 16 {
            return Err(OdohProtocolError::Invalid("invalid ODoH response"));
        }
        let mut response_secret = [0_u8; 16];
        self.context
            .export(RESPONSE_INFO, &mut response_secret)
            .map_err(|_| OdohProtocolError::Cryptography)?;
        let (key, nonce) =
            derive_response_secrets(&response_secret, &self.query_plaintext, &response.key_id)?;
        response_secret.zeroize();
        let cipher =
            ResponseAes128Gcm::new_from_slice(&key).map_err(|_| OdohProtocolError::Cryptography)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &response.encrypted_message,
                    aad: &response.aad()?,
                },
            )
            .map_err(|_| OdohProtocolError::Cryptography)?;
        decode_plaintext(&plaintext)
    }
}

impl Drop for QueryContext {
    fn drop(&mut self) {
        self.query_plaintext.zeroize();
    }
}

pub struct OpenedQuery {
    dns: Vec<u8>,
    response_secret: [u8; 16],
    query_plaintext: Vec<u8>,
}

impl OpenedQuery {
    pub fn dns(&self) -> &[u8] {
        &self.dns
    }

    pub fn seal_response(
        self,
        dns_response: &[u8],
        response_nonce: [u8; 16],
        block_size: usize,
    ) -> Result<OdohMessage, OdohProtocolError> {
        if dns_response.len() > MAX_ODOH_RESPONSE_SIZE {
            return Err(OdohProtocolError::TooLarge {
                actual: dns_response.len(),
                maximum: MAX_ODOH_RESPONSE_SIZE,
            });
        }
        let plaintext = encode_plaintext(dns_response, block_size)?;
        let (mut key, nonce) = derive_response_secrets(
            &self.response_secret,
            &self.query_plaintext,
            &response_nonce,
        )?;
        let cipher =
            ResponseAes128Gcm::new_from_slice(&key).map_err(|_| OdohProtocolError::Cryptography)?;
        let response = OdohMessage {
            message_type: OdohMessageType::Response,
            key_id: response_nonce.to_vec(),
            encrypted_message: Vec::new(),
        };
        let encrypted_message = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &response.aad()?,
                },
            )
            .map_err(|_| OdohProtocolError::Cryptography)?;
        key.zeroize();
        OdohMessage::new(
            OdohMessageType::Response,
            response_nonce.to_vec(),
            encrypted_message,
        )
    }
}

impl Drop for OpenedQuery {
    fn drop(&mut self) {
        self.dns.zeroize();
        self.response_secret.zeroize();
        self.query_plaintext.zeroize();
    }
}

pub fn seal_query(
    configuration: &OdohConfig,
    dns: &[u8],
) -> Result<(OdohMessage, QueryContext), OdohProtocolError> {
    if dns.len() > MAX_ODOH_QUERY_SIZE {
        return Err(OdohProtocolError::TooLarge {
            actual: dns.len(),
            maximum: MAX_ODOH_QUERY_SIZE,
        });
    }
    let key_id = configuration.key_id()?;
    let public_key =
        <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(&configuration.public_key)
            .map_err(|_| OdohProtocolError::Invalid("invalid HPKE public key"))?;
    let (encapsulated, mut context) = setup_sender::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &public_key,
        QUERY_INFO,
    )
    .map_err(|_| OdohProtocolError::Cryptography)?;
    let query_plaintext = encode_plaintext(dns, 128)?;
    let provisional = OdohMessage {
        message_type: OdohMessageType::Query,
        key_id: key_id.to_vec(),
        encrypted_message: Vec::new(),
    };
    let ciphertext = context
        .seal(&query_plaintext, &provisional.aad()?)
        .map_err(|_| OdohProtocolError::Cryptography)?;
    let mut encrypted_message = encapsulated.to_bytes().to_vec();
    encrypted_message.extend(ciphertext);
    Ok((
        OdohMessage::new(OdohMessageType::Query, key_id.to_vec(), encrypted_message)?,
        QueryContext {
            context,
            query_plaintext,
        },
    ))
}

pub fn open_query(
    private_key: &[u8; 32],
    configuration: &OdohConfig,
    query: &OdohMessage,
) -> Result<OpenedQuery, OdohProtocolError> {
    if query.message_type != OdohMessageType::Query
        || query.key_id.as_slice() != configuration.key_id()?
    {
        return Err(OdohProtocolError::Invalid(
            "query uses the wrong ODoH configuration",
        ));
    }
    if query.encrypted_message.len() <= X25519_ENCAPSULATED_KEY_SIZE {
        return Err(OdohProtocolError::Invalid("truncated HPKE query"));
    }
    let private_key = <X25519HkdfSha256 as KemTrait>::PrivateKey::from_bytes(private_key)
        .map_err(|_| OdohProtocolError::Cryptography)?;
    let encapsulated = <X25519HkdfSha256 as KemTrait>::EncappedKey::from_bytes(
        &query.encrypted_message[..X25519_ENCAPSULATED_KEY_SIZE],
    )
    .map_err(|_| OdohProtocolError::Cryptography)?;
    let mut context = setup_receiver::<AesGcm128, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private_key,
        &encapsulated,
        QUERY_INFO,
    )
    .map_err(|_| OdohProtocolError::Cryptography)?;
    let query_plaintext = context
        .open(
            &query.encrypted_message[X25519_ENCAPSULATED_KEY_SIZE..],
            &query.aad()?,
        )
        .map_err(|_| OdohProtocolError::Cryptography)?;
    let dns = decode_plaintext(&query_plaintext)?;
    let mut response_secret = [0_u8; 16];
    context
        .export(RESPONSE_INFO, &mut response_secret)
        .map_err(|_| OdohProtocolError::Cryptography)?;
    Ok(OpenedQuery {
        dns,
        response_secret,
        query_plaintext,
    })
}

pub fn derive_response_secrets(
    secret: &[u8; 16],
    query_plaintext: &[u8],
    response_nonce: &[u8],
) -> Result<([u8; 16], [u8; 12]), OdohProtocolError> {
    let nonce_length =
        u16::try_from(response_nonce.len()).map_err(|_| OdohProtocolError::TooLarge {
            actual: response_nonce.len(),
            maximum: u16::MAX as usize,
        })?;
    let mut salt = Vec::with_capacity(query_plaintext.len() + 2 + response_nonce.len());
    salt.extend(query_plaintext);
    salt.extend(nonce_length.to_be_bytes());
    salt.extend(response_nonce);
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), secret);
    let mut key = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    hkdf.expand(RESPONSE_KEY_INFO, &mut key)
        .map_err(|_| OdohProtocolError::Cryptography)?;
    hkdf.expand(RESPONSE_NONCE_INFO, &mut nonce)
        .map_err(|_| OdohProtocolError::Cryptography)?;
    salt.zeroize();
    Ok((key, nonce))
}

pub fn encode_plaintext(dns: &[u8], block_size: usize) -> Result<Vec<u8>, OdohProtocolError> {
    if dns.is_empty() || dns.len() > u16::MAX as usize || block_size == 0 {
        return Err(OdohProtocolError::Invalid("invalid DNS plaintext size"));
    }
    let padding_size = (block_size - dns.len() % block_size) % block_size;
    if padding_size > u16::MAX as usize {
        return Err(OdohProtocolError::TooLarge {
            actual: padding_size,
            maximum: u16::MAX as usize,
        });
    }
    let mut output = Vec::with_capacity(4 + dns.len() + padding_size);
    write_tls_vector(&mut output, dns, false)?;
    output.extend((padding_size as u16).to_be_bytes());
    output.resize(output.len() + padding_size, 0);
    Ok(output)
}

pub fn decode_plaintext(input: &[u8]) -> Result<Vec<u8>, OdohProtocolError> {
    let mut decoder = TlsDecoder::new(input);
    let dns = decoder.vector(false)?.to_vec();
    let padding = decoder.vector(true)?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(OdohProtocolError::Invalid(
            "ODoH plaintext padding is nonzero",
        ));
    }
    decoder.finish()?;
    Ok(dns)
}

#[cfg(test)]
mod tests {
    use hpke::Kem as _;

    use super::*;

    fn configuration_and_private_key() -> (OdohConfig, [u8; 32]) {
        let (private, public) = X25519HkdfSha256::gen_keypair();
        (
            OdohConfig {
                public_key: public.to_bytes().as_slice().try_into().expect("32 bytes"),
            },
            private.to_bytes().as_slice().try_into().expect("32 bytes"),
        )
    }

    #[test]
    fn deterministic_plaintext_and_response_kdf_match_hsd() {
        let dns = hex::decode(
            "123401100001000000000001037777770972656c617974657374000001000100002904d0000080000000",
        )
        .expect("hex");
        let plaintext = encode_plaintext(&dns, 128).expect("valid");
        assert_eq!(
            hex::encode(&plaintext),
            "002a123401100001000000000001037777770972656c617974657374000001000100002904d000008000000000560000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        let (key, nonce) = derive_response_secrets(
            &hex::decode("000102030405060708090a0b0c0d0e0f")
                .expect("hex")
                .try_into()
                .expect("16 bytes"),
            &plaintext,
            &hex::decode("101112131415161718191a1b1c1d1e1f").expect("hex"),
        )
        .expect("valid");
        assert_eq!(hex::encode(key), "56193fc769e00a71a627887fd954dab9");
        assert_eq!(hex::encode(nonce), "6dcdcf8e2b4ec24f49ac986f");
    }

    #[test]
    fn requester_and_target_complete_rfc9230_round_trip() {
        let (configuration, private_key) = configuration_and_private_key();
        let query_dns = b"\x12\x34query";
        let response_dns = b"\x12\x34response";
        let (query, context) = seal_query(&configuration, query_dns).expect("seals");
        let opened = open_query(&private_key, &configuration, &query).expect("opens");
        assert_eq!(opened.dns(), query_dns);
        let response = opened
            .seal_response(response_dns, [9; 16], 128)
            .expect("seals");
        assert_eq!(
            context.open_response(&response).expect("opens"),
            response_dns
        );
    }

    #[test]
    fn wrong_key_and_nonzero_padding_fail_closed() {
        let (configuration, private_key) = configuration_and_private_key();
        let (wrong_configuration, wrong_private_key) = configuration_and_private_key();
        let (query, _) = seal_query(&configuration, b"dns").expect("seals");
        assert!(open_query(&wrong_private_key, &wrong_configuration, &query).is_err());

        let mut plaintext = encode_plaintext(b"dns", 8).expect("valid");
        *plaintext.last_mut().expect("padding") = 1;
        assert!(decode_plaintext(&plaintext).is_err());
        assert!(open_query(&private_key, &wrong_configuration, &query).is_err());
    }
}
