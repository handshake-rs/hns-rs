use hns_covenants::{Resource, ResourceRecord};
use k256::ecdsa::VerifyingKey;

use crate::ChatProtocolError;

const PREFIX: &str = "hnschat=";
const CANONICAL_PREFIX: &str = "hnschat=v1;key=owner;pk=";
const GENERATION_FIELD: &str = ";generation=";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChatKeyMode {
    Owner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChatIdentityBindingV1 {
    pub key_mode: ChatKeyMode,
    pub xonly_public_key: [u8; 32],
    pub generation: u32,
}

pub fn parse_chat_binding(text: &str) -> Result<ChatIdentityBindingV1, ChatProtocolError> {
    if !text.is_ascii() || text.is_empty() || text.bytes().any(|byte| !byte.is_ascii_graphic()) {
        return Err(ChatProtocolError::Invalid(
            "resource binding must contain only visible ASCII without whitespace",
        ));
    }
    let remainder = text
        .strip_prefix(CANONICAL_PREFIX)
        .ok_or(ChatProtocolError::Invalid(
            "resource fields are missing, unknown, duplicated, or out of order",
        ))?;
    let (public_key, generation) = match remainder.split_once(GENERATION_FIELD) {
        Some((public_key, generation)) => {
            if generation.contains(';') {
                return Err(ChatProtocolError::Invalid(
                    "resource has duplicate, unknown, or trailing fields",
                ));
            }
            (public_key, parse_generation(generation)?)
        }
        None => {
            if remainder.contains(';') {
                return Err(ChatProtocolError::Invalid(
                    "resource has duplicate, unknown, or trailing fields",
                ));
            }
            (remainder, 1)
        }
    };
    let xonly_public_key = parse_xonly_public_key(public_key)?;
    Ok(ChatIdentityBindingV1 {
        key_mode: ChatKeyMode::Owner,
        xonly_public_key,
        generation,
    })
}

pub fn encode_chat_binding(binding: &ChatIdentityBindingV1) -> Result<String, ChatProtocolError> {
    if binding.key_mode != ChatKeyMode::Owner || binding.generation == 0 {
        return Err(ChatProtocolError::Invalid(
            "version 1 requires owner key mode and nonzero generation",
        ));
    }
    validate_xonly_public_key(&binding.xonly_public_key)?;
    Ok(format!(
        "{CANONICAL_PREFIX}{}{GENERATION_FIELD}{}",
        hex::encode(binding.xonly_public_key),
        binding.generation
    ))
}

pub fn select_chat_binding<'a>(
    records: impl IntoIterator<Item = &'a str>,
) -> Result<ChatIdentityBindingV1, ChatProtocolError> {
    let mut selected = None;
    for record in records {
        if !record.starts_with(PREFIX) {
            continue;
        }
        let parsed = parse_chat_binding(record)?;
        if selected.replace(parsed).is_some() {
            return Err(ChatProtocolError::AmbiguousBinding);
        }
    }
    selected.ok_or(ChatProtocolError::MissingBinding)
}

pub fn select_chat_binding_from_resource(
    resource: &Resource,
) -> Result<ChatIdentityBindingV1, ChatProtocolError> {
    let mut selected = None;
    for record in resource.records() {
        let ResourceRecord::Txt { strings } = record else {
            continue;
        };
        let length = strings.iter().try_fold(0_usize, |total, string| {
            total
                .checked_add(string.len())
                .ok_or(ChatProtocolError::TooLarge {
                    actual: usize::MAX,
                    maximum: hns_covenants::MAX_RESOURCE_SIZE,
                })
        })?;
        if length > hns_covenants::MAX_RESOURCE_SIZE {
            return Err(ChatProtocolError::TooLarge {
                actual: length,
                maximum: hns_covenants::MAX_RESOURCE_SIZE,
            });
        }
        let mut text = Vec::with_capacity(length);
        for string in strings {
            text.extend_from_slice(string);
        }
        if !text.starts_with(PREFIX.as_bytes()) {
            continue;
        }
        let text = std::str::from_utf8(&text)
            .map_err(|_| ChatProtocolError::Invalid("hnschat TXT record is not canonical ASCII"))?;
        let parsed = parse_chat_binding(text)?;
        if selected.replace(parsed).is_some() {
            return Err(ChatProtocolError::AmbiguousBinding);
        }
    }
    selected.ok_or(ChatProtocolError::MissingBinding)
}

fn parse_generation(text: &str) -> Result<u32, ChatProtocolError> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ChatProtocolError::Invalid(
            "generation is not canonical decimal",
        ));
    }
    let generation = text
        .parse::<u32>()
        .map_err(|_| ChatProtocolError::Invalid("generation exceeds u32"))?;
    if generation == 0 {
        return Err(ChatProtocolError::Invalid("generation must be nonzero"));
    }
    Ok(generation)
}

fn parse_xonly_public_key(text: &str) -> Result<[u8; 32], ChatProtocolError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ChatProtocolError::Invalid(
            "public key must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    let decoded = hex::decode(text)
        .map_err(|_| ChatProtocolError::Invalid("public key is not hexadecimal"))?;
    let public_key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ChatProtocolError::Invalid("public key is not 32 bytes"))?;
    validate_xonly_public_key(&public_key)?;
    Ok(public_key)
}

fn validate_xonly_public_key(public_key: &[u8; 32]) -> Result<(), ChatProtocolError> {
    let mut compressed = [0_u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(public_key);
    VerifyingKey::from_sec1_bytes(&compressed)
        .map(|_| ())
        .map_err(|_| ChatProtocolError::Invalid("invalid secp256k1 x-only public key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917";
    const FIXTURES: &str = include_str!("../fixtures/chat-v1/hns-chat-resource-v1.txt");

    fn fixture(name: &str) -> &str {
        FIXTURES
            .lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value))
            .unwrap_or_else(|| panic!("missing fixture {name}"))
    }

    #[test]
    fn canonical_and_compatibility_forms_parse() {
        let explicit = parse_chat_binding(fixture("valid_explicit")).expect("explicit generation");
        assert_eq!(explicit.generation, 7);
        assert_eq!(explicit.key_mode, ChatKeyMode::Owner);
        let omitted = parse_chat_binding(&format!("hnschat=v1;key=owner;pk={KEY}"))
            .expect("compatibility form");
        assert_eq!(omitted.generation, 1);
        assert_eq!(
            encode_chat_binding(&omitted).expect("canonical encoding"),
            format!("hnschat=v1;key=owner;pk={KEY};generation=1")
        );
    }

    #[test]
    fn malformed_bindings_fail_closed() {
        for value in [
            fixture("invalid_uppercase").to_owned(),
            fixture("invalid_duplicate").to_owned(),
            fixture("invalid_unknown").to_owned(),
            fixture("invalid_zero_generation").to_owned(),
            fixture("invalid_leading_zero_generation").to_owned(),
            fixture("invalid_x_coordinate").to_owned(),
            format!("hnschat=v1;key=owner;key=owner;pk={KEY};generation=1"),
            format!("hnschat=v1;key=owner;pk={KEY};generation=1;"),
            format!("hnschat=v1;key=owner;pk={KEY};generation=1 "),
        ] {
            assert!(parse_chat_binding(&value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn selection_rejects_multiple_candidate_records() {
        let canonical = format!("hnschat=v1;key=owner;pk={KEY};generation=1");
        assert_eq!(
            select_chat_binding(["unrelated", canonical.as_str()])
                .expect("one binding")
                .generation,
            1
        );
        assert_eq!(
            select_chat_binding([canonical.as_str(), canonical.as_str()]),
            Err(ChatProtocolError::AmbiguousBinding)
        );
    }

    #[test]
    fn authenticated_resource_txt_selection_concatenates_chunks_and_rejects_ambiguity() {
        let binding = fixture("valid_explicit");
        let split = binding.len() / 2;
        let mut raw = vec![0, 6, 2, split as u8];
        raw.extend_from_slice(&binding.as_bytes()[..split]);
        raw.push((binding.len() - split) as u8);
        raw.extend_from_slice(&binding.as_bytes()[split..]);
        let resource = Resource::decode(&raw).expect("resource");
        assert_eq!(
            select_chat_binding_from_resource(&resource)
                .expect("binding")
                .generation,
            7
        );
        raw.extend_from_slice(&[6, 1, binding.len() as u8]);
        raw.extend_from_slice(binding.as_bytes());
        let resource = Resource::decode(&raw).expect("resource");
        assert_eq!(
            select_chat_binding_from_resource(&resource),
            Err(ChatProtocolError::AmbiguousBinding)
        );
    }
}
