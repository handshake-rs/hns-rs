//! Parsing and deterministic selection of `hrm1` Handshake TXT commitments.
//!
//! A commitment is represented as one TXT record with multiple character
//! strings. The strings are deliberately accepted as a slice: joining them
//! before parsing would make records with different wire encodings
//! indistinguishable.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use thiserror::Error;

use crate::uri::is_valid_absolute_uri;

const HRM_MARKER: &str = "hrm1";
const HASH_PREFIX: &str = "sha256:";
const SHA256_BASE64URL_LENGTH: usize = 43;

// These are limits of the existing version-0 Handshake resource encoding,
// rather than configurable policy defaults.
const HNS_MAX_RESOURCE_BYTES: usize = 512;
const HNS_MAX_TXT_STRINGS: usize = u8::MAX as usize;
const HNS_MAX_TXT_STRING_BYTES: usize = u8::MAX as usize;
const HNS_MAX_TXT_RECORDS: usize = u8::MAX as usize;

/// Bounds applied while parsing and combining HRM TXT commitments.
///
/// The defaults retain the Handshake 255-byte character-string and 512-byte
/// resource limits. Four URIs matches the draft HRM locator-attempt default.
/// Extension limits are additionally bounded by the TXT string count and
/// complete encoded-record byte limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitmentLimits {
    /// Maximum number of candidate TXT records inspected during selection.
    pub maximum_candidate_records: usize,
    /// Maximum character-strings in one TXT record or a merged commitment.
    pub maximum_txt_strings: usize,
    /// Maximum bytes in one TXT character-string.
    pub maximum_txt_string_bytes: usize,
    /// Maximum standalone version-0 resource bytes occupied by the TXT record.
    pub maximum_record_bytes: usize,
    /// Maximum distinct retrieval URIs in one commitment.
    pub maximum_uris: usize,
    /// Maximum distinct `x-` extension keys in one commitment.
    pub maximum_extension_keys: usize,
    /// Maximum distinct `x-` extension key/value pairs in one commitment.
    pub maximum_extension_values: usize,
}

impl Default for CommitmentLimits {
    fn default() -> Self {
        Self {
            maximum_candidate_records: HNS_MAX_TXT_RECORDS,
            maximum_txt_strings: HNS_MAX_TXT_STRINGS,
            maximum_txt_string_bytes: HNS_MAX_TXT_STRING_BYTES,
            maximum_record_bytes: HNS_MAX_RESOURCE_BYTES,
            maximum_uris: 4,
            maximum_extension_keys: HNS_MAX_TXT_STRINGS,
            maximum_extension_values: HNS_MAX_TXT_STRINGS,
        }
    }
}

/// A syntactically valid version-1 HRM commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HrmCommitment {
    pub sequence: u64,
    pub envelope_hash: [u8; 32],
    pub uris: Vec<String>,
    pub extensions: BTreeMap<String, Vec<String>>,
}

/// Failure to parse or unambiguously select an HRM commitment.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CommitmentError {
    #[error("invalid HRM commitment limits: {0}")]
    InvalidLimits(&'static str),
    #[error("HRM TXT record is empty")]
    EmptyRecord,
    #[error("first HRM TXT character-string is not exactly `hrm1`")]
    InvalidMarker,
    #[error("too many candidate TXT records: {actual} exceeds {maximum}")]
    TooManyCandidateRecords { actual: usize, maximum: usize },
    #[error("too many HRM TXT character-strings: {actual} exceeds {maximum}")]
    TooManyStrings { actual: usize, maximum: usize },
    #[error("HRM TXT character-string {index} is too long: {actual} bytes exceeds {maximum}")]
    StringTooLong {
        index: usize,
        actual: usize,
        maximum: usize,
    },
    #[error("HRM TXT character-string {index} contains non-printable ASCII")]
    NonPrintableAscii { index: usize },
    #[error("HRM TXT record is too large: {actual} bytes exceeds {maximum}")]
    RecordTooLarge { actual: usize, maximum: usize },
    #[error("HRM TXT character-string {index} is not one key=value field")]
    MalformedField { index: usize },
    #[error("missing required HRM commitment field `{0}`")]
    MissingField(&'static str),
    #[error("duplicate singleton HRM commitment field `{0}`")]
    DuplicateSingleton(&'static str),
    #[error("HRM commitment sequence is not canonical unsigned decimal")]
    InvalidSequence,
    #[error("HRM commitment hash is not canonical unpadded base64url SHA-256")]
    InvalidHash,
    #[error("HRM commitment URI at character-string {index} is invalid")]
    InvalidUri { index: usize },
    #[error("too many HRM commitment URIs: {actual} exceeds {maximum}")]
    TooManyUris { actual: usize, maximum: usize },
    #[error("unknown critical HRM commitment field `{0}`")]
    UnknownField(String),
    #[error("too many HRM commitment extension keys: {actual} exceeds {maximum}")]
    TooManyExtensionKeys { actual: usize, maximum: usize },
    #[error("too many HRM commitment extension values: {actual} exceeds {maximum}")]
    TooManyExtensionValues { actual: usize, maximum: usize },
    #[error("no syntactically valid `hrm1` commitment was present")]
    Missing,
    #[error("conflicting HRM commitment hashes at greatest sequence {sequence}")]
    ConflictingSequence { sequence: u64 },
}

/// Parse one chunk-preserving HRM TXT record.
pub fn parse_txt_commitment<S: AsRef<str>>(
    strings: &[S],
    limits: &CommitmentLimits,
) -> Result<HrmCommitment, CommitmentError> {
    validate_limits(limits)?;
    validate_txt_shape(strings, limits)?;

    if strings.is_empty() {
        return Err(CommitmentError::EmptyRecord);
    }
    if strings[0].as_ref() != HRM_MARKER {
        return Err(CommitmentError::InvalidMarker);
    }

    let mut sequence = None;
    let mut envelope_hash = None;
    let mut uris = BTreeSet::new();
    let mut extensions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut extension_value_count = 0usize;

    for (index, string) in strings.iter().enumerate().skip(1) {
        let string = string.as_ref();
        let Some((key, value)) = string.split_once('=') else {
            return Err(CommitmentError::MalformedField { index });
        };
        if key.is_empty() {
            return Err(CommitmentError::MalformedField { index });
        }

        match key {
            "seq" => {
                if sequence.is_some() {
                    return Err(CommitmentError::DuplicateSingleton("seq"));
                }
                sequence = Some(parse_sequence(value)?);
            }
            "hash" => {
                if envelope_hash.is_some() {
                    return Err(CommitmentError::DuplicateSingleton("hash"));
                }
                envelope_hash = Some(parse_hash(value)?);
            }
            "uri" => {
                if !is_valid_absolute_uri(value) {
                    return Err(CommitmentError::InvalidUri { index });
                }
                uris.insert(value.to_owned());
                if uris.len() > limits.maximum_uris {
                    return Err(CommitmentError::TooManyUris {
                        actual: uris.len(),
                        maximum: limits.maximum_uris,
                    });
                }
            }
            extension if extension.starts_with("x-") => {
                let is_new_key = !extensions.contains_key(extension);
                if is_new_key && extensions.len() == limits.maximum_extension_keys {
                    return Err(CommitmentError::TooManyExtensionKeys {
                        actual: extensions.len().saturating_add(1),
                        maximum: limits.maximum_extension_keys,
                    });
                }

                let values = extensions.entry(extension.to_owned()).or_default();
                if values.insert(value.to_owned()) {
                    extension_value_count = extension_value_count.saturating_add(1);
                    if extension_value_count > limits.maximum_extension_values {
                        return Err(CommitmentError::TooManyExtensionValues {
                            actual: extension_value_count,
                            maximum: limits.maximum_extension_values,
                        });
                    }
                }
            }
            unknown => return Err(CommitmentError::UnknownField(unknown.to_owned())),
        }
    }

    let sequence = sequence.ok_or(CommitmentError::MissingField("seq"))?;
    let envelope_hash = envelope_hash.ok_or(CommitmentError::MissingField("hash"))?;
    if uris.is_empty() {
        return Err(CommitmentError::MissingField("uri"));
    }

    Ok(HrmCommitment {
        sequence,
        envelope_hash,
        uris: uris.into_iter().collect(),
        extensions: extensions
            .into_iter()
            .map(|(key, values)| (key, values.into_iter().collect()))
            .collect(),
    })
}

/// Alias for [`parse_txt_commitment`] using the draft's short operation name.
pub fn parse_txt<S: AsRef<str>>(
    strings: &[S],
    limits: &CommitmentLimits,
) -> Result<HrmCommitment, CommitmentError> {
    parse_txt_commitment(strings, limits)
}

/// Select the greatest-sequence commitment from candidate TXT records.
///
/// Records whose first character-string is not exactly `hrm1` are unrelated
/// and ignored. Marked records that fail parsing are not among the draft's set
/// of "syntactically valid `hrm1` records" and are also ignored. Equal-greatest
/// valid commitments must have one hash; their URI and extension sets are
/// combined deterministically within `limits`.
pub fn select_commitment<I, R, S>(
    records: I,
    limits: &CommitmentLimits,
) -> Result<HrmCommitment, CommitmentError>
where
    I: IntoIterator<Item = R>,
    R: AsRef<[S]>,
    S: AsRef<str>,
{
    validate_limits(limits)?;

    let mut parsed = Vec::new();
    for (record_index, record) in records.into_iter().enumerate() {
        let candidate_count = record_index.saturating_add(1);
        if candidate_count > limits.maximum_candidate_records {
            return Err(CommitmentError::TooManyCandidateRecords {
                actual: candidate_count,
                maximum: limits.maximum_candidate_records,
            });
        }

        let strings = record.as_ref();
        if strings.first().map(AsRef::as_ref) != Some(HRM_MARKER) {
            continue;
        }
        if let Ok(commitment) = parse_txt_commitment(strings, limits) {
            parsed.push(commitment);
        }
    }

    let greatest_sequence = parsed
        .iter()
        .map(|commitment| commitment.sequence)
        .max()
        .ok_or(CommitmentError::Missing)?;
    let mut greatest = parsed
        .into_iter()
        .filter(|commitment| commitment.sequence == greatest_sequence);
    let mut selected = greatest.next().ok_or(CommitmentError::Missing)?;

    let mut uris: BTreeSet<String> = selected.uris.into_iter().collect();
    let mut extensions: BTreeMap<String, BTreeSet<String>> = selected
        .extensions
        .into_iter()
        .map(|(key, values)| (key, values.into_iter().collect()))
        .collect();

    for commitment in greatest {
        if commitment.envelope_hash != selected.envelope_hash {
            return Err(CommitmentError::ConflictingSequence {
                sequence: greatest_sequence,
            });
        }
        uris.extend(commitment.uris);
        for (key, values) in commitment.extensions {
            extensions.entry(key).or_default().extend(values);
        }
    }

    selected.uris = uris.into_iter().collect();
    selected.extensions = extensions
        .into_iter()
        .map(|(key, values)| (key, values.into_iter().collect()))
        .collect();
    validate_materialized_commitment(&selected, limits)?;
    Ok(selected)
}

fn validate_limits(limits: &CommitmentLimits) -> Result<(), CommitmentError> {
    if limits.maximum_candidate_records == 0
        || limits.maximum_candidate_records > HNS_MAX_TXT_RECORDS
    {
        return Err(CommitmentError::InvalidLimits(
            "maximum_candidate_records must be in 1..=255",
        ));
    }
    if limits.maximum_txt_strings == 0 || limits.maximum_txt_strings > HNS_MAX_TXT_STRINGS {
        return Err(CommitmentError::InvalidLimits(
            "maximum_txt_strings must be in 1..=255",
        ));
    }
    if limits.maximum_txt_string_bytes == 0
        || limits.maximum_txt_string_bytes > HNS_MAX_TXT_STRING_BYTES
    {
        return Err(CommitmentError::InvalidLimits(
            "maximum_txt_string_bytes must be in 1..=255",
        ));
    }
    if limits.maximum_record_bytes == 0 || limits.maximum_record_bytes > HNS_MAX_RESOURCE_BYTES {
        return Err(CommitmentError::InvalidLimits(
            "maximum_record_bytes must be in 1..=512",
        ));
    }
    if limits.maximum_uris == 0 || limits.maximum_uris > HNS_MAX_TXT_STRINGS {
        return Err(CommitmentError::InvalidLimits(
            "maximum_uris must be in 1..=255",
        ));
    }
    if limits.maximum_extension_keys > HNS_MAX_TXT_STRINGS {
        return Err(CommitmentError::InvalidLimits(
            "maximum_extension_keys must not exceed 255",
        ));
    }
    if limits.maximum_extension_values > HNS_MAX_TXT_STRINGS {
        return Err(CommitmentError::InvalidLimits(
            "maximum_extension_values must not exceed 255",
        ));
    }
    Ok(())
}

fn validate_txt_shape<S: AsRef<str>>(
    strings: &[S],
    limits: &CommitmentLimits,
) -> Result<(), CommitmentError> {
    if strings.len() > limits.maximum_txt_strings {
        return Err(CommitmentError::TooManyStrings {
            actual: strings.len(),
            maximum: limits.maximum_txt_strings,
        });
    }

    // Standalone version-0 wire size: version, record type, string count, and
    // then one length byte plus the bytes of every character-string.
    let mut encoded_bytes = 3usize;
    for (index, string) in strings.iter().enumerate() {
        let bytes = string.as_ref().as_bytes();
        if bytes.len() > limits.maximum_txt_string_bytes {
            return Err(CommitmentError::StringTooLong {
                index,
                actual: bytes.len(),
                maximum: limits.maximum_txt_string_bytes,
            });
        }
        if !bytes.iter().all(|byte| matches!(byte, 0x20..=0x7e)) {
            return Err(CommitmentError::NonPrintableAscii { index });
        }
        encoded_bytes = encoded_bytes.saturating_add(1).saturating_add(bytes.len());
    }

    if encoded_bytes > limits.maximum_record_bytes {
        return Err(CommitmentError::RecordTooLarge {
            actual: encoded_bytes,
            maximum: limits.maximum_record_bytes,
        });
    }
    Ok(())
}

fn validate_materialized_commitment(
    commitment: &HrmCommitment,
    limits: &CommitmentLimits,
) -> Result<(), CommitmentError> {
    if commitment.uris.len() > limits.maximum_uris {
        return Err(CommitmentError::TooManyUris {
            actual: commitment.uris.len(),
            maximum: limits.maximum_uris,
        });
    }
    if commitment.extensions.len() > limits.maximum_extension_keys {
        return Err(CommitmentError::TooManyExtensionKeys {
            actual: commitment.extensions.len(),
            maximum: limits.maximum_extension_keys,
        });
    }
    let extension_value_count = commitment.extensions.values().map(Vec::len).sum::<usize>();
    if extension_value_count > limits.maximum_extension_values {
        return Err(CommitmentError::TooManyExtensionValues {
            actual: extension_value_count,
            maximum: limits.maximum_extension_values,
        });
    }

    let mut strings = Vec::with_capacity(
        3usize
            .saturating_add(commitment.uris.len())
            .saturating_add(extension_value_count),
    );
    strings.push(HRM_MARKER.to_owned());
    strings.push(format!("seq={}", commitment.sequence));
    strings.push(format!(
        "hash={HASH_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(commitment.envelope_hash)
    ));
    strings.extend(commitment.uris.iter().map(|uri| format!("uri={uri}")));
    for (key, values) in &commitment.extensions {
        strings.extend(values.iter().map(|value| format!("{key}={value}")));
    }
    validate_txt_shape(&strings, limits)
}

fn parse_sequence(value: &str) -> Result<u64, CommitmentError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(CommitmentError::InvalidSequence);
    }
    value
        .parse::<u64>()
        .map_err(|_| CommitmentError::InvalidSequence)
}

fn parse_hash(value: &str) -> Result<[u8; 32], CommitmentError> {
    let encoded = value
        .strip_prefix(HASH_PREFIX)
        .ok_or(CommitmentError::InvalidHash)?;
    if encoded.len() != SHA256_BASE64URL_LENGTH || encoded.contains('=') {
        return Err(CommitmentError::InvalidHash);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CommitmentError::InvalidHash)?;
    let digest: [u8; 32] = decoded
        .try_into()
        .map_err(|_| CommitmentError::InvalidHash)?;
    if URL_SAFE_NO_PAD.encode(digest) != encoded {
        return Err(CommitmentError::InvalidHash);
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_field(byte: u8) -> String {
        format!("hash=sha256:{}", URL_SAFE_NO_PAD.encode([byte; 32]))
    }

    fn record(sequence: u64, hash_byte: u8, uri: &str) -> Vec<String> {
        vec![
            "hrm1".to_owned(),
            format!("seq={sequence}"),
            hash_field(hash_byte),
            format!("uri={uri}"),
        ]
    }

    #[test]
    fn parses_valid_chunked_record_and_canonicalizes_sets() {
        let strings = vec![
            "hrm1".to_owned(),
            "uri=ipfs:bafybeigdyrzt".to_owned(),
            "x-vendor=z".to_owned(),
            "seq=18446744073709551615".to_owned(),
            hash_field(0xa5),
            "uri=https://registry.example/a?x=1%202".to_owned(),
            "x-vendor=a=b".to_owned(),
            "x-empty=".to_owned(),
            "x-vendor=z".to_owned(),
        ];

        let parsed = parse_txt(&strings, &CommitmentLimits::default()).expect("valid");
        assert_eq!(parsed.sequence, u64::MAX);
        assert_eq!(parsed.envelope_hash, [0xa5; 32]);
        assert_eq!(
            parsed.uris,
            [
                "https://registry.example/a?x=1%202".to_owned(),
                "ipfs:bafybeigdyrzt".to_owned(),
            ]
        );
        assert_eq!(parsed.extensions["x-empty"], [""]);
        assert_eq!(parsed.extensions["x-vendor"], ["a=b", "z"]);
    }

    #[test]
    fn requires_exact_marker_in_its_own_first_chunk() {
        let limits = CommitmentLimits::default();
        for marker in ["HRM1", "hrm1 ", " hrm1", "hrm1\t"] {
            let mut strings = record(1, 0, "https://example/a");
            strings[0] = marker.to_owned();
            assert_eq!(
                parse_txt_commitment(&strings, &limits),
                if marker == "hrm1\t" {
                    Err(CommitmentError::NonPrintableAscii { index: 0 })
                } else {
                    Err(CommitmentError::InvalidMarker)
                }
            );
        }

        let joined = vec![
            "hrm1 seq=1".to_owned(),
            hash_field(0),
            "uri=https://example/a".to_owned(),
        ];
        assert_eq!(
            parse_txt_commitment(&joined, &limits),
            Err(CommitmentError::InvalidMarker)
        );
        assert_eq!(
            parse_txt_commitment::<String>(&[], &limits),
            Err(CommitmentError::EmptyRecord)
        );
    }

    #[test]
    fn accepts_only_canonical_u64_decimal() {
        let limits = CommitmentLimits::default();
        for invalid in [
            "",
            "00",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1_0",
            "18446744073709551616",
        ] {
            let mut strings = record(0, 0, "https://example/a");
            strings[1] = format!("seq={invalid}");
            assert_eq!(
                parse_txt_commitment(&strings, &limits),
                Err(CommitmentError::InvalidSequence),
                "accepted {invalid:?}"
            );
        }

        for (text, expected) in [("0", 0), ("1", 1), ("18446744073709551615", u64::MAX)] {
            let mut strings = record(0, 0, "https://example/a");
            strings[1] = format!("seq={text}");
            assert_eq!(
                parse_txt_commitment(&strings, &limits)
                    .expect("canonical")
                    .sequence,
                expected
            );
        }
    }

    #[test]
    fn accepts_only_exact_canonical_sha256_hash() {
        let limits = CommitmentLimits::default();
        let canonical = format!("sha256:{}", URL_SAFE_NO_PAD.encode([0xff; 32]));
        let mut invalid = vec![
            canonical.replace("sha256:", "SHA256:"),
            format!("{canonical}="),
            "sha256:AA".to_owned(),
            format!("sha256:{}", "_".repeat(43)),
            format!("sha256:{}", "+".repeat(43)),
        ];
        let mut noncanonical_tail = URL_SAFE_NO_PAD.encode([0; 32]);
        noncanonical_tail.pop();
        noncanonical_tail.push('B');
        invalid.push(format!("sha256:{noncanonical_tail}"));

        for hash in invalid {
            let mut strings = record(1, 0, "https://example/a");
            strings[2] = format!("hash={hash}");
            assert_eq!(
                parse_txt_commitment(&strings, &limits),
                Err(CommitmentError::InvalidHash),
                "accepted {hash:?}"
            );
        }
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_critical_fields() {
        let limits = CommitmentLimits::default();
        let valid = record(1, 0, "https://example/a");

        for (removed, field) in [(1, "seq"), (2, "hash"), (3, "uri")] {
            let mut strings = valid.clone();
            strings.remove(removed);
            assert_eq!(
                parse_txt_commitment(&strings, &limits),
                Err(CommitmentError::MissingField(field))
            );
        }

        for (duplicate, field) in [("seq=2", "seq"), (&hash_field(1), "hash")] {
            let mut strings = valid.clone();
            strings.push(duplicate.to_owned());
            assert_eq!(
                parse_txt_commitment(&strings, &limits),
                Err(CommitmentError::DuplicateSingleton(field))
            );
        }

        let mut unknown = valid.clone();
        unknown.push("future=value".to_owned());
        assert_eq!(
            parse_txt_commitment(&unknown, &limits),
            Err(CommitmentError::UnknownField("future".to_owned()))
        );

        let mut malformed = valid;
        malformed.push("x-no-equals".to_owned());
        assert_eq!(
            parse_txt_commitment(&malformed, &limits),
            Err(CommitmentError::MalformedField { index: 4 })
        );
    }

    #[test]
    fn validates_and_bounds_uris() {
        let limits = CommitmentLimits::default();
        for invalid in [
            "relative/path",
            ":missing-scheme",
            "1http://example/a",
            "ht*tp://example/a",
            "https:",
            "https://example/a b",
            "https://example/%q0",
            "https://example/%0",
            "https://example/\\path",
            "https://[",
            "https://exa[mple",
            "https://example/a#one#two",
        ] {
            let strings = record(1, 0, invalid);
            assert_eq!(
                parse_txt_commitment(&strings, &limits),
                Err(CommitmentError::InvalidUri { index: 3 }),
                "accepted {invalid:?}"
            );
        }

        let mut duplicate = record(1, 0, "https://example/a");
        duplicate.push("uri=https://example/a".to_owned());
        assert_eq!(
            parse_txt_commitment(&duplicate, &limits)
                .expect("duplicate non-singleton URI is equivalent")
                .uris,
            ["https://example/a"]
        );

        let mut excess = record(1, 0, "https://example/0");
        excess.extend((1..=4).map(|index| format!("uri=https://example/{index}")));
        assert_eq!(
            parse_txt_commitment(&excess, &limits),
            Err(CommitmentError::TooManyUris {
                actual: 5,
                maximum: 4,
            })
        );
    }

    #[test]
    fn enforces_printable_ascii_and_wire_bounds() {
        let limits = CommitmentLimits::default();
        let mut non_ascii = record(1, 0, "https://example/a");
        non_ascii.push("x-note=café".to_owned());
        assert_eq!(
            parse_txt_commitment(&non_ascii, &limits),
            Err(CommitmentError::NonPrintableAscii { index: 4 })
        );

        let mut control = record(1, 0, "https://example/a");
        control.push("x-note=line\nbreak".to_owned());
        assert_eq!(
            parse_txt_commitment(&control, &limits),
            Err(CommitmentError::NonPrintableAscii { index: 4 })
        );

        let long_uri = format!("https://example/{}", "a".repeat(235));
        assert_eq!(format!("uri={long_uri}").len(), 255);
        parse_txt_commitment(&record(1, 0, &long_uri), &limits).expect("255-byte string");

        let too_long_uri = format!("https://example/{}", "a".repeat(236));
        assert_eq!(
            parse_txt_commitment(&record(1, 0, &too_long_uri), &limits),
            Err(CommitmentError::StringTooLong {
                index: 3,
                actual: 256,
                maximum: 255,
            })
        );

        let strings = record(1, 0, "https://example/a");
        let encoded_size = 3 + strings.iter().map(|value| 1 + value.len()).sum::<usize>();
        let tight = CommitmentLimits {
            maximum_record_bytes: encoded_size - 1,
            ..limits
        };
        assert_eq!(
            parse_txt_commitment(&strings, &tight),
            Err(CommitmentError::RecordTooLarge {
                actual: encoded_size,
                maximum: encoded_size - 1,
            })
        );
    }

    #[test]
    fn extension_limits_count_distinct_preserved_chunks() {
        let strings = [
            "hrm1".to_owned(),
            "seq=1".to_owned(),
            hash_field(0),
            "uri=https://example/a".to_owned(),
            "x-a=1".to_owned(),
            "x-a=1".to_owned(),
            "x-a=2".to_owned(),
            "x-b=1".to_owned(),
        ];
        let one_key = CommitmentLimits {
            maximum_extension_keys: 1,
            ..CommitmentLimits::default()
        };
        assert_eq!(
            parse_txt_commitment(&strings, &one_key),
            Err(CommitmentError::TooManyExtensionKeys {
                actual: 2,
                maximum: 1,
            })
        );

        let two_values = CommitmentLimits {
            maximum_extension_values: 2,
            ..CommitmentLimits::default()
        };
        assert_eq!(
            parse_txt_commitment(&strings, &two_values),
            Err(CommitmentError::TooManyExtensionValues {
                actual: 3,
                maximum: 2,
            })
        );
    }

    #[test]
    fn selects_greatest_sequence_and_ignores_unrelated_records() {
        let records = vec![
            vec!["ordinary TXT".to_owned()],
            record(7, 7, "https://example/7"),
            record(3, 3, "https://example/3"),
            vec!["hrm1x".to_owned(), "not=a-commitment".to_owned()],
        ];
        let selected = select_commitment(&records, &CommitmentLimits::default()).expect("selected");
        assert_eq!(selected.sequence, 7);
        assert_eq!(selected.envelope_hash, [7; 32]);
        assert_eq!(selected.uris, ["https://example/7"]);
    }

    #[test]
    fn equal_sequence_hash_merges_deterministically() {
        let mut first = record(9, 9, "https://example/c");
        first.extend([
            "x-z=2".to_owned(),
            "x-z=1".to_owned(),
            "x-common=same".to_owned(),
        ]);
        let mut second = record(9, 9, "https://example/a");
        second.extend([
            "uri=https://example/b".to_owned(),
            "x-a=3".to_owned(),
            "x-z=1".to_owned(),
            "x-common=same".to_owned(),
        ]);

        let limits = CommitmentLimits::default();
        let left = select_commitment([first.clone(), second.clone()], &limits).expect("left");
        let right = select_commitment([second, first], &limits).expect("right");
        assert_eq!(left, right);
        assert_eq!(
            left.uris,
            [
                "https://example/a",
                "https://example/b",
                "https://example/c"
            ]
        );
        assert_eq!(left.extensions["x-z"], ["1", "2"]);
        assert_eq!(left.extensions["x-common"], ["same"]);
    }

    #[test]
    fn only_conflicting_hashes_at_greatest_sequence_fail() {
        let limits = CommitmentLimits::default();
        let lower_conflict = [
            record(4, 0, "https://example/lower-a"),
            record(4, 1, "https://example/lower-b"),
            record(5, 2, "https://example/greatest"),
        ];
        assert_eq!(
            select_commitment(lower_conflict, &limits)
                .expect("lower conflict irrelevant")
                .sequence,
            5
        );

        let greatest_conflict = [
            record(5, 2, "https://example/a"),
            record(5, 3, "https://example/b"),
            record(4, 4, "https://example/lower"),
        ];
        assert_eq!(
            select_commitment(greatest_conflict, &limits),
            Err(CommitmentError::ConflictingSequence { sequence: 5 })
        );
    }

    #[test]
    fn merged_replica_sets_remain_bounded() {
        let limits = CommitmentLimits::default();
        let records = (0..=4)
            .map(|index| record(1, 0, &format!("https://example/{index}")))
            .collect::<Vec<_>>();
        assert_eq!(
            select_commitment(&records, &limits),
            Err(CommitmentError::TooManyUris {
                actual: 5,
                maximum: 4,
            })
        );

        let first = {
            let mut value = record(1, 0, "https://example/a");
            value.push(format!("x-a={}", "a".repeat(210)));
            value
        };
        let second = {
            let mut value = record(1, 0, "https://example/a");
            value.push(format!("x-b={}", "b".repeat(210)));
            value
        };
        assert!(matches!(
            select_commitment([first, second], &limits),
            Err(CommitmentError::RecordTooLarge { .. })
        ));
    }

    #[test]
    fn selection_uses_only_syntactically_valid_marked_records() {
        let limits = CommitmentLimits::default();
        let unrelated = [vec!["txt".to_owned()], vec![]];
        assert_eq!(
            select_commitment(&unrelated, &limits),
            Err(CommitmentError::Missing)
        );

        let malformed = [
            record(1, 0, "https://example/a"),
            vec!["hrm1".to_owned(), "seq=2".to_owned()],
        ];
        assert_eq!(
            select_commitment(&malformed, &limits)
                .expect("malformed marked record is outside the valid candidate set")
                .sequence,
            1
        );

        let only_malformed = [vec!["hrm1".to_owned(), "seq=2".to_owned()]];
        assert_eq!(
            select_commitment(&only_malformed, &limits),
            Err(CommitmentError::Missing)
        );
    }

    #[test]
    fn candidate_and_merged_extension_limits_are_enforced() {
        let defaults = CommitmentLimits::default();
        let records = [
            record(1, 0, "https://example/a"),
            record(1, 0, "https://example/b"),
        ];
        let one_candidate = CommitmentLimits {
            maximum_candidate_records: 1,
            ..defaults
        };
        assert_eq!(
            select_commitment(&records, &one_candidate),
            Err(CommitmentError::TooManyCandidateRecords {
                actual: 2,
                maximum: 1,
            })
        );

        let mut first = record(1, 0, "https://example/a");
        first.push("x-a=1".to_owned());
        let mut second = record(1, 0, "https://example/b");
        second.push("x-b=2".to_owned());
        let one_extension = CommitmentLimits {
            maximum_extension_keys: 1,
            ..defaults
        };
        assert_eq!(
            select_commitment([first, second], &one_extension),
            Err(CommitmentError::TooManyExtensionKeys {
                actual: 2,
                maximum: 1,
            })
        );
    }

    #[test]
    fn invalid_limits_cannot_relax_handshake_wire_bounds() {
        let limits = CommitmentLimits {
            maximum_record_bytes: 513,
            ..CommitmentLimits::default()
        };
        assert!(matches!(
            parse_txt_commitment(&record(1, 0, "https://example/a"), &limits),
            Err(CommitmentError::InvalidLimits(_))
        ));
        let limits = CommitmentLimits {
            maximum_txt_string_bytes: 256,
            ..CommitmentLimits::default()
        };
        assert!(matches!(
            parse_txt_commitment(&record(1, 0, "https://example/a"), &limits),
            Err(CommitmentError::InvalidLimits(_))
        ));
    }
}
