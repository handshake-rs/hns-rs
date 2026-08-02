use hns_encoding::Decoder;

use crate::{CovenantError, MAX_RESOURCE_SIZE};

const RESOURCE_VERSION: u8 = 0;
const MAX_DNS_NAME_SIZE: usize = 255;
const MAX_DNS_POINTERS: usize = 10;

/// A decoded DNS name from an HSD resource record.
///
/// Labels retain arbitrary bytes. The root name therefore has no labels, and
/// callers do not need to round-trip through a Unicode or presentation-format
/// string before making authorization decisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceName {
    labels: Vec<Vec<u8>>,
}

impl ResourceName {
    /// Raw labels in left-to-right DNS order.
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// Whether this is the DNS root name.
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }
}

/// One assigned record in HSD's version-zero resource encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceRecord {
    /// DNSSEC delegation signer record.
    Ds {
        /// DNSSEC key tag in network byte order on wire.
        key_tag: u16,
        /// DNSSEC algorithm identifier.
        algorithm: u8,
        /// DNSSEC digest identifier.
        digest_type: u8,
        /// Exact digest bytes.
        digest: Vec<u8>,
    },
    /// Delegated authoritative name server.
    Ns {
        /// Exact decoded DNS label sequence.
        name_server: ResourceName,
    },
    /// IPv4 glue for a delegated name server.
    Glue4 {
        /// Exact decoded DNS label sequence.
        name_server: ResourceName,
        /// IPv4 address octets.
        address: [u8; 4],
    },
    /// IPv6 glue for a delegated name server.
    Glue6 {
        /// Exact decoded DNS label sequence.
        name_server: ResourceName,
        /// IPv6 address octets.
        address: [u8; 16],
    },
    /// HSD synthetic IPv4 name-server address.
    Synth4 {
        /// IPv4 address octets.
        address: [u8; 4],
    },
    /// HSD synthetic IPv6 name-server address.
    Synth6 {
        /// IPv6 address octets.
        address: [u8; 16],
    },
    /// One HSD TXT record containing bounded byte strings.
    Txt {
        /// Exact TXT chunks without a UTF-8 assumption.
        strings: Vec<Vec<u8>>,
    },
}

impl ResourceRecord {
    /// HSD's assigned one-byte resource record tag.
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Ds { .. } => 0,
            Self::Ns { .. } => 1,
            Self::Glue4 { .. } => 2,
            Self::Glue6 { .. } => 3,
            Self::Synth4 { .. } => 4,
            Self::Synth6 { .. } => 5,
            Self::Txt { .. } => 6,
        }
    }
}

/// A bounded, fully consumed HSD version-zero name resource.
///
/// The original bytes are retained exactly, including HSD DNS compression
/// pointers. [`Resource::encode`] therefore reproduces the authenticated
/// NameState data byte-for-byte instead of inventing a normalized wire shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resource {
    raw: Vec<u8>,
    records: Vec<ResourceRecord>,
}

impl Resource {
    /// Validate owned resource bytes and retain them without normalization.
    pub fn new(raw: Vec<u8>) -> Result<Self, CovenantError> {
        let records = decode_records(&raw)?;
        Ok(Self { raw, records })
    }

    /// Decode an exact resource byte slice.
    pub fn decode(raw: &[u8]) -> Result<Self, CovenantError> {
        if raw.len() > MAX_RESOURCE_SIZE {
            return Err(CovenantError::TooLarge {
                actual: raw.len(),
                maximum: MAX_RESOURCE_SIZE,
            });
        }
        Self::new(raw.to_vec())
    }

    /// Exact HSD bytes supplied to the decoder.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Clone the exact HSD bytes.
    pub fn encode(&self) -> Vec<u8> {
        self.raw.clone()
    }

    /// Consume the resource and return its exact HSD bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.raw
    }

    /// Typed records in their exact wire order.
    pub fn records(&self) -> &[ResourceRecord] {
        &self.records
    }
}

fn decode_records(raw: &[u8]) -> Result<Vec<ResourceRecord>, CovenantError> {
    if raw.len() > MAX_RESOURCE_SIZE {
        return Err(CovenantError::TooLarge {
            actual: raw.len(),
            maximum: MAX_RESOURCE_SIZE,
        });
    }

    let mut decoder = Decoder::new(raw);
    if decoder.read_u8()? != RESOURCE_VERSION {
        return Err(CovenantError::UnsupportedResourceVersion);
    }

    let mut records = Vec::new();
    let mut name_offsets = [false; MAX_RESOURCE_SIZE];
    while decoder.remaining() != 0 {
        let kind = decoder.read_u8()?;
        let record = match kind {
            0 => {
                let key_tag = u16::from_be_bytes(decoder.read_array()?);
                let algorithm = decoder.read_u8()?;
                let digest_type = decoder.read_u8()?;
                let digest_length = usize::from(decoder.read_u8()?);
                let digest = decoder.read_bounded_vec(digest_length, u8::MAX as usize)?;
                ResourceRecord::Ds {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                }
            }
            1 => ResourceRecord::Ns {
                name_server: decode_name(raw, &mut decoder, &mut name_offsets)?,
            },
            2 => ResourceRecord::Glue4 {
                name_server: decode_name(raw, &mut decoder, &mut name_offsets)?,
                address: decoder.read_array()?,
            },
            3 => ResourceRecord::Glue6 {
                name_server: decode_name(raw, &mut decoder, &mut name_offsets)?,
                address: decoder.read_array()?,
            },
            4 => ResourceRecord::Synth4 {
                address: decoder.read_array()?,
            },
            5 => ResourceRecord::Synth6 {
                address: decoder.read_array()?,
            },
            6 => {
                let count = usize::from(decoder.read_u8()?);
                let mut strings = Vec::with_capacity(count.min(32));
                for _ in 0..count {
                    let length = usize::from(decoder.read_u8()?);
                    strings.push(decoder.read_bounded_vec(length, u8::MAX as usize)?);
                }
                ResourceRecord::Txt { strings }
            }
            kind => return Err(CovenantError::UnsupportedResourceRecord { kind }),
        };
        records.push(record);
    }
    decoder.finish()?;
    Ok(records)
}

fn decode_name(
    raw: &[u8],
    decoder: &mut Decoder<'_>,
    known_offsets: &mut [bool; MAX_RESOURCE_SIZE],
) -> Result<ResourceName, CovenantError> {
    let start = decoder.position();
    let mut position = start;
    let mut encoded_end = None;
    let mut labels = Vec::new();
    let mut literal_offsets = Vec::new();
    let mut followed_offsets = [false; MAX_RESOURCE_SIZE];
    let mut pointer_count = 0_usize;
    let mut expanded_size = 1_usize;

    loop {
        let length = *raw
            .get(position)
            .ok_or(CovenantError::InvalidResource("truncated DNS name"))?;
        match length & 0xc0 {
            0x00 => {
                if length == 0 {
                    if encoded_end.is_none() {
                        encoded_end = position.checked_add(1);
                    }
                    break;
                }
                if length > 63 {
                    return Err(CovenantError::InvalidResource("DNS label exceeds 63 bytes"));
                }
                literal_offsets.push(position);
                let label_start = position
                    .checked_add(1)
                    .ok_or(CovenantError::InvalidResource("DNS name offset overflow"))?;
                let label_end = label_start
                    .checked_add(usize::from(length))
                    .ok_or(CovenantError::InvalidResource("DNS name offset overflow"))?;
                let label = raw
                    .get(label_start..label_end)
                    .ok_or(CovenantError::InvalidResource("truncated DNS label"))?;
                expanded_size = expanded_size
                    .checked_add(1 + label.len())
                    .ok_or(CovenantError::InvalidResource("DNS name size overflow"))?;
                if expanded_size > MAX_DNS_NAME_SIZE {
                    return Err(CovenantError::InvalidResource(
                        "DNS name exceeds 255 wire bytes",
                    ));
                }
                labels.push(label.to_vec());
                position = label_end;
            }
            0xc0 => {
                let pointer_position = position;
                let low = *raw.get(position + 1).ok_or(CovenantError::InvalidResource(
                    "truncated DNS compression pointer",
                ))?;
                let target = (usize::from(length & 0x3f) << 8) | usize::from(low);
                if target >= pointer_position
                    || target >= raw.len()
                    || !known_offsets.get(target).copied().unwrap_or(false)
                {
                    return Err(CovenantError::InvalidResource(
                        "DNS compression pointer is not a prior label",
                    ));
                }
                if followed_offsets[target] || pointer_count >= MAX_DNS_POINTERS {
                    return Err(CovenantError::InvalidResource(
                        "DNS compression pointer loop or depth overflow",
                    ));
                }
                followed_offsets[target] = true;
                pointer_count += 1;
                if encoded_end.is_none() {
                    encoded_end = position.checked_add(2);
                }
                position = target;
            }
            _ => {
                return Err(CovenantError::InvalidResource("invalid DNS label prefix"));
            }
        }
    }

    let encoded_end = encoded_end.ok_or(CovenantError::InvalidResource(
        "DNS name has no encoded end",
    ))?;
    let consumed = encoded_end
        .checked_sub(start)
        .ok_or(CovenantError::InvalidResource("DNS name offset underflow"))?;
    decoder.read_slice(consumed)?;
    for offset in literal_offsets {
        known_offsets[offset] = true;
    }
    Ok(ResourceName { labels })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = include_str!("../../../fixtures/hsd/name-state-resource-v1.txt");

    fn fixture(name: &str) -> Vec<u8> {
        let value = FIXTURES
            .lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value))
            .unwrap_or_else(|| panic!("missing fixture {name}"));
        hex::decode(value).expect("fixture hex")
    }

    #[test]
    fn exact_hsd_resource_round_trip_and_typed_records() {
        let raw = fixture("resource_all_records");
        let resource = Resource::decode(&raw).expect("HSD resource");
        assert_eq!(resource.as_bytes(), raw.as_slice());
        assert_eq!(resource.encode(), raw);
        assert_eq!(
            resource
                .records()
                .iter()
                .map(ResourceRecord::kind)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4, 5, 6]
        );

        let ResourceRecord::Glue4 {
            name_server,
            address,
        } = &resource.records()[2]
        else {
            panic!("expected GLUE4");
        };
        assert_eq!(
            name_server.labels(),
            &[b"ns1".to_vec(), b"example".to_vec()]
        );
        assert_eq!(*address, [192, 0, 2, 1]);

        let ResourceRecord::Txt { strings } = &resource.records()[6] else {
            panic!("expected TXT");
        };
        assert_eq!(strings, &[b"wallet".to_vec(), b"proof".to_vec()]);
    }

    #[test]
    fn malformed_or_unrecognized_resources_fail_closed() {
        for raw in [
            Vec::new(),
            vec![1],
            vec![0, 7],
            vec![0, 4, 127, 0],
            vec![0, 1, 0xc0, 4],
            vec![0, 1, 3, b'n', b's'],
        ] {
            assert!(Resource::decode(&raw).is_err(), "accepted {raw:02x?}");
        }
        assert!(Resource::decode(&vec![0; MAX_RESOURCE_SIZE + 1]).is_err());

        let mut trailing = fixture("resource_all_records");
        trailing.push(7);
        assert!(Resource::decode(&trailing).is_err());
    }
}
