use hns_encoding::{Decoder, Encoder};
use hns_primitives::{Dollarydoos, Height, NameHash, Outpoint, TransactionHash};

use crate::{CovenantError, MAX_NAME_SIZE, MAX_RESOURCE_SIZE, Resource, hash_name};

const NAME_STATE_FIELD_MASK: u16 = (1 << 10) - 1;

/// Maximum byte length of HSD's canonical `NameState.write` value.
pub const MAX_NAME_STATE_SIZE: usize = 668;

/// Largest integer HSD's JavaScript `readVarint` accepts without precision
/// loss. Consensus monetary values are below this ceiling.
pub const HSD_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

/// HSD-compatible authenticated name-tree value.
///
/// `name_hash` is the external Urkel key and is not duplicated in the encoded
/// value. Strict decoding binds every non-null state's name to that supplied
/// key, preventing a proof consumer from authenticating one key while acting
/// on another name. The resource field remains exact opaque consensus data;
/// use [`NameState::resource`] for separate, fallible DNS resource parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NameState {
    /// External authenticated-tree key; excluded from the value encoding.
    pub name_hash: NameHash,
    /// Exact lowercase Handshake label retained by HSD.
    pub name: Vec<u8>,
    /// Auction or claim start height.
    pub height: Height,
    /// Last renewal height.
    pub renewal: Height,
    /// Current ownership outpoint, or HSD's exact null sentinel.
    pub owner: Outpoint,
    /// Locked winning value.
    pub value: Dollarydoos,
    /// Highest revealed bid.
    pub highest: Dollarydoos,
    /// Exact consensus resource bytes; validity as DNS data is not implied.
    pub resource_data: Vec<u8>,
    /// Transfer start height, or zero when no transfer is pending.
    pub transfer: Height,
    /// Revocation height, or zero when not revoked.
    pub revoked: Height,
    /// Claim height, or zero for non-claimed names.
    pub claimed: Height,
    /// Completed renewal count.
    pub renewals: u32,
    /// Whether the name completed REGISTER.
    pub registered: bool,
    /// Whether HSD retained resource data through expiration reset.
    pub expired: bool,
    /// Whether the originating claim used weak proof.
    pub weak: bool,
}

impl NameState {
    /// Construct HSD's null value for an external authenticated-tree key.
    pub const fn null(name_hash: NameHash) -> Self {
        Self {
            name_hash,
            name: Vec::new(),
            height: Height::new(0),
            renewal: Height::new(0),
            owner: Outpoint::NULL,
            value: Dollarydoos::new(0),
            highest: Dollarydoos::new(0),
            resource_data: Vec::new(),
            transfer: Height::new(0),
            revoked: Height::new(0),
            claimed: Height::new(0),
            renewals: 0,
            registered: false,
            expired: false,
            weak: false,
        }
    }

    /// HSD's exact null-state predicate. The external key and cached name are
    /// intentionally not part of the predicate.
    pub fn is_null(&self) -> bool {
        self.height.get() == 0
            && self.renewal.get() == 0
            && self.owner.is_null()
            && self.value.get() == 0
            && self.highest.get() == 0
            && self.resource_data.is_empty()
            && self.transfer.get() == 0
            && self.revoked.get() == 0
            && self.claimed.get() == 0
            && self.renewals == 0
            && !self.registered
            && !self.expired
            && !self.weak
    }

    /// Current owner output, or `None` for HSD's exact null-outpoint sentinel.
    pub fn owner_outpoint(&self) -> Option<Outpoint> {
        (!self.owner.is_null()).then_some(self.owner)
    }

    /// Parse the exact resource bytes without changing them.
    ///
    /// Handshake consensus permits arbitrary data up to 512 bytes. Therefore
    /// malformed DNS resource bytes do not invalidate a NameState; they fail
    /// only when a consumer explicitly requests this typed projection.
    pub fn resource(&self) -> Result<Option<Resource>, CovenantError> {
        if self.resource_data.is_empty() {
            Ok(None)
        } else {
            Resource::decode(&self.resource_data).map(Some)
        }
    }

    /// Validate the mandatory authenticated key/value name binding.
    pub fn validate_key_binding(&self) -> Result<(), CovenantError> {
        if !self.is_null() && hash_name(&self.name)? != self.name_hash {
            return Err(CovenantError::NameStateHashMismatch);
        }
        Ok(())
    }

    /// Encode exactly the value written by HSD's `NameState.write`.
    ///
    /// The authenticated-tree key is deliberately excluded.
    pub fn encode(&self) -> Result<Vec<u8>, CovenantError> {
        validate_lengths(self.name.len(), self.resource_data.len())?;
        validate_safe_integer(self.value.get())?;
        validate_safe_integer(self.highest.get())?;
        self.validate_key_binding()?;

        let mut field = 0_u16;
        if !self.owner.is_null() {
            field |= 1 << 0;
        }
        if self.value.get() != 0 {
            field |= 1 << 1;
        }
        if self.highest.get() != 0 {
            field |= 1 << 2;
        }
        if self.transfer.get() != 0 {
            field |= 1 << 3;
        }
        if self.revoked.get() != 0 {
            field |= 1 << 4;
        }
        if self.claimed.get() != 0 {
            field |= 1 << 5;
        }
        if self.renewals != 0 {
            field |= 1 << 6;
        }
        if self.registered {
            field |= 1 << 7;
        }
        if self.expired {
            field |= 1 << 8;
        }
        if self.weak {
            field |= 1 << 9;
        }

        let mut encoder = Encoder::with_capacity(MAX_NAME_STATE_SIZE);
        encoder.put_u8(self.name.len() as u8);
        encoder.put_bytes(&self.name);
        encoder.put_u16_le(self.resource_data.len() as u16);
        encoder.put_bytes(&self.resource_data);
        encoder.put_u32_le(self.height.get());
        encoder.put_u32_le(self.renewal.get());
        encoder.put_u16_le(field);
        if !self.owner.is_null() {
            encoder.put_bytes(self.owner.transaction_hash.as_bytes());
            encoder.put_compact_size(u64::from(self.owner.index));
        }
        if self.value.get() != 0 {
            encoder.put_compact_size(self.value.get());
        }
        if self.highest.get() != 0 {
            encoder.put_compact_size(self.highest.get());
        }
        if self.transfer.get() != 0 {
            encoder.put_u32_le(self.transfer.get());
        }
        if self.revoked.get() != 0 {
            encoder.put_u32_le(self.revoked.get());
        }
        if self.claimed.get() != 0 {
            encoder.put_u32_le(self.claimed.get());
        }
        if self.renewals != 0 {
            encoder.put_compact_size(u64::from(self.renewals));
        }
        Ok(encoder.into_bytes())
    }

    /// Decode and fully consume an HSD NameState value under its Urkel key.
    pub fn decode(name_hash: NameHash, input: &[u8]) -> Result<Self, CovenantError> {
        if input.len() > MAX_NAME_STATE_SIZE {
            return Err(CovenantError::TooLarge {
                actual: input.len(),
                maximum: MAX_NAME_STATE_SIZE,
            });
        }

        let mut decoder = Decoder::new(input);
        let name_length = usize::from(decoder.read_u8()?);
        if name_length > MAX_NAME_SIZE {
            return Err(CovenantError::InvalidNameState("name exceeds 63 bytes"));
        }
        let name = decoder.read_bounded_vec(name_length, MAX_NAME_SIZE)?;
        let resource_length = usize::from(decoder.read_u16_le()?);
        if resource_length > MAX_RESOURCE_SIZE {
            return Err(CovenantError::InvalidNameState(
                "resource data exceeds 512 bytes",
            ));
        }
        let resource_data = decoder.read_bounded_vec(resource_length, MAX_RESOURCE_SIZE)?;
        let height = Height::new(decoder.read_u32_le()?);
        let renewal = Height::new(decoder.read_u32_le()?);
        let field = decoder.read_u16_le()?;
        if field & !NAME_STATE_FIELD_MASK != 0 {
            return Err(CovenantError::InvalidNameState(
                "optional-field bitmap contains unknown bits",
            ));
        }

        let owner = if field & (1 << 0) != 0 {
            let transaction_hash = TransactionHash::new(decoder.read_array()?);
            let index = read_u32_compact(&mut decoder, "owner index exceeds u32")?;
            Outpoint {
                transaction_hash,
                index,
            }
        } else {
            Outpoint::NULL
        };
        let value = if field & (1 << 1) != 0 {
            Dollarydoos::new(read_safe_integer(&mut decoder)?)
        } else {
            Dollarydoos::new(0)
        };
        let highest = if field & (1 << 2) != 0 {
            Dollarydoos::new(read_safe_integer(&mut decoder)?)
        } else {
            Dollarydoos::new(0)
        };
        let transfer = if field & (1 << 3) != 0 {
            Height::new(decoder.read_u32_le()?)
        } else {
            Height::new(0)
        };
        let revoked = if field & (1 << 4) != 0 {
            Height::new(decoder.read_u32_le()?)
        } else {
            Height::new(0)
        };
        let claimed = if field & (1 << 5) != 0 {
            Height::new(decoder.read_u32_le()?)
        } else {
            Height::new(0)
        };
        let renewals = if field & (1 << 6) != 0 {
            read_u32_compact(&mut decoder, "renewal count exceeds u32")?
        } else {
            0
        };
        let state = Self {
            name_hash,
            name,
            height,
            renewal,
            owner,
            value,
            highest,
            resource_data,
            transfer,
            revoked,
            claimed,
            renewals,
            registered: field & (1 << 7) != 0,
            expired: field & (1 << 8) != 0,
            weak: field & (1 << 9) != 0,
        };
        decoder.finish()?;
        state.validate_key_binding()?;
        if state.encode()?.as_slice() != input {
            return Err(CovenantError::NonCanonicalNameState);
        }
        Ok(state)
    }
}

/// Encode an exact HSD NameState value, excluding its authenticated-tree key.
pub fn encode_name_state(state: &NameState) -> Result<Vec<u8>, CovenantError> {
    state.encode()
}

/// Decode an exact HSD NameState value and bind it to its authenticated-tree
/// key.
pub fn decode_name_state(name_hash: NameHash, input: &[u8]) -> Result<NameState, CovenantError> {
    NameState::decode(name_hash, input)
}

fn validate_lengths(name_length: usize, resource_length: usize) -> Result<(), CovenantError> {
    if name_length > MAX_NAME_SIZE {
        return Err(CovenantError::TooLarge {
            actual: name_length,
            maximum: MAX_NAME_SIZE,
        });
    }
    if resource_length > MAX_RESOURCE_SIZE {
        return Err(CovenantError::TooLarge {
            actual: resource_length,
            maximum: MAX_RESOURCE_SIZE,
        });
    }
    Ok(())
}

fn validate_safe_integer(value: u64) -> Result<(), CovenantError> {
    if value > HSD_MAX_SAFE_INTEGER {
        return Err(CovenantError::InvalidNameState(
            "compact integer exceeds HSD's safe-integer range",
        ));
    }
    Ok(())
}

fn read_safe_integer(decoder: &mut Decoder<'_>) -> Result<u64, CovenantError> {
    let value = decoder.read_compact_size()?;
    validate_safe_integer(value)?;
    Ok(value)
}

fn read_u32_compact(
    decoder: &mut Decoder<'_>,
    overflow_reason: &'static str,
) -> Result<u32, CovenantError> {
    u32::try_from(decoder.read_compact_size()?)
        .map_err(|_| CovenantError::InvalidNameState(overflow_reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = include_str!("../fixtures/hsd/name-state-resource-v1.txt");

    fn fixture(name: &str) -> Vec<u8> {
        let value = FIXTURES
            .lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(key, value)| (key == name).then_some(value))
            .unwrap_or_else(|| panic!("missing fixture {name}"));
        hex::decode(value).expect("fixture hex")
    }

    fn fixture_hash(name: &str) -> NameHash {
        NameHash::new(
            fixture(name)
                .try_into()
                .unwrap_or_else(|_| panic!("fixture {name} is not a hash")),
        )
    }

    #[test]
    fn exact_hsd_name_states_round_trip_with_bound_owner() {
        let minimal_raw = fixture("name_state_minimal");
        let minimal = NameState::decode(fixture_hash("name_state_minimal_key"), &minimal_raw)
            .expect("minimal HSD state");
        assert_eq!(minimal.name, b"alpha");
        assert_eq!(minimal.height, Height::new(100));
        assert_eq!(minimal.owner_outpoint(), None);
        assert_eq!(minimal.encode().expect("encode"), minimal_raw);

        let populated_raw = fixture("name_state_populated");
        let populated = NameState::decode(fixture_hash("name_state_populated_key"), &populated_raw)
            .expect("populated HSD state");
        assert_eq!(populated.name, b"handshake");
        let owner = populated.owner_outpoint().expect("owner");
        assert_eq!(owner.index, 70_000);
        assert_eq!(
            owner.transaction_hash.into_bytes(),
            core::array::from_fn(|index| index as u8)
        );
        assert_eq!(populated.value, Dollarydoos::new(123_456_789));
        assert!(populated.registered && populated.expired && populated.weak);
        assert_eq!(
            populated
                .resource()
                .expect("resource")
                .expect("present")
                .encode(),
            fixture("resource_all_records")
        );
        assert_eq!(populated.encode().expect("encode"), populated_raw);
    }

    #[test]
    fn key_value_binding_is_mandatory_for_non_null_states() {
        let raw = fixture("name_state_minimal");
        let wrong_key = NameHash::new([0x55; 32]);
        assert!(matches!(
            NameState::decode(wrong_key, &raw),
            Err(CovenantError::NameStateHashMismatch)
        ));
    }

    #[test]
    fn malformed_resource_data_remains_lossless_and_separately_fallible() {
        let mut state = NameState {
            name_hash: hash_name(b"alpha").expect("hash"),
            name: b"alpha".to_vec(),
            height: Height::new(1),
            renewal: Height::new(1),
            owner: Outpoint::NULL,
            value: Dollarydoos::new(0),
            highest: Dollarydoos::new(0),
            resource_data: vec![1],
            transfer: Height::new(0),
            revoked: Height::new(0),
            claimed: Height::new(0),
            renewals: 0,
            registered: false,
            expired: false,
            weak: false,
        };
        let raw = state.encode().expect("opaque resource is consensus-valid");
        state = NameState::decode(state.name_hash, &raw).expect("state remains decodable");
        assert_eq!(state.resource_data, vec![1]);
        assert!(state.resource().is_err());
    }

    #[test]
    fn malformed_noncanonical_and_oversized_values_fail_closed() {
        let mut trailing = fixture("name_state_minimal");
        trailing.push(0);
        assert!(NameState::decode(fixture_hash("name_state_minimal_key"), &trailing).is_err());
        assert!(
            NameState::decode(NameHash::new([0; 32]), &vec![0; MAX_NAME_STATE_SIZE + 1]).is_err()
        );

        let mut noncanonical = Encoder::new();
        noncanonical.put_u8(0);
        noncanonical.put_u16_le(0);
        noncanonical.put_u32_le(0);
        noncanonical.put_u32_le(0);
        noncanonical.put_u16_le(1 << 1);
        noncanonical.put_compact_size(0);
        assert!(matches!(
            NameState::decode(NameHash::new([0; 32]), &noncanonical.into_bytes()),
            Err(CovenantError::NonCanonicalNameState)
        ));

        let mut unknown_bits = Encoder::new();
        unknown_bits.put_u8(0);
        unknown_bits.put_u16_le(0);
        unknown_bits.put_u32_le(0);
        unknown_bits.put_u32_le(0);
        unknown_bits.put_u16_le(1 << 10);
        assert!(matches!(
            NameState::decode(NameHash::new([0; 32]), &unknown_bits.into_bytes()),
            Err(CovenantError::InvalidNameState(_))
        ));
    }
}
