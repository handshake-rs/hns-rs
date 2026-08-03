use std::cmp::Ordering;
use std::collections::HashMap;

use hns_encoding::{Decoder, Encoder};

use crate::named::{NamedRouteRecordV2, NamedRouteTrust};
use crate::record::{RouteRecord, blake2b_256, validate_host, validate_public_key};
use crate::{HNSR_RENDEZVOUS_SERVICE, HnsrProtocolError, MAX_RECORDS_PER_KEY, MAX_STORED_RECORDS};

const PEER_ROUTE_DOMAIN: &[u8] = b"HNSR-PEER-ROUTE-V1\0";
const RENDEZVOUS_NODE_DOMAIN: &[u8] = b"HNSR-RENDEZVOUS-NODE-V1\0";
const SAMPLE_DOMAIN: &[u8] = b"HNSR-SAMPLE-ROUTES-V1\0";
const CONTACT_SIZE: usize = 100;

pub fn route_key(
    network_magic: u32,
    endpoint_key: &[u8; 33],
) -> Result<[u8; 32], HnsrProtocolError> {
    validate_public_key(endpoint_key)?;
    Ok(blake2b_256(&[
        PEER_ROUTE_DOMAIN,
        &network_magic.to_le_bytes(),
        endpoint_key,
    ]))
}

pub fn rendezvous_node_id(
    network_magic: u32,
    peer_key: &[u8; 33],
) -> Result<[u8; 32], HnsrProtocolError> {
    validate_public_key(peer_key)?;
    Ok(blake2b_256(&[
        RENDEZVOUS_NODE_DOMAIN,
        &network_magic.to_le_bytes(),
        peer_key,
    ]))
}

pub fn sample_score(seed: &[u8; 32], raw_record: &[u8]) -> [u8; 32] {
    blake2b_256(&[SAMPLE_DOMAIN, seed, raw_record])
}

pub fn compare_distance(left: &[u8; 32], right: &[u8; 32], target: &[u8; 32]) -> Ordering {
    for index in 0..32 {
        match (left[index] ^ target[index]).cmp(&(right[index] ^ target[index])) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RendezvousContact {
    pub node_id: [u8; 32],
    pub host_type: u8,
    pub host: [u8; 16],
    pub port: u16,
    pub services: u64,
    pub peer_key: [u8; 33],
    pub observed_at: u64,
}

impl RendezvousContact {
    pub fn verify(
        &self,
        network_magic: u32,
        now: u64,
        allow_private: bool,
    ) -> Result<(), HnsrProtocolError> {
        if self.services & HNSR_RENDEZVOUS_SERVICE == 0
            || self.observed_at > now.saturating_add(600)
            || now.saturating_sub(self.observed_at) > 86_400
            || self.node_id != rendezvous_node_id(network_magic, &self.peer_key)?
        {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSR rendezvous contact",
            ));
        }
        validate_host(self.host_type, &self.host, self.port, allow_private)
    }

    pub fn encode(&self) -> Result<Vec<u8>, HnsrProtocolError> {
        validate_public_key(&self.peer_key)?;
        if !matches!(self.host_type, 1 | 2) || self.port == 0 {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSR rendezvous address",
            ));
        }
        let mut encoder = Encoder::with_capacity(CONTACT_SIZE);
        encoder.put_bytes(&self.node_id);
        encoder.put_u8(self.host_type);
        encoder.put_bytes(&self.host);
        encoder.put_u16_le(self.port);
        encoder.put_u64_le(self.services);
        encoder.put_bytes(&self.peer_key);
        encoder.put_u64_le(self.observed_at);
        Ok(encoder.into_bytes())
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let mut decoder = Decoder::new(input);
        let contact = Self::read_from(&mut decoder)?;
        decoder.finish()?;
        Ok(contact)
    }

    pub(crate) fn read_from(decoder: &mut Decoder<'_>) -> Result<Self, HnsrProtocolError> {
        let contact = Self {
            node_id: decoder.read_array()?,
            host_type: decoder.read_u8()?,
            host: decoder.read_array()?,
            port: decoder.read_u16_le()?,
            services: decoder.read_u64_le()?,
            peer_key: decoder.read_array()?,
            observed_at: decoder.read_u64_le()?,
        };
        contact.encode()?;
        Ok(contact)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteStoreLimits {
    pub total_records: usize,
    pub records_per_key: usize,
    pub records_per_source: usize,
}

impl Default for RouteStoreLimits {
    fn default() -> Self {
        Self {
            total_records: MAX_STORED_RECORDS,
            records_per_key: MAX_RECORDS_PER_KEY,
            records_per_source: 256,
        }
    }
}

#[derive(Clone, Debug)]
struct StoredRoute {
    endpoint_key: [u8; 33],
    sequence: u64,
    expires_at: u64,
    sampleable: bool,
    source: String,
    raw: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct VerifiedRoute {
    endpoint_key: [u8; 33],
    sequence: u64,
    expires_at: u64,
    sampleable: bool,
}

#[derive(Clone, Debug)]
pub struct RouteStore {
    network_magic: u32,
    allow_private: bool,
    limits: RouteStoreLimits,
    records: HashMap<[u8; 32], Vec<StoredRoute>>,
    source_counts: HashMap<String, usize>,
    size: usize,
}

impl RouteStore {
    pub fn new(
        network_magic: u32,
        allow_private: bool,
        limits: RouteStoreLimits,
    ) -> Result<Self, HnsrProtocolError> {
        if limits.total_records == 0
            || limits.records_per_key == 0
            || limits.records_per_source == 0
            || limits.records_per_key > limits.total_records
        {
            return Err(HnsrProtocolError::Invalid(
                "invalid HNSR route store limits",
            ));
        }
        Ok(Self {
            network_magic,
            allow_private,
            limits,
            records: HashMap::new(),
            source_counts: HashMap::new(),
            size: 0,
        })
    }

    pub const fn len(&self) -> usize {
        self.size
    }

    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn put(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        now: u64,
        source: String,
    ) -> Result<u64, HnsrProtocolError> {
        if source.is_empty() {
            return Err(HnsrProtocolError::Invalid("empty HNSR route source"));
        }
        let record = RouteRecord::decode(&raw)?;
        if record.route_key != key {
            return Err(HnsrProtocolError::Invalid("HNSR route key mismatch"));
        }
        record.verify(self.network_magic, now, self.allow_private)?;
        self.insert_verified(
            key,
            VerifiedRoute {
                endpoint_key: record.delegation.endpoint_key,
                sequence: record.sequence,
                expires_at: record.expires_at,
                sampleable: true,
            },
            raw,
            now,
            source,
        )
    }

    pub fn put_named(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        trust: &NamedRouteTrust<'_>,
        now: u64,
        source: String,
    ) -> Result<u64, HnsrProtocolError> {
        if source.is_empty() {
            return Err(HnsrProtocolError::Invalid("empty HNSR route source"));
        }
        if trust.identity.network_magic != self.network_magic {
            return Err(HnsrProtocolError::Invalid(
                "named HNSR route store network mismatch",
            ));
        }
        let record = NamedRouteRecordV2::decode(&raw)?;
        if record.route_key != key {
            return Err(HnsrProtocolError::Invalid("HNSR route key mismatch"));
        }
        record.verify(trust, now)?;
        self.insert_verified(
            key,
            VerifiedRoute {
                endpoint_key: record.delegation.endpoint_key,
                sequence: record.sequence,
                expires_at: record.expires_at,
                sampleable: false,
            },
            raw,
            now,
            source,
        )
    }

    pub fn put_named_for_admission(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        now: u64,
        source: String,
    ) -> Result<u64, HnsrProtocolError> {
        if source.is_empty() {
            return Err(HnsrProtocolError::Invalid("empty HNSR route source"));
        }
        let record = NamedRouteRecordV2::decode(&raw)?;
        if record.authorization.network_magic != self.network_magic || record.route_key != key {
            return Err(HnsrProtocolError::Invalid("HNSR route key mismatch"));
        }
        record.verify_untrusted_admission(now, self.allow_private)?;
        self.insert_verified(
            key,
            VerifiedRoute {
                endpoint_key: record.delegation.endpoint_key,
                sequence: record.sequence,
                expires_at: record.expires_at,
                sampleable: false,
            },
            raw,
            now,
            source,
        )
    }

    fn insert_verified(
        &mut self,
        key: [u8; 32],
        verified: VerifiedRoute,
        raw: Vec<u8>,
        now: u64,
        source: String,
    ) -> Result<u64, HnsrProtocolError> {
        if source.is_empty() {
            return Err(HnsrProtocolError::Invalid("empty HNSR route source"));
        }
        self.prune_key(&key, now);

        let previous = self.records.get(&key).and_then(|items| {
            items
                .iter()
                .position(|item| item.endpoint_key == verified.endpoint_key)
                .map(|index| (index, items[index].clone()))
        });
        if let Some((_, item)) = &previous
            && item.sequence >= verified.sequence
        {
            return Err(HnsrProtocolError::StaleSequence);
        }
        let key_count = self.records.get(&key).map_or(0, Vec::len);
        if previous.is_none() && key_count >= self.limits.records_per_key {
            return Err(HnsrProtocolError::Capacity);
        }
        if previous.is_none() && self.size >= self.limits.total_records {
            return Err(HnsrProtocolError::Capacity);
        }
        let source_count = self.source_counts.get(&source).copied().unwrap_or(0);
        let replaces_same_source = previous
            .as_ref()
            .is_some_and(|(_, item)| item.source == source);
        if source_count >= self.limits.records_per_source && !replaces_same_source {
            return Err(HnsrProtocolError::Capacity);
        }

        if let Some((index, item)) = previous {
            if let Some(items) = self.records.get_mut(&key) {
                items.remove(index);
            }
            self.decrement_source(&item.source);
            self.size -= 1;
        }
        self.records.entry(key).or_default().push(StoredRoute {
            endpoint_key: verified.endpoint_key,
            sequence: verified.sequence,
            expires_at: verified.expires_at,
            sampleable: verified.sampleable,
            source: source.clone(),
            raw,
        });
        *self.source_counts.entry(source).or_default() += 1;
        self.size += 1;
        Ok(verified.expires_at)
    }

    pub fn get(&mut self, key: &[u8; 32], maximum: usize, now: u64) -> Vec<Vec<u8>> {
        self.prune_key(key, now);
        let mut items = self.records.get(key).cloned().unwrap_or_default();
        items.sort_by(|left, right| right.sequence.cmp(&left.sequence));
        items
            .into_iter()
            .take(maximum.min(MAX_RECORDS_PER_KEY))
            .map(|item| item.raw)
            .collect()
    }

    pub fn sample(&mut self, maximum: usize, seed: &[u8; 32], now: u64) -> Vec<Vec<u8>> {
        self.prune_all(now);
        let mut records = self
            .records
            .values()
            .flat_map(|items| items.iter())
            .filter(|item| item.sampleable)
            .map(|item| (sample_score(seed, &item.raw), item.raw.clone()))
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(&right.0));
        records
            .into_iter()
            .take(maximum.min(MAX_RECORDS_PER_KEY))
            .map(|(_, raw)| raw)
            .collect()
    }

    pub fn prune_all(&mut self, now: u64) {
        let keys = self.records.keys().copied().collect::<Vec<_>>();
        for key in keys {
            self.prune_key(&key, now);
        }
    }

    fn prune_key(&mut self, key: &[u8; 32], now: u64) {
        let Some(mut items) = self.records.remove(key) else {
            return;
        };
        let mut retained = Vec::with_capacity(items.len());
        for item in items.drain(..) {
            if item.expires_at <= now {
                self.decrement_source(&item.source);
                self.size -= 1;
            } else {
                retained.push(item);
            }
        }
        if !retained.is_empty() {
            self.records.insert(*key, retained);
        }
    }

    fn decrement_source(&mut self, source: &str) {
        if let Some(count) = self.source_counts.get_mut(source) {
            *count -= 1;
            if *count == 0 {
                self.source_counts.remove(source);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::record::{EndpointDelegation, RelayTicket, public_key};
    use crate::{HNS_NODE_V1, MAX_CIRCUITS};

    use super::*;

    const MAGIC: u32 = 2_922_943_951;

    fn record(now: u64, sequence: u64, endpoint_private: [u8; 32]) -> RouteRecord {
        let endpoint_key = public_key(&endpoint_private).expect("key");
        let relay_private = [9; 32];
        let relay_key = public_key(&relay_private).expect("key");
        let mut ticket = RelayTicket {
            network_magic: MAGIC,
            profile: HNS_NODE_V1,
            transport: 0,
            host_type: 1,
            host: [0; 16],
            port: 14_039,
            relay_key,
            endpoint_key,
            reservation_id: [8; 16],
            issued_at: now,
            expires_at: now + 1800,
            max_active_circuits: MAX_CIRCUITS.min(8),
            max_bytes_per_circuit: 1_048_576,
            max_total_bytes: 8_388_608,
            flags: 0,
            relay_signature: Vec::new(),
            endpoint_signature: Vec::new(),
        };
        ticket.sign_relay(&relay_private).expect("sign");
        ticket.sign_endpoint(&endpoint_private).expect("sign");
        let mut delegation = EndpointDelegation {
            authorization_id: [0; 32],
            endpoint_key,
            sequence,
            issued_at: now,
            expires_at: now + 900,
            max_active_circuits: 8,
            max_bytes_per_circuit: 1_048_576,
            flags: 0,
            signature: Vec::new(),
        };
        delegation.sign(MAGIC, &endpoint_private).expect("sign");
        let mut record = RouteRecord {
            route_key: route_key(MAGIC, &endpoint_key).expect("key"),
            profile: HNS_NODE_V1,
            sequence,
            issued_at: now,
            expires_at: now + 900,
            authorization: Vec::new(),
            delegation,
            tickets: vec![ticket],
            endpoint_signature: Vec::new(),
        };
        record.sign(&endpoint_private).expect("sign");
        record
    }

    #[test]
    fn contact_identity_and_xor_order_match_hsd() {
        let generator =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .expect("hex")
                .try_into()
                .expect("33 bytes");
        assert_eq!(
            hex::encode(route_key(MAGIC, &generator).expect("route key")),
            "71d82772c6460a42e83e91dbcc09c5e020dbe7dec0d1d644b5318cf4daddc120"
        );
        assert_eq!(
            hex::encode(rendezvous_node_id(MAGIC, &generator).expect("node ID")),
            "edea356b705f8b600016db159332228d504b363a48dd81e28df0b816b91c35ff"
        );

        let key = public_key(&[1; 32]).expect("key");
        let timestamp = 1_700_000_000;
        let contact = RendezvousContact {
            node_id: rendezvous_node_id(MAGIC, &key).expect("ID"),
            host_type: 1,
            host: hex::decode("00000000000000000000ffff7f000001")
                .expect("hex")
                .try_into()
                .expect("16 bytes"),
            port: 14_039,
            services: HNSR_RENDEZVOUS_SERVICE,
            peer_key: key,
            observed_at: timestamp,
        };
        let encoded = contact.encode().expect("valid");
        assert_eq!(encoded.len(), CONTACT_SIZE);
        let decoded = RendezvousContact::decode(&encoded).expect("valid");
        decoded.verify(MAGIC, timestamp, true).expect("valid");
        assert_eq!(
            compare_distance(&[1; 32], &[2; 32], &[0; 32]),
            Ordering::Less
        );
    }

    #[test]
    fn store_requires_increasing_sequences_and_expires_records() {
        let now = 1_700_000_000;
        let mut store = RouteStore::new(
            MAGIC,
            true,
            RouteStoreLimits {
                total_records: 4,
                records_per_key: 2,
                records_per_source: 1,
            },
        )
        .expect("valid");
        let first = record(now, 1, [1; 32]);
        let key = first.route_key;
        store
            .put(
                key,
                first.encode().expect("valid"),
                now,
                "peer-a".to_owned(),
            )
            .expect("stored");
        assert!(matches!(
            store.put(
                key,
                first.encode().expect("valid"),
                now,
                "peer-a".to_owned()
            ),
            Err(HnsrProtocolError::StaleSequence)
        ));
        let second = record(now, 2, [1; 32]);
        store
            .put(
                key,
                second.encode().expect("valid"),
                now,
                "peer-a".to_owned(),
            )
            .expect("replaced");
        assert_eq!(store.len(), 1);
        assert_eq!(store.get(&key, 16, now + 900).len(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn deterministic_sampling_and_per_source_quotas_are_enforced() {
        let now = 1_700_000_000;
        let first = record(now, 1, [1; 32]);
        let second = record(now, 1, [2; 32]);
        let mut store = RouteStore::new(
            MAGIC,
            true,
            RouteStoreLimits {
                total_records: 4,
                records_per_key: 2,
                records_per_source: 1,
            },
        )
        .expect("valid");
        store
            .put(
                first.route_key,
                first.encode().expect("valid"),
                now,
                "peer-a".to_owned(),
            )
            .expect("stored");
        assert!(matches!(
            store.put(
                second.route_key,
                second.encode().expect("valid"),
                now,
                "peer-a".to_owned()
            ),
            Err(HnsrProtocolError::Capacity)
        ));
        store
            .put(
                second.route_key,
                second.encode().expect("valid"),
                now,
                "peer-b".to_owned(),
            )
            .expect("stored");
        let first_sample = store.sample(2, &[3; 32], now);
        let second_sample = store.sample(2, &[3; 32], now);
        assert_eq!(first_sample, second_sample);
    }
}
