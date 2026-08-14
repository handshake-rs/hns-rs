use std::cmp::Ordering;
use std::collections::HashMap;

use hns_encoding::{Decoder, Encoder};
use hns_service_authority::{
    authority_state::CurrentCommittedNamedService,
    hrm::{NamedServiceIdentity, ServiceGenerationObservation, VerifiedNamedService},
};

use crate::named::{NamedRouteRecordV2, NamedRouteTrust};
use crate::named_hrm::{HrmNamedRoutePolicy, NamedRouteRecordV3, named_route_key_v3};
use crate::record::{RouteRecord, blake2b_256, validate_host, validate_public_key};
use crate::{
    HNSR_RENDEZVOUS_SERVICE, HnsrProtocolError, MAX_RECORDS_PER_KEY, MAX_ROUTE_LIFETIME,
    MAX_STORED_RECORDS,
};

const PEER_ROUTE_DOMAIN: &[u8] = b"HNSR-PEER-ROUTE-V1\0";
const RENDEZVOUS_NODE_DOMAIN: &[u8] = b"HNSR-RENDEZVOUS-NODE-V1\0";
const SAMPLE_DOMAIN: &[u8] = b"HNSR-SAMPLE-ROUTES-V1\0";
const NAMED_V3_CANONICAL_HASH_DOMAIN: &[u8] = b"HNSR-NAMED-V3-CANONICAL-RECORD-V1\0";
const NAMED_V3_LEDGER_CHECKSUM_DOMAIN: &[u8] = b"HNSR-NAMED-V3-LEDGER-SNAPSHOT-V1\0";
const NAMED_V3_LEDGER_FINGERPRINT_DOMAIN: &[u8] = b"HNSR-NAMED-V3-LEDGER-CAS-V1\0";
const NAMED_V3_LEDGER_MAGIC: &[u8; 8] = b"HNSRV3L\0";
const NAMED_V3_LEDGER_SCHEMA: u8 = 1;
const NAMED_V3_LEDGER_HEADER_SIZE: usize = 44;
const NAMED_V3_LEDGER_ENTRY_SIZE: usize = 155;
const NAMED_V3_LEDGER_CHECKSUM_SIZE: usize = 32;
const CONTACT_SIZE: usize = 100;

/// Mutually exclusive route-record namespaces retained by a rendezvous store.
///
/// The model is part of replacement and conflict scope. In particular, a
/// legacy `hsa1` route can never replace or poison an HRM-backed named route,
/// even though both named models deliberately derive the same stable lookup
/// key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RouteRecordModel {
    UnnamedV1,
    LegacyNamedV2,
    HrmNamedV3,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RouteStoreKey {
    model: RouteRecordModel,
    route_key: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct NamedRouteV3LedgerKey {
    route_key: [u8; 32],
    endpoint_key: [u8; 33],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamedRouteV3LedgerEntry {
    endpoint_high_water: u64,
    endpoint_delegation_id: [u8; 32],
    endpoint_conflicted: bool,
    route_high_water: u64,
    retain_until: u64,
    route_conflicted: bool,
    route_canonical_hash: [u8; 32],
}

/// Opaque, deterministic persistence image for the V3 route replay ledger.
///
/// The encoded BLAKE2b-256 checksum detects accidental corruption only. It is
/// not a MAC, signature, or rollback proof. Embeddings must persist snapshots
/// atomically in authenticated, anti-rollback local storage; accepting an
/// attacker-modified older snapshot can lower replay protection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedRouteV3LedgerSnapshot {
    network_magic: u32,
    capacity: usize,
    records_per_key: usize,
    revision: u64,
    pruned_through: u64,
    entries: Vec<(NamedRouteV3LedgerKey, NamedRouteV3LedgerEntry)>,
}

impl NamedRouteV3LedgerSnapshot {
    /// Handshake network to which every replay scope is bound.
    pub const fn network_magic(&self) -> u32 {
        self.network_magic
    }

    /// Exact maximum ledger-entry count of the originating store.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Exact per-route-key ledger scope limit of the originating store.
    pub const fn records_per_key(&self) -> usize {
        self.records_per_key
    }

    /// Monotonic mutation marker included in the checksummed payload.
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Greatest trusted time at which expired ledger scopes were deleted.
    ///
    /// Restoring or time-pruning this snapshot with an earlier time fails
    /// closed rather than reviving a scope that was already forgotten.
    pub const fn pruned_through(&self) -> u64 {
        self.pruned_through
    }

    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Domain-separated fingerprint of the exact checksummed encoding.
    ///
    /// Embeddings can pair this with [`Self::revision`] in an atomic
    /// compare-and-swap so concurrent forks from the same revision do not
    /// silently overwrite one another.
    pub fn fingerprint(&self) -> [u8; 32] {
        blake2b_256(&[NAMED_V3_LEDGER_FINGERPRINT_DOMAIN, &self.encode()])
    }

    /// Encode entries in strict `(route_key, endpoint_key)` order.
    ///
    /// The trailing checksum is corruption detection, not authentication.
    pub fn encode(&self) -> Vec<u8> {
        let payload_size = NAMED_V3_LEDGER_HEADER_SIZE.saturating_add(
            self.entries
                .len()
                .saturating_mul(NAMED_V3_LEDGER_ENTRY_SIZE),
        );
        let mut bytes =
            Vec::with_capacity(payload_size.saturating_add(NAMED_V3_LEDGER_CHECKSUM_SIZE));
        bytes.extend_from_slice(NAMED_V3_LEDGER_MAGIC);
        bytes.push(NAMED_V3_LEDGER_SCHEMA);
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&self.network_magic.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.capacity)
                .expect("validated HNSR V3 ledger capacity fits u32")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(self.records_per_key)
                .expect("validated HNSR V3 ledger per-key capacity fits u32")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&self.revision.to_le_bytes());
        bytes.extend_from_slice(&self.pruned_through.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(self.entries.len())
                .expect("validated HNSR V3 ledger length fits u32")
                .to_le_bytes(),
        );
        for (key, entry) in &self.entries {
            bytes.extend_from_slice(&key.route_key);
            bytes.extend_from_slice(&key.endpoint_key);
            bytes.extend_from_slice(&entry.endpoint_high_water.to_le_bytes());
            bytes.extend_from_slice(&entry.endpoint_delegation_id);
            bytes.push(u8::from(entry.endpoint_conflicted));
            bytes.extend_from_slice(&entry.route_high_water.to_le_bytes());
            bytes.extend_from_slice(&entry.retain_until.to_le_bytes());
            bytes.push(u8::from(entry.route_conflicted));
            bytes.extend_from_slice(&entry.route_canonical_hash);
        }
        let checksum = named_v3_ledger_checksum(&bytes);
        bytes.extend_from_slice(&checksum);
        bytes
    }

    /// Decode one exact, bounded, canonical snapshot.
    pub fn decode(input: &[u8]) -> Result<Self, HnsrProtocolError> {
        let minimum_size = NAMED_V3_LEDGER_HEADER_SIZE + NAMED_V3_LEDGER_CHECKSUM_SIZE;
        let maximum_size = NAMED_V3_LEDGER_HEADER_SIZE
            + MAX_STORED_RECORDS * NAMED_V3_LEDGER_ENTRY_SIZE
            + NAMED_V3_LEDGER_CHECKSUM_SIZE;
        if input.len() < minimum_size || input.len() > maximum_size {
            return Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot);
        }
        let payload_size = input.len() - NAMED_V3_LEDGER_CHECKSUM_SIZE;
        let (payload, supplied_checksum) = input.split_at(payload_size);
        if supplied_checksum != named_v3_ledger_checksum(payload) {
            return Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot);
        }

        let corrupt = |_| HnsrProtocolError::CorruptNamedRouteLedgerSnapshot;
        let mut decoder = Decoder::new(payload);
        if decoder
            .read_slice(NAMED_V3_LEDGER_MAGIC.len())
            .map_err(corrupt)?
            != NAMED_V3_LEDGER_MAGIC
            || decoder.read_u8().map_err(corrupt)? != NAMED_V3_LEDGER_SCHEMA
            || decoder.read_array::<3>().map_err(corrupt)? != [0; 3]
        {
            return Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot);
        }
        let network_magic = decoder.read_u32_le().map_err(corrupt)?;
        let capacity = usize::try_from(decoder.read_u32_le().map_err(corrupt)?)
            .map_err(|_| HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)?;
        let records_per_key = usize::try_from(decoder.read_u32_le().map_err(corrupt)?)
            .map_err(|_| HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)?;
        let revision = decoder.read_u64_le().map_err(corrupt)?;
        let pruned_through = decoder.read_u64_le().map_err(corrupt)?;
        let entry_count = usize::try_from(decoder.read_u32_le().map_err(corrupt)?)
            .map_err(|_| HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)?;
        if capacity == 0
            || capacity > MAX_STORED_RECORDS
            || records_per_key == 0
            || records_per_key > MAX_RECORDS_PER_KEY
            || records_per_key > capacity
            || entry_count > capacity
            || u64::try_from(entry_count)
                .map_err(|_| HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)?
                > revision
            || revision == u64::MAX
            || (revision == 0 && (entry_count != 0 || pruned_through != 0))
            || payload.len()
                != NAMED_V3_LEDGER_HEADER_SIZE
                    .checked_add(
                        entry_count
                            .checked_mul(NAMED_V3_LEDGER_ENTRY_SIZE)
                            .ok_or(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)?,
                    )
                    .ok_or(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)?
        {
            return Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot);
        }

        let mut entries = Vec::with_capacity(entry_count);
        let mut previous_key: Option<NamedRouteV3LedgerKey> = None;
        let mut route_key_count = 0_usize;
        for _ in 0..entry_count {
            let key = NamedRouteV3LedgerKey {
                route_key: decoder.read_array().map_err(corrupt)?,
                endpoint_key: decoder.read_array().map_err(corrupt)?,
            };
            validate_public_key(&key.endpoint_key)
                .map_err(|_| HnsrProtocolError::CorruptNamedRouteLedgerSnapshot)?;
            if previous_key.is_some_and(|previous| previous >= key) {
                return Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot);
            }
            route_key_count =
                if previous_key.is_some_and(|previous| previous.route_key == key.route_key) {
                    route_key_count + 1
                } else {
                    1
                };
            if route_key_count > records_per_key {
                return Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot);
            }
            let endpoint_high_water = decoder.read_u64_le().map_err(corrupt)?;
            let endpoint_delegation_id = decoder.read_array().map_err(corrupt)?;
            let endpoint_conflicted = match decoder.read_u8().map_err(corrupt)? {
                0 => false,
                1 => true,
                _ => return Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot),
            };
            let route_high_water = decoder.read_u64_le().map_err(corrupt)?;
            let retain_until = decoder.read_u64_le().map_err(corrupt)?;
            let route_conflicted = match decoder.read_u8().map_err(corrupt)? {
                0 => false,
                1 => true,
                _ => return Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot),
            };
            let route_canonical_hash = decoder.read_array().map_err(corrupt)?;
            if endpoint_high_water == 0
                || route_high_water == 0
                || retain_until == 0
                || retain_until <= pruned_through
            {
                return Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot);
            }
            entries.push((
                key,
                NamedRouteV3LedgerEntry {
                    endpoint_high_water,
                    endpoint_delegation_id,
                    endpoint_conflicted,
                    route_high_water,
                    retain_until,
                    route_conflicted,
                    route_canonical_hash,
                },
            ));
            previous_key = Some(key);
        }
        decoder.finish().map_err(corrupt)?;
        let snapshot = Self {
            network_magic,
            capacity,
            records_per_key,
            revision,
            pruned_through,
            entries,
        };
        if snapshot.encode() != input {
            return Err(HnsrProtocolError::CorruptNamedRouteLedgerSnapshot);
        }
        Ok(snapshot)
    }
}

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

fn named_v3_canonical_hash(raw_record: &[u8]) -> [u8; 32] {
    blake2b_256(&[NAMED_V3_CANONICAL_HASH_DOMAIN, raw_record])
}

fn named_v3_ledger_checksum(payload: &[u8]) -> [u8; 32] {
    blake2b_256(&[NAMED_V3_LEDGER_CHECKSUM_DOMAIN, payload])
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
    pub verification_attempts_total: usize,
    pub verification_attempts_per_source: usize,
    pub verification_window_seconds: u64,
}

impl Default for RouteStoreLimits {
    fn default() -> Self {
        Self {
            total_records: MAX_STORED_RECORDS,
            records_per_key: MAX_RECORDS_PER_KEY,
            records_per_source: 256,
            verification_attempts_total: 1_024,
            verification_attempts_per_source: 64,
            verification_window_seconds: 60,
        }
    }
}

#[derive(Clone, Debug)]
struct StoredRoute {
    endpoint_key: [u8; 33],
    sequence: u64,
    expires_at: u64,
    sampleable: bool,
    named_v3_current_verified: bool,
    named_v3_endpoint_sequence: u64,
    named_v3_endpoint_delegation_id: [u8; 32],
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

#[derive(Clone, Copy, Debug)]
struct NamedV3VerifiedCandidate {
    route: VerifiedRoute,
    endpoint_sequence: u64,
    endpoint_delegation_id: [u8; 32],
    retain_until: u64,
}

fn named_v3_retention_horizon(signed_route_expires_at: u64, observation_now: u64) -> u64 {
    signed_route_expires_at.max(observation_now.saturating_add(MAX_ROUTE_LIFETIME))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InsertDisposition {
    New,
    Replace(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamedV3CounterDisposition {
    Stale,
    Idempotent,
    Conflict,
    AlreadyConflicted,
    Advance,
}

impl NamedV3CounterDisposition {
    const fn mutates(self) -> bool {
        matches!(self, Self::Conflict | Self::Advance)
    }

    const fn matches_final(self) -> bool {
        matches!(self, Self::Idempotent | Self::Advance)
    }

    const fn is_conflict(self) -> bool {
        matches!(self, Self::Conflict | Self::AlreadyConflicted)
    }
}

/// The endpoint-delegation and route observations form a product lattice.
/// Neither dimension is allowed to short-circuit classification or mutation
/// of the other one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamedV3LedgerDisposition {
    new_scope: bool,
    endpoint: NamedV3CounterDisposition,
    route: NamedV3CounterDisposition,
}

impl NamedV3LedgerDisposition {
    const fn new_scope() -> Self {
        Self {
            new_scope: true,
            endpoint: NamedV3CounterDisposition::Advance,
            route: NamedV3CounterDisposition::Advance,
        }
    }

    const fn counter_mutates(self) -> bool {
        self.new_scope || self.endpoint.mutates() || self.route.mutates()
    }

    const fn candidate_matches_final(self) -> bool {
        self.new_scope || (self.endpoint.matches_final() && self.route.matches_final())
    }

    const fn is_idempotent(self) -> bool {
        !self.new_scope
            && matches!(self.endpoint, NamedV3CounterDisposition::Idempotent)
            && matches!(self.route, NamedV3CounterDisposition::Idempotent)
    }

    const fn is_conflict(self) -> bool {
        self.endpoint.is_conflict() || self.route.is_conflict()
    }

    const fn is_stale(self) -> bool {
        matches!(self.endpoint, NamedV3CounterDisposition::Stale)
            || matches!(self.route, NamedV3CounterDisposition::Stale)
    }

    fn rejection(self) -> Option<HnsrProtocolError> {
        if self.candidate_matches_final() {
            None
        } else if self.is_conflict() {
            Some(HnsrProtocolError::ConflictingSequence)
        } else if self.is_stale() {
            Some(HnsrProtocolError::StaleSequence)
        } else {
            Some(HnsrProtocolError::Invalid(
                "HNSR V3 product-lattice disposition is incomplete",
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NamedV3LiveDisposition {
    New,
    Replace(usize),
    Idempotent(usize),
    RemoveRejected(Option<usize>),
    KeepRejected,
}

fn next_named_v3_ledger_entry(
    current: Option<NamedRouteV3LedgerEntry>,
    disposition: NamedV3LedgerDisposition,
    candidate: &NamedV3VerifiedCandidate,
    route_canonical_hash: [u8; 32],
) -> Result<NamedRouteV3LedgerEntry, HnsrProtocolError> {
    if disposition.new_scope {
        if current.is_some() {
            return Err(HnsrProtocolError::Invalid(
                "HNSR V3 new replay scope already exists",
            ));
        }
        return Ok(NamedRouteV3LedgerEntry {
            endpoint_high_water: candidate.endpoint_sequence,
            endpoint_delegation_id: candidate.endpoint_delegation_id,
            endpoint_conflicted: false,
            route_high_water: candidate.route.sequence,
            retain_until: candidate.retain_until,
            route_conflicted: false,
            route_canonical_hash,
        });
    }

    let mut entry = current.ok_or(HnsrProtocolError::Invalid(
        "HNSR V3 replay ledger scope disappeared",
    ))?;
    match disposition.endpoint {
        NamedV3CounterDisposition::Stale
            if candidate.endpoint_sequence < entry.endpoint_high_water => {}
        NamedV3CounterDisposition::Idempotent
            if candidate.endpoint_sequence == entry.endpoint_high_water
                && !entry.endpoint_conflicted
                && candidate.endpoint_delegation_id == entry.endpoint_delegation_id => {}
        NamedV3CounterDisposition::Conflict
            if candidate.endpoint_sequence == entry.endpoint_high_water
                && candidate.endpoint_delegation_id != entry.endpoint_delegation_id =>
        {
            entry.endpoint_conflicted = true;
            entry.endpoint_delegation_id = entry
                .endpoint_delegation_id
                .min(candidate.endpoint_delegation_id);
        }
        NamedV3CounterDisposition::AlreadyConflicted
            if candidate.endpoint_sequence == entry.endpoint_high_water
                && entry.endpoint_conflicted => {}
        NamedV3CounterDisposition::Advance
            if candidate.endpoint_sequence > entry.endpoint_high_water =>
        {
            entry.endpoint_high_water = candidate.endpoint_sequence;
            entry.endpoint_delegation_id = candidate.endpoint_delegation_id;
            entry.endpoint_conflicted = false;
        }
        _ => {
            return Err(HnsrProtocolError::Invalid(
                "HNSR V3 endpoint replay disposition changed",
            ));
        }
    }
    match disposition.route {
        NamedV3CounterDisposition::Stale if candidate.route.sequence < entry.route_high_water => {}
        NamedV3CounterDisposition::Idempotent
            if candidate.route.sequence == entry.route_high_water
                && !entry.route_conflicted
                && route_canonical_hash == entry.route_canonical_hash => {}
        NamedV3CounterDisposition::Conflict
            if candidate.route.sequence == entry.route_high_water
                && route_canonical_hash != entry.route_canonical_hash =>
        {
            entry.route_conflicted = true;
            entry.route_canonical_hash = entry.route_canonical_hash.min(route_canonical_hash);
        }
        NamedV3CounterDisposition::AlreadyConflicted
            if candidate.route.sequence == entry.route_high_water && entry.route_conflicted => {}
        NamedV3CounterDisposition::Advance if candidate.route.sequence > entry.route_high_water => {
            entry.route_high_water = candidate.route.sequence;
            entry.route_canonical_hash = route_canonical_hash;
            entry.route_conflicted = false;
        }
        _ => {
            return Err(HnsrProtocolError::Invalid(
                "HNSR V3 route replay disposition changed",
            ));
        }
    }
    entry.retain_until = entry.retain_until.max(candidate.retain_until);
    Ok(entry)
}

#[derive(Clone, Copy, Debug)]
struct VerificationWindow {
    started_at: u64,
    attempts: usize,
}

/// Volatile in-memory route cache and V3 admission ledger.
///
/// This type does not enforce persistence-before-reply and is intentionally
/// non-cloneable so one mutable ledger cannot fork accidentally. Production
/// nodes which retain the finite V3 ledger across restart use
/// [`crate::LeasedPersistentRendezvousService`] and its guarded
/// `handle_and_emit` boundary. Live route bytes remain volatile in both modes
/// and require full re-admission or current-authority revalidation after restart.
///
/// The mutable ledger must not be forked by cloning:
///
/// ```compile_fail
/// use hns_hnsr_protocol::RouteStore;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<RouteStore>();
/// ```
#[derive(Debug)]
pub struct RouteStore {
    network_magic: u32,
    allow_private: bool,
    limits: RouteStoreLimits,
    records: HashMap<RouteStoreKey, Vec<StoredRoute>>,
    named_v3_ledger: HashMap<NamedRouteV3LedgerKey, NamedRouteV3LedgerEntry>,
    named_v3_ledger_route_counts: HashMap<[u8; 32], usize>,
    named_v3_ledger_revision: u64,
    named_v3_pruned_through: u64,
    source_counts: HashMap<String, usize>,
    global_verification_window: Option<VerificationWindow>,
    verification_windows: HashMap<String, VerificationWindow>,
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
            || limits.verification_attempts_total == 0
            || limits.verification_attempts_per_source == 0
            || limits.verification_window_seconds == 0
            || limits.records_per_key > limits.total_records
            || limits.total_records > MAX_STORED_RECORDS
            || limits.records_per_key > MAX_RECORDS_PER_KEY
            || limits.verification_attempts_per_source > limits.verification_attempts_total
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
            named_v3_ledger: HashMap::new(),
            named_v3_ledger_route_counts: HashMap::new(),
            named_v3_ledger_revision: 0,
            named_v3_pruned_through: 0,
            source_counts: HashMap::new(),
            global_verification_window: None,
            verification_windows: HashMap::new(),
            size: 0,
        })
    }

    pub const fn len(&self) -> usize {
        self.size
    }

    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn named_v3_ledger_len(&self) -> usize {
        self.named_v3_ledger.len()
    }

    /// Mutation marker for this volatile low-level ledger.
    ///
    /// This marker and [`Self::named_v3_ledger_snapshot`] are insufficient by
    /// themselves to enforce persistence-before-reply or outcome-ambiguous
    /// retry ordering. Use [`crate::LeasedPersistentRendezvousService`] and its
    /// guarded `handle_and_emit` boundary for production persistence.
    pub const fn named_v3_ledger_revision(&self) -> u64 {
        self.named_v3_ledger_revision
    }

    /// Greatest trusted time at which expired V3 ledger scopes were deleted.
    pub const fn named_v3_pruned_through(&self) -> u64 {
        self.named_v3_pruned_through
    }

    /// Capture the volatile retention-bounded V3 storage-admission ledger.
    ///
    /// Live route bytes and current HNSA authority are deliberately absent.
    /// This low-level method may prune and mutate the ledger before returning;
    /// it does not retain a pending CAS or withhold a reply. Persistent
    /// embeddings use [`crate::LeasedPersistentRendezvousService`] through its
    /// guarded `handle_and_emit` boundary.
    pub fn named_v3_ledger_snapshot(
        &mut self,
        now: u64,
    ) -> Result<NamedRouteV3LedgerSnapshot, HnsrProtocolError> {
        self.prune_named_v3_ledger(now)?;
        let mut entries = self
            .named_v3_ledger
            .iter()
            .map(|(key, entry)| (*key, *entry))
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|(key, _)| *key);
        Ok(NamedRouteV3LedgerSnapshot {
            network_magic: self.network_magic,
            capacity: self.limits.total_records,
            records_per_key: self.limits.records_per_key,
            revision: self.named_v3_ledger_revision,
            pruned_through: self.named_v3_pruned_through,
            entries,
        })
    }

    /// Restore a compatible replay ledger into an otherwise fresh store.
    ///
    /// Live routes are deliberately absent from the snapshot and must pass
    /// full V3 verification again. The embedding must authenticate and
    /// anti-rollback the snapshot storage; its checksum alone does neither.
    /// `minimum_revision` must come from that authenticated external state.
    pub fn restore_named_v3_ledger(
        &mut self,
        snapshot: NamedRouteV3LedgerSnapshot,
        now: u64,
        minimum_revision: u64,
    ) -> Result<(), HnsrProtocolError> {
        if self.size != 0
            || !self.records.is_empty()
            || !self.source_counts.is_empty()
            || !self.named_v3_ledger.is_empty()
            || !self.named_v3_ledger_route_counts.is_empty()
            || self.named_v3_ledger_revision != 0
            || self.named_v3_pruned_through != 0
            || snapshot.network_magic != self.network_magic
            || snapshot.capacity != self.limits.total_records
            || snapshot.records_per_key != self.limits.records_per_key
            || snapshot.entries.len() > self.limits.total_records
            || snapshot.revision < minimum_revision
        {
            return Err(HnsrProtocolError::IncompatibleNamedRouteLedgerSnapshot);
        }
        if now < snapshot.pruned_through {
            return Err(HnsrProtocolError::ClockRollback);
        }
        let mut entries = snapshot.entries;
        let before = entries.len();
        entries.retain(|(_, entry)| entry.retain_until > now);
        let (revision, pruned_through) = if entries.len() == before {
            (snapshot.revision, snapshot.pruned_through)
        } else {
            (
                Self::next_named_v3_ledger_revision_from(snapshot.revision)?,
                now,
            )
        };
        let mut route_counts = HashMap::new();
        for (key, _) in &entries {
            *route_counts.entry(key.route_key).or_default() += 1;
        }
        self.named_v3_ledger_revision = revision;
        self.named_v3_pruned_through = pruned_through;
        self.named_v3_ledger = entries.into_iter().collect();
        self.named_v3_ledger_route_counts = route_counts;
        Ok(())
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
        self.charge_verification(&source, now)?;
        let record = RouteRecord::decode(&raw)?;
        if record.route_key != key {
            return Err(HnsrProtocolError::Invalid("HNSR route key mismatch"));
        }
        let verified = VerifiedRoute {
            endpoint_key: record.delegation.endpoint_key,
            sequence: record.sequence,
            expires_at: record.expires_at,
            sampleable: true,
        };
        let store_key = RouteStoreKey {
            model: RouteRecordModel::UnnamedV1,
            route_key: key,
        };
        let disposition = self.preflight_insert(&store_key, &verified, now, &source)?;
        record.verify(self.network_magic, now, self.allow_private)?;
        self.insert_verified(store_key, verified, raw, source, disposition)
    }

    /// Store a fully current-state-verified legacy version-2 named route.
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
        self.charge_verification(&source, now)?;
        if trust.identity.network_magic != self.network_magic {
            return Err(HnsrProtocolError::Invalid(
                "named HNSR route store network mismatch",
            ));
        }
        let record = NamedRouteRecordV2::decode(&raw)?;
        if record.route_key != key {
            return Err(HnsrProtocolError::Invalid("HNSR route key mismatch"));
        }
        let verified = VerifiedRoute {
            endpoint_key: record.delegation.endpoint_key,
            sequence: record.sequence,
            expires_at: record.expires_at,
            sampleable: false,
        };
        let store_key = RouteStoreKey {
            model: RouteRecordModel::LegacyNamedV2,
            route_key: key,
        };
        let disposition = self.preflight_insert(&store_key, &verified, now, &source)?;
        record.verify(trust, now)?;
        self.insert_verified(store_key, verified, raw, source, disposition)
    }

    /// Store a legacy version-2 route after bounded internal-consistency
    /// admission only.
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
        self.charge_verification(&source, now)?;
        let record = NamedRouteRecordV2::decode(&raw)?;
        if record.authorization.network_magic != self.network_magic || record.route_key != key {
            return Err(HnsrProtocolError::Invalid("HNSR route key mismatch"));
        }
        let verified = VerifiedRoute {
            endpoint_key: record.delegation.endpoint_key,
            sequence: record.sequence,
            expires_at: record.expires_at,
            sampleable: false,
        };
        let store_key = RouteStoreKey {
            model: RouteRecordModel::LegacyNamedV2,
            route_key: key,
        };
        let disposition = self.preflight_insert(&store_key, &verified, now, &source)?;
        record.verify_untrusted_admission(now, self.allow_private)?;
        self.insert_verified(store_key, verified, raw, source, disposition)
    }

    /// Explicit alias for [`Self::put_named`] that names the retained legacy
    /// model at call sites which also support HRM-backed routes.
    pub fn put_named_v2(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        trust: &NamedRouteTrust<'_>,
        now: u64,
        source: String,
    ) -> Result<u64, HnsrProtocolError> {
        self.put_named(key, raw, trust, now, source)
    }

    /// Explicit alias for [`Self::put_named_for_admission`] for the legacy
    /// version-2 authority model.
    pub fn put_named_v2_for_admission(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        now: u64,
        source: String,
    ) -> Result<u64, HnsrProtocolError> {
        self.put_named_for_admission(key, raw, now, source)
    }

    /// Store an HRM-backed version-3 route under durably committed HNSA
    /// authority.
    ///
    /// Withdrawn authority is rejected. The authority aggregate must have
    /// crossed its exact durable CAS boundary before it can produce the
    /// [`CurrentCommittedNamedService`] accepted here.
    pub fn put_named_v3(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        committed_service: &CurrentCommittedNamedService<'_>,
        policy: HrmNamedRoutePolicy,
        now: u64,
        source: String,
    ) -> Result<u64, HnsrProtocolError> {
        ensure_current_committed_named_v3_lease(committed_service)?;
        let mut affected_route_key = None;
        let result = (|| {
            self.ensure_named_v3_time(now)?;
            if committed_service.trusted_time_high_water() != now {
                return Err(HnsrProtocolError::Invalid(
                    "committed HNSA authority operation-time mismatch",
                ));
            }
            let service = committed_service
                .active()
                .ok_or(HnsrProtocolError::Invalid(
                    "committed HNSA service is withdrawn",
                ))?;
            affected_route_key = Some(named_route_key_v3(service.identity())?);
            self.put_named_v3_uncommitted(key, raw, service, policy, now, source)
        })();
        self.finish_current_authority_operation(committed_service, affected_route_key, result)
    }

    /// Low-level current-authority insertion without a durable HNSA boundary.
    ///
    /// Production callers must use [`Self::put_named_v3`]. This method exists
    /// for validators and tests which deliberately manage the authority CAS
    /// boundary outside this type; raw validator output alone is not safe for
    /// operational use.
    #[doc(hidden)]
    pub fn put_named_v3_uncommitted(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        service: &VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
        source: String,
    ) -> Result<u64, HnsrProtocolError> {
        self.ensure_named_v3_time(now)?;
        if source.is_empty() {
            return Err(HnsrProtocolError::Invalid("empty HNSR route source"));
        }
        self.charge_verification(&source, now)?;
        if service.identity().network_magic != self.network_magic {
            return Err(HnsrProtocolError::Invalid(
                "HRM-backed named route store network mismatch",
            ));
        }
        let record = NamedRouteRecordV3::decode(&raw)?;
        if record.route_key != key || record.endpoint_delegation.network_magic != self.network_magic
        {
            return Err(HnsrProtocolError::Invalid("HNSR route key mismatch"));
        }
        let mut candidate = NamedV3VerifiedCandidate {
            route: VerifiedRoute {
                endpoint_key: record.endpoint_delegation.endpoint_key,
                sequence: record.record_sequence,
                expires_at: record.expires_at,
                sampleable: false,
            },
            endpoint_sequence: record.endpoint_delegation.endpoint_sequence,
            endpoint_delegation_id: record
                .endpoint_delegation
                .id()
                .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation"))?,
            retain_until: named_v3_retention_horizon(record.expires_at, now),
        };
        self.preflight_untrusted_named_v3(key, &candidate, &raw, now, &source)?;
        let current = record.verify_current_uncommitted(service, policy, now)?;
        candidate.route.expires_at = current.cache_until();
        self.insert_verified_named_v3(key, candidate, true, raw, now, source)
    }

    /// Store an HRM-backed version-3 route after bounded internal admission.
    /// This does not establish current HNS or HRM/HNSA authority.
    pub fn put_named_v3_for_admission(
        &mut self,
        key: [u8; 32],
        raw: Vec<u8>,
        now: u64,
        source: String,
    ) -> Result<u64, HnsrProtocolError> {
        self.ensure_named_v3_time(now)?;
        if source.is_empty() {
            return Err(HnsrProtocolError::Invalid("empty HNSR route source"));
        }
        self.charge_verification(&source, now)?;
        let record = NamedRouteRecordV3::decode(&raw)?;
        if record.route_key != key || record.endpoint_delegation.network_magic != self.network_magic
        {
            return Err(HnsrProtocolError::Invalid("HNSR route key mismatch"));
        }
        let candidate = NamedV3VerifiedCandidate {
            route: VerifiedRoute {
                endpoint_key: record.endpoint_delegation.endpoint_key,
                sequence: record.record_sequence,
                expires_at: record.expires_at,
                sampleable: false,
            },
            endpoint_sequence: record.endpoint_delegation.endpoint_sequence,
            endpoint_delegation_id: record
                .endpoint_delegation
                .id()
                .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA endpoint delegation"))?,
            retain_until: named_v3_retention_horizon(record.expires_at, now),
        };
        self.preflight_untrusted_named_v3(key, &candidate, &raw, now, &source)?;
        record.verify_admission(now, self.allow_private)?;
        self.insert_verified_named_v3(key, candidate, false, raw, now, source)
    }

    /// Apply one durably committed, still-current HNSA decision to retained V3
    /// routes.
    ///
    /// Active authority revalidates the exact named-service namespace. A
    /// committed withdrawal removes its live bytes while retaining the
    /// independent replay ledger. `identity` binds a withdrawal tombstone to
    /// the intended service under its subject.
    pub fn revalidate_named_v3_current(
        &mut self,
        identity: &NamedServiceIdentity,
        committed_service: &CurrentCommittedNamedService<'_>,
        policy: HrmNamedRoutePolicy,
        now: u64,
    ) -> Result<usize, HnsrProtocolError> {
        ensure_current_committed_named_v3_lease(committed_service)?;
        let mut affected_route_key = None;
        let result = (|| {
            self.ensure_named_v3_time(now)?;
            validate_current_committed_named_v3_binding(
                identity,
                committed_service,
                self.network_magic,
                now,
            )?;
            affected_route_key = Some(named_route_key_v3(identity)?);
            match committed_service.active() {
                Some(service) => self.revalidate_named_v3_current_uncommitted(service, policy, now),
                None => self.invalidate_named_v3_withdrawal_uncommitted(
                    identity,
                    committed_service.observation(),
                ),
            }
        })();
        self.finish_current_authority_operation(committed_service, affected_route_key, result)
    }

    /// Low-level revalidation against active validator output which has not
    /// been tied to the authority aggregate's current durable revision.
    ///
    /// Endpoint-delegation and route high-water marks and their equivocation
    /// tombstones are intentionally
    /// independent of live bytes: rotation removes stale routes but never
    /// lowers or deletes the exact route/endpoint ledger scope. Only a fully
    /// verified, correctly ordered greater counter clears its conflict.
    ///
    /// Production callers must use the current-committed authority wrapper.
    #[doc(hidden)]
    pub fn revalidate_named_v3_current_uncommitted(
        &mut self,
        service: &VerifiedNamedService,
        policy: HrmNamedRoutePolicy,
        now: u64,
    ) -> Result<usize, HnsrProtocolError> {
        self.ensure_named_v3_time(now)?;
        if service.identity().network_magic != self.network_magic {
            return Err(HnsrProtocolError::Invalid(
                "HRM-backed named route store network mismatch",
            ));
        }
        let store_key = RouteStoreKey {
            model: RouteRecordModel::HrmNamedV3,
            route_key: named_route_key_v3(service.identity())?,
        };
        self.prune_named_v3_ledger(now)?;
        let Some(items) = self.records.remove(&store_key) else {
            return Ok(0);
        };
        let mut retained = Vec::with_capacity(items.len());
        for mut item in items {
            let verified = NamedRouteRecordV3::decode(&item.raw).and_then(|record| {
                record
                    .verify_current_uncommitted(service, policy, now)
                    .map(|current| current.cache_until())
            });
            match verified {
                Ok(cache_until) => {
                    item.expires_at = cache_until;
                    item.named_v3_current_verified = true;
                    retained.push(item);
                }
                Err(_) => {
                    self.decrement_source(&item.source);
                    self.size -= 1;
                }
            }
        }
        let retained_count = retained.len();
        if !retained.is_empty() {
            self.records.insert(store_key, retained);
        }
        Ok(retained_count)
    }

    /// Apply a durably committed, still-current HNSA withdrawal tombstone to
    /// the exact V3 named-service namespace.
    pub fn invalidate_named_v3_withdrawal(
        &mut self,
        identity: &NamedServiceIdentity,
        committed_service: &CurrentCommittedNamedService<'_>,
        now: u64,
    ) -> Result<usize, HnsrProtocolError> {
        ensure_current_committed_named_v3_lease(committed_service)?;
        let mut affected_route_key = None;
        let result = (|| {
            self.ensure_named_v3_time(now)?;
            validate_current_committed_named_v3_binding(
                identity,
                committed_service,
                self.network_magic,
                now,
            )?;
            affected_route_key = Some(named_route_key_v3(identity)?);
            if !committed_service.is_withdrawn() {
                return Err(HnsrProtocolError::Invalid(
                    "committed HNSA service is active",
                ));
            }
            self.invalidate_named_v3_withdrawal_uncommitted(
                identity,
                committed_service.observation(),
            )
        })();
        self.finish_current_authority_operation(committed_service, affected_route_key, result)
    }

    /// Low-level withdrawal application without proof that the observation is
    /// still current in its durably acknowledged authority aggregate.
    ///
    /// Production callers must use the current-committed authority wrapper.
    #[doc(hidden)]
    pub fn invalidate_named_v3_withdrawal_uncommitted(
        &mut self,
        identity: &NamedServiceIdentity,
        observation: &ServiceGenerationObservation,
    ) -> Result<usize, HnsrProtocolError> {
        let resource_id = identity
            .resource_id()
            .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA named-service identity"))?;
        if !observation.is_withdrawn()
            || observation.network_magic() != self.network_magic
            || observation.network_magic() != identity.network_magic
            || observation.subject() != identity.name_hash
            || observation.resource_id() != resource_id
        {
            return Err(HnsrProtocolError::Invalid(
                "HNSA withdrawal does not match named route namespace",
            ));
        }
        let store_key = RouteStoreKey {
            model: RouteRecordModel::HrmNamedV3,
            route_key: named_route_key_v3(identity)?,
        };
        Ok(self.remove_named_v3_live_routes(store_key))
    }

    fn finish_current_authority_operation<T>(
        &mut self,
        committed_service: &CurrentCommittedNamedService<'_>,
        affected_route_key: Option<[u8; 32]>,
        result: Result<T, HnsrProtocolError>,
    ) -> Result<T, HnsrProtocolError> {
        if ensure_current_committed_named_v3_lease(committed_service).is_err() {
            if let Some(route_key) = affected_route_key {
                self.remove_named_v3_live_routes(RouteStoreKey {
                    model: RouteRecordModel::HrmNamedV3,
                    route_key,
                });
            }
            return Err(current_committed_named_v3_lease_lost());
        }
        result
    }

    fn remove_named_v3_live_routes(&mut self, store_key: RouteStoreKey) -> usize {
        let Some(items) = self.records.remove(&store_key) else {
            return 0;
        };
        let removed = items.len();
        for item in items {
            self.decrement_source(&item.source);
            self.size -= 1;
        }
        removed
    }

    fn charge_verification(&mut self, source: &str, now: u64) -> Result<(), HnsrProtocolError> {
        let duration = self.limits.verification_window_seconds;
        let global = self
            .global_verification_window
            .get_or_insert(VerificationWindow {
                started_at: now,
                attempts: 0,
            });
        if now >= global.started_at.saturating_add(duration) {
            *global = VerificationWindow {
                started_at: now,
                attempts: 0,
            };
            self.verification_windows.clear();
        }
        if global.attempts >= self.limits.verification_attempts_total {
            return Err(HnsrProtocolError::VerificationRateLimited);
        }

        let source_window = self
            .verification_windows
            .entry(source.to_owned())
            .or_insert(VerificationWindow {
                started_at: now,
                attempts: 0,
            });
        if now >= source_window.started_at.saturating_add(duration) {
            *source_window = VerificationWindow {
                started_at: now,
                attempts: 0,
            };
        }
        if source_window.attempts >= self.limits.verification_attempts_per_source {
            return Err(HnsrProtocolError::VerificationRateLimited);
        }
        source_window.attempts += 1;
        global.attempts += 1;
        Ok(())
    }

    fn preflight_insert(
        &mut self,
        key: &RouteStoreKey,
        verified: &VerifiedRoute,
        now: u64,
        source: &str,
    ) -> Result<InsertDisposition, HnsrProtocolError> {
        self.prune_store_key(key, now);
        let previous = self.records.get(key).and_then(|items| {
            items
                .iter()
                .enumerate()
                .find(|(_, item)| item.endpoint_key == verified.endpoint_key)
        });
        if let Some((index, item)) = previous {
            if item.sequence >= verified.sequence {
                return Err(HnsrProtocolError::StaleSequence);
            }
            let source_count = self.source_counts.get(source).copied().unwrap_or(0);
            if source_count >= self.limits.records_per_source && item.source != source {
                return Err(HnsrProtocolError::Capacity);
            }
            return Ok(InsertDisposition::Replace(index));
        }
        let key_count = self.records.get(key).map_or(0, Vec::len);
        if key_count >= self.limits.records_per_key {
            return Err(HnsrProtocolError::Capacity);
        }
        if self.size >= self.limits.total_records {
            return Err(HnsrProtocolError::Capacity);
        }
        let source_count = self.source_counts.get(source).copied().unwrap_or(0);
        if source_count >= self.limits.records_per_source {
            return Err(HnsrProtocolError::Capacity);
        }
        Ok(InsertDisposition::New)
    }

    fn insert_verified(
        &mut self,
        key: RouteStoreKey,
        verified: VerifiedRoute,
        raw: Vec<u8>,
        source: String,
        disposition: InsertDisposition,
    ) -> Result<u64, HnsrProtocolError> {
        if source.is_empty() {
            return Err(HnsrProtocolError::Invalid("empty HNSR route source"));
        }
        if let InsertDisposition::Replace(index) = disposition {
            let matches = self.records.get(&key).is_some_and(|items| {
                items.get(index).is_some_and(|item| {
                    item.endpoint_key == verified.endpoint_key && item.sequence < verified.sequence
                })
            });
            if !matches {
                return Err(HnsrProtocolError::Invalid(
                    "HNSR route replacement state changed",
                ));
            }
            let item = self
                .records
                .get_mut(&key)
                .and_then(|items| (index < items.len()).then(|| items.remove(index)))
                .ok_or(HnsrProtocolError::Invalid(
                    "HNSR route replacement state changed",
                ))?;
            self.decrement_source(&item.source);
            self.size -= 1;
        }
        self.records.entry(key).or_default().push(StoredRoute {
            endpoint_key: verified.endpoint_key,
            sequence: verified.sequence,
            expires_at: verified.expires_at,
            sampleable: verified.sampleable,
            named_v3_current_verified: false,
            named_v3_endpoint_sequence: 0,
            named_v3_endpoint_delegation_id: [0; 32],
            source: source.clone(),
            raw,
        });
        *self.source_counts.entry(source).or_default() += 1;
        self.size += 1;
        Ok(verified.expires_at)
    }

    fn preflight_named_v3_ledger(
        &self,
        key: &NamedRouteV3LedgerKey,
        endpoint_sequence: u64,
        endpoint_delegation_id: &[u8; 32],
        route_sequence: u64,
        route_canonical_hash: &[u8; 32],
    ) -> Result<NamedV3LedgerDisposition, HnsrProtocolError> {
        let Some(entry) = self.named_v3_ledger.get(key) else {
            if self.named_v3_ledger.len() >= self.limits.total_records
                || self
                    .named_v3_ledger_route_counts
                    .get(&key.route_key)
                    .copied()
                    .unwrap_or(0)
                    >= self.limits.records_per_key
            {
                return Err(HnsrProtocolError::Capacity);
            }
            return Ok(NamedV3LedgerDisposition::new_scope());
        };
        let endpoint = match endpoint_sequence.cmp(&entry.endpoint_high_water) {
            Ordering::Less => NamedV3CounterDisposition::Stale,
            Ordering::Greater => NamedV3CounterDisposition::Advance,
            Ordering::Equal
                if entry.endpoint_conflicted
                    && *endpoint_delegation_id < entry.endpoint_delegation_id =>
            {
                NamedV3CounterDisposition::Conflict
            }
            Ordering::Equal if entry.endpoint_conflicted => {
                NamedV3CounterDisposition::AlreadyConflicted
            }
            Ordering::Equal if entry.endpoint_delegation_id != *endpoint_delegation_id => {
                NamedV3CounterDisposition::Conflict
            }
            Ordering::Equal => NamedV3CounterDisposition::Idempotent,
        };
        let route = match route_sequence.cmp(&entry.route_high_water) {
            Ordering::Less => NamedV3CounterDisposition::Stale,
            Ordering::Greater => NamedV3CounterDisposition::Advance,
            Ordering::Equal
                if entry.route_conflicted && *route_canonical_hash < entry.route_canonical_hash =>
            {
                NamedV3CounterDisposition::Conflict
            }
            Ordering::Equal if entry.route_conflicted => {
                NamedV3CounterDisposition::AlreadyConflicted
            }
            Ordering::Equal if entry.route_canonical_hash != *route_canonical_hash => {
                NamedV3CounterDisposition::Conflict
            }
            Ordering::Equal => NamedV3CounterDisposition::Idempotent,
        };
        Ok(NamedV3LedgerDisposition {
            new_scope: false,
            endpoint,
            route,
        })
    }

    fn preflight_named_v3_live(
        &mut self,
        store_key: &RouteStoreKey,
        candidate: &NamedV3VerifiedCandidate,
        raw: &[u8],
        now: u64,
        source: &str,
        ledger_disposition: NamedV3LedgerDisposition,
    ) -> Result<NamedV3LiveDisposition, HnsrProtocolError> {
        let verified = &candidate.route;
        let endpoint_sequence = candidate.endpoint_sequence;
        let endpoint_delegation_id = candidate.endpoint_delegation_id;
        self.prune_store_key(store_key, now);
        let previous = self.records.get(store_key).and_then(|items| {
            items
                .iter()
                .enumerate()
                .find(|(_, item)| item.endpoint_key == verified.endpoint_key)
        });
        if !ledger_disposition.candidate_matches_final() {
            return Ok(if ledger_disposition.counter_mutates() {
                NamedV3LiveDisposition::RemoveRejected(previous.map(|(index, _)| index))
            } else {
                // A verified stale record may extend the retention horizon
                // without invalidating unrelated live bytes that already
                // realize both durable high-waters.
                NamedV3LiveDisposition::KeepRejected
            });
        }

        let disposition = match (ledger_disposition.new_scope, previous) {
            (true, None) => NamedV3LiveDisposition::New,
            (true, Some(_)) => {
                return Err(HnsrProtocolError::Invalid(
                    "HNSR V3 live state exists without replay ledger",
                ));
            }
            (false, None) => NamedV3LiveDisposition::New,
            (false, Some((index, item)))
                if ledger_disposition.is_idempotent()
                    && item.named_v3_endpoint_sequence == endpoint_sequence
                    && item.named_v3_endpoint_delegation_id == endpoint_delegation_id
                    && item.sequence == verified.sequence
                    && item.raw == raw =>
            {
                NamedV3LiveDisposition::Idempotent(index)
            }
            (false, Some(_)) if ledger_disposition.is_idempotent() => {
                return Err(HnsrProtocolError::Invalid(
                    "HNSR V3 idempotent live state disagrees with replay ledger",
                ));
            }
            (false, Some((index, item))) => {
                let endpoint_agrees = match ledger_disposition.endpoint {
                    NamedV3CounterDisposition::Idempotent => {
                        item.named_v3_endpoint_sequence == endpoint_sequence
                            && item.named_v3_endpoint_delegation_id == endpoint_delegation_id
                    }
                    NamedV3CounterDisposition::Advance => {
                        item.named_v3_endpoint_sequence < endpoint_sequence
                    }
                    _ => false,
                };
                let route_agrees = match ledger_disposition.route {
                    NamedV3CounterDisposition::Idempotent => {
                        item.sequence == verified.sequence && item.raw == raw
                    }
                    NamedV3CounterDisposition::Advance => item.sequence < verified.sequence,
                    _ => false,
                };
                if !endpoint_agrees || !route_agrees {
                    return Err(HnsrProtocolError::Invalid(
                        "HNSR V3 live state disagrees with replay ledger",
                    ));
                }
                NamedV3LiveDisposition::Replace(index)
            }
        };
        if disposition == NamedV3LiveDisposition::New {
            let key_count = self.records.get(store_key).map_or(0, Vec::len);
            if key_count >= self.limits.records_per_key || self.size >= self.limits.total_records {
                return Err(HnsrProtocolError::Capacity);
            }
        }
        let source_count = self.source_counts.get(source).copied().unwrap_or(0);
        let replaces_same_source = previous.is_some_and(|(_, item)| item.source == source);
        if !matches!(disposition, NamedV3LiveDisposition::Idempotent(_))
            && source_count >= self.limits.records_per_source
            && !replaces_same_source
        {
            return Err(HnsrProtocolError::Capacity);
        }
        Ok(disposition)
    }

    /// Apply only deterministic structure, sequence, and capacity checks to an
    /// unverified V3 candidate. Time-based pruning is trusted local
    /// maintenance, but candidate-derived replacement or conflict state is not
    /// mutated here. The verified insertion repeats this entire matrix before
    /// committing so this check cannot authorize a stale disposition.
    fn preflight_untrusted_named_v3(
        &mut self,
        route_key: [u8; 32],
        candidate: &NamedV3VerifiedCandidate,
        raw: &[u8],
        now: u64,
        source: &str,
    ) -> Result<(), HnsrProtocolError> {
        let verified = &candidate.route;
        self.prune_named_v3_ledger(now)?;
        let store_key = RouteStoreKey {
            model: RouteRecordModel::HrmNamedV3,
            route_key,
        };
        let ledger_key = NamedRouteV3LedgerKey {
            route_key,
            endpoint_key: verified.endpoint_key,
        };
        let canonical_hash = named_v3_canonical_hash(raw);
        let ledger_disposition = self.preflight_named_v3_ledger(
            &ledger_key,
            candidate.endpoint_sequence,
            &candidate.endpoint_delegation_id,
            verified.sequence,
            &canonical_hash,
        )?;
        if !ledger_disposition.candidate_matches_final() && !ledger_disposition.counter_mutates() {
            let retained_through = self
                .named_v3_ledger
                .get(&ledger_key)
                .ok_or(HnsrProtocolError::Invalid(
                    "HNSR V3 replay ledger state changed",
                ))?
                .retain_until;
            if candidate.retain_until <= retained_through {
                return Err(ledger_disposition
                    .rejection()
                    .ok_or(HnsrProtocolError::Invalid(
                        "HNSR V3 rejected product-lattice state has no error",
                    ))?);
            } else {
                // The untrusted interval can outlive the existing horizon.
                // Complete cryptographic verification before it may renew the
                // durable counter-product protection.
            }
        }
        self.preflight_named_v3_live(&store_key, candidate, raw, now, source, ledger_disposition)?;
        Ok(())
    }

    /// Insert only after the caller has completed all V3 signature and time
    /// validation. The cheap structural preflight is repeated authoritatively
    /// here, so no malformed or incorrectly signed candidate can reach the
    /// replay-ledger mutation below.
    fn insert_verified_named_v3(
        &mut self,
        route_key: [u8; 32],
        candidate: NamedV3VerifiedCandidate,
        current_verified: bool,
        raw: Vec<u8>,
        now: u64,
        source: String,
    ) -> Result<u64, HnsrProtocolError> {
        let NamedV3VerifiedCandidate {
            route: verified,
            endpoint_sequence,
            endpoint_delegation_id,
            retain_until: _,
        } = candidate;
        self.prune_named_v3_ledger(now)?;
        let store_key = RouteStoreKey {
            model: RouteRecordModel::HrmNamedV3,
            route_key,
        };
        let ledger_key = NamedRouteV3LedgerKey {
            route_key,
            endpoint_key: verified.endpoint_key,
        };
        let canonical_hash = named_v3_canonical_hash(&raw);
        let ledger_disposition = self.preflight_named_v3_ledger(
            &ledger_key,
            endpoint_sequence,
            &endpoint_delegation_id,
            verified.sequence,
            &canonical_hash,
        )?;
        let live_disposition = self.preflight_named_v3_live(
            &store_key,
            &candidate,
            &raw,
            now,
            &source,
            ledger_disposition,
        )?;
        let previous_entry = self.named_v3_ledger.get(&ledger_key).copied();
        let next_entry = next_named_v3_ledger_entry(
            previous_entry,
            ledger_disposition,
            &candidate,
            canonical_hash,
        )?;
        let ledger_will_mutate = previous_entry != Some(next_entry);
        let next_revision = ledger_will_mutate
            .then(|| self.next_named_v3_ledger_revision())
            .transpose()?;

        let accepted_live = matches!(
            live_disposition,
            NamedV3LiveDisposition::New
                | NamedV3LiveDisposition::Replace(_)
                | NamedV3LiveDisposition::Idempotent(_)
        );
        if accepted_live != ledger_disposition.candidate_matches_final() {
            return Err(HnsrProtocolError::Invalid(
                "HNSR V3 live and replay dispositions disagree",
            ));
        }

        match live_disposition {
            NamedV3LiveDisposition::RemoveRejected(Some(index))
            | NamedV3LiveDisposition::Replace(index) => {
                let item = self
                    .records
                    .get_mut(&store_key)
                    .and_then(|items| (index < items.len()).then(|| items.remove(index)))
                    .ok_or(HnsrProtocolError::Invalid(
                        "HNSR V3 live replacement state changed",
                    ))?;
                self.decrement_source(&item.source);
                self.size -= 1;
                if self.records.get(&store_key).is_some_and(Vec::is_empty) {
                    self.records.remove(&store_key);
                }
            }
            NamedV3LiveDisposition::New
            | NamedV3LiveDisposition::RemoveRejected(None)
            | NamedV3LiveDisposition::KeepRejected
            | NamedV3LiveDisposition::Idempotent(_) => {}
        }

        let mut stored_until = verified.expires_at;
        if let NamedV3LiveDisposition::Idempotent(index) = live_disposition {
            let item = self
                .records
                .get_mut(&store_key)
                .and_then(|items| items.get_mut(index))
                .ok_or(HnsrProtocolError::Invalid(
                    "HNSR V3 idempotent live state changed",
                ))?;
            if item.endpoint_key != verified.endpoint_key
                || item.named_v3_endpoint_sequence != endpoint_sequence
                || item.named_v3_endpoint_delegation_id != endpoint_delegation_id
                || item.sequence != verified.sequence
                || item.raw != raw
            {
                return Err(HnsrProtocolError::Invalid(
                    "HNSR V3 idempotent live state changed",
                ));
            }
            if current_verified {
                item.expires_at = verified.expires_at;
                item.named_v3_current_verified = true;
            } else if !item.named_v3_current_verified {
                item.expires_at = item.expires_at.min(verified.expires_at);
            }
            stored_until = item.expires_at;
        }

        if matches!(
            live_disposition,
            NamedV3LiveDisposition::New | NamedV3LiveDisposition::Replace(_)
        ) {
            self.records
                .entry(store_key)
                .or_default()
                .push(StoredRoute {
                    endpoint_key: verified.endpoint_key,
                    sequence: verified.sequence,
                    expires_at: verified.expires_at,
                    sampleable: false,
                    named_v3_current_verified: current_verified,
                    named_v3_endpoint_sequence: endpoint_sequence,
                    named_v3_endpoint_delegation_id: endpoint_delegation_id,
                    source: source.clone(),
                    raw,
                });
            *self.source_counts.entry(source).or_default() += 1;
            self.size += 1;
        }

        if ledger_will_mutate {
            let replaced = self.named_v3_ledger.insert(ledger_key, next_entry);
            if previous_entry.is_none() {
                debug_assert!(replaced.is_none());
                *self
                    .named_v3_ledger_route_counts
                    .entry(ledger_key.route_key)
                    .or_default() += 1;
            } else {
                debug_assert!(replaced.is_some());
            }
            self.named_v3_ledger_revision = next_revision.ok_or(HnsrProtocolError::Invalid(
                "HNSR V3 replay ledger revision missing",
            ))?;
        }

        if let Some(error) = ledger_disposition.rejection() {
            return Err(error);
        }
        Ok(stored_until)
    }

    /// Look up only the original unnamed version-1 namespace.
    ///
    /// Named callers must select [`Self::get_named_v2`] or
    /// [`Self::get_named_v3`] explicitly; this API never performs a named
    /// authority-model fallback.
    pub fn get(&mut self, key: &[u8; 32], maximum: usize, now: u64) -> Vec<Vec<u8>> {
        self.get_unnamed_v1(key, maximum, now)
    }

    /// Look up one explicit route-record model without cross-model fallback.
    pub fn get_model(
        &mut self,
        model: RouteRecordModel,
        key: &[u8; 32],
        maximum: usize,
        now: u64,
    ) -> Vec<Vec<u8>> {
        let effective_now = if model == RouteRecordModel::HrmNamedV3 {
            now.max(self.named_v3_pruned_through)
        } else {
            now
        };
        let store_key = RouteStoreKey {
            model,
            route_key: *key,
        };
        self.prune_store_key(&store_key, effective_now);
        let mut items = self.records.get(&store_key).cloned().unwrap_or_default();
        items.sort_by(|left, right| right.sequence.cmp(&left.sequence));
        items
            .into_iter()
            .filter(|item| {
                model != RouteRecordModel::HrmNamedV3
                    || !self
                        .named_v3_ledger
                        .get(&NamedRouteV3LedgerKey {
                            route_key: *key,
                            endpoint_key: item.endpoint_key,
                        })
                        .is_some_and(|entry| {
                            entry.retain_until > effective_now
                                && (entry.endpoint_conflicted || entry.route_conflicted)
                        })
            })
            .take(maximum.min(MAX_RECORDS_PER_KEY))
            .map(|item| item.raw)
            .collect()
    }

    pub fn get_unnamed_v1(&mut self, key: &[u8; 32], maximum: usize, now: u64) -> Vec<Vec<u8>> {
        self.get_model(RouteRecordModel::UnnamedV1, key, maximum, now)
    }

    pub fn get_named_v2(&mut self, key: &[u8; 32], maximum: usize, now: u64) -> Vec<Vec<u8>> {
        self.get_model(RouteRecordModel::LegacyNamedV2, key, maximum, now)
    }

    pub fn get_named_v3(&mut self, key: &[u8; 32], maximum: usize, now: u64) -> Vec<Vec<u8>> {
        self.get_model(RouteRecordModel::HrmNamedV3, key, maximum, now)
    }

    /// Report whether one exact model/route/endpoint scope is fail-closed due
    /// to two valid, byte-distinct records at the same sequence.
    pub fn is_conflicted(
        &mut self,
        model: RouteRecordModel,
        key: &[u8; 32],
        endpoint_key: &[u8; 33],
        now: u64,
    ) -> bool {
        let effective_now = if model == RouteRecordModel::HrmNamedV3 {
            now.max(self.named_v3_pruned_through)
        } else {
            now
        };
        let store_key = RouteStoreKey {
            model,
            route_key: *key,
        };
        self.prune_store_key(&store_key, effective_now);
        model == RouteRecordModel::HrmNamedV3
            && self
                .named_v3_ledger
                .get(&NamedRouteV3LedgerKey {
                    route_key: *key,
                    endpoint_key: *endpoint_key,
                })
                .is_some_and(|entry| {
                    entry.retain_until > effective_now
                        && (entry.endpoint_conflicted || entry.route_conflicted)
                })
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
            let effective_now = if key.model == RouteRecordModel::HrmNamedV3 {
                now.max(self.named_v3_pruned_through)
            } else {
                now
            };
            self.prune_store_key(&key, effective_now);
        }
    }

    /// Remove admission-ledger scopes only after their bounded signed-expiry
    /// and post-observation overlap horizon has elapsed.
    pub fn prune_named_v3_ledger(&mut self, now: u64) -> Result<usize, HnsrProtocolError> {
        self.ensure_named_v3_time(now)?;
        let before = self.named_v3_ledger.len();
        let removed = self
            .named_v3_ledger
            .values()
            .filter(|entry| entry.retain_until <= now)
            .count();
        if removed == 0 {
            return Ok(0);
        }
        let revision = self.next_named_v3_ledger_revision()?;
        self.named_v3_ledger
            .retain(|_, entry| entry.retain_until > now);
        debug_assert_eq!(removed, before - self.named_v3_ledger.len());
        self.rebuild_named_v3_ledger_route_counts();
        self.named_v3_ledger_revision = revision;
        self.named_v3_pruned_through = now;
        Ok(removed)
    }

    fn ensure_named_v3_time(&self, now: u64) -> Result<(), HnsrProtocolError> {
        if now < self.named_v3_pruned_through {
            Err(HnsrProtocolError::ClockRollback)
        } else {
            Ok(())
        }
    }

    fn rebuild_named_v3_ledger_route_counts(&mut self) {
        let mut counts = HashMap::new();
        for key in self.named_v3_ledger.keys() {
            *counts.entry(key.route_key).or_default() += 1;
        }
        debug_assert!(
            counts
                .values()
                .all(|count| *count <= self.limits.records_per_key)
        );
        self.named_v3_ledger_route_counts = counts;
    }

    fn prune_store_key(&mut self, key: &RouteStoreKey, now: u64) {
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

    fn next_named_v3_ledger_revision(&self) -> Result<u64, HnsrProtocolError> {
        Self::next_named_v3_ledger_revision_from(self.named_v3_ledger_revision)
    }

    fn next_named_v3_ledger_revision_from(revision: u64) -> Result<u64, HnsrProtocolError> {
        revision
            .checked_add(1)
            .filter(|next| *next != u64::MAX)
            .ok_or(HnsrProtocolError::NamedRouteLedgerRevisionExhausted)
    }
}

fn validate_current_committed_named_v3_binding(
    identity: &NamedServiceIdentity,
    committed_service: &CurrentCommittedNamedService<'_>,
    network_magic: u32,
    now: u64,
) -> Result<(), HnsrProtocolError> {
    if committed_service.trusted_time_high_water() != now {
        return Err(HnsrProtocolError::Invalid(
            "committed HNSA authority operation-time mismatch",
        ));
    }
    let resource_id = identity
        .resource_id()
        .map_err(|_| HnsrProtocolError::Invalid("invalid HNSA named-service identity"))?;
    let observation = committed_service.observation();
    if identity.network_magic != network_magic
        || observation.network_magic() != network_magic
        || observation.subject() != identity.name_hash
        || observation.resource_id() != resource_id
        || committed_service.active().is_some_and(|service| {
            service.identity() != identity || service.generation_observation() != observation
        })
    {
        return Err(HnsrProtocolError::Invalid(
            "current committed HNSA service does not match named route namespace",
        ));
    }
    Ok(())
}

fn ensure_current_committed_named_v3_lease(
    committed_service: &CurrentCommittedNamedService<'_>,
) -> Result<(), HnsrProtocolError> {
    committed_service
        .ensure_lease_held()
        .map_err(|_| current_committed_named_v3_lease_lost())
}

const fn current_committed_named_v3_lease_lost() -> HnsrProtocolError {
    HnsrProtocolError::Invalid("committed HNSA authority lease was lost")
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
    fn configured_store_limits_cannot_exceed_protocol_ceiling() {
        let limits = RouteStoreLimits {
            total_records: MAX_STORED_RECORDS + 1,
            ..RouteStoreLimits::default()
        };
        assert!(RouteStore::new(MAGIC, true, limits).is_err());

        let limits = RouteStoreLimits {
            records_per_key: MAX_RECORDS_PER_KEY + 1,
            ..RouteStoreLimits::default()
        };
        assert!(RouteStore::new(MAGIC, true, limits).is_err());
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
                verification_attempts_total: 1_024,
                verification_attempts_per_source: 64,
                verification_window_seconds: 60,
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
                verification_attempts_total: 1_024,
                verification_attempts_per_source: 64,
                verification_window_seconds: 60,
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

    #[test]
    fn named_v3_retention_saturates_and_prunes_at_the_maximum_half_open_boundary() {
        let observation_now = u64::MAX - (MAX_ROUTE_LIFETIME - 1);
        let signed_expiry = observation_now + 1;
        let retain_until = named_v3_retention_horizon(signed_expiry, observation_now);
        assert_eq!(retain_until, u64::MAX);

        let route_key = [0xa1; 32];
        let ledger_key = NamedRouteV3LedgerKey {
            route_key,
            endpoint_key: [0x02; 33],
        };
        let mut store = RouteStore::new(MAGIC, true, RouteStoreLimits::default()).expect("store");
        store.named_v3_ledger.insert(
            ledger_key,
            NamedRouteV3LedgerEntry {
                endpoint_high_water: 1,
                endpoint_delegation_id: [0xb1; 32],
                endpoint_conflicted: false,
                route_high_water: 1,
                retain_until,
                route_conflicted: false,
                route_canonical_hash: [0xc1; 32],
            },
        );
        store.named_v3_ledger_route_counts.insert(route_key, 1);
        store.named_v3_ledger_revision = 1;

        assert_eq!(
            store
                .prune_named_v3_ledger(u64::MAX - 1)
                .expect("retain before exclusive boundary"),
            0
        );
        let retained = store
            .named_v3_ledger_snapshot(u64::MAX - 1)
            .expect("snapshot before exclusive boundary");
        assert_eq!(retained.entries[0].1.retain_until, u64::MAX);
        assert_eq!(
            store
                .prune_named_v3_ledger(u64::MAX)
                .expect("prune at exclusive boundary"),
            1
        );
        assert_eq!(store.named_v3_ledger_len(), 0);
        assert_eq!(store.named_v3_pruned_through(), u64::MAX);
        let pruned = store
            .named_v3_ledger_snapshot(u64::MAX)
            .expect("snapshot at saturated pruning floor");
        let encoded = pruned.encode();
        assert_eq!(
            NamedRouteV3LedgerSnapshot::decode(&encoded).expect("decode saturated snapshot"),
            pruned
        );
    }
}
