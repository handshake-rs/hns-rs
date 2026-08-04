//! Runtime-neutral HNSR requester and opaque circuit-relay state machines.
//!
//! The embedding product owns authenticated Handshake connections and socket
//! scheduling. This module owns the protocol state that must not be duplicated
//! by browser, mobile, or node adapters: exact ticket admission, peer binding,
//! deadlines, directional credit, queue and byte bounds, generation revocation,
//! disconnect cleanup, and fail-closed restart snapshots.

use std::collections::{HashMap, VecDeque};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use thiserror::Error;

use crate::{
    AcceptBody, CloseBody, DataBody, ErrorBody, HnsrErrorCode, HnsrOpcode, HnsrPacket,
    HnsrProtocolError, IncomingBody, MAX_CIRCUIT_QUEUE, MAX_CIRCUITS, MAX_DATA_SIZE, MAX_WINDOW,
    MIN_WINDOW, OpenBody, OpenedBody, RelayService, RelayTicket, WindowBody,
};

const SNAPSHOT_SCHEMA: u8 = 1;
const REQUESTER_SNAPSHOT_MAGIC: &[u8; 8] = b"HNSRQR1\0";
const RELAY_SNAPSHOT_MAGIC: &[u8; 8] = b"HNSRRL1\0";
const SNAPSHOT_CHECKSUM_BYTES: usize = 32;
const MAX_PEER_ID_BYTES: usize = 128;
const MAX_OPEN_DEADLINE_SECONDS: u64 = 10;
const MAX_RUNTIME_CIRCUITS: usize = 65_536;
const MAX_RUNTIME_PENDING: usize = 65_536;
const MAX_RUNTIME_INFLIGHT_ACTIONS: usize = 262_144;

/// Stable adapter-owned identity of one authenticated outer connection.
///
/// The bytes are opaque to this crate but must identify one exact live
/// connection. Adapters normally use a generation-bound connection ID rather
/// than an address, so a reconnect cannot inherit circuit authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HnsrPeerId(Vec<u8>);

impl HnsrPeerId {
    /// Validate one bounded nonempty connection identity.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, HnsrRuntimeError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_PEER_ID_BYTES {
            return Err(HnsrRuntimeError::InvalidPeer);
        }
        Ok(Self(bytes))
    }

    /// Borrow the exact adapter identity bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Generation-bound identifier for one queued relay action.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HnsrActionId {
    /// Runtime generation that admitted the action.
    pub generation: u64,
    /// Nonzero action sequence within that generation.
    pub sequence: u64,
}

/// One exact HNSR packet and authenticated outer-connection destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsrRoute {
    /// Exact live connection selected by the state machine.
    pub destination: HnsrPeerId,
    /// Strict canonical HNSR packet.
    pub packet: HnsrPacket,
}

/// A relay route retained as queued until the adapter acknowledges its write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedHnsrRoute {
    /// Generation-bound completion token.
    pub action_id: HnsrActionId,
    /// Exact packet route.
    pub route: HnsrRoute,
}

/// Requester limits and exact ticket-validation context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsrRequesterConfig {
    /// Handshake network magic required in every relay ticket.
    pub network_magic: u32,
    /// Exact enabled HNSR service profile.
    pub profile: u16,
    /// Whether private relay addresses are admitted on a controlled network.
    pub allow_private_relay: bool,
    /// Maximum pending plus active requester circuits.
    pub maximum_circuits: u16,
    /// Maximum buffered inbound opaque bytes per circuit.
    pub maximum_queue_bytes: usize,
    /// Local ceiling below the signed ticket byte ceiling.
    pub maximum_bytes_per_circuit: u64,
}

impl HnsrRequesterConfig {
    fn validate(self) -> Result<Self, HnsrRuntimeError> {
        if self.profile == 0
            || self.maximum_circuits == 0
            || self.maximum_circuits > MAX_CIRCUITS
            || self.maximum_queue_bytes == 0
            || self.maximum_queue_bytes > MAX_CIRCUIT_QUEUE
            || self.maximum_bytes_per_circuit == 0
        {
            return Err(HnsrRuntimeError::InvalidConfig);
        }
        Ok(self)
    }
}

/// Opaque relay circuit and scheduler bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpaqueRelayConfig {
    /// Maximum circuit opens awaiting endpoint acceptance.
    pub maximum_pending: usize,
    /// Maximum established circuits.
    pub maximum_circuits: usize,
    /// Maximum pending plus established circuits involving one outer peer.
    pub maximum_circuits_per_peer: u16,
    /// Maximum unacknowledged DATA bytes per direction per circuit.
    pub maximum_queue_bytes: usize,
    /// Maximum unacknowledged routes across the runtime.
    pub maximum_inflight_actions: usize,
    /// Maximum unacknowledged routes for one circuit or pending open.
    pub maximum_inflight_actions_per_circuit: usize,
    /// Maximum unacknowledged routes destined for one outer peer.
    pub maximum_inflight_actions_per_peer: usize,
    /// Local ceiling below each signed ticket byte ceiling.
    pub maximum_bytes_per_circuit: u64,
    /// Endpoint acceptance deadline, at most ten seconds.
    pub accept_timeout_seconds: u64,
}

impl Default for OpaqueRelayConfig {
    fn default() -> Self {
        Self {
            maximum_pending: 1_024,
            maximum_circuits: 4_096,
            maximum_circuits_per_peer: MAX_CIRCUITS,
            maximum_queue_bytes: MAX_CIRCUIT_QUEUE,
            maximum_inflight_actions: 65_536,
            maximum_inflight_actions_per_circuit: 128,
            maximum_inflight_actions_per_peer: 4_096,
            maximum_bytes_per_circuit: 16 * 1024 * 1024,
            accept_timeout_seconds: MAX_OPEN_DEADLINE_SECONDS,
        }
    }
}

impl OpaqueRelayConfig {
    fn validate(self) -> Result<Self, HnsrRuntimeError> {
        if self.maximum_pending == 0
            || self.maximum_pending > MAX_RUNTIME_PENDING
            || self.maximum_circuits == 0
            || self.maximum_circuits > MAX_RUNTIME_CIRCUITS
            || self.maximum_circuits_per_peer == 0
            || self.maximum_circuits_per_peer > MAX_CIRCUITS
            || self.maximum_queue_bytes == 0
            || self.maximum_queue_bytes > MAX_CIRCUIT_QUEUE
            || self.maximum_inflight_actions == 0
            || self.maximum_inflight_actions > MAX_RUNTIME_INFLIGHT_ACTIONS
            || self.maximum_inflight_actions_per_circuit < 2
            || self.maximum_inflight_actions_per_circuit > self.maximum_inflight_actions
            || self.maximum_inflight_actions_per_peer < self.maximum_inflight_actions_per_circuit
            || self.maximum_inflight_actions_per_peer > self.maximum_inflight_actions
            || self.maximum_bytes_per_circuit == 0
            || self.accept_timeout_seconds == 0
            || self.accept_timeout_seconds > MAX_OPEN_DEADLINE_SECONDS
        {
            return Err(HnsrRuntimeError::InvalidConfig);
        }
        Ok(self)
    }
}

/// Name-free runtime status shared by requester and relay adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsrRuntimeStatus {
    /// Current nonzero policy/runtime generation.
    pub generation: u64,
    /// Whether new work is admitted.
    pub enabled: bool,
    /// Pending circuit negotiations.
    pub pending_circuits: usize,
    /// Established circuits.
    pub active_circuits: usize,
    /// Buffered or unacknowledged opaque bytes.
    pub queued_bytes: usize,
    /// Unacknowledged routed actions retained by the opaque relay.
    pub queued_actions: usize,
    /// Greatest trusted Unix time admitted by this runtime.
    pub trusted_time_high_water: u64,
    /// Cumulative admitted circuit opens.
    pub admitted_opens: u64,
    /// Cumulative established circuits.
    pub opened_circuits: u64,
    /// Cumulative opaque bytes sent or forwarded.
    pub bytes_sent: u64,
    /// Cumulative opaque bytes received or forwarded.
    pub bytes_received: u64,
    /// Cumulative work revoked by policy, disconnect, expiry, or restart.
    pub revoked_work: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RuntimeCounters {
    admitted_opens: u64,
    opened_circuits: u64,
    bytes_sent: u64,
    bytes_received: u64,
    revoked_work: u64,
}

/// Durable requester snapshot.
///
/// Live connection identities and circuit contents are deliberately absent.
/// Restore advances the generation and accounts every snapshotted live item as
/// revoked, so a process restart can never resurrect outer-connection state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsrRequesterSnapshot {
    session: [u8; 16],
    generation: u64,
    enabled: bool,
    trusted_time_high_water: u64,
    config: HnsrRequesterConfig,
    counters: RuntimeCounters,
    live_pending: u32,
    live_circuits: u32,
}

/// Durable opaque-relay snapshot with fail-closed live-state recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpaqueRelaySnapshot {
    session: [u8; 16],
    generation: u64,
    enabled: bool,
    trusted_time_high_water: u64,
    config: OpaqueRelayConfig,
    counters: RuntimeCounters,
    live_pending: u32,
    live_circuits: u32,
    live_actions: u32,
    queued_bytes: u64,
}

impl HnsrRequesterSnapshot {
    /// Encode an exact, versioned snapshot with a BLAKE2b-256 checksum.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(160);
        bytes.extend_from_slice(REQUESTER_SNAPSHOT_MAGIC);
        bytes.push(SNAPSHOT_SCHEMA);
        bytes.extend_from_slice(&[0; 3]);
        encode_snapshot_header(
            &mut bytes,
            self.session,
            self.generation,
            self.enabled,
        );
        bytes.extend_from_slice(&self.trusted_time_high_water.to_le_bytes());
        bytes.extend_from_slice(&self.config.network_magic.to_le_bytes());
        bytes.extend_from_slice(&self.config.profile.to_le_bytes());
        bytes.push(u8::from(self.config.allow_private_relay));
        bytes.extend_from_slice(&self.config.maximum_circuits.to_le_bytes());
        push_usize(&mut bytes, self.config.maximum_queue_bytes);
        bytes.extend_from_slice(&self.config.maximum_bytes_per_circuit.to_le_bytes());
        encode_counters(&mut bytes, self.counters);
        bytes.extend_from_slice(&self.live_pending.to_le_bytes());
        bytes.extend_from_slice(&self.live_circuits.to_le_bytes());
        append_snapshot_checksum(&mut bytes);
        bytes
    }

    /// Decode an exact requester snapshot and reject corruption or extensions.
    pub fn decode(input: &[u8]) -> Result<Self, HnsrRuntimeError> {
        let payload = verified_snapshot_payload(input, REQUESTER_SNAPSHOT_MAGIC)?;
        let mut reader = SnapshotReader::new(payload);
        reader.skip(12)?;
        let (session, generation, enabled) = decode_snapshot_header(&mut reader)?;
        let trusted_time_high_water = reader.u64()?;
        let config = HnsrRequesterConfig {
            network_magic: reader.u32()?,
            profile: reader.u16()?,
            allow_private_relay: reader.boolean()?,
            maximum_circuits: reader.u16()?,
            maximum_queue_bytes: reader.usize()?,
            maximum_bytes_per_circuit: reader.u64()?,
        }
        .validate()?;
        let counters = decode_counters(&mut reader)?;
        let snapshot = Self {
            session,
            generation,
            enabled,
            trusted_time_high_water,
            config,
            counters,
            live_pending: reader.u32()?,
            live_circuits: reader.u32()?,
        };
        reader.finish()?;
        validate_session(snapshot.session, snapshot.generation)?;
        Ok(snapshot)
    }
}

impl OpaqueRelaySnapshot {
    /// Encode an exact, versioned snapshot with a BLAKE2b-256 checksum.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(RELAY_SNAPSHOT_MAGIC);
        bytes.push(SNAPSHOT_SCHEMA);
        bytes.extend_from_slice(&[0; 3]);
        encode_snapshot_header(
            &mut bytes,
            self.session,
            self.generation,
            self.enabled,
        );
        bytes.extend_from_slice(&self.trusted_time_high_water.to_le_bytes());
        push_usize(&mut bytes, self.config.maximum_pending);
        push_usize(&mut bytes, self.config.maximum_circuits);
        bytes.extend_from_slice(&self.config.maximum_circuits_per_peer.to_le_bytes());
        push_usize(&mut bytes, self.config.maximum_queue_bytes);
        push_usize(&mut bytes, self.config.maximum_inflight_actions);
        push_usize(
            &mut bytes,
            self.config.maximum_inflight_actions_per_circuit,
        );
        push_usize(
            &mut bytes,
            self.config.maximum_inflight_actions_per_peer,
        );
        bytes.extend_from_slice(&self.config.maximum_bytes_per_circuit.to_le_bytes());
        bytes.extend_from_slice(&self.config.accept_timeout_seconds.to_le_bytes());
        encode_counters(&mut bytes, self.counters);
        bytes.extend_from_slice(&self.live_pending.to_le_bytes());
        bytes.extend_from_slice(&self.live_circuits.to_le_bytes());
        bytes.extend_from_slice(&self.live_actions.to_le_bytes());
        bytes.extend_from_slice(&self.queued_bytes.to_le_bytes());
        append_snapshot_checksum(&mut bytes);
        bytes
    }

    /// Decode an exact opaque-relay snapshot and reject corruption or extensions.
    pub fn decode(input: &[u8]) -> Result<Self, HnsrRuntimeError> {
        let payload = verified_snapshot_payload(input, RELAY_SNAPSHOT_MAGIC)?;
        let mut reader = SnapshotReader::new(payload);
        reader.skip(12)?;
        let (session, generation, enabled) = decode_snapshot_header(&mut reader)?;
        let trusted_time_high_water = reader.u64()?;
        let config = OpaqueRelayConfig {
            maximum_pending: reader.usize()?,
            maximum_circuits: reader.usize()?,
            maximum_circuits_per_peer: reader.u16()?,
            maximum_queue_bytes: reader.usize()?,
            maximum_inflight_actions: reader.usize()?,
            maximum_inflight_actions_per_circuit: reader.usize()?,
            maximum_inflight_actions_per_peer: reader.usize()?,
            maximum_bytes_per_circuit: reader.u64()?,
            accept_timeout_seconds: reader.u64()?,
        }
        .validate()?;
        let counters = decode_counters(&mut reader)?;
        let snapshot = Self {
            session,
            generation,
            enabled,
            trusted_time_high_water,
            config,
            counters,
            live_pending: reader.u32()?,
            live_circuits: reader.u32()?,
            live_actions: reader.u32()?,
            queued_bytes: reader.u64()?,
        };
        reader.finish()?;
        validate_session(snapshot.session, snapshot.generation)?;
        Ok(snapshot)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequesterPending {
    relay: HnsrPeerId,
    ticket: RelayTicket,
    initial_window: u32,
    deadline: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequesterCircuit {
    relay: HnsrPeerId,
    ticket: RelayTicket,
    send_credit: u32,
    receive_credit: u32,
    total_bytes: u64,
    queued_bytes: usize,
    inbound: VecDeque<Vec<u8>>,
}

/// Requester event emitted after one admitted inbound packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HnsrRequesterEvent {
    /// Circuit establishment completed.
    Opened {
        /// Relay-generated circuit ID.
        circuit_id: [u8; 8],
        /// Endpoint nonce used by the inner profile handshake.
        endpoint_nonce: [u8; 16],
    },
    /// At least one bounded opaque frame is buffered.
    DataAvailable {
        /// Established circuit.
        circuit_id: [u8; 8],
        /// Total buffered bytes after this frame.
        queued_bytes: usize,
    },
    /// Remote circuit closure or error.
    Closed {
        /// Circuit ID, or the open request ID if establishment failed.
        context_id: [u8; 8],
        /// Defined or future-generic diagnostic reason.
        reason: u16,
    },
}

/// Bounded HNSR circuit requester.
#[derive(Debug)]
pub struct HnsrRequester {
    session: [u8; 16],
    generation: u64,
    enabled: bool,
    trusted_time_high_water: u64,
    config: HnsrRequesterConfig,
    pending: HashMap<[u8; 8], RequesterPending>,
    circuits: HashMap<[u8; 8], RequesterCircuit>,
    ticket_usage: HashMap<[u8; 16], ReservationUsage>,
    counters: RuntimeCounters,
}

impl HnsrRequester {
    /// Create a fresh requester for one process session and policy generation.
    pub fn new(
        session: [u8; 16],
        generation: u64,
        config: HnsrRequesterConfig,
        trusted_now: u64,
    ) -> Result<Self, HnsrRuntimeError> {
        validate_session(session, generation)?;
        Ok(Self {
            session,
            generation,
            enabled: true,
            trusted_time_high_water: trusted_now,
            config: config.validate()?,
            pending: HashMap::new(),
            circuits: HashMap::new(),
            ticket_usage: HashMap::new(),
            counters: RuntimeCounters::default(),
        })
    }

    /// Restore policy and counters under a mandatory fresh session, generation
    /// floor, and nondecreasing trusted time. Callers must durably advance the
    /// floor whenever policy or configuration changes. Every formerly live
    /// item is revoked and no circuit is restored.
    pub fn restore(
        snapshot: HnsrRequesterSnapshot,
        fresh_session: [u8; 16],
        minimum_generation: u64,
        trusted_now: u64,
    ) -> Result<Self, HnsrRuntimeError> {
        validate_restore_guard(
            snapshot.generation,
            snapshot.trusted_time_high_water,
            minimum_generation,
            trusted_now,
        )?;
        validate_fresh_session(snapshot.session, fresh_session)?;
        let generation = snapshot
            .generation
            .checked_add(1)
            .ok_or(HnsrRuntimeError::GenerationExhausted)?;
        let mut counters = snapshot.counters;
        counters.revoked_work = counters.revoked_work.saturating_add(u64::from(
            snapshot.live_pending.saturating_add(snapshot.live_circuits),
        ));
        Ok(Self {
            session: fresh_session,
            generation,
            enabled: snapshot.enabled,
            trusted_time_high_water: trusted_now,
            config: snapshot.config.validate()?,
            pending: HashMap::new(),
            circuits: HashMap::new(),
            ticket_usage: HashMap::new(),
            counters,
        })
    }

    /// Current name-free status.
    pub fn status(&self) -> HnsrRuntimeStatus {
        HnsrRuntimeStatus {
            generation: self.generation,
            enabled: self.enabled,
            pending_circuits: self.pending.len(),
            active_circuits: self.circuits.len(),
            queued_bytes: self.circuits.values().map(|circuit| circuit.queued_bytes).sum(),
            queued_actions: 0,
            trusted_time_high_water: self.trusted_time_high_water,
            admitted_opens: self.counters.admitted_opens,
            opened_circuits: self.counters.opened_circuits,
            bytes_sent: self.counters.bytes_sent,
            bytes_received: self.counters.bytes_received,
            revoked_work: self.counters.revoked_work,
        }
    }

    /// Capture a checksummable durable snapshot.
    pub fn snapshot(&self) -> HnsrRequesterSnapshot {
        HnsrRequesterSnapshot {
            session: self.session,
            generation: self.generation,
            enabled: self.enabled,
            trusted_time_high_water: self.trusted_time_high_water,
            config: self.config,
            counters: self.counters,
            live_pending: u32::try_from(self.pending.len()).unwrap_or(u32::MAX),
            live_circuits: u32::try_from(self.circuits.len()).unwrap_or(u32::MAX),
        }
    }

    /// Advance the persisted trusted-time high-water mark.
    /// Equal time is accepted; rollback is rejected without changing state.
    pub fn observe_time(&mut self, trusted_now: u64) -> Result<(), HnsrRuntimeError> {
        if trusted_now < self.trusted_time_high_water {
            return Err(HnsrRuntimeError::ClockRollback);
        }
        self.trusted_time_high_water = trusted_now;
        Ok(())
    }

    /// Replace requester enablement with optimistic generation matching.
    /// Disabling returns best-effort CLOSE routes and immediately drops all
    /// local authority regardless of whether those routes are delivered.
    pub fn replace_enabled(
        &mut self,
        expected_generation: u64,
        enabled: bool,
    ) -> Result<Vec<HnsrRoute>, HnsrRuntimeError> {
        if expected_generation != self.generation {
            return Err(HnsrRuntimeError::StaleGeneration);
        }
        if self.enabled == enabled {
            return Ok(Vec::new());
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(HnsrRuntimeError::GenerationExhausted)?;
        self.enabled = enabled;
        if enabled {
            return Ok(Vec::new());
        }
        Ok(self.revoke_all(HnsrErrorCode::Shutdown as u16, "requester disabled"))
    }

    /// Begin one exact ticket-bound circuit open.
    #[allow(
        clippy::too_many_arguments,
        reason = "authenticated relay identity, ticket, clock, deadline, and credit are independent trust inputs"
    )]
    pub fn begin_open(
        &mut self,
        relay: HnsrPeerId,
        authenticated_relay_key: [u8; 33],
        ticket: RelayTicket,
        now: u64,
        deadline: u64,
        initial_window: u32,
    ) -> Result<HnsrRoute, HnsrRuntimeError> {
        self.observe_time(now)?;
        self.ensure_enabled()?;
        if self.pending.len().saturating_add(self.circuits.len())
            >= usize::from(self.config.maximum_circuits)
        {
            return Err(HnsrRuntimeError::Capacity);
        }
        validate_deadline(now, deadline)?;
        if !(MIN_WINDOW..=MAX_WINDOW).contains(&initial_window)
            || ticket.network_magic != self.config.network_magic
            || ticket.profile != self.config.profile
            || ticket.relay_key != authenticated_relay_key
            || ticket.expires_at <= deadline
        {
            return Err(HnsrRuntimeError::InvalidAdmission);
        }
        ticket.verify_for_profile(
            self.config.network_magic,
            self.config.profile,
            now,
            self.config.allow_private_relay,
        )?;
        self.ticket_usage
            .retain(|_, usage| usage.expires_at > now);
        let usage = self
            .ticket_usage
            .entry(ticket.reservation_id)
            .or_insert(ReservationUsage {
                bytes: 0,
                expires_at: ticket.expires_at,
            });
        if usage.expires_at != ticket.expires_at || usage.bytes >= ticket.max_total_bytes {
            return Err(HnsrRuntimeError::ByteLimit);
        }
        let context_id = random_unique_id(&self.pending, &self.circuits)?;
        let requester_nonce = random_nonzero()?;
        let packet = HnsrPacket::new(
            HnsrOpcode::Open,
            context_id,
            OpenBody {
                ticket_id: ticket.id()?,
                reservation_id: ticket.reservation_id,
                endpoint_key: ticket.endpoint_key,
                profile: ticket.profile,
                requester_nonce,
                initial_window,
            }
            .encode()?,
        )?;
        self.pending.insert(
            context_id,
            RequesterPending {
                relay: relay.clone(),
                ticket,
                initial_window,
                deadline,
            },
        );
        self.counters.admitted_opens = self.counters.admitted_opens.saturating_add(1);
        Ok(HnsrRoute {
            destination: relay,
            packet,
        })
    }

    /// Admit one relay packet for pending or established requester state.
    pub fn handle(
        &mut self,
        source: &HnsrPeerId,
        packet: &HnsrPacket,
        now: u64,
    ) -> Result<Option<HnsrRequesterEvent>, HnsrRuntimeError> {
        self.observe_time(now)?;
        self.ensure_enabled()?;
        match packet.opcode {
            HnsrOpcode::Opened => self.handle_opened(source, packet, now).map(Some),
            HnsrOpcode::Data => self.handle_data(source, packet).map(Some),
            HnsrOpcode::Window => {
                self.handle_window(source, packet)?;
                Ok(None)
            }
            HnsrOpcode::Close => self.handle_close(source, packet).map(Some),
            HnsrOpcode::Error => self.handle_error(source, packet).map(Some),
            _ => Err(HnsrRuntimeError::UnexpectedOpcode),
        }
    }

    /// Send one bounded opaque DATA frame under directional credit.
    pub fn send_data(
        &mut self,
        circuit_id: [u8; 8],
        bytes: Vec<u8>,
    ) -> Result<HnsrRoute, HnsrRuntimeError> {
        self.ensure_enabled()?;
        let circuit = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(HnsrRuntimeError::UnknownCircuit)?;
        let length = u32::try_from(bytes.len()).map_err(|_| HnsrRuntimeError::ByteLimit)?;
        let maximum = circuit
            .ticket
            .max_bytes_per_circuit
            .min(self.config.maximum_bytes_per_circuit);
        let amount = u64::from(length);
        let usage = self
            .ticket_usage
            .get(&circuit.ticket.reservation_id)
            .ok_or(HnsrRuntimeError::InvalidAdmission)?;
        if bytes.is_empty()
            || bytes.len() > MAX_DATA_SIZE
            || circuit.total_bytes.saturating_add(amount) > maximum
            || usage.bytes.saturating_add(amount) > circuit.ticket.max_total_bytes
        {
            return Err(HnsrRuntimeError::ByteLimit);
        }
        if length > circuit.send_credit {
            return Err(HnsrRuntimeError::FlowControl);
        }
        let next_usage = usage.bytes.saturating_add(amount);
        let packet = HnsrPacket::new(
            HnsrOpcode::Data,
            circuit_id,
            DataBody { bytes }.encode()?,
        )?;
        circuit.send_credit -= length;
        circuit.total_bytes = circuit.total_bytes.saturating_add(amount);
        let reservation_id = circuit.ticket.reservation_id;
        self.ticket_usage
            .get_mut(&reservation_id)
            .ok_or(HnsrRuntimeError::InvalidAdmission)?
            .bytes = next_usage;
        self.counters.bytes_sent = self.counters.bytes_sent.saturating_add(amount);
        Ok(HnsrRoute {
            destination: circuit.relay.clone(),
            packet,
        })
    }

    /// Consume one buffered DATA frame and replenish exactly that credit.
    pub fn take_data(
        &mut self,
        circuit_id: [u8; 8],
    ) -> Result<(Vec<u8>, HnsrRoute), HnsrRuntimeError> {
        self.ensure_enabled()?;
        let circuit = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(HnsrRuntimeError::UnknownCircuit)?;
        let bytes = circuit
            .inbound
            .pop_front()
            .ok_or(HnsrRuntimeError::NoQueuedData)?;
        circuit.queued_bytes = circuit.queued_bytes.saturating_sub(bytes.len());
        let credit_delta = u32::try_from(bytes.len()).map_err(|_| HnsrRuntimeError::ByteLimit)?;
        circuit.receive_credit = circuit
            .receive_credit
            .checked_add(credit_delta)
            .filter(|credit| *credit <= MAX_WINDOW)
            .ok_or(HnsrRuntimeError::FlowControl)?;
        let packet = HnsrPacket::new(
            HnsrOpcode::Window,
            circuit_id,
            WindowBody { credit_delta }.encode()?,
        )?;
        Ok((
            bytes,
            HnsrRoute {
                destination: circuit.relay.clone(),
                packet,
            },
        ))
    }

    /// Close one circuit locally before returning a best-effort route.
    pub fn close(
        &mut self,
        circuit_id: [u8; 8],
        reason: u16,
        detail: &str,
    ) -> Result<HnsrRoute, HnsrRuntimeError> {
        let circuit = self
            .circuits
            .remove(&circuit_id)
            .ok_or(HnsrRuntimeError::UnknownCircuit)?;
        let packet = close_packet(circuit_id, reason, detail)?;
        self.counters.revoked_work = self.counters.revoked_work.saturating_add(1);
        Ok(HnsrRoute {
            destination: circuit.relay,
            packet,
        })
    }

    /// Cancel one pending open using its original requester context.
    pub fn cancel_open(
        &mut self,
        context_id: [u8; 8],
        reason: u16,
        detail: &str,
    ) -> Result<HnsrRoute, HnsrRuntimeError> {
        let pending = self
            .pending
            .remove(&context_id)
            .ok_or(HnsrRuntimeError::UnknownRequest)?;
        let packet = close_packet(context_id, reason, detail)?;
        self.counters.revoked_work = self.counters.revoked_work.saturating_add(1);
        Ok(HnsrRoute {
            destination: pending.relay,
            packet,
        })
    }

    /// Revoke every circuit associated with one disconnected relay.
    pub fn disconnect(&mut self, relay: &HnsrPeerId) -> usize {
        let pending = self
            .pending
            .iter()
            .filter_map(|(context, state)| (state.relay == *relay).then_some(*context))
            .collect::<Vec<_>>();
        let circuits = self
            .circuits
            .iter()
            .filter_map(|(context, state)| (state.relay == *relay).then_some(*context))
            .collect::<Vec<_>>();
        for context in &pending {
            self.pending.remove(context);
        }
        for context in &circuits {
            self.circuits.remove(context);
        }
        let revoked = pending.len().saturating_add(circuits.len());
        self.counters.revoked_work = self
            .counters
            .revoked_work
            .saturating_add(u64::try_from(revoked).unwrap_or(u64::MAX));
        revoked
    }

    /// Expire open deadlines and ticket lifetimes.
    pub fn expire(&mut self, now: u64) -> Result<usize, HnsrRuntimeError> {
        self.observe_time(now)?;
        self.ticket_usage
            .retain(|_, usage| usage.expires_at > now);
        let pending = self
            .pending
            .iter()
            .filter_map(|(context, state)| {
                (state.deadline <= now || state.ticket.expires_at <= now).then_some(*context)
            })
            .collect::<Vec<_>>();
        let circuits = self
            .circuits
            .iter()
            .filter_map(|(context, state)| (state.ticket.expires_at <= now).then_some(*context))
            .collect::<Vec<_>>();
        for context in &pending {
            self.pending.remove(context);
        }
        for context in &circuits {
            self.circuits.remove(context);
        }
        let revoked = pending.len().saturating_add(circuits.len());
        self.counters.revoked_work = self
            .counters
            .revoked_work
            .saturating_add(u64::try_from(revoked).unwrap_or(u64::MAX));
        Ok(revoked)
    }

    fn handle_opened(
        &mut self,
        source: &HnsrPeerId,
        packet: &HnsrPacket,
        now: u64,
    ) -> Result<HnsrRequesterEvent, HnsrRuntimeError> {
        let pending = self
            .pending
            .get(&packet.context_id)
            .ok_or(HnsrRuntimeError::UnknownRequest)?;
        if pending.relay != *source {
            return Err(HnsrRuntimeError::WrongPeer);
        }
        if pending.deadline <= now || pending.ticket.expires_at <= now {
            return Err(HnsrRuntimeError::InvalidAdmission);
        }
        let opened = OpenedBody::decode(&packet.body)?;
        if opened.accepted_window > pending.initial_window
            || self.circuits.contains_key(&opened.circuit_id)
        {
            return Err(HnsrRuntimeError::InvalidAdmission);
        }
        let pending = self
            .pending
            .remove(&packet.context_id)
            .ok_or(HnsrRuntimeError::UnknownRequest)?;
        self.circuits.insert(
            opened.circuit_id,
            RequesterCircuit {
                relay: pending.relay,
                ticket: pending.ticket,
                send_credit: opened.accepted_window,
                receive_credit: opened.accepted_window,
                total_bytes: 0,
                queued_bytes: 0,
                inbound: VecDeque::new(),
            },
        );
        self.counters.opened_circuits = self.counters.opened_circuits.saturating_add(1);
        Ok(HnsrRequesterEvent::Opened {
            circuit_id: opened.circuit_id,
            endpoint_nonce: opened.endpoint_nonce,
        })
    }

    fn handle_data(
        &mut self,
        source: &HnsrPeerId,
        packet: &HnsrPacket,
    ) -> Result<HnsrRequesterEvent, HnsrRuntimeError> {
        let circuit = self
            .circuits
            .get_mut(&packet.context_id)
            .ok_or(HnsrRuntimeError::UnknownCircuit)?;
        if circuit.relay != *source {
            return Err(HnsrRuntimeError::WrongPeer);
        }
        let data = DataBody::decode(&packet.body)?;
        let length = u32::try_from(data.bytes.len()).map_err(|_| HnsrRuntimeError::ByteLimit)?;
        let maximum = circuit
            .ticket
            .max_bytes_per_circuit
            .min(self.config.maximum_bytes_per_circuit);
        let amount = u64::from(length);
        let usage = self
            .ticket_usage
            .get(&circuit.ticket.reservation_id)
            .ok_or(HnsrRuntimeError::InvalidAdmission)?;
        if circuit.total_bytes.saturating_add(amount) > maximum
            || usage.bytes.saturating_add(amount) > circuit.ticket.max_total_bytes
        {
            return Err(HnsrRuntimeError::ByteLimit);
        }
        if length > circuit.receive_credit
            || circuit.queued_bytes.saturating_add(data.bytes.len())
                > self.config.maximum_queue_bytes
        {
            return Err(HnsrRuntimeError::FlowControl);
        }
        let next_usage = usage.bytes.saturating_add(amount);
        circuit.receive_credit -= length;
        circuit.total_bytes = circuit.total_bytes.saturating_add(amount);
        circuit.queued_bytes = circuit.queued_bytes.saturating_add(data.bytes.len());
        circuit.inbound.push_back(data.bytes);
        let reservation_id = circuit.ticket.reservation_id;
        self.ticket_usage
            .get_mut(&reservation_id)
            .ok_or(HnsrRuntimeError::InvalidAdmission)?
            .bytes = next_usage;
        self.counters.bytes_received = self
            .counters
            .bytes_received
            .saturating_add(u64::from(length));
        Ok(HnsrRequesterEvent::DataAvailable {
            circuit_id: packet.context_id,
            queued_bytes: circuit.queued_bytes,
        })
    }

    fn handle_window(
        &mut self,
        source: &HnsrPeerId,
        packet: &HnsrPacket,
    ) -> Result<(), HnsrRuntimeError> {
        let circuit = self
            .circuits
            .get_mut(&packet.context_id)
            .ok_or(HnsrRuntimeError::UnknownCircuit)?;
        if circuit.relay != *source {
            return Err(HnsrRuntimeError::WrongPeer);
        }
        let window = WindowBody::decode(&packet.body)?;
        circuit.send_credit = circuit
            .send_credit
            .checked_add(window.credit_delta)
            .filter(|credit| *credit <= MAX_WINDOW)
            .ok_or(HnsrRuntimeError::FlowControl)?;
        Ok(())
    }

    fn handle_close(
        &mut self,
        source: &HnsrPeerId,
        packet: &HnsrPacket,
    ) -> Result<HnsrRequesterEvent, HnsrRuntimeError> {
        let close = CloseBody::decode(&packet.body)?;
        if let Some(pending) = self.pending.get(&packet.context_id) {
            if pending.relay != *source {
                return Err(HnsrRuntimeError::WrongPeer);
            }
            self.pending.remove(&packet.context_id);
        } else {
            let circuit = self
                .circuits
                .get(&packet.context_id)
                .ok_or(HnsrRuntimeError::UnknownCircuit)?;
            if circuit.relay != *source {
                return Err(HnsrRuntimeError::WrongPeer);
            }
            self.circuits.remove(&packet.context_id);
        }
        self.counters.revoked_work = self.counters.revoked_work.saturating_add(1);
        Ok(HnsrRequesterEvent::Closed {
            context_id: packet.context_id,
            reason: close.reason,
        })
    }

    fn handle_error(
        &mut self,
        source: &HnsrPeerId,
        packet: &HnsrPacket,
    ) -> Result<HnsrRequesterEvent, HnsrRuntimeError> {
        let error = ErrorBody::decode(&packet.body)?;
        if let Some(pending) = self.pending.get(&packet.context_id) {
            if pending.relay != *source {
                return Err(HnsrRuntimeError::WrongPeer);
            }
            self.pending.remove(&packet.context_id);
        } else if let Some(circuit) = self.circuits.get(&packet.context_id) {
            if circuit.relay != *source {
                return Err(HnsrRuntimeError::WrongPeer);
            }
            self.circuits.remove(&packet.context_id);
        } else {
            return Err(HnsrRuntimeError::UnknownRequest);
        }
        self.counters.revoked_work = self.counters.revoked_work.saturating_add(1);
        Ok(HnsrRequesterEvent::Closed {
            context_id: packet.context_id,
            reason: error.reason,
        })
    }

    fn revoke_all(&mut self, reason: u16, detail: &str) -> Vec<HnsrRoute> {
        let pending = self
            .pending
            .drain()
            .filter_map(|(context_id, state)| {
                close_packet(context_id, reason, detail)
                    .ok()
                    .map(|packet| HnsrRoute {
                        destination: state.relay,
                        packet,
                    })
            })
            .collect::<Vec<_>>();
        let circuits = self
            .circuits
            .drain()
            .filter_map(|(circuit_id, circuit)| {
                close_packet(circuit_id, reason, detail)
                    .ok()
                    .map(|packet| HnsrRoute {
                        destination: circuit.relay,
                        packet,
                    })
            })
            .collect::<Vec<_>>();
        let revoked = pending.len().saturating_add(circuits.len());
        self.counters.revoked_work = self
            .counters
            .revoked_work
            .saturating_add(u64::try_from(revoked).unwrap_or(u64::MAX));
        let mut routes = pending;
        routes.extend(circuits);
        routes
    }

    fn ensure_enabled(&self) -> Result<(), HnsrRuntimeError> {
        if self.enabled {
            Ok(())
        } else {
            Err(HnsrRuntimeError::Disabled)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelaySide {
    Requester,
    Endpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RelayPending {
    requester: HnsrPeerId,
    endpoint: HnsrPeerId,
    requester_context: [u8; 8],
    ticket: RelayTicket,
    initial_window: u32,
    deadline: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RelayCircuit {
    requester: HnsrPeerId,
    endpoint: HnsrPeerId,
    reservation_id: [u8; 16],
    expires_at: u64,
    maximum_bytes: u64,
    maximum_total_bytes: u64,
    requester_credit: u32,
    endpoint_credit: u32,
    forwarded_bytes: u64,
    queued_to_requester: usize,
    queued_to_endpoint: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReservationUsage {
    bytes: u64,
    expires_at: u64,
}

impl RelayCircuit {
    fn side(&self, source: &HnsrPeerId) -> Result<RelaySide, HnsrRuntimeError> {
        if self.requester == *source {
            Ok(RelaySide::Requester)
        } else if self.endpoint == *source {
            Ok(RelaySide::Endpoint)
        } else {
            Err(HnsrRuntimeError::WrongPeer)
        }
    }

    fn destination(&self, side: RelaySide) -> HnsrPeerId {
        match side {
            RelaySide::Requester => self.endpoint.clone(),
            RelaySide::Endpoint => self.requester.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InflightKind {
    Incoming,
    Opened,
    Data { destination: RelaySide, bytes: usize },
    Control,
    Close,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InflightAction {
    circuit_id: [u8; 8],
    destination: HnsrPeerId,
    kind: InflightKind,
}

/// Bounded opaque HNSR circuit relay.
///
/// The runtime never sees inner plaintext semantics. DATA remains opaque and
/// every returned route remains counted against its circuit queue until
/// [`Self::acknowledge`] is called.
#[derive(Debug)]
pub struct OpaqueRelayRuntime {
    session: [u8; 16],
    generation: u64,
    enabled: bool,
    trusted_time_high_water: u64,
    config: OpaqueRelayConfig,
    pending: HashMap<[u8; 8], RelayPending>,
    circuits: HashMap<[u8; 8], RelayCircuit>,
    reservation_usage: HashMap<[u8; 16], ReservationUsage>,
    inflight: HashMap<HnsrActionId, InflightAction>,
    next_action_sequence: u64,
    counters: RuntimeCounters,
}

impl OpaqueRelayRuntime {
    /// Create a fresh opaque relay runtime.
    pub fn new(
        session: [u8; 16],
        generation: u64,
        config: OpaqueRelayConfig,
        trusted_now: u64,
    ) -> Result<Self, HnsrRuntimeError> {
        validate_session(session, generation)?;
        Ok(Self {
            session,
            generation,
            enabled: true,
            trusted_time_high_water: trusted_now,
            config: config.validate()?,
            pending: HashMap::new(),
            circuits: HashMap::new(),
            reservation_usage: HashMap::new(),
            inflight: HashMap::new(),
            next_action_sequence: 1,
            counters: RuntimeCounters::default(),
        })
    }

    /// Restore policy and counters under a fresh process session, caller-held
    /// generation floor, and nondecreasing trusted time. Snapshotted live work
    /// is counted as revoked and never reconstructed.
    pub fn restore(
        snapshot: OpaqueRelaySnapshot,
        fresh_session: [u8; 16],
        minimum_generation: u64,
        trusted_now: u64,
    ) -> Result<Self, HnsrRuntimeError> {
        validate_restore_guard(
            snapshot.generation,
            snapshot.trusted_time_high_water,
            minimum_generation,
            trusted_now,
        )?;
        validate_fresh_session(snapshot.session, fresh_session)?;
        let generation = snapshot
            .generation
            .checked_add(1)
            .ok_or(HnsrRuntimeError::GenerationExhausted)?;
        let mut counters = snapshot.counters;
        counters.revoked_work = counters.revoked_work.saturating_add(u64::from(
            snapshot
                .live_pending
                .saturating_add(snapshot.live_circuits)
                .saturating_add(snapshot.live_actions),
        ));
        Ok(Self {
            session: fresh_session,
            generation,
            enabled: snapshot.enabled,
            trusted_time_high_water: trusted_now,
            config: snapshot.config.validate()?,
            pending: HashMap::new(),
            circuits: HashMap::new(),
            reservation_usage: HashMap::new(),
            inflight: HashMap::new(),
            next_action_sequence: 1,
            counters,
        })
    }

    /// Current name-free relay status.
    pub fn status(&self) -> HnsrRuntimeStatus {
        HnsrRuntimeStatus {
            generation: self.generation,
            enabled: self.enabled,
            pending_circuits: self.pending.len(),
            active_circuits: self.circuits.len(),
            queued_bytes: self.queued_bytes(),
            queued_actions: self.inflight.len(),
            trusted_time_high_water: self.trusted_time_high_water,
            admitted_opens: self.counters.admitted_opens,
            opened_circuits: self.counters.opened_circuits,
            bytes_sent: self.counters.bytes_sent,
            bytes_received: self.counters.bytes_received,
            revoked_work: self.counters.revoked_work,
        }
    }

    /// Capture durable settings, counters, and fail-closed live-work counts.
    pub fn snapshot(&self) -> OpaqueRelaySnapshot {
        OpaqueRelaySnapshot {
            session: self.session,
            generation: self.generation,
            enabled: self.enabled,
            trusted_time_high_water: self.trusted_time_high_water,
            config: self.config,
            counters: self.counters,
            live_pending: u32::try_from(self.pending.len()).unwrap_or(u32::MAX),
            live_circuits: u32::try_from(self.circuits.len()).unwrap_or(u32::MAX),
            live_actions: u32::try_from(self.inflight.len()).unwrap_or(u32::MAX),
            queued_bytes: u64::try_from(self.queued_bytes()).unwrap_or(u64::MAX),
        }
    }

    /// Advance the persisted trusted-time high-water mark.
    /// Equal time is accepted; rollback is rejected without changing state.
    pub fn observe_time(&mut self, trusted_now: u64) -> Result<(), HnsrRuntimeError> {
        if trusted_now < self.trusted_time_high_water {
            return Err(HnsrRuntimeError::ClockRollback);
        }
        self.trusted_time_high_water = trusted_now;
        Ok(())
    }

    /// Replace opaque-relay enablement with optimistic generation matching.
    /// A disable clears live authority before returning best-effort closures.
    pub fn replace_enabled(
        &mut self,
        expected_generation: u64,
        enabled: bool,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrRuntimeError> {
        if expected_generation != self.generation {
            return Err(HnsrRuntimeError::StaleGeneration);
        }
        if self.enabled == enabled {
            return Ok(Vec::new());
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(HnsrRuntimeError::GenerationExhausted)?;
        self.enabled = enabled;
        self.inflight.clear();
        self.next_action_sequence = 1;
        if enabled {
            return Ok(Vec::new());
        }
        Ok(self.revoke_all(HnsrErrorCode::Shutdown as u16, "opaque relay disabled"))
    }

    /// Admit one circuit-plane packet from an authenticated outer connection.
    /// Reservation-plane packets remain handled by [`RelayService`].
    pub fn handle(
        &mut self,
        reservations: &RelayService,
        source: &HnsrPeerId,
        packet: &HnsrPacket,
        now: u64,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrRuntimeError> {
        self.observe_time(now)?;
        self.ensure_enabled()?;
        match packet.opcode {
            HnsrOpcode::Open => self.handle_open(reservations, source, packet, now),
            HnsrOpcode::Accept => self.handle_accept(source, packet, now),
            HnsrOpcode::Data => self.handle_data(source, packet),
            HnsrOpcode::Window => self.handle_window(source, packet),
            HnsrOpcode::Close | HnsrOpcode::Error => self.handle_close(source, packet),
            _ => Err(HnsrRuntimeError::UnexpectedOpcode),
        }
    }

    /// Acknowledge one exact adapter write.
    ///
    /// Failed writes immediately revoke the associated pending or active
    /// circuit. Successful DATA writes release their queue accounting.
    pub fn acknowledge(
        &mut self,
        action_id: HnsrActionId,
        delivered: bool,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrRuntimeError> {
        if action_id.generation != self.generation {
            return Err(HnsrRuntimeError::StaleGeneration);
        }
        let action = self
            .inflight
            .remove(&action_id)
            .ok_or(HnsrRuntimeError::UnknownAction)?;
        if let InflightKind::Data { destination, bytes } = action.kind {
            if let Some(circuit) = self.circuits.get_mut(&action.circuit_id) {
                let queued = match destination {
                    RelaySide::Requester => &mut circuit.queued_to_requester,
                    RelaySide::Endpoint => &mut circuit.queued_to_endpoint,
                };
                *queued = queued.saturating_sub(bytes);
            }
        }
        if delivered {
            return Ok(Vec::new());
        }
        match action.kind {
            InflightKind::Incoming => {
                let pending = self.pending.remove(&action.circuit_id);
                if let Some(pending) = pending {
                    self.counters.revoked_work = self.counters.revoked_work.saturating_add(1);
                    let packet = error_packet(
                        pending.requester_context,
                        HnsrErrorCode::EndpointGone as u16,
                        "endpoint write failed",
                    )?;
                    Ok(vec![self.queue_control(
                        pending.requester,
                        action.circuit_id,
                        packet,
                        InflightKind::Close,
                    )?])
                } else {
                    Ok(Vec::new())
                }
            }
            InflightKind::Opened | InflightKind::Data { .. } | InflightKind::Control => {
                Ok(self.revoke_circuit(
                    action.circuit_id,
                    HnsrErrorCode::EndpointGone as u16,
                    "outer write failed",
                ))
            }
            InflightKind::Close => Ok(Vec::new()),
        }
    }

    /// Revoke all work involving one disconnected outer connection.
    pub fn disconnect(&mut self, peer: &HnsrPeerId) -> Vec<QueuedHnsrRoute> {
        self.drop_inflight_for_peer(peer);
        let pending = self
            .pending
            .iter()
            .filter_map(|(circuit_id, state)| {
                (state.requester == *peer || state.endpoint == *peer).then_some(*circuit_id)
            })
            .collect::<Vec<_>>();
        let circuits = self
            .circuits
            .iter()
            .filter_map(|(circuit_id, state)| {
                (state.requester == *peer || state.endpoint == *peer).then_some(*circuit_id)
            })
            .collect::<Vec<_>>();
        let mut routes = Vec::new();
        for circuit_id in pending {
            if let Some(state) = self.pending.remove(&circuit_id) {
                self.drop_inflight_for(circuit_id);
                let (destination, destination_context) = if state.requester == *peer {
                    (state.endpoint, circuit_id)
                } else {
                    (state.requester, state.requester_context)
                };
                if let Ok(packet) = close_packet(
                    destination_context,
                    HnsrErrorCode::EndpointGone as u16,
                    "outer peer disconnected",
                ) {
                    if let Ok(route) = self.queue_control(
                        destination,
                        circuit_id,
                        packet,
                        InflightKind::Close,
                    ) {
                        routes.push(route);
                    }
                }
                self.counters.revoked_work = self.counters.revoked_work.saturating_add(1);
            }
        }
        for circuit_id in circuits {
            routes.extend(self.revoke_circuit(
                circuit_id,
                HnsrErrorCode::EndpointGone as u16,
                "outer peer disconnected",
            ));
        }
        routes
    }

    /// Revoke every circuit bound to one removed relay reservation.
    pub fn revoke_reservation(
        &mut self,
        reservation_id: [u8; 16],
    ) -> Vec<QueuedHnsrRoute> {
        self.reservation_usage.remove(&reservation_id);
        let pending = self
            .pending
            .iter()
            .filter_map(|(circuit_id, state)| {
                (state.ticket.reservation_id == reservation_id).then_some(*circuit_id)
            })
            .collect::<Vec<_>>();
        let circuits = self
            .circuits
            .iter()
            .filter_map(|(circuit_id, state)| {
                (state.reservation_id == reservation_id).then_some(*circuit_id)
            })
            .collect::<Vec<_>>();
        let mut routes = Vec::new();
        for circuit_id in pending {
            if let Some(state) = self.pending.remove(&circuit_id) {
                routes.extend(self.revoke_pending(
                    circuit_id,
                    state,
                    HnsrErrorCode::Expired as u16,
                    "reservation revoked",
                ));
            }
        }
        for circuit_id in circuits {
            routes.extend(self.revoke_circuit(
                circuit_id,
                HnsrErrorCode::Expired as u16,
                "reservation revoked",
            ));
        }
        routes
    }

    /// Expire endpoint-accept deadlines and ticket lifetimes.
    pub fn expire(
        &mut self,
        now: u64,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrRuntimeError> {
        self.observe_time(now)?;
        self.reservation_usage
            .retain(|_, usage| usage.expires_at > now);
        let pending = self
            .pending
            .iter()
            .filter_map(|(circuit_id, state)| {
                (state.deadline <= now || state.ticket.expires_at <= now).then_some(*circuit_id)
            })
            .collect::<Vec<_>>();
        let circuits = self
            .circuits
            .iter()
            .filter_map(|(circuit_id, state)| (state.expires_at <= now).then_some(*circuit_id))
            .collect::<Vec<_>>();
        let mut routes = Vec::new();
        for circuit_id in pending {
            if let Some(state) = self.pending.remove(&circuit_id) {
                routes.extend(self.revoke_pending(
                    circuit_id,
                    state,
                    HnsrErrorCode::Timeout as u16,
                    "endpoint acceptance expired",
                ));
            }
        }
        for circuit_id in circuits {
            routes.extend(self.revoke_circuit(
                circuit_id,
                HnsrErrorCode::Expired as u16,
                "relay ticket expired",
            ));
        }
        Ok(routes)
    }

    fn handle_open(
        &mut self,
        reservations: &RelayService,
        requester: &HnsrPeerId,
        packet: &HnsrPacket,
        now: u64,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrRuntimeError> {
        if self.pending.len() >= self.config.maximum_pending
            || self.circuits.len() >= self.config.maximum_circuits
            || self.peer_work(requester) >= usize::from(self.config.maximum_circuits_per_peer)
            || self.pending.values().any(|pending| {
                pending.requester == *requester && pending.requester_context == packet.context_id
            })
        {
            return Err(HnsrRuntimeError::Capacity);
        }
        let open = OpenBody::decode(&packet.body)?;
        let admission = reservations.admit_circuit(&open, now)?;
        self.reservation_usage
            .retain(|_, usage| usage.expires_at > now);
        let endpoint = HnsrPeerId::new(admission.source.into_bytes())?;
        if endpoint == *requester
            || self.peer_work(&endpoint) >= usize::from(self.config.maximum_circuits_per_peer)
            || self.reservation_work(&open.reservation_id)
                >= usize::from(admission.ticket.max_active_circuits)
        {
            return Err(HnsrRuntimeError::Capacity);
        }
        let circuit_id = random_unique_id(&self.pending, &self.circuits)?;
        self.ensure_action_capacity(&endpoint, circuit_id, false)?;
        let deadline = now
            .checked_add(self.config.accept_timeout_seconds)
            .ok_or(HnsrRuntimeError::Deadline)?
            .min(admission.ticket.expires_at);
        let usage = self
            .reservation_usage
            .entry(admission.ticket.reservation_id)
            .or_insert(ReservationUsage {
                bytes: 0,
                expires_at: admission.ticket.expires_at,
            });
        if usage.expires_at != admission.ticket.expires_at
            || usage.bytes >= admission.ticket.max_total_bytes
        {
            return Err(HnsrRuntimeError::ByteLimit);
        }
        self.pending.insert(
            circuit_id,
            RelayPending {
                requester: requester.clone(),
                endpoint: endpoint.clone(),
                requester_context: packet.context_id,
                ticket: admission.ticket,
                initial_window: open.initial_window,
                deadline,
            },
        );
        self.counters.admitted_opens = self.counters.admitted_opens.saturating_add(1);
        let incoming = HnsrPacket::new(
            HnsrOpcode::Incoming,
            circuit_id,
            IncomingBody {
                ticket_id: open.ticket_id,
                open_request_id: packet.context_id,
                profile: open.profile,
                requester_nonce: open.requester_nonce,
                initial_window: open.initial_window,
            }
            .encode()?,
        )?;
        Ok(vec![self.queue_control(
            endpoint,
            circuit_id,
            incoming,
            InflightKind::Incoming,
        )?])
    }

    fn handle_accept(
        &mut self,
        endpoint: &HnsrPeerId,
        packet: &HnsrPacket,
        now: u64,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrRuntimeError> {
        let pending = self
            .pending
            .get(&packet.context_id)
            .ok_or(HnsrRuntimeError::UnknownRequest)?;
        if pending.endpoint != *endpoint {
            return Err(HnsrRuntimeError::WrongPeer);
        }
        if pending.deadline <= now || pending.ticket.expires_at <= now {
            return Err(HnsrRuntimeError::InvalidAdmission);
        }
        let accept = AcceptBody::decode(&packet.body)?;
        if accept.accepted_window > pending.initial_window
            || self.circuits.len() >= self.config.maximum_circuits
            || self.reservation_work(&pending.ticket.reservation_id)
                > usize::from(pending.ticket.max_active_circuits)
        {
            return Err(HnsrRuntimeError::Capacity);
        }
        self.ensure_action_capacity(&pending.requester, packet.context_id, true)?;
        let pending = self
            .pending
            .remove(&packet.context_id)
            .ok_or(HnsrRuntimeError::UnknownRequest)?;
        self.drop_inflight_for(packet.context_id);
        let maximum_bytes = pending
            .ticket
            .max_bytes_per_circuit
            .min(self.config.maximum_bytes_per_circuit);
        self.circuits.insert(
            packet.context_id,
            RelayCircuit {
                requester: pending.requester.clone(),
                endpoint: pending.endpoint,
                reservation_id: pending.ticket.reservation_id,
                expires_at: pending.ticket.expires_at,
                maximum_bytes,
                maximum_total_bytes: pending.ticket.max_total_bytes,
                requester_credit: accept.accepted_window,
                endpoint_credit: accept.accepted_window,
                forwarded_bytes: 0,
                queued_to_requester: 0,
                queued_to_endpoint: 0,
            },
        );
        self.counters.opened_circuits = self.counters.opened_circuits.saturating_add(1);
        let opened = HnsrPacket::new(
            HnsrOpcode::Opened,
            pending.requester_context,
            OpenedBody {
                circuit_id: packet.context_id,
                accepted_window: accept.accepted_window,
                endpoint_nonce: accept.endpoint_nonce,
            }
            .encode()?,
        )?;
        Ok(vec![self.queue_control(
            pending.requester,
            packet.context_id,
            opened,
            InflightKind::Opened,
        )?])
    }

    fn handle_data(
        &mut self,
        source: &HnsrPeerId,
        packet: &HnsrPacket,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrRuntimeError> {
        let data = DataBody::decode(&packet.body)?;
        let bytes = data.bytes.len();
        let length = u32::try_from(bytes).map_err(|_| HnsrRuntimeError::ByteLimit)?;
        let maximum_queue_bytes = self.config.maximum_queue_bytes;
        let amount = u64::from(length);
        let capacity_destination = {
            let circuit = self
                .circuits
                .get(&packet.context_id)
                .ok_or(HnsrRuntimeError::UnknownCircuit)?;
            let side = circuit.side(source)?;
            circuit.destination(side)
        };
        self.ensure_action_capacity(&capacity_destination, packet.context_id, false)?;
        let (destination, destination_side, reservation_id, maximum_total_bytes) = {
            let circuit = self
                .circuits
                .get_mut(&packet.context_id)
                .ok_or(HnsrRuntimeError::UnknownCircuit)?;
            let side = circuit.side(source)?;
            let usage = self
                .reservation_usage
                .get(&circuit.reservation_id)
                .ok_or(HnsrRuntimeError::InvalidAdmission)?;
            if circuit.forwarded_bytes.saturating_add(amount) > circuit.maximum_bytes
                || usage.bytes.saturating_add(amount) > circuit.maximum_total_bytes
            {
                return Err(HnsrRuntimeError::ByteLimit);
            }
            match side {
                RelaySide::Requester => {
                    if length > circuit.requester_credit
                        || circuit.queued_to_endpoint.saturating_add(bytes)
                            > maximum_queue_bytes
                    {
                        return Err(HnsrRuntimeError::FlowControl);
                    }
                    circuit.requester_credit -= length;
                    circuit.forwarded_bytes = circuit.forwarded_bytes.saturating_add(amount);
                    circuit.queued_to_endpoint = circuit.queued_to_endpoint.saturating_add(bytes);
                    (
                        circuit.endpoint.clone(),
                        RelaySide::Endpoint,
                        circuit.reservation_id,
                        circuit.maximum_total_bytes,
                    )
                }
                RelaySide::Endpoint => {
                    if length > circuit.endpoint_credit
                        || circuit.queued_to_requester.saturating_add(bytes)
                            > maximum_queue_bytes
                    {
                        return Err(HnsrRuntimeError::FlowControl);
                    }
                    circuit.endpoint_credit -= length;
                    circuit.forwarded_bytes = circuit.forwarded_bytes.saturating_add(amount);
                    circuit.queued_to_requester = circuit.queued_to_requester.saturating_add(bytes);
                    (
                        circuit.requester.clone(),
                        RelaySide::Requester,
                        circuit.reservation_id,
                        circuit.maximum_total_bytes,
                    )
                }
            }
        };
        let usage = self
            .reservation_usage
            .get_mut(&reservation_id)
            .ok_or(HnsrRuntimeError::InvalidAdmission)?;
        if usage.bytes.saturating_add(amount) > maximum_total_bytes {
            return Err(HnsrRuntimeError::ByteLimit);
        }
        usage.bytes = usage.bytes.saturating_add(amount);
        self.counters.bytes_received = self
            .counters
            .bytes_received
            .saturating_add(u64::from(length));
        self.counters.bytes_sent = self.counters.bytes_sent.saturating_add(u64::from(length));
        Ok(vec![self.queue_control(
            destination,
            packet.context_id,
            packet.clone(),
            InflightKind::Data {
                destination: destination_side,
                bytes,
            },
        )?])
    }

    fn handle_window(
        &mut self,
        source: &HnsrPeerId,
        packet: &HnsrPacket,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrRuntimeError> {
        let window = WindowBody::decode(&packet.body)?;
        let capacity_destination = {
            let circuit = self
                .circuits
                .get(&packet.context_id)
                .ok_or(HnsrRuntimeError::UnknownCircuit)?;
            let side = circuit.side(source)?;
            circuit.destination(side)
        };
        self.ensure_action_capacity(&capacity_destination, packet.context_id, false)?;
        let destination = {
            let circuit = self
                .circuits
                .get_mut(&packet.context_id)
                .ok_or(HnsrRuntimeError::UnknownCircuit)?;
            let side = circuit.side(source)?;
            let credit = match side {
                RelaySide::Requester => &mut circuit.endpoint_credit,
                RelaySide::Endpoint => &mut circuit.requester_credit,
            };
            *credit = credit
                .checked_add(window.credit_delta)
                .filter(|value| *value <= MAX_WINDOW)
                .ok_or(HnsrRuntimeError::FlowControl)?;
            circuit.destination(side)
        };
        Ok(vec![self.queue_control(
            destination,
            packet.context_id,
            packet.clone(),
            InflightKind::Control,
        )?])
    }

    fn handle_close(
        &mut self,
        source: &HnsrPeerId,
        packet: &HnsrPacket,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrRuntimeError> {
        if packet.opcode == HnsrOpcode::Close {
            let _ = CloseBody::decode(&packet.body)?;
        } else {
            let _ = ErrorBody::decode(&packet.body)?;
        }
        if let Some(circuit_id) = self.pending_wire_context(source, packet.context_id)? {
            let pending = self
                .pending
                .remove(&circuit_id)
                .ok_or(HnsrRuntimeError::UnknownRequest)?;
            self.drop_inflight_for(circuit_id);
            self.counters.revoked_work = self.counters.revoked_work.saturating_add(1);
            let (destination, destination_context) = if pending.requester == *source {
                (pending.endpoint, circuit_id)
            } else {
                (pending.requester, pending.requester_context)
            };
            let translated = recontext_packet(packet, destination_context)?;
            return Ok(vec![self.queue_control(
                destination,
                circuit_id,
                translated,
                InflightKind::Close,
            )?]);
        }
        let circuit = self
            .circuits
            .get(&packet.context_id)
            .ok_or(HnsrRuntimeError::UnknownCircuit)?;
        let side = circuit.side(source)?;
        let destination = circuit.destination(side);
        self.circuits.remove(&packet.context_id);
        self.drop_inflight_for(packet.context_id);
        self.counters.revoked_work = self.counters.revoked_work.saturating_add(1);
        Ok(vec![self.queue_control(
            destination,
            packet.context_id,
            packet.clone(),
            InflightKind::Close,
        )?])
    }

    fn pending_wire_context(
        &self,
        source: &HnsrPeerId,
        wire_context: [u8; 8],
    ) -> Result<Option<[u8; 8]>, HnsrRuntimeError> {
        let mut matched = None;
        for (circuit_id, pending) in &self.pending {
            let is_match = (pending.requester == *source
                && pending.requester_context == wire_context)
                || (pending.endpoint == *source && *circuit_id == wire_context);
            if is_match {
                if matched.replace(*circuit_id).is_some() {
                    return Err(HnsrRuntimeError::InvalidAdmission);
                }
            }
        }
        Ok(matched)
    }

    fn queue_control(
        &mut self,
        destination: HnsrPeerId,
        circuit_id: [u8; 8],
        packet: HnsrPacket,
        kind: InflightKind,
    ) -> Result<QueuedHnsrRoute, HnsrRuntimeError> {
        self.ensure_action_capacity(&destination, circuit_id, false)?;
        let action_id = HnsrActionId {
            generation: self.generation,
            sequence: self.next_action_sequence,
        };
        self.next_action_sequence = self
            .next_action_sequence
            .checked_add(1)
            .ok_or(HnsrRuntimeError::GenerationExhausted)?;
        self.inflight.insert(
            action_id,
            InflightAction {
                circuit_id,
                destination: destination.clone(),
                kind,
            },
        );
        Ok(QueuedHnsrRoute {
            action_id,
            route: HnsrRoute {
                destination,
                packet,
            },
        })
    }

    fn ensure_action_capacity(
        &self,
        destination: &HnsrPeerId,
        circuit_id: [u8; 8],
        replacing_circuit_actions: bool,
    ) -> Result<(), HnsrRuntimeError> {
        let retained = self.inflight.values().filter(|action| {
            !replacing_circuit_actions || action.circuit_id != circuit_id
        });
        let mut total = 0usize;
        let mut for_circuit = 0usize;
        let mut for_peer = 0usize;
        for action in retained {
            total = total.saturating_add(1);
            if action.circuit_id == circuit_id {
                for_circuit = for_circuit.saturating_add(1);
            }
            if action.destination == *destination {
                for_peer = for_peer.saturating_add(1);
            }
        }
        if total >= self.config.maximum_inflight_actions
            || for_circuit >= self.config.maximum_inflight_actions_per_circuit
            || for_peer >= self.config.maximum_inflight_actions_per_peer
        {
            return Err(HnsrRuntimeError::Capacity);
        }
        Ok(())
    }

    fn revoke_circuit(
        &mut self,
        circuit_id: [u8; 8],
        reason: u16,
        detail: &str,
    ) -> Vec<QueuedHnsrRoute> {
        let Some(circuit) = self.circuits.remove(&circuit_id) else {
            return Vec::new();
        };
        self.drop_inflight_for(circuit_id);
        self.counters.revoked_work = self.counters.revoked_work.saturating_add(1);
        let mut routes = Vec::new();
        for destination in [circuit.requester, circuit.endpoint] {
            if let Ok(packet) = close_packet(circuit_id, reason, detail) {
                if let Ok(route) = self.queue_control(
                    destination,
                    circuit_id,
                    packet,
                    InflightKind::Close,
                ) {
                    routes.push(route);
                }
            }
        }
        routes
    }

    fn revoke_pending(
        &mut self,
        circuit_id: [u8; 8],
        pending: RelayPending,
        reason: u16,
        detail: &str,
    ) -> Vec<QueuedHnsrRoute> {
        self.drop_inflight_for(circuit_id);
        self.counters.revoked_work = self.counters.revoked_work.saturating_add(1);
        let packets = [
            (
                pending.requester,
                error_packet(pending.requester_context, reason, detail),
            ),
            (
                pending.endpoint,
                close_packet(circuit_id, reason, detail),
            ),
        ];
        let mut routes = Vec::new();
        for (destination, packet) in packets {
            if let Ok(packet) = packet {
                if let Ok(route) =
                    self.queue_control(destination, circuit_id, packet, InflightKind::Close)
                {
                    routes.push(route);
                }
            }
        }
        routes
    }

    fn revoke_all(&mut self, reason: u16, detail: &str) -> Vec<QueuedHnsrRoute> {
        let pending = self.pending.drain().collect::<Vec<_>>();
        let circuits = self.circuits.drain().collect::<Vec<_>>();
        self.inflight.clear();
        let mut routes = Vec::new();
        for (circuit_id, state) in pending {
            routes.extend(self.revoke_pending(circuit_id, state, reason, detail));
        }
        for (circuit_id, state) in circuits {
            self.counters.revoked_work = self.counters.revoked_work.saturating_add(1);
            for destination in [state.requester, state.endpoint] {
                if let Ok(packet) = close_packet(circuit_id, reason, detail) {
                    if let Ok(route) = self.queue_control(
                        destination,
                        circuit_id,
                        packet,
                        InflightKind::Close,
                    ) {
                        routes.push(route);
                    }
                }
            }
        }
        routes
    }

    fn drop_inflight_for(&mut self, circuit_id: [u8; 8]) {
        let actions = self
            .inflight
            .iter()
            .filter_map(|(action_id, action)| {
                (action.circuit_id == circuit_id).then_some(*action_id)
            })
            .collect::<Vec<_>>();
        for action_id in actions {
            self.inflight.remove(&action_id);
        }
    }

    fn drop_inflight_for_peer(&mut self, peer: &HnsrPeerId) {
        self.inflight
            .retain(|_, action| action.destination != *peer);
    }

    fn peer_work(&self, peer: &HnsrPeerId) -> usize {
        self.pending
            .values()
            .filter(|state| state.requester == *peer || state.endpoint == *peer)
            .count()
            .saturating_add(
                self.circuits
                    .values()
                    .filter(|state| state.requester == *peer || state.endpoint == *peer)
                    .count(),
            )
    }

    fn reservation_work(&self, reservation_id: &[u8; 16]) -> usize {
        self.pending
            .values()
            .filter(|state| state.ticket.reservation_id == *reservation_id)
            .count()
            .saturating_add(
                self.circuits
                    .values()
                    .filter(|state| state.reservation_id == *reservation_id)
                    .count(),
            )
    }

    fn queued_bytes(&self) -> usize {
        self.circuits
            .values()
            .map(|state| {
                state
                    .queued_to_requester
                    .saturating_add(state.queued_to_endpoint)
            })
            .sum()
    }

    fn ensure_enabled(&self) -> Result<(), HnsrRuntimeError> {
        if self.enabled {
            Ok(())
        } else {
            Err(HnsrRuntimeError::Disabled)
        }
    }
}

fn validate_session(session: [u8; 16], generation: u64) -> Result<(), HnsrRuntimeError> {
    if session == [0; 16] || generation == 0 {
        return Err(HnsrRuntimeError::InvalidSession);
    }
    Ok(())
}

fn validate_fresh_session(
    previous: [u8; 16],
    fresh: [u8; 16],
) -> Result<(), HnsrRuntimeError> {
    if previous == [0; 16] || fresh == [0; 16] || previous == fresh {
        return Err(HnsrRuntimeError::InvalidSession);
    }
    Ok(())
}

fn validate_restore_guard(
    snapshot_generation: u64,
    snapshot_time_high_water: u64,
    minimum_generation: u64,
    trusted_now: u64,
) -> Result<(), HnsrRuntimeError> {
    if minimum_generation == 0 || snapshot_generation < minimum_generation {
        return Err(HnsrRuntimeError::StaleGeneration);
    }
    if trusted_now < snapshot_time_high_water {
        return Err(HnsrRuntimeError::ClockRollback);
    }
    Ok(())
}

fn validate_deadline(now: u64, deadline: u64) -> Result<(), HnsrRuntimeError> {
    if deadline <= now || deadline.saturating_sub(now) > MAX_OPEN_DEADLINE_SECONDS {
        return Err(HnsrRuntimeError::Deadline);
    }
    Ok(())
}

fn random_nonzero<const N: usize>() -> Result<[u8; N], HnsrRuntimeError> {
    for _ in 0..8 {
        let mut value = [0; N];
        getrandom::fill(&mut value).map_err(|_| HnsrRuntimeError::Randomness)?;
        if value.iter().any(|byte| *byte != 0) {
            return Ok(value);
        }
    }
    Err(HnsrRuntimeError::Randomness)
}

fn random_unique_id<A, B>(
    pending: &HashMap<[u8; 8], A>,
    circuits: &HashMap<[u8; 8], B>,
) -> Result<[u8; 8], HnsrRuntimeError> {
    for _ in 0..8 {
        let candidate = random_nonzero()?;
        if !pending.contains_key(&candidate) && !circuits.contains_key(&candidate) {
            return Ok(candidate);
        }
    }
    Err(HnsrRuntimeError::Randomness)
}

fn close_packet(
    context_id: [u8; 8],
    reason: u16,
    detail: &str,
) -> Result<HnsrPacket, HnsrRuntimeError> {
    Ok(HnsrPacket::new(
        HnsrOpcode::Close,
        context_id,
        CloseBody {
            reason,
            detail: detail.to_owned(),
        }
        .encode()?,
    )?)
}

fn error_packet(
    context_id: [u8; 8],
    reason: u16,
    detail: &str,
) -> Result<HnsrPacket, HnsrRuntimeError> {
    Ok(HnsrPacket::new(
        HnsrOpcode::Error,
        context_id,
        ErrorBody {
            reason,
            detail: detail.to_owned(),
        }
        .encode()?,
    )?)
}

fn recontext_packet(
    packet: &HnsrPacket,
    context_id: [u8; 8],
) -> Result<HnsrPacket, HnsrRuntimeError> {
    Ok(HnsrPacket::new(
        packet.opcode,
        context_id,
        packet.body.clone(),
    )?)
}

fn encode_snapshot_header(
    bytes: &mut Vec<u8>,
    session: [u8; 16],
    generation: u64,
    enabled: bool,
) {
    bytes.extend_from_slice(&session);
    bytes.extend_from_slice(&generation.to_le_bytes());
    bytes.push(u8::from(enabled));
}

fn decode_snapshot_header(
    reader: &mut SnapshotReader<'_>,
) -> Result<([u8; 16], u64, bool), HnsrRuntimeError> {
    Ok((reader.array()?, reader.u64()?, reader.boolean()?))
}

fn encode_counters(bytes: &mut Vec<u8>, counters: RuntimeCounters) {
    for value in [
        counters.admitted_opens,
        counters.opened_circuits,
        counters.bytes_sent,
        counters.bytes_received,
        counters.revoked_work,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
}

fn decode_counters(
    reader: &mut SnapshotReader<'_>,
) -> Result<RuntimeCounters, HnsrRuntimeError> {
    Ok(RuntimeCounters {
        admitted_opens: reader.u64()?,
        opened_circuits: reader.u64()?,
        bytes_sent: reader.u64()?,
        bytes_received: reader.u64()?,
        revoked_work: reader.u64()?,
    })
}

fn push_usize(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&u64::try_from(value).unwrap_or(u64::MAX).to_le_bytes());
}

fn append_snapshot_checksum(bytes: &mut Vec<u8>) {
    let checksum = snapshot_checksum(bytes);
    bytes.extend_from_slice(&checksum);
}

fn verified_snapshot_payload<'a>(
    input: &'a [u8],
    magic: &[u8; 8],
) -> Result<&'a [u8], HnsrRuntimeError> {
    if input.len() < 12 + SNAPSHOT_CHECKSUM_BYTES {
        return Err(HnsrRuntimeError::CorruptSnapshot);
    }
    let payload_length = input.len() - SNAPSHOT_CHECKSUM_BYTES;
    let (payload, supplied_checksum) = input.split_at(payload_length);
    if payload.get(..8) != Some(magic.as_slice())
        || payload.get(8) != Some(&SNAPSHOT_SCHEMA)
        || payload.get(9..12) != Some([0, 0, 0].as_slice())
        || supplied_checksum != snapshot_checksum(payload)
    {
        return Err(HnsrRuntimeError::CorruptSnapshot);
    }
    Ok(payload)
}

fn snapshot_checksum(input: &[u8]) -> [u8; SNAPSHOT_CHECKSUM_BYTES] {
    let mut hasher = Blake2bVar::new(SNAPSHOT_CHECKSUM_BYTES)
        .expect("valid HNSR snapshot checksum length");
    hasher.update(input);
    let mut checksum = [0; SNAPSHOT_CHECKSUM_BYTES];
    hasher
        .finalize_variable(&mut checksum)
        .expect("valid HNSR snapshot checksum buffer");
    checksum
}

struct SnapshotReader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> SnapshotReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn skip(&mut self, length: usize) -> Result<(), HnsrRuntimeError> {
        let _ = self.bytes(length)?;
        Ok(())
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], HnsrRuntimeError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(HnsrRuntimeError::CorruptSnapshot)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(HnsrRuntimeError::CorruptSnapshot)?;
        self.position = end;
        Ok(bytes)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], HnsrRuntimeError> {
        let mut value = [0; N];
        value.copy_from_slice(self.bytes(N)?);
        Ok(value)
    }

    fn boolean(&mut self) -> Result<bool, HnsrRuntimeError> {
        match self.array::<1>()?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(HnsrRuntimeError::CorruptSnapshot),
        }
    }

    fn u16(&mut self) -> Result<u16, HnsrRuntimeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, HnsrRuntimeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, HnsrRuntimeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn usize(&mut self) -> Result<usize, HnsrRuntimeError> {
        usize::try_from(self.u64()?).map_err(|_| HnsrRuntimeError::CorruptSnapshot)
    }

    fn finish(self) -> Result<(), HnsrRuntimeError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(HnsrRuntimeError::CorruptSnapshot)
        }
    }
}

/// Runtime admission, state, or adapter-completion failure.
#[derive(Debug, Error)]
pub enum HnsrRuntimeError {
    /// Strict wire, ticket, signature, or record validation failed.
    #[error(transparent)]
    Protocol(#[from] HnsrProtocolError),
    /// A local runtime bound is zero or exceeds the protocol ceiling.
    #[error("invalid HNSR runtime configuration")]
    InvalidConfig,
    /// A process session is zero, reused, or otherwise invalid.
    #[error("invalid or reused HNSR runtime session")]
    InvalidSession,
    /// An outer-connection identity is empty or oversized.
    #[error("invalid HNSR outer peer identity")]
    InvalidPeer,
    /// The supplied generation does not match current runtime state.
    #[error("stale HNSR runtime generation")]
    StaleGeneration,
    /// A generation or queued-action sequence cannot advance safely.
    #[error("HNSR runtime generation exhausted")]
    GenerationExhausted,
    /// Trusted time moved behind the persisted high-water mark.
    #[error("HNSR trusted clock rollback detected")]
    ClockRollback,
    /// Cryptographic random generation failed repeatedly.
    #[error("HNSR runtime randomness unavailable")]
    Randomness,
    /// This requester or relay role is explicitly disabled.
    #[error("HNSR runtime role is disabled")]
    Disabled,
    /// A configured global, peer, ticket, or reservation bound is full.
    #[error("HNSR runtime capacity reached")]
    Capacity,
    /// Ticket, relay identity, profile, window, or expiry admission failed.
    #[error("invalid HNSR circuit admission")]
    InvalidAdmission,
    /// An open or acceptance deadline is invalid or expired.
    #[error("invalid or expired HNSR circuit deadline")]
    Deadline,
    /// The packet does not identify pending requester state.
    #[error("unknown HNSR circuit request")]
    UnknownRequest,
    /// The packet does not identify an established circuit.
    #[error("unknown HNSR circuit")]
    UnknownCircuit,
    /// The outer connection does not own the addressed state.
    #[error("HNSR packet arrived from the wrong outer peer")]
    WrongPeer,
    /// The packet opcode is not valid for this runtime surface.
    #[error("unexpected HNSR runtime opcode")]
    UnexpectedOpcode,
    /// Directional credit or an unacknowledged queue bound was exceeded.
    #[error("HNSR circuit flow-control bound exceeded")]
    FlowControl,
    /// An opaque frame or cumulative byte ceiling was exceeded.
    #[error("HNSR circuit byte bound exceeded")]
    ByteLimit,
    /// No requester data frame is ready to consume.
    #[error("no queued HNSR requester data")]
    NoQueuedData,
    /// A completion token is unknown or was already acknowledged.
    #[error("unknown HNSR queued action")]
    UnknownAction,
    /// A snapshot is malformed, extended, truncated, or checksum-invalid.
    #[error("corrupt HNSR runtime snapshot")]
    CorruptSnapshot,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        DEFAULT_WINDOW, EndpointReservation, HNS_NODE_V1, HnsrService, RelayConfig,
        RelayLimits,
    };

    const MAGIC: u32 = 0x6d6f_6f6e;
    const NOW: u64 = 1_700_000_000;

    fn peer(value: &str) -> HnsrPeerId {
        HnsrPeerId::new(value.as_bytes().to_vec()).expect("bounded peer")
    }

    fn requester_config() -> HnsrRequesterConfig {
        HnsrRequesterConfig {
            network_magic: MAGIC,
            profile: HNS_NODE_V1,
            allow_private_relay: true,
            maximum_circuits: 4,
            maximum_queue_bytes: MAX_CIRCUIT_QUEUE,
            maximum_bytes_per_circuit: 65_536,
        }
    }

    fn confirmed_reservation() -> (HnsrService, RelayTicket) {
        let config = RelayConfig {
            network_magic: MAGIC,
            transport: 0,
            host_type: 1,
            host: [0; 16],
            port: 14_039,
            allow_private_address: true,
            supported_profiles: BTreeSet::from([HNS_NODE_V1]),
            limits: RelayLimits {
                maximum_reservations: 8,
                maximum_reservations_per_source: 2,
                maximum_bytes_per_circuit: 65_536,
            },
        };
        let mut service = HnsrService::new(
            Some(RelayService::new(config, [2; 32]).expect("relay")),
            None,
        );
        let relay_key = service.relay().expect("relay").relay_key();
        let endpoint =
            EndpointReservation::new(MAGIC, HNS_NODE_V1, [1; 32]).expect("endpoint");
        let reserve = endpoint
            .reserve(&relay_key, [3; 8], 120, 2, 65_536, [4; 16])
            .expect("reserve");
        let offer = service
            .handle(&reserve, "endpoint", NOW)
            .expect("reserve admitted")
            .expect("offer");
        let (confirmation, ticket) = endpoint
            .confirm_offer(&offer, &relay_key, NOW, true)
            .expect("confirm offer");
        let confirmed = service
            .handle(&confirmation, "endpoint", NOW)
            .expect("confirmation admitted")
            .expect("confirmed");
        let ticket = endpoint
            .accept_confirmation(&confirmed, ticket)
            .expect("ticket");
        (service, ticket)
    }

    fn open_circuit(
        service: &HnsrService,
        ticket: RelayTicket,
    ) -> (HnsrRequester, OpaqueRelayRuntime, [u8; 8]) {
        open_circuit_with_config(service, ticket, OpaqueRelayConfig::default())
    }

    fn open_circuit_with_config(
        service: &HnsrService,
        ticket: RelayTicket,
        relay_config: OpaqueRelayConfig,
    ) -> (HnsrRequester, OpaqueRelayRuntime, [u8; 8]) {
        let relay_peer = peer("relay");
        let requester_peer = peer("requester");
        let endpoint_peer = peer("endpoint");
        let mut requester =
            HnsrRequester::new([10; 16], 1, requester_config(), NOW).expect("requester");
        let open = requester
            .begin_open(
                relay_peer.clone(),
                ticket.relay_key,
                ticket,
                NOW,
                NOW + 5,
                DEFAULT_WINDOW,
            )
            .expect("open");
        let mut relay = OpaqueRelayRuntime::new([11; 16], 1, relay_config, NOW)
            .expect("opaque relay");
        let incoming = relay
            .handle(
                service.relay().expect("relay reservations"),
                &requester_peer,
                &open.packet,
                NOW,
            )
            .expect("open admitted")
            .pop()
            .expect("incoming");
        assert_eq!(incoming.route.destination, endpoint_peer);
        relay
            .acknowledge(incoming.action_id, true)
            .expect("incoming delivered");
        let accept = HnsrPacket::new(
            HnsrOpcode::Accept,
            incoming.route.packet.context_id,
            AcceptBody {
                accepted_window: DEFAULT_WINDOW,
                endpoint_nonce: [12; 16],
            }
            .encode()
            .expect("accept body"),
        )
        .expect("accept packet");
        let opened = relay
            .handle(
                service.relay().expect("relay reservations"),
                &endpoint_peer,
                &accept,
                NOW + 1,
            )
            .expect("accept admitted")
            .pop()
            .expect("opened");
        assert_eq!(opened.route.destination, requester_peer);
        relay
            .acknowledge(opened.action_id, true)
            .expect("opened delivered");
        let event = requester
            .handle(&relay_peer, &opened.route.packet, NOW + 1)
            .expect("opened admitted")
            .expect("opened event");
        let HnsrRequesterEvent::Opened { circuit_id, .. } = event else {
            panic!("unexpected requester event");
        };
        (requester, relay, circuit_id)
    }

    fn pending_open() -> (
        HnsrService,
        HnsrRequester,
        OpaqueRelayRuntime,
        HnsrPacket,
        [u8; 8],
    ) {
        let (service, ticket) = confirmed_reservation();
        let mut requester =
            HnsrRequester::new([40; 16], 1, requester_config(), NOW).expect("requester");
        let open = requester
            .begin_open(
                peer("relay"),
                ticket.relay_key,
                ticket,
                NOW,
                NOW + 5,
                DEFAULT_WINDOW,
            )
            .expect("open");
        let requester_context = open.packet.context_id;
        let mut relay =
            OpaqueRelayRuntime::new([41; 16], 1, OpaqueRelayConfig::default(), NOW)
                .expect("relay runtime");
        let incoming = relay
            .handle(
                service.relay().expect("relay reservations"),
                &peer("requester"),
                &open.packet,
                NOW,
            )
            .expect("open admitted")
            .pop()
            .expect("incoming");
        relay
            .acknowledge(incoming.action_id, true)
            .expect("incoming delivered");
        (
            service,
            requester,
            relay,
            incoming.route.packet,
            requester_context,
        )
    }

    #[test]
    fn requester_and_opaque_relay_bind_peers_credit_queues_and_bytes() {
        let (service, ticket) = confirmed_reservation();
        let (mut requester, mut relay, circuit_id) = open_circuit(&service, ticket);
        let requester_peer = peer("requester");
        let endpoint_peer = peer("endpoint");
        let relay_peer = peer("relay");

        let outbound = requester
            .send_data(circuit_id, vec![7; MAX_DATA_SIZE])
            .expect("requester data");
        let forwarded = relay
            .handle(
                service.relay().expect("relay reservations"),
                &requester_peer,
                &outbound.packet,
                NOW + 1,
            )
            .expect("data forwarded")
            .pop()
            .expect("data route");
        assert_eq!(forwarded.route.destination, endpoint_peer);
        assert_eq!(relay.status().queued_bytes, MAX_DATA_SIZE);
        relay
            .acknowledge(forwarded.action_id, true)
            .expect("data delivered");
        assert_eq!(relay.status().queued_bytes, 0);

        let inbound = HnsrPacket::new(
            HnsrOpcode::Data,
            circuit_id,
            DataBody {
                bytes: vec![8; 1024],
            }
            .encode()
            .expect("data body"),
        )
        .expect("data packet");
        let forwarded = relay
            .handle(
                service.relay().expect("relay reservations"),
                &endpoint_peer,
                &inbound,
                NOW + 1,
            )
            .expect("inbound forwarded")
            .pop()
            .expect("inbound route");
        relay
            .acknowledge(forwarded.action_id, true)
            .expect("inbound delivered");
        let event = requester
            .handle(&relay_peer, &forwarded.route.packet, NOW + 1)
            .expect("inbound admitted")
            .expect("data event");
        assert!(matches!(
            event,
            HnsrRequesterEvent::DataAvailable {
                queued_bytes: 1024,
                ..
            }
        ));
        let (bytes, window) = requester.take_data(circuit_id).expect("consume data");
        assert_eq!(bytes, vec![8; 1024]);
        let window_route = relay
            .handle(
                service.relay().expect("relay reservations"),
                &requester_peer,
                &window.packet,
                NOW + 1,
            )
            .expect("window forwarded")
            .pop()
            .expect("window route");
        assert_eq!(window_route.route.destination, endpoint_peer);
    }

    #[test]
    fn wrong_peers_failed_writes_and_stale_actions_fail_closed() {
        let (service, ticket) = confirmed_reservation();
        let requester_peer = peer("requester");
        let endpoint_peer = peer("endpoint");
        let wrong_peer = peer("wrong");
        let mut requester =
            HnsrRequester::new([20; 16], 1, requester_config(), NOW).expect("requester");
        let open = requester
            .begin_open(
                peer("relay"),
                ticket.relay_key,
                ticket,
                NOW,
                NOW + 5,
                DEFAULT_WINDOW,
            )
            .expect("open");
        let mut relay = OpaqueRelayRuntime::new([21; 16], 1, OpaqueRelayConfig::default(), NOW)
            .expect("opaque relay");
        let incoming = relay
            .handle(
                service.relay().expect("relay reservations"),
                &requester_peer,
                &open.packet,
                NOW,
            )
            .expect("open admitted")
            .pop()
            .expect("incoming");
        let accept = HnsrPacket::new(
            HnsrOpcode::Accept,
            incoming.route.packet.context_id,
            AcceptBody {
                accepted_window: DEFAULT_WINDOW,
                endpoint_nonce: [22; 16],
            }
            .encode()
            .expect("accept body"),
        )
        .expect("accept packet");
        assert!(matches!(
            relay.handle(
                service.relay().expect("relay reservations"),
                &wrong_peer,
                &accept,
                NOW + 1,
            ),
            Err(HnsrRuntimeError::WrongPeer)
        ));
        assert_eq!(relay.status().pending_circuits, 1);
        relay
            .handle(
                service.relay().expect("relay reservations"),
                &endpoint_peer,
                &accept,
                NOW + 1,
            )
            .expect("valid endpoint remains admissible");
        let old_action = incoming.action_id;
        relay
            .replace_enabled(1, false)
            .expect("disable and revoke");
        assert!(matches!(
            relay.acknowledge(old_action, true),
            Err(HnsrRuntimeError::StaleGeneration)
        ));
        assert_eq!(relay.status().active_circuits, 0);
    }

    #[test]
    fn pending_terminal_packets_translate_requester_and_relay_contexts() {
        let (service, mut requester, mut relay, incoming, requester_context) = pending_open();
        let relay_circuit_id = incoming.context_id;
        assert_ne!(relay_circuit_id, requester_context);
        let cancellation = requester
            .cancel_open(
                requester_context,
                HnsrErrorCode::Normal as u16,
                "request cancelled",
            )
            .expect("request cancellation");
        let forwarded = relay
            .handle(
                service.relay().expect("relay reservations"),
                &peer("requester"),
                &cancellation.packet,
                NOW + 1,
            )
            .expect("cancellation admitted")
            .pop()
            .expect("endpoint cancellation");
        assert_eq!(forwarded.route.destination, peer("endpoint"));
        assert_eq!(forwarded.route.packet.context_id, relay_circuit_id);
        assert_eq!(relay.status().pending_circuits, 0);
        assert!(matches!(
            relay.handle(
                service.relay().expect("relay reservations"),
                &peer("requester"),
                &cancellation.packet,
                NOW + 1,
            ),
            Err(HnsrRuntimeError::UnknownCircuit)
        ));

        let (service, mut requester, mut relay, incoming, requester_context) = pending_open();
        let endpoint_error = error_packet(
            incoming.context_id,
            HnsrErrorCode::Refused as u16,
            "endpoint refused",
        )
        .expect("endpoint error");
        let requester_error = relay
            .handle(
                service.relay().expect("relay reservations"),
                &peer("endpoint"),
                &endpoint_error,
                NOW + 1,
            )
            .expect("endpoint error admitted")
            .pop()
            .expect("requester error");
        assert_eq!(requester_error.route.destination, peer("requester"));
        assert_eq!(requester_error.route.packet.context_id, requester_context);
        assert!(matches!(
            requester
                .handle(&peer("relay"), &requester_error.route.packet, NOW + 1)
                .expect("requester error"),
            Some(HnsrRequesterEvent::Closed { context_id, .. })
                if context_id == requester_context
        ));
        assert_eq!(requester.status().pending_circuits, 0);
        assert_eq!(relay.status().queued_actions, 1);
        assert!(relay.disconnect(&peer("requester")).is_empty());
        assert_eq!(relay.status().queued_actions, 0);

        let (_service, mut requester, mut relay, _incoming, requester_context) = pending_open();
        let disconnected = relay.disconnect(&peer("endpoint"));
        assert_eq!(disconnected.len(), 1);
        assert_eq!(disconnected[0].route.destination, peer("requester"));
        assert_eq!(disconnected[0].route.packet.context_id, requester_context);
        assert!(matches!(
            requester
                .handle(&peer("relay"), &disconnected[0].route.packet, NOW + 1)
                .expect("endpoint disconnect close"),
            Some(HnsrRequesterEvent::Closed { context_id, .. })
                if context_id == requester_context
        ));
        assert_eq!(requester.status().pending_circuits, 0);
        let (_service, _requester, mut relay, incoming, _requester_context) = pending_open();
        let disconnected = relay.disconnect(&peer("requester"));
        assert_eq!(disconnected.len(), 1);
        assert_eq!(disconnected[0].route.destination, peer("endpoint"));
        assert_eq!(disconnected[0].route.packet.context_id, incoming.context_id);
    }

    #[test]
    fn inflight_actions_are_bounded_globally_per_circuit_and_per_peer() {
        let route = |context_id| {
            close_packet(context_id, HnsrErrorCode::Normal as u16, "bounded action")
                .expect("close")
        };
        let config = OpaqueRelayConfig {
            maximum_inflight_actions: 2,
            maximum_inflight_actions_per_circuit: 2,
            maximum_inflight_actions_per_peer: 2,
            ..OpaqueRelayConfig::default()
        };
        let mut global = OpaqueRelayRuntime::new([50; 16], 1, config, NOW).expect("relay");
        global
            .queue_control(peer("a"), [1; 8], route([1; 8]), InflightKind::Control)
            .expect("global one");
        global
            .queue_control(peer("b"), [2; 8], route([2; 8]), InflightKind::Control)
            .expect("global two");
        assert!(matches!(
            global.queue_control(peer("c"), [3; 8], route([3; 8]), InflightKind::Control),
            Err(HnsrRuntimeError::Capacity)
        ));

        let config = OpaqueRelayConfig {
            maximum_inflight_actions: 4,
            maximum_inflight_actions_per_circuit: 2,
            maximum_inflight_actions_per_peer: 2,
            ..OpaqueRelayConfig::default()
        };
        let mut per_peer = OpaqueRelayRuntime::new([51; 16], 1, config, NOW).expect("relay");
        for context in [[1; 8], [2; 8]] {
            per_peer
                .queue_control(
                    peer("same"),
                    context,
                    route(context),
                    InflightKind::Control,
                )
                .expect("peer action");
        }
        assert!(matches!(
            per_peer.queue_control(
                peer("same"),
                [3; 8],
                route([3; 8]),
                InflightKind::Control,
            ),
            Err(HnsrRuntimeError::Capacity)
        ));

        let mut per_circuit = OpaqueRelayRuntime::new([52; 16], 1, config, NOW).expect("relay");
        per_circuit
            .queue_control(peer("a"), [4; 8], route([4; 8]), InflightKind::Control)
            .expect("circuit one");
        per_circuit
            .queue_control(peer("b"), [4; 8], route([4; 8]), InflightKind::Control)
            .expect("circuit two");
        assert!(matches!(
            per_circuit.queue_control(
                peer("c"),
                [4; 8],
                route([4; 8]),
                InflightKind::Control,
            ),
            Err(HnsrRuntimeError::Capacity)
        ));

        let (service, ticket) = confirmed_reservation();
        let (requester, mut relay, circuit_id) =
            open_circuit_with_config(&service, ticket, config);
        let window = HnsrPacket::new(
            HnsrOpcode::Window,
            circuit_id,
            WindowBody { credit_delta: 1 }.encode().expect("window"),
        )
        .expect("window packet");
        let first = relay
            .handle(
                service.relay().expect("relay reservations"),
                &peer("requester"),
                &window,
                NOW + 1,
            )
            .expect("first window")
            .pop()
            .expect("first route");
        let _second = relay
            .handle(
                service.relay().expect("relay reservations"),
                &peer("requester"),
                &window,
                NOW + 1,
            )
            .expect("second window");
        assert!(matches!(
            relay.handle(
                service.relay().expect("relay reservations"),
                &peer("requester"),
                &window,
                NOW + 1,
            ),
            Err(HnsrRuntimeError::Capacity)
        ));
        assert_eq!(relay.status().queued_actions, 2);
        assert_eq!(
            relay.circuits.get(&circuit_id).expect("circuit").endpoint_credit,
            DEFAULT_WINDOW + 2
        );
        relay
            .acknowledge(first.action_id, true)
            .expect("release action");
        relay
            .handle(
                service.relay().expect("relay reservations"),
                &peer("requester"),
                &window,
                NOW + 1,
            )
            .expect("window after acknowledgement");
        assert_eq!(
            relay.circuits.get(&circuit_id).expect("circuit").endpoint_credit,
            DEFAULT_WINDOW + 3
        );
        assert_eq!(requester.status().active_circuits, 1);
    }

    #[test]
    fn snapshots_round_trip_exact_settings_and_restore_without_live_authority() {
        let (service, ticket) = confirmed_reservation();
        let mut requester =
            HnsrRequester::new([30; 16], 7, requester_config(), NOW).expect("requester");
        let open = requester
            .begin_open(
                peer("relay"),
                ticket.relay_key,
                ticket,
                NOW,
                NOW + 5,
                DEFAULT_WINDOW,
            )
            .expect("pending open");
        let snapshot = requester.snapshot();
        let encoded = snapshot.encode();
        assert_eq!(HnsrRequesterSnapshot::decode(&encoded).expect("snapshot"), snapshot);
        let restored = HnsrRequester::restore(snapshot.clone(), [31; 16], 7, NOW + 1)
            .expect("fresh restore");
        assert_eq!(restored.status().generation, 8);
        assert_eq!(restored.status().pending_circuits, 0);
        assert_eq!(restored.status().revoked_work, 1);
        assert_eq!(restored.status().trusted_time_high_water, NOW + 1);

        requester
            .replace_enabled(7, false)
            .expect("later requester opt-out");
        let disabled_requester = requester.snapshot();
        assert!(matches!(
            HnsrRequester::restore(snapshot, [36; 16], 8, NOW + 1),
            Err(HnsrRuntimeError::StaleGeneration)
        ));
        assert!(matches!(
            HnsrRequester::restore(disabled_requester.clone(), [37; 16], 8, NOW - 1),
            Err(HnsrRuntimeError::ClockRollback)
        ));
        let disabled_requester =
            HnsrRequester::restore(disabled_requester, [38; 16], 8, NOW + 1)
                .expect("latest opt-out restore");
        assert!(!disabled_requester.status().enabled);
        assert_eq!(disabled_requester.status().generation, 9);

        let mut corrupt = encoded;
        corrupt[40] ^= 1;
        assert!(matches!(
            HnsrRequesterSnapshot::decode(&corrupt),
            Err(HnsrRuntimeError::CorruptSnapshot)
        ));

        let mut relay = OpaqueRelayRuntime::new([32; 16], 4, OpaqueRelayConfig::default(), NOW)
            .expect("opaque relay");
        let _incoming = relay
            .handle(
                service.relay().expect("relay reservations"),
                &peer("requester"),
                &open.packet,
                NOW,
            )
            .expect("pending relay open");
        let relay_snapshot = relay.snapshot();
        let relay_encoded = relay_snapshot.encode();
        assert_eq!(
            OpaqueRelaySnapshot::decode(&relay_encoded).expect("relay snapshot"),
            relay_snapshot
        );
        let restored_relay =
            OpaqueRelayRuntime::restore(relay_snapshot, [33; 16], 4, NOW + 1)
                .expect("relay restore");
        assert!(restored_relay.status().enabled);
        assert_eq!(restored_relay.status().generation, 5);
        assert_eq!(restored_relay.status().pending_circuits, 0);
        assert_eq!(restored_relay.status().active_circuits, 0);
        assert_eq!(restored_relay.status().revoked_work, 2);

        let mut disabled =
            OpaqueRelayRuntime::new([34; 16], 9, OpaqueRelayConfig::default(), NOW)
                .expect("relay");
        disabled
            .replace_enabled(9, false)
            .expect("persistent opt-out");
        let disabled = OpaqueRelayRuntime::restore(
            OpaqueRelaySnapshot::decode(&disabled.snapshot().encode()).expect("disabled snapshot"),
            [35; 16],
            10,
            NOW + 1,
        )
        .expect("disabled restore");
        assert!(!disabled.status().enabled);
        assert_eq!(disabled.status().generation, 11);

        let (rollback_service, _requester, mut rollback_relay, incoming, _) = pending_open();
        let rollback = close_packet(
            incoming.context_id,
            HnsrErrorCode::Normal as u16,
            "rollback",
        )
        .expect("close");
        assert!(matches!(
            rollback_relay.handle(
                rollback_service.relay().expect("relay reservations"),
                &peer("endpoint"),
                &rollback,
                NOW - 1,
            ),
            Err(HnsrRuntimeError::ClockRollback)
        ));

        let (_service, ticket) = confirmed_reservation();
        let mut rollback_requester =
            HnsrRequester::new([39; 16], 1, requester_config(), NOW).expect("requester");
        assert!(matches!(
            rollback_requester.begin_open(
                peer("relay"),
                ticket.relay_key,
                ticket,
                NOW - 1,
                NOW + 1,
                DEFAULT_WINDOW,
            ),
            Err(HnsrRuntimeError::ClockRollback)
        ));
    }
}
